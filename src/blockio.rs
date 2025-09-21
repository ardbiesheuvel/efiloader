// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::status::*;
use crate::EfiProtocol;
use crate::FileLoader;
use crate::Lba;
use crate::{guid, Bool, Guid};

use alloc::boxed::Box;
use core::ffi::c_void;

const EFI_BLOCK_IO_PROTOCOL_REVISION: u64 = 0x00010000;

const EFI_BLOCK_IO_PROTOCOL_GUID: Guid = guid!("964e5b21-6459-11d2-8e39-00a0c969723b");

/// EFI_BLOCK_IO_MEDIA - refer to the UEFI specification for the meaning of individual fields.
#[repr(C)]
pub struct EfiBlockIoMedia {
    pub media_id: u32,
    pub removable_media: Bool,
    pub media_present: Bool,
    pub logical_partition: Bool,
    pub read_only: Bool,
    pub write_caching: Bool,
    pub block_size: u32,
    pub io_align: u32,
    pub last_block: Lba,
}

/// EFI_BLOCK_IO_PROTOCOL - refer to the UEFI specification for the meaning of individual fields.
#[repr(C)]
pub struct EfiBlockIoProtocol {
    pub revision: u64,
    pub media: *mut EfiBlockIoMedia,
    pub reset: Reset<Self>,
    pub read_blocks: ReadWriteBlocks,
    pub write_blocks: ReadWriteBlocks,
    pub flush_blocks: FlushBlocks,

    loader: Box<dyn FileLoader + Send + 'static>,
    _media: Box<EfiBlockIoMedia>,
}
unsafe impl Send for EfiBlockIoProtocol {}

type Reset<T> = extern "efiapi" fn(this: *mut T, extended_verification: Bool) -> Status;

type ReadWriteBlocks = extern "efiapi" fn(
    this: *mut EfiBlockIoProtocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status;

type FlushBlocks = extern "efiapi" fn(this: *mut EfiBlockIoProtocol) -> Status;

impl EfiBlockIoProtocol {
    const BSIZE: usize = 512;

    /// Wrap a FileLoader into an implementation of the EFI block I/O protocol and return it.
    /// This permits the OS loader to access the file (or file system) if it consumes raw block I/O
    /// (e.g., GRUB on Linux)
    pub fn new(loader: impl FileLoader + Send + 'static) -> Result<Self, &'static str> {
        let size = loader.get_size();
        if size % Self::BSIZE != 0 {
            return Err("File is not aligned to sector size");
        }
        let mut m = Box::new(EfiBlockIoMedia {
            media_id: 42,
            removable_media: 0,
            media_present: 1,
            logical_partition: 0,
            read_only: 1,
            write_caching: 0,
            block_size: Self::BSIZE as u32,
            io_align: Self::BSIZE as u32,
            last_block: (size / Self::BSIZE) as u64,
        });
        Ok(EfiBlockIoProtocol {
            revision: EFI_BLOCK_IO_PROTOCOL_REVISION,
            media: &mut *m as *mut _,
            reset: reset,
            read_blocks: read_blocks,
            write_blocks: write_blocks,
            flush_blocks: flush_blocks,

            loader: Box::new(loader),
            _media: m,
        })
    }
}

impl EfiProtocol for EfiBlockIoProtocol {
    fn guid(&self) -> &'static Guid {
        &EFI_BLOCK_IO_PROTOCOL_GUID
    }
}

extern "efiapi" fn reset(_this: *mut EfiBlockIoProtocol, _extended_verification: Bool) -> Status {
    Status::EFI_SUCCESS
}

extern "efiapi" fn read_blocks(
    this: *mut EfiBlockIoProtocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    log::trace!("Calling read_blocks");
    let this = unsafe { &mut *this };
    if media_id != this._media.media_id {
        return Status::EFI_MEDIA_CHANGED;
    }
    if lba > this._media.last_block {
        return Status::EFI_INVALID_PARAMETER;
    }
    if buffer_size % EfiBlockIoProtocol::BSIZE != 0 {
        return Status::EFI_BAD_BUFFER_SIZE;
    }

    let ret = if let Ok(_) = unsafe {
        this.loader.load_range(
            buffer,
            lba as usize * EfiBlockIoProtocol::BSIZE,
            buffer_size,
        )
    } {
        Status::EFI_SUCCESS
    } else {
        Status::EFI_DEVICE_ERROR
    };
    ret
}

extern "efiapi" fn write_blocks(
    _this: *mut EfiBlockIoProtocol,
    _media_id: u32,
    _lba: Lba,
    _buffer_size: usize,
    _buffer: *mut c_void,
) -> Status {
    Status::EFI_WRITE_PROTECTED
}

extern "efiapi" fn flush_blocks(_this: *mut EfiBlockIoProtocol) -> Status {
    Status::EFI_SUCCESS
}
