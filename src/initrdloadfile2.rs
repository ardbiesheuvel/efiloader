// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::devicepath::EFI_DEVICE_PATH_PROTOCOL_GUID;
use crate::devicepath::{DevicePath, VendorMedia};
use crate::devicepath::{DevicePathSubtype::*, DevicePathType::*};
use crate::EfiContext;
use crate::EfiProtocol;
use crate::FileLoader;
use crate::{guid, Guid};
use crate::{status::*, Bool};

use alloc::boxed::Box;
use core::{ffi::c_void, mem::*};

pub const EFI_LOAD_FILE2_PROTOCOL_GUID: Guid = guid!(
    0x4006c0c1,
    0xfcb3,
    0x403e,
    [0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d]
);

type LoadFile = extern "efiapi" fn(
    *mut EfiLoadFile2,
    *const DevicePath,
    Bool,
    *mut usize,
    *mut c_void,
) -> Status;

#[repr(C)]
pub struct EfiLoadFile2 {
    load_file: LoadFile,
    loader: Box<dyn FileLoader + Send + 'static>,
}

impl EfiProtocol for EfiLoadFile2 {
    fn guid(&self) -> &'static Guid {
        &EFI_LOAD_FILE2_PROTOCOL_GUID
    }
}

#[repr(C)]
struct InitrdDevicePath {
    vendor: VendorMedia,
    end: DevicePath,
}

impl EfiProtocol for InitrdDevicePath {
    fn guid(&self) -> &'static Guid {
        &EFI_DEVICE_PATH_PROTOCOL_GUID
    }
}

const LINUX_EFI_INITRD_MEDIA_GUID: Guid = guid!(
    0x5568e427,
    0x68fc,
    0x4f3d,
    [0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68]
);

extern "efiapi" fn load_file(
    this: *mut EfiLoadFile2,
    file_path: *const DevicePath,
    boot_policy: Bool,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if boot_policy != 0 {
        return Status::EFI_UNSUPPORTED;
    }

    if buffer_size.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let file_path = unsafe { &*file_path };
    if file_path._type != EFI_DEV_END_PATH {
        return Status::EFI_NOT_FOUND;
    }

    let this = unsafe { &mut *this };
    let filesize = this.loader.get_size();

    let buffer_size = unsafe { &mut *buffer_size };
    if *buffer_size < filesize || buffer.is_null() {
        *buffer_size = filesize;
        return Status::EFI_BUFFER_TOO_SMALL;
    }

    let buffer =
        unsafe { core::slice::from_raw_parts_mut(buffer as *mut MaybeUninit<u8>, filesize) };

    if let Ok(_) = this.loader.load_file(buffer) {
        *buffer_size = filesize;
        Status::EFI_SUCCESS
    } else {
        Status::EFI_DEVICE_ERROR
    }
}

/// Installs the EfiLoadFile2 protocol and the DevicePath protocol on a new handle, taking
/// ownership of [`loader`] and exposing the initrd it carries via LoadFile2 using the
/// VendorMedia device path known to Linux.
pub(crate) fn install(ctx: &EfiContext, loader: impl FileLoader + Send + 'static) {
    let lf = EfiLoadFile2 {
        load_file,
        loader: Box::new(loader),
    };
    let handle = ctx.install_protocol(None, lf);
    ctx.install_protocol(
        Some(handle),
        InitrdDevicePath {
            vendor: VendorMedia {
                header: DevicePath {
                    _type: EFI_DEV_MEDIA,
                    subtype: EFI_DEV_MEDIA_VENDOR,
                    size: size_of::<VendorMedia>() as u16,
                },
                vendor_guid: LINUX_EFI_INITRD_MEDIA_GUID,
            },
            end: DevicePath {
                _type: EFI_DEV_END_PATH,
                subtype: EFI_DEV_END_ENTIRE,
                size: size_of::<DevicePath>() as u16,
            },
        },
    );
}
