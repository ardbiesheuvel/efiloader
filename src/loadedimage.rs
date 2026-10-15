// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::efi_system_table;
use crate::guid;
use crate::new_handle;
use crate::EfiContext;
use crate::EfiProtocol;
use crate::PeImage;
use crate::ProtocolOwner;
use crate::{memorytype::*, status::*, systemtable::*, Guid, Handle};

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;
use core::marker::PhantomPinned;
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const EFI_LOADED_IMAGE_PROTOCOL_GUID: Guid = guid!(
    0x5B1B31A1,
    0x9562,
    0x11d2,
    [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B]
);

pub const LINUX_EFI_LOADED_IMAGE_RAND_GUID: Guid = guid!(
    0xf5a37b6d,
    0x3344,
    0x42a5,
    [0xb6, 0xbb, 0x97, 0x86, 0x48, 0xc1, 0x89, 0x0a]
);

pub const EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID: Guid = guid!(
    0xbc62157e,
    0x3e33,
    0x4fec,
    [0x99, 0x20, 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf]
);

const EFI_LOADED_IMAGE_PROTOCOL_REVISION: u32 = 0x1000;

/// The handle of the image that is currently running, or 0 if none is
static CURRENT_IMAGE: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn current_image() -> Handle {
    CURRENT_IMAGE.load(Ordering::Relaxed)
}

type ImageUnload = extern "efiapi" fn(Handle) -> Status;

extern "efiapi" fn unload(_handle: Handle) -> Status {
    Status::EFI_UNSUPPORTED
}

#[repr(C)]
pub struct EfiLoadedImage {
    revision: u32,
    parent_handle: Handle,
    system_table: *const SystemTable,
    device_handle: Handle,
    file_path: *const (), //DevicePath,
    /// The stack pointer that start_image() recorded when entering the image, which Exit() uses
    /// to return from it. This is 0 whenever the image is not running.
    pub(crate) reserved: Cell<usize>,
    load_options_size: Cell<u32>,
    load_options: Cell<*const ()>,
    image_base: *const (),
    image_size: u64,
    image_code_type: EfiMemoryType,
    image_data_type: EfiMemoryType,
    unload: ImageUnload,

    ctx: &'static EfiContext,
    image_handle: Handle,
    entrypoint: *const u8,
    /// Whether the image has been started, which may only happen once
    started: Cell<bool>,
    // Pointers to this instance are held by LoadedImageData and by EFI images, so it must not be
    // moved, and references to it must not be assumed to be unique
    pin: PhantomPinned,
}

// SAFETY: EfiLoadedImage instances are only accessed by the EFI runtime, and by the EFI images it
// starts. EFI boot services are single threaded, so sending them to another thread cannot result
// in data races.
unsafe impl Send for EfiLoadedImage {}

impl EfiProtocol for EfiLoadedImage {
    fn guid(&self) -> &'static Guid {
        &EFI_LOADED_IMAGE_PROTOCOL_GUID
    }
}

struct RandomizedImage;
impl EfiProtocol for RandomizedImage {
    fn guid(&self) -> &'static Guid {
        &LINUX_EFI_LOADED_IMAGE_RAND_GUID
    }
}

/// The loaded image device path protocol instance of an image loaded by LoadImage(), which carries
/// a copy of the device path that was passed to LoadImage(), if any.
pub(crate) struct LoadedImageDevicePath(pub(crate) Option<Box<[u8]>>);

impl EfiProtocol for LoadedImageDevicePath {
    fn as_proto_ptr(&self) -> *const () {
        self.0
            .as_ref()
            .map_or(ptr::null(), |dp| dp.as_ptr() as *const ())
    }

    fn guid(&self) -> &'static Guid {
        &EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID
    }
}

pub struct LoadedImageData {
    pub image_handle: Handle,
    loaded_image: *const EfiLoadedImage,
    load_options: Vec<u16>,
}

impl LoadedImageData {
    pub(crate) fn new<'b>(
        ctx: &'static EfiContext,
        pe_image: &'b PeImage,
        code_type: EfiMemoryType,
        data_type: EfiMemoryType,
        randomized: bool,
        parent: Handle,
    ) -> Option<LoadedImageData> {
        let handle: Handle = new_handle();
        let li = Box::pin(EfiLoadedImage {
            revision: EFI_LOADED_IMAGE_PROTOCOL_REVISION,
            parent_handle: parent,
            system_table: efi_system_table(),
            device_handle: 0,
            file_path: ptr::null(),
            reserved: Cell::new(0),
            load_options_size: Cell::new(0),
            load_options: Cell::new(ptr::null()),
            image_base: pe_image.image_base(),
            image_size: pe_image.image_size(),
            image_code_type: code_type,
            image_data_type: data_type,
            unload: unload,

            ctx: ctx,
            image_handle: handle,
            entrypoint: pe_image.entry_point(),
            started: Cell::new(false),
            pin: PhantomPinned,
        });
        let p = &*li as *const EfiLoadedImage;

        ctx.install_pinned_protocol(handle, li, ProtocolOwner::Runtime)
            .ok()?;
        let lid = LoadedImageData {
            image_handle: handle,
            loaded_image: p,
            load_options: Vec::new(),
        };
        if randomized {
            // This can only fail if the protocol is already installed on this handle
            let _ = ctx.install_pinned_protocol(
                handle,
                Box::pin(RandomizedImage {}),
                ProtocolOwner::Runtime,
            );
        }
        Some(lid)
    }

    fn loaded_image(&self) -> &EfiLoadedImage {
        // SAFETY: `loaded_image` points to the pinned EfiLoadedImage that new() installed into the
        // protocol database as a runtime owned entry, which is never uninstalled. Only shared
        // references to it are ever created, given that EFI images hold pointers to it too.
        unsafe { &*self.loaded_image }
    }
}

impl Drop for LoadedImageData {
    fn drop(&mut self) {
        // The load options are about to be freed
        let loaded_image = self.loaded_image();
        loaded_image.load_options.set(ptr::null());
        loaded_image.load_options_size.set(0);
    }
}

impl EfiLoadedImage {
    pub fn start_image(&self) -> Status {
        const EFI_STACK_SIZE: usize = 128 * 1024;

        // Images may only be started once. This also prevents an image that is running from being
        // started again, which would clobber the stack pointer that Exit() relies on to return
        // from it.
        if self.started.get() {
            return Status::EFI_INVALID_PARAMETER;
        }

        let stack = {
            let s = self
                .ctx
                .memmap
                .allocate_pool::<u8>(EfiMemoryType::EfiBootServicesData, EFI_STACK_SIZE);
            if s.is_err() {
                return Status::EFI_OUT_OF_RESOURCES;
            }
            s.unwrap().as_ptr()
        };

        self.started.set(true);
        let previous = CURRENT_IMAGE.swap(self.image_handle, Ordering::Relaxed);
        // SAFETY: `stack` points to a 16 byte aligned pool allocation of EFI_STACK_SIZE bytes, and
        // so offsetting it by EFI_STACK_SIZE produces a suitably aligned pointer to the top of the
        // stack. `entrypoint` points to the entry point of a PE/COFF image that was loaded and
        // relocated by PeLoader, which is called with the image handle and system table pointer as
        // arguments, as the UEFI spec requires. start_image() records the stack pointer in
        // `reserved`, so that Exit() can return from start_image() via exit_image(), and clears it
        // again when the image returns.
        let ret = unsafe {
            start_image(
                self.image_handle,
                efi_system_table(),
                self.entrypoint as _,
                self.reserved.as_ptr(),
                stack.offset(EFI_STACK_SIZE as isize),
            )
        };
        CURRENT_IMAGE.store(previous, Ordering::Relaxed);
        self.ctx.memmap.free_pool(stack).ok();
        ret
    }
}

impl LoadedImageData {
    pub fn set_load_options(&mut self, load_options: Vec<u16>) {
        self.load_options = load_options;

        let c = &self.load_options;
        let loaded_image = self.loaded_image();
        loaded_image.load_options.set(c.as_ptr() as *const ());
        loaded_image
            .load_options_size
            .set((c.len() * core::mem::size_of::<u16>()) as u32);
    }

    pub fn start_image(&mut self) -> Status {
        self.loaded_image().start_image()
    }
}

unsafe extern "C" {
    fn start_image(
        image_handle: Handle,
        system_table: *const SystemTable,
        entrypoint: *const (),
        sp_buffer: *mut usize,
        stack: *mut u8,
    ) -> Status;

    pub fn exit_image(status: Status, sp: usize) -> !;
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("start_image_aarch64.s"));
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("start_image_x86_64.s"));
