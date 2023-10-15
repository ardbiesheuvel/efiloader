// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::efi_system_table;
use crate::guid;
use crate::new_handle;
use crate::EfiContext;
use crate::EfiProtocol;
use crate::PeImage;
use crate::{memorytype::*, status::*, systemtable::*, Guid, Handle};

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;

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

const EFI_LOADED_IMAGE_PROTOCOL_REVISION: u32 = 0x1000;

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
    pub reserved: usize,
    load_options_size: u32,
    load_options: *const (),
    image_base: *const (),
    image_size: u64,
    image_code_type: EfiMemoryType,
    image_data_type: EfiMemoryType,
    unload: ImageUnload,

    ctx: &'static EfiContext,
    image_handle: Handle,
    entrypoint: *const u8,
}
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

pub struct LoadedImageData {
    pub image_handle: Handle,
    loaded_image: *mut EfiLoadedImage,
    load_options: Vec<u16>,
}

impl LoadedImageData {
    pub(crate) fn new<'b>(
        ctx: &'static EfiContext,
        pe_image: &'b PeImage,
        code_type: EfiMemoryType,
        data_type: EfiMemoryType,
        randomized: bool,
    ) -> LoadedImageData {
        let handle: Handle = new_handle();
        let li = Box::new(EfiLoadedImage {
            revision: EFI_LOADED_IMAGE_PROTOCOL_REVISION,
            parent_handle: 0,
            system_table: efi_system_table(),
            device_handle: 0,
            file_path: ptr::null(),
            reserved: usize::MAX,
            load_options_size: 0,
            load_options: ptr::null(),
            image_base: pe_image.image_base(),
            image_size: pe_image.image_size(),
            image_code_type: code_type,
            image_data_type: data_type,
            unload: unload,

            ctx: ctx,
            image_handle: handle,
            entrypoint: pe_image.entry_point(),
        });
        let p = &*li as *const _;

        ctx.install_pinned_protocol(handle, Box::into_pin(li));
        let lid = LoadedImageData {
            image_handle: handle,
            loaded_image: p as _,
            load_options: Vec::new(),
        };
        if randomized {
            ctx.install_protocol(Some(handle), RandomizedImage {});
        }
        lid
    }
}

impl Drop for LoadedImageData {
    fn drop(&mut self) {
        let loaded_image = unsafe { &mut *self.loaded_image };
        loaded_image.load_options = ptr::null();
        loaded_image.load_options_size = 0;
    }
}

impl EfiLoadedImage {
    pub fn start_image(&self) -> Status {
        const EFI_STACK_SIZE: usize = 128 * 1024;

        let stack = {
            let s = self
                .ctx
                .allocate_pool(EfiMemoryType::EfiBootServicesData, EFI_STACK_SIZE);
            if s.is_err() {
                return Status::EFI_OUT_OF_RESOURCES;
            }
            s.unwrap().as_ptr()
        };

        let ret = unsafe {
            start_image(
                self.image_handle,
                efi_system_table(),
                self.entrypoint as _,
                &self.reserved,
                stack.offset(EFI_STACK_SIZE as isize),
            )
        };
        self.ctx.free_pool(stack).ok();
        ret
    }
}

impl LoadedImageData {
    pub fn set_load_options(&mut self, load_options: Vec<u16>) {
        self.load_options = load_options;

        let c = &self.load_options;
        let loaded_image = unsafe { &mut *self.loaded_image };
        loaded_image.load_options = c.as_ptr() as *const ();
        loaded_image.load_options_size = (c.len() * core::mem::size_of::<u16>()) as u32;
    }

    pub fn start_image(&mut self) -> Status {
        let loaded_image = unsafe { &mut *self.loaded_image };
        loaded_image.start_image()
    }
}

extern "C" {
    fn start_image(
        image_handle: Handle,
        system_table: *const SystemTable,
        entrypoint: *const (),
        sp_buffer: *const usize,
        stack: *mut u8,
    ) -> Status;

    pub fn exit_image(status: Status, sp: usize) -> !;
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("start_image_aarch64.s"));
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("start_image_x86_64.s"));
