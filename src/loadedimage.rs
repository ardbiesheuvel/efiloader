// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::efi_system_table;
use crate::guid;
use crate::memmap;
use crate::new_handle;
use crate::EfiContext;
use crate::EfiProtocol;
use crate::PeImage;
use crate::ProtocolDb;
use crate::ProtocolOwner;
use crate::{memorytype::*, status::*, systemtable::*, Char16, Guid, Handle};

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::Cell;
use core::marker::PhantomPinned;
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

pub const EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID: Guid = guid!(
    0xbc62157e,
    0x3e33,
    0x4fec,
    [0x99, 0x20, 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf]
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
    /// The copy of the device path that `file_path` points to, if any
    file_path_buf: Option<Box<[u8]>>,
    /// Whether the image has been started, which may only happen once
    started: Cell<bool>,
    /// The size of and the pointer to the exit data that the image passed to Exit(), if any, which
    /// StartImage() passes back to its caller
    pub(crate) exit_data: Cell<(usize, *mut Char16)>,
    // EFI images hold pointers to this instance, so it must not be moved, and references to it
    // must not be assumed to be unique
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
    ctx: &'static EfiContext,
    load_options: Vec<u16>,
}

/// Describes where an image originates from, which is recorded in its loaded image protocol
#[derive(Default)]
pub(crate) struct ImageOrigin {
    /// The handle of the image that loaded the image, or 0 if it was loaded by the embedder
    pub(crate) parent: Handle,
    /// The handle of the device that the image was loaded from, or 0 if unknown
    pub(crate) device_handle: Handle,
    /// A copy of the device path of the image file relative to the device it was loaded from, if
    /// any
    pub(crate) file_path: Option<Box<[u8]>>,
}

/// Returns a pointer to the loaded image protocol instance of the image with handle `handle`, if
/// it is an image that was loaded by the EFI runtime. (Loaded image protocols installed by EFI
/// images are not EfiLoadedImage instances.) The instance remains valid until the image is
/// unloaded, which only happens to images that have not been started.
pub(crate) fn find_loaded_image(db: &ProtocolDb, handle: Handle) -> Option<*const EfiLoadedImage> {
    db.get(&(handle, EFI_LOADED_IMAGE_PROTOCOL_GUID))
        .filter(|p| p.owner == ProtocolOwner::Runtime)
        .map(|p| p.as_proto_ptr() as *const EfiLoadedImage)
}

impl LoadedImageData {
    pub(crate) fn new<'b>(
        ctx: &'static EfiContext,
        pe_image: &'b PeImage,
        code_type: EfiMemoryType,
        data_type: EfiMemoryType,
        randomized: bool,
        origin: ImageOrigin,
    ) -> Option<LoadedImageData> {
        let handle: Handle = new_handle();
        let file_path = origin
            .file_path
            .as_ref()
            .map_or(ptr::null(), |fp| fp.as_ptr() as *const ());
        let li = Box::pin(EfiLoadedImage {
            revision: EFI_LOADED_IMAGE_PROTOCOL_REVISION,
            parent_handle: origin.parent,
            system_table: efi_system_table(),
            device_handle: origin.device_handle,
            file_path,
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
            file_path_buf: origin.file_path,
            started: Cell::new(false),
            exit_data: Cell::new((0, ptr::null_mut())),
            pin: PhantomPinned,
        });

        ctx.install_pinned_protocol(handle, li, ProtocolOwner::Runtime)
            .ok()?;
        let lid = LoadedImageData {
            image_handle: handle,
            ctx: ctx,
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

    /// Invokes `f` on the loaded image protocol instance of the image, and returns the result,
    /// unless the image has been unloaded, in which case None is returned.
    fn with_loaded_image<R>(&self, f: impl FnOnce(&EfiLoadedImage) -> R) -> Option<R> {
        let li = find_loaded_image(&self.ctx.protocol_db.borrow(), self.image_handle)?;
        // SAFETY: `li` points to the pinned EfiLoadedImage that new() installed into the protocol
        // database as a runtime owned entry, which is only uninstalled when the image is unloaded.
        // This cannot happen while `f` runs: either `f` does not call into the EFI runtime, or it
        // starts the image, after which it can no longer be unloaded. Only shared references to
        // the instance are ever created, given that EFI images hold pointers to it too.
        Some(f(unsafe { &*li }))
    }
}

impl Drop for LoadedImageData {
    fn drop(&mut self) {
        // The load options are about to be freed
        self.with_loaded_image(|li| {
            li.load_options.set(ptr::null());
            li.load_options_size.set(0);
        });
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
        let previous = self.ctx.current_image.replace(self.image_handle);
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
        self.ctx.current_image.set(previous);
        self.ctx.memmap.free_pool(stack).ok();
        ret
    }
}

impl LoadedImageData {
    pub fn set_load_options(&mut self, load_options: Vec<u16>) {
        self.load_options = load_options;

        let p = self.load_options.as_ptr() as *const ();
        let size = (self.load_options.len() * core::mem::size_of::<u16>()) as u32;
        self.with_loaded_image(|li| {
            li.load_options.set(p);
            li.load_options_size.set(size);
        });
    }

    pub fn start_image(&mut self) -> Status {
        // Images that have been unloaded no longer exist
        self.with_loaded_image(|li| li.start_image())
            .unwrap_or(Status::EFI_INVALID_PARAMETER)
    }
}

impl EfiContext {
    /// Unloads the image with handle `handle`, provided that it has not been started, by
    /// uninstalling the protocols that the EFI runtime installed onto the image handle, and freeing
    /// the memory occupied by the image. Returns EFI_INVALID_PARAMETER if `handle` is not the handle
    /// of an image loaded by the EFI runtime, and EFI_UNSUPPORTED if the image has been started.
    pub(crate) fn unload_image(&self, handle: Handle) -> Result<(), Status> {
        let mut db = self.protocol_db.borrow_mut();
        let li = find_loaded_image(&db, handle).ok_or(Status::EFI_INVALID_PARAMETER)?;
        // SAFETY: `li` points to the EfiLoadedImage instance of the image, which remains valid
        // until it is uninstalled below.
        let (started, base, size) =
            unsafe { ((*li).started.get(), (*li).image_base, (*li).image_size) };
        if started {
            return Err(Status::EFI_UNSUPPORTED);
        }

        // Uninstall the loaded image protocol, along with the other protocols that the EFI runtime
        // installed onto the image handle. Protocols installed by others are left alone.
        db.retain(|k, e| k.0 != handle || e.owner != ProtocolOwner::Runtime);
        drop(db);

        // Lift the restrictions on the permissions of the memory occupied by the image that were
        // applied when it was loaded, and free it. If the former fails, leak the memory rather than
        // hand it out again with restricted permissions.
        let pages = memmap::size_to_pages(size as usize);
        let range = base as usize..base as usize + (pages << EFI_PAGE_SHIFT);
        if self
            .mapper
            .remap_range(&range, 0, EFI_MEMORY_RO | EFI_MEMORY_XP)
            .is_ok()
        {
            // This cannot fail, given that the pages were allocated when the image was loaded
            self.memmap.free_pages(base as u64, pages).ok();
        }
        Ok(())
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
core::arch::global_asm!(include_str!("start_image_aarch64.S"));
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("start_image_x86_64.S"));
