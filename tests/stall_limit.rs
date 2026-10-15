// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the limit on the total time that images may stall for via Stall(), which the embedder
//! may impose via EfiContext::set_stall_limit(). These live in a separate test binary, given that
//! the limit applies to all subsequent calls to Stall().

mod common;
use common::*;

use core::ffi::c_void;
use core::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

static CHILD_IMAGE: AtomicUsize = AtomicUsize::new(0);
static CHILD_IMAGE_SIZE: AtomicUsize = AtomicUsize::new(0);
/// The number of calls to Stall() that returned to the child image
static CHILD_STALLS: AtomicUsize = AtomicUsize::new(0);
/// Set if the child image resumed after a call to Stall() failed
static CHILD_RESUMED: AtomicBool = AtomicBool::new(false);
/// The status that StartImage() returned to the parent image for the child image
static CHILD_START_STATUS: AtomicUsize = AtomicUsize::new(0);
/// Set if the parent image resumed after its call to Stall()
static PARENT_RESUMED: AtomicBool = AtomicBool::new(false);

/// An image entry point that stalls for a second at a time, up to a minute in total
extern "efiapi" fn child_entry(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: The system table pointer passed to the entry point is valid, and so is the boot
    // services table pointer it holds.
    let bs = unsafe { ptr::read((*system_table).boot_services) };
    for _ in 0..60 {
        // SAFETY: Stall() takes no pointer arguments.
        let status = unsafe { (bs.stall)(1_000_000) };
        if status != Status::EFI_SUCCESS {
            CHILD_RESUMED.store(true, SeqCst);
            return status;
        }
        CHILD_STALLS.fetch_add(1, SeqCst);
    }
    Status::EFI_SUCCESS
}

/// An image entry point that loads and starts a child image from the buffer described by
/// CHILD_IMAGE and CHILD_IMAGE_SIZE, and then stalls for a second, like images that give the user
/// a chance to read an error message before returning do.
extern "efiapi" fn parent_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: The system table pointer passed to the entry point is valid, and so is the boot
    // services table pointer it holds. CHILD_IMAGE points to a buffer of CHILD_IMAGE_SIZE bytes.
    let status = unsafe {
        let bs = ptr::read((*system_table).boot_services);
        let mut child = 0;
        let status = (bs.load_image)(
            0,
            image_handle,
            ptr::null_mut(),
            CHILD_IMAGE.load(SeqCst) as *mut c_void,
            CHILD_IMAGE_SIZE.load(SeqCst),
            &mut child,
        );
        if status != Status::EFI_SUCCESS {
            return status;
        }

        let mut exit_data_size = 0;
        let mut exit_data = ptr::null_mut();
        let status = (bs.start_image)(child, &mut exit_data_size, &mut exit_data);
        CHILD_START_STATUS.store(status.0, SeqCst);

        (bs.stall)(1_000_000)
    };
    PARENT_RESUMED.store(true, SeqCst);
    status
}

/// The image that exceeds the stall limit is terminated, as if it had called Exit() with
/// EFI_TIMEOUT, which is what StartImage() returns to its parent. So is every image that calls
/// Stall() after that, so that a parent image that keeps stalling after its child image has been
/// terminated cannot hang the embedder either.
#[test]
fn images_exceeding_the_stall_limit_are_terminated() {
    let efi = setup();
    efi.context().set_stall_limit(10_000_000);

    let child = pe_image(child_entry);
    CHILD_IMAGE.store(child.as_ptr() as usize, SeqCst);
    CHILD_IMAGE_SIZE.store(child.len(), SeqCst);

    let parent = efi.load_image(&pe_image(parent_entry)).unwrap();
    let mut exit_data_size = 0;
    let mut exit_data = ptr::null_mut();
    // SAFETY: All pointers are valid.
    let status = unsafe { (efi.bs().start_image)(parent, &mut exit_data_size, &mut exit_data) };

    // The child image was terminated by the call to Stall() that exceeded the limit
    assert_eq!(CHILD_STALLS.load(SeqCst), 10);
    assert!(!CHILD_RESUMED.load(SeqCst));
    assert_eq!(Status(CHILD_START_STATUS.load(SeqCst)), Status::EFI_TIMEOUT);

    // The parent image was terminated by its subsequent call to Stall()
    assert!(!PARENT_RESUMED.load(SeqCst));
    assert_eq!(status, Status::EFI_TIMEOUT);
}
