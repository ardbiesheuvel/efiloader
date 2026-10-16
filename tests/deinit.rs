// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for tearing down the EFI runtime using efiloader::deinit(), and creating a new one. These
//! live in a separate test binary, as they tear down the EFI runtime that the other tests share.

mod common;
use common::*;

use core::ffi::c_void;
use core::ops::Range;
use core::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

/// Serializes the tests, as there is only a single EFI runtime at any given time
static LOCK: Mutex<()> = Mutex::new(());

/// The system table that was passed to the image that was started most recently
static SYSTEM_TABLE: AtomicUsize = AtomicUsize::new(0);

extern "efiapi" fn entry(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    SYSTEM_TABLE.store(system_table as usize, Ordering::Release);
    Status::EFI_SUCCESS
}

/// Creates an EFI runtime that uses `ram` as system RAM, and returns it along with the system table
/// that it passes to the images that it starts.
fn create_runtime(ram: &Range<usize>) -> (&'static efiloader::EfiContext, *const SystemTable) {
    let memmap = efiloader::memmap::MemoryMap::new();
    // SAFETY: The mapping is used exclusively as system RAM by the EFI runtime until it is torn
    // down, after which it is unmapped.
    unsafe { memmap.declare_memory_region(ram) }.expect("failed to declare system RAM");
    let efi = efiloader::init(None, memmap, Mapper, None::<NoRandom>)
        .expect("failed to initialize the EFI runtime");

    let mut image = efi
        .load_image(&MemFile(pe_image(entry)))
        .expect("failed to load the image");
    assert_eq!(image.start_image(), Status::EFI_SUCCESS);
    let st = SYSTEM_TABLE.load(Ordering::Acquire) as *const SystemTable;
    (efi, st)
}

/// Tears down the EFI runtime, and unmaps the memory that it used as system RAM
///
/// # Safety
///
/// The caller must not use any references to the EFI runtime or to the memory afterwards.
unsafe fn destroy_runtime(ram: Range<usize>) {
    // SAFETY: The caller guarantees that the EFI runtime is no longer used, and no images are
    // running.
    unsafe { efiloader::deinit() };
    // SAFETY: The caller guarantees that the memory is no longer used, and deinit() does not
    // access it.
    assert_eq!(
        unsafe { libc::munmap(ram.start as *mut c_void, ram.len()) },
        0
    );
}

/// Returns the GUIDs of the entries in the EFI configuration table of `st`
fn configuration_table_guids(st: *const SystemTable) -> Vec<Guid> {
    // SAFETY: `st` points to the system table of the EFI runtime, which has not been torn down.
    let st = unsafe { &*st };
    (0..st.number_of_table_entries)
        // SAFETY: The configuration table array holds NumberOfTableEntries entries.
        .map(|i| unsafe { ptr::read(st.configuration_table.add(i)) }.vendor_guid)
        .collect()
}

/// As long as the EFI runtime exists, init() returns it, and ignores its arguments.
#[test]
fn init_returns_the_existing_runtime() {
    let _guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let ram = map_ram();
    let (efi, _) = create_runtime(&ram);

    let memmap = efiloader::memmap::MemoryMap::new();
    let again = efiloader::init(None, memmap, Mapper, None::<NoRandom>);
    assert!(again.is_ok_and(|e| ptr::eq(e, efi)));

    // SAFETY: The EFI runtime and its memory are not used after this point.
    unsafe { destroy_runtime(ram) };
}

/// After deinit(), init() creates a new EFI runtime from its arguments, which carries over none of
/// the state of the previous one.
#[test]
fn deinit_permits_a_new_runtime_to_be_created() {
    let _guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let (guid, table) = (new_guid(), new_interface());

    let ram = map_ram();
    let (efi, st) = create_runtime(&ram);
    efi.install_configtable(&guid, table as *const ());
    assert!(configuration_table_guids(st).contains(&guid));
    // SAFETY: The EFI runtime and its memory are not used after this point.
    unsafe { destroy_runtime(ram) };

    let ram = map_ram();
    let (_, st) = create_runtime(&ram);
    assert!(ram.contains(&(st as usize)));
    assert!(!configuration_table_guids(st).contains(&guid));
    // SAFETY: The EFI runtime and its memory are not used after this point.
    unsafe { destroy_runtime(ram) };
}
