// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for ExitBootServices(), described in section 7.4 of the UEFI specification. These live in a
//! test binary of their own, given that boot services must no longer be used once
//! ExitBootServices() succeeds.

mod common;
use common::*;

/// ExitBootServices() returns EFI_INVALID_PARAMETER if "MapKey is incorrect", in which case
/// "GetMemoryMap() with ExitBootServices() must be called again", and EFI_SUCCESS if "Boot services
/// have been terminated".
#[test]
fn exit_boot_services() {
    let efi = setup();
    let bs = efi.bs();
    let image_handle = efi.image_handle();

    let stale = efi.memory_map().map_key;

    // Change the memory map, which changes the map key
    let mut page = 0;
    // SAFETY: `page` is a valid EFI_PHYSICAL_ADDRESS.
    let status = unsafe { (bs.allocate_pages)(ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 1, &mut page) };
    assert_eq!(status, Status::EFI_SUCCESS);

    let map_key = efi.memory_map().map_key;
    assert_ne!(map_key, stale);

    for key in [stale, map_key.wrapping_add(1), !map_key] {
        // SAFETY: ExitBootServices() takes no pointer arguments.
        let status = unsafe { (bs.exit_boot_services)(image_handle, key) };
        assert_eq!(status, Status::EFI_INVALID_PARAMETER, "{key:#x}");
    }

    // The memory map key is still current
    assert_eq!(efi.memory_map().map_key, map_key);

    // SAFETY: ExitBootServices() takes no pointer arguments.
    let status = unsafe { (bs.exit_boot_services)(image_handle, map_key) };
    assert_eq!(status, Status::EFI_SUCCESS);
}
