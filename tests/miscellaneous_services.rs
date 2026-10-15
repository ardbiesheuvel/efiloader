// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the miscellaneous boot services described in section 7.5 of the UEFI specification:
//! Stall(), CopyMem(), SetMem(), InstallConfigurationTable() and CalculateCrc32(), as well as for
//! the boot services table itself. SetWatchdogTimer() and GetNextMonotonicCount() are not covered,
//! as efiloader does not implement them.

mod common;
use common::*;

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

/// The boot services table starts with a table header, which "contains the
/// EFI_BOOT_SERVICES_SIGNATURE and EFI_BOOT_SERVICES_REVISION values along with the size of the
/// EFI_BOOT_SERVICES structure and a 32-bit CRC to verify that the contents of the EFI Boot Services
/// Table are valid".
#[test]
fn boot_services_table_header() {
    let efi = setup();
    let st = efi.system_table();
    let hdr = efi.bs().hdr;

    assert_eq!(hdr.signature, EFI_BOOT_SERVICES_SIGNATURE);
    assert_eq!(hdr.revision, st.hdr.revision);
    assert_eq!(hdr.header_size as usize, size_of::<BootServices>());
    // SAFETY: The system table points to the boot services table.
    assert!(unsafe { table_crc_is_valid(st.boot_services.cast()) });
}

/// The boot services and the configuration tables are exposed via the EFI system table, which has
/// a header with "the EFI_SYSTEM_TABLE_SIGNATURE and EFI_SYSTEM_TABLE_REVISION values along with
/// the size of the EFI_SYSTEM_TABLE structure and a 32-bit CRC to verify that the contents of the
/// EFI System Table are valid".
#[test]
fn system_table_header() {
    let efi = setup();
    let st = efi.system_table();

    assert_eq!(st.hdr.signature, EFI_SYSTEM_TABLE_SIGNATURE);
    assert_eq!(st.hdr.revision >> 16, 2);
    assert_eq!(st.hdr.header_size as usize, size_of::<SystemTable>());
    // SAFETY: The system table pointer is valid.
    assert!(unsafe { table_crc_is_valid(efi.system_table_ptr().cast()) });
    assert!(!st.boot_services.is_null());
}

static STALLED: AtomicUsize = AtomicUsize::new(0);

extern "efiapi" fn stall(microseconds: usize) -> Status {
    std::thread::sleep(Duration::from_micros(microseconds as u64));
    STALLED.fetch_add(microseconds, SeqCst);
    Status::EFI_SUCCESS
}

/// Stall() returns "EFI_SUCCESS: Execution was stalled at least the requested number of
/// Microseconds". efiloader leaves the implementation to the embedder, so install one first.
#[test]
fn stall_stalls_execution() {
    let efi = setup();
    efi.context().override_stall_handler(stall);

    // The boot services table is updated in a way that keeps its CRC valid
    let st = efi.system_table();
    // SAFETY: The system table points to the boot services table.
    assert!(unsafe { table_crc_is_valid(st.boot_services.cast()) });

    let bs = efi.bs();
    for microseconds in [0, 1, 2000] {
        let stalled = STALLED.load(SeqCst);
        let start = Instant::now();
        // SAFETY: Stall() takes no pointer arguments.
        assert_eq!(unsafe { (bs.stall)(microseconds) }, Status::EFI_SUCCESS);
        assert!(start.elapsed() >= Duration::from_micros(microseconds as u64));
        assert_eq!(STALLED.load(SeqCst), stalled + microseconds);
    }
}

/// CopyMem() "copies the contents of one buffer to another buffer".
#[test]
fn copy_mem_copies_buffer() {
    let efi = setup();
    let bs = efi.bs();

    let src: Vec<u8> = (0..=255).collect();
    let mut dst = vec![0xa5u8; 258];
    // SAFETY: `src` holds 256 bytes, and `dst` has room for them after its first byte.
    unsafe { (bs.copy_mem)(dst[1..].as_mut_ptr().cast(), src.as_ptr().cast(), 256) };
    assert_eq!(dst[0], 0xa5);
    assert_eq!(&dst[1..257], &src[..]);
    assert_eq!(dst[257], 0xa5);
}

/// CopyMem() handles buffers that overlap, i.e., it behaves as if Source is copied into a temporary
/// buffer first, regardless of whether Destination is above or below Source.
#[test]
fn copy_mem_handles_overlapping_buffers() {
    let efi = setup();
    let bs = efi.bs();

    let initial: Vec<u8> = (0..64).collect();
    for (src, dst) in [(0, 7), (7, 0), (0, 1), (1, 0)] {
        let mut buffer = initial.clone();
        let p = buffer.as_mut_ptr();
        // SAFETY: Both ranges of 32 bytes are within `buffer`.
        unsafe { (bs.copy_mem)(p.add(dst).cast(), p.add(src).cast(), 32) };

        let mut expected = initial.clone();
        expected.copy_within(src..src + 32, dst);
        assert_eq!(buffer, expected, "{src} -> {dst}");
    }
}

/// CopyMem(): "If Length is 0, then no data is copied."
#[test]
fn copy_mem_with_zero_length() {
    let efi = setup();
    let bs = efi.bs();

    let src = [1u8; 16];
    let mut dst = [0u8; 16];
    // SAFETY: Both pointers are valid, even though nothing should be copied.
    unsafe { (bs.copy_mem)(dst.as_mut_ptr().cast(), src.as_ptr().cast(), 0) };
    assert_eq!(dst, [0; 16]);
}

/// SetMem() "fills a buffer with a specified value": "Size: Number of bytes in Buffer to fill."
#[test]
fn set_mem_fills_buffer() {
    let efi = setup();
    let bs = efi.bs();

    for (size, value) in [(0, 0x11), (1, 0x22), (13, 0x33), (4096, 0x44)] {
        let mut buffer = vec![0xa5u8; size + 2];
        // SAFETY: `buffer` has room for `size` bytes after its first byte.
        unsafe { (bs.set_mem)(buffer[1..].as_mut_ptr().cast(), size, value) };
        assert_eq!(buffer[0], 0xa5);
        assert!(buffer[1..=size].iter().all(|&b| b == value), "{size}");
        assert_eq!(buffer[size + 1], 0xa5);
    }
}

/// CalculateCrc32() "computes the 32-bit CRC for the data buffer specified by Data and DataSize",
/// which is the same CRC that the table headers carry.
#[test]
fn calculate_crc32_computes_crc() {
    let efi = setup();
    let bs = efi.bs();

    let pattern: Vec<u8> = (0..4097u32).map(|i| (i * 7 + i / 256) as u8).collect();
    for (data, expected) in [
        (&b"123456789"[..], Some(0xcbf4_3926)),
        (&b"\0"[..], Some(0xd202_ef8d)),
        (&pattern[..], None),
    ] {
        let mut crc = 0;
        // SAFETY: All pointers are valid, and `data` holds `data.len()` bytes.
        let status = unsafe { (bs.calculate_crc32)(data.as_ptr().cast(), data.len(), &mut crc) };
        assert_eq!(status, Status::EFI_SUCCESS);
        assert_eq!(crc, crc32(data));
        if let Some(expected) = expected {
            assert_eq!(crc, expected);
        }
    }
}

/// CalculateCrc32() returns EFI_INVALID_PARAMETER if "Data is NULL", "Crc32 is NULL" or "DataSize
/// is 0".
#[test]
fn calculate_crc32_rejects_invalid_parameters() {
    let efi = setup();
    let bs = efi.bs();

    let data = [0u8; 16];
    let mut crc = 0;
    // SAFETY: CalculateCrc32() must not dereference NULL pointers.
    unsafe {
        assert_eq!(
            (bs.calculate_crc32)(ptr::null(), 16, &mut crc),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.calculate_crc32)(data.as_ptr().cast(), 16, ptr::null_mut()),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.calculate_crc32)(data.as_ptr().cast(), 0, &mut crc),
            Status::EFI_INVALID_PARAMETER
        );
    }
}

fn install_configuration_table(bs: &BootServices, guid: *const Guid, table: *mut c_void) -> Status {
    // SAFETY: `guid` is a valid pointer or NULL, and the table is never dereferenced.
    unsafe { (bs.install_configuration_table)(guid, table) }
}

fn assert_system_table_crc_is_valid(efi: &Efi) {
    // SAFETY: The system table pointer is valid.
    assert!(unsafe { table_crc_is_valid(efi.system_table_ptr().cast()) });
}

/// InstallConfigurationTable(): "If Guid is not present in the System Table, and Table is not NULL,
/// then the (Guid, Table) pair is added to the System Table." "If Guid is present in the System
/// Table, and Table is not NULL, then the (Guid, Table) pair is updated with the new Table value."
/// "If Guid is present in the System Table, and Table is NULL, then the entry associated with Guid
/// is removed from the System Table."
#[test]
fn install_configuration_table_adds_updates_and_removes_entries() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let (table1, table2) = (new_interface(), new_interface());

    let before = efi.configuration_tables();
    assert!(before.iter().all(|e| e.0 != guid));

    assert_eq!(
        install_configuration_table(&bs, &guid, table1),
        Status::EFI_SUCCESS
    );
    let after = efi.configuration_tables();
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(after.iter().filter(|e| e.0 == guid).count(), 1);
    assert!(after.contains(&(guid, table1)));
    assert!(before.iter().all(|e| after.contains(e)));
    assert_system_table_crc_is_valid(&efi);

    assert_eq!(
        install_configuration_table(&bs, &guid, table2),
        Status::EFI_SUCCESS
    );
    let after = efi.configuration_tables();
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(after.iter().filter(|e| e.0 == guid).count(), 1);
    assert!(after.contains(&(guid, table2)));
    assert_system_table_crc_is_valid(&efi);

    assert_eq!(
        install_configuration_table(&bs, &guid, ptr::null_mut()),
        Status::EFI_SUCCESS
    );
    let after = efi.configuration_tables();
    assert_eq!(after, before);
    assert_system_table_crc_is_valid(&efi);
}

/// InstallConfigurationTable() maintains an arbitrary number of entries, whose list "must be
/// allocated from pool memory with PoolType set to EfiRuntimeServicesData".
#[test]
fn install_configuration_table_with_many_entries() {
    let efi = setup();
    let bs = efi.bs();

    // GetMemoryMap() may install a configuration table, so call it before taking a snapshot
    efi.memory_map();
    let before = efi.configuration_tables();

    let entries: Vec<_> = (0..40).map(|_| (new_guid(), new_interface())).collect();
    for (guid, table) in &entries {
        assert_eq!(
            install_configuration_table(&bs, guid, *table),
            Status::EFI_SUCCESS
        );
    }
    let after = efi.configuration_tables();
    assert_eq!(after.len(), before.len() + entries.len());
    assert!(entries.iter().chain(&before).all(|e| after.contains(e)));
    assert_system_table_crc_is_valid(&efi);

    let map = efi.memory_map();
    let st = efi.system_table();
    let start = st.configuration_table as u64;
    let size = (st.number_of_table_entries * size_of::<ConfigurationTable>()) as u64;
    assert_eq!(
        map.type_of(start..start + size),
        Some(EFI_RUNTIME_SERVICES_DATA)
    );

    for (guid, _) in &entries {
        assert_eq!(
            install_configuration_table(&bs, guid, ptr::null_mut()),
            Status::EFI_SUCCESS
        );
    }
    let after = efi.configuration_tables();
    assert_eq!(after.len(), before.len());
    assert!(before.iter().all(|e| after.contains(e)));
    assert_system_table_crc_is_valid(&efi);
}

/// InstallConfigurationTable(): "If Guid is not present in the System Table, and Table is NULL,
/// then EFI_NOT_FOUND is returned."
#[test]
fn install_configuration_table_rejects_removing_nonexistent_entry() {
    let efi = setup();
    let bs = efi.bs();

    let before = efi.configuration_tables();
    assert_eq!(
        install_configuration_table(&bs, &new_guid(), ptr::null_mut()),
        Status::EFI_NOT_FOUND
    );
    assert_eq!(efi.configuration_tables(), before);
}

/// InstallConfigurationTable() returns EFI_INVALID_PARAMETER if "Guid is NULL".
#[test]
fn install_configuration_table_rejects_null_guid() {
    let efi = setup();
    let bs = efi.bs();

    let before = efi.configuration_tables();
    assert_eq!(
        install_configuration_table(&bs, ptr::null(), new_interface()),
        Status::EFI_INVALID_PARAMETER
    );
    assert_eq!(efi.configuration_tables(), before);
}
