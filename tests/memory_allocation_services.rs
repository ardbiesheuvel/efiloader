// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the memory allocation services described in section 7.2 of the UEFI specification:
//! AllocatePages(), FreePages(), GetMemoryMap(), AllocatePool() and FreePool().

mod common;
use common::*;

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use core::slice;

fn allocate_pages(
    bs: &BootServices,
    allocation_type: u32,
    memory_type: u32,
    pages: usize,
    memory: u64,
) -> Result<u64, Status> {
    let mut memory = memory;
    // SAFETY: `memory` is a valid EFI_PHYSICAL_ADDRESS.
    let status = unsafe { (bs.allocate_pages)(allocation_type, memory_type, pages, &mut memory) };
    if status == Status::EFI_SUCCESS {
        Ok(memory)
    } else {
        Err(status)
    }
}

fn free_pages(bs: &BootServices, memory: u64, pages: usize) -> Status {
    // SAFETY: FreePages() does not access the memory it frees.
    unsafe { (bs.free_pages)(memory, pages) }
}

fn allocate_pool(bs: &BootServices, pool_type: u32, size: usize) -> Result<*mut c_void, Status> {
    let mut buffer = ptr::null_mut();
    // SAFETY: `buffer` is a valid pointer sized location.
    let status = unsafe { (bs.allocate_pool)(pool_type, size, &mut buffer) };
    if status == Status::EFI_SUCCESS {
        Ok(buffer)
    } else {
        Err(status)
    }
}

fn free_pool(bs: &BootServices, buffer: *mut c_void) -> Status {
    // SAFETY: FreePool() does not access the memory it frees.
    unsafe { (bs.free_pool)(buffer) }
}

/// The status codes that AllocatePages() may return when the requested pages are not available:
/// "EFI_OUT_OF_RESOURCES: The pages could not be allocated" and "EFI_NOT_FOUND: The requested
/// pages could not be found".
fn is_unavailable(result: Result<u64, Status>) -> bool {
    matches!(
        result,
        Err(Status::EFI_OUT_OF_RESOURCES) | Err(Status::EFI_NOT_FOUND)
    )
}

/// AllocatePages() returns EFI_INVALID_PARAMETER if "Type is not AllocateAnyPages or
/// AllocateMaxAddress or AllocateAddress".
#[test]
fn allocate_pages_rejects_invalid_allocation_type() {
    let efi = setup();
    let bs = efi.bs();
    // Pass the address of free pages, which would be a valid input for any allocation type
    let free = efi.memory_map().find_free_pages(1).unwrap();

    for allocation_type in [MAX_ALLOCATE_TYPE, 0x8000_0000, u32::MAX] {
        assert_eq!(
            allocate_pages(&bs, allocation_type, EFI_LOADER_DATA, 1, free),
            Err(Status::EFI_INVALID_PARAMETER),
            "Type {allocation_type:#x}"
        );
    }
}

/// AllocatePages() returns EFI_INVALID_PARAMETER if "MemoryType is in the range
/// EfiMaxMemoryType..0x6FFFFFFF".
#[test]
fn allocate_pages_rejects_invalid_memory_type() {
    let efi = setup();
    let bs = efi.bs();
    let free = efi.memory_map().find_free_pages(1).unwrap();

    for memory_type in [EFI_MAX_MEMORY_TYPE, 0x1000, 0x6fff_ffff] {
        for (allocation_type, memory) in [
            (ALLOCATE_ANY_PAGES, 0),
            (ALLOCATE_MAX_ADDRESS, u64::MAX),
            (ALLOCATE_ADDRESS, free),
        ] {
            assert_eq!(
                allocate_pages(&bs, allocation_type, memory_type, 1, memory),
                Err(Status::EFI_INVALID_PARAMETER),
                "Type {allocation_type} MemoryType {memory_type:#x}"
            );
        }
    }
}

/// AllocatePages() returns EFI_INVALID_PARAMETER if "MemoryType is EfiPersistentMemory or
/// EfiUnacceptedMemoryType".
#[test]
fn allocate_pages_rejects_persistent_and_unaccepted_memory() {
    let efi = setup();
    let bs = efi.bs();

    for memory_type in [EFI_PERSISTENT_MEMORY, EFI_UNACCEPTED_MEMORY_TYPE] {
        assert_eq!(
            allocate_pages(&bs, ALLOCATE_ANY_PAGES, memory_type, 1, 0),
            Err(Status::EFI_INVALID_PARAMETER),
            "MemoryType {memory_type}"
        );
    }
}

/// AllocatePages() returns EFI_INVALID_PARAMETER if "Memory is NULL".
#[test]
fn allocate_pages_rejects_null_memory() {
    let efi = setup();
    let bs = efi.bs();

    for allocation_type in [ALLOCATE_ANY_PAGES, ALLOCATE_MAX_ADDRESS, ALLOCATE_ADDRESS] {
        // SAFETY: AllocatePages() must not dereference a NULL Memory pointer.
        let status =
            unsafe { (bs.allocate_pages)(allocation_type, EFI_LOADER_DATA, 1, ptr::null_mut()) };
        assert_eq!(
            status,
            Status::EFI_INVALID_PARAMETER,
            "Type {allocation_type}"
        );
    }
}

/// "Allocation requests of Type AllocateAnyPages allocate any available range of pages that
/// satisfies the request. On input, the address pointed to by Memory is ignored."
#[test]
fn allocate_any_pages() {
    let efi = setup();
    let bs = efi.bs();
    let ram = efi.ram();

    // Pass an input value that would not be valid for the other allocation types
    let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 3, 0x123).unwrap();
    assert_eq!(base % PAGE, 0);
    assert!(ram.start <= base && base + 3 * PAGE <= ram.end, "{base:#x}");

    // The pages are owned by the caller, and the memory map describes them as MemoryType
    // SAFETY: The pages were just allocated.
    unsafe { ptr::write_bytes(base as *mut u8, 0xaa, 3 * EFI_PAGE_SIZE) };
    assert_eq!(
        efi.memory_map().type_of(base..base + 3 * PAGE),
        Some(EFI_LOADER_DATA)
    );

    assert_eq!(free_pages(&bs, base, 3), Status::EFI_SUCCESS);
}

/// AllocatePages() "changes the memory map to indicate that the pages are now of type MemoryType",
/// which may be any type that UEFI images are permitted to allocate.
#[test]
fn allocate_pages_of_each_memory_type() {
    let efi = setup();
    let bs = efi.bs();

    for memory_type in ALLOCATABLE_MEMORY_TYPES {
        let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, memory_type, 2, 0)
            .unwrap_or_else(|status| panic!("MemoryType {memory_type}: {status:?}"));
        assert_eq!(
            efi.memory_map().type_of(base..base + 2 * PAGE),
            Some(memory_type),
            "MemoryType {memory_type}"
        );

        assert_eq!(free_pages(&bs, base, 2), Status::EFI_SUCCESS);
        assert_eq!(
            efi.memory_map().type_of(base..base + 2 * PAGE),
            Some(EFI_CONVENTIONAL_MEMORY),
            "MemoryType {memory_type}"
        );
    }
}

/// "Allocation requests of Type AllocateMaxAddress allocate any available range of pages whose
/// uppermost address is less than or equal to the address pointed to by Memory on input."
#[test]
fn allocate_max_address() {
    let efi = setup();
    let bs = efi.bs();
    let ram = efi.ram();

    // Memory is allocated top down, so most of the lower half of RAM should be free. Use a limit
    // that is not page aligned, as well as one that is the last byte of a page.
    let mid = ram.start + RAM_SIZE as u64 / 2;
    for max in [mid + 0x123, mid - PAGE - 1] {
        let base = allocate_pages(&bs, ALLOCATE_MAX_ADDRESS, EFI_LOADER_DATA, 4, max)
            .unwrap_or_else(|status| panic!("max {max:#x}: {status:?}"));
        assert_eq!(base % PAGE, 0);
        assert!(base >= ram.start, "{base:#x}");
        assert!(
            base + 4 * PAGE - 1 <= max,
            "{base:#x}..{:#x} is above {max:#x}",
            base + 4 * PAGE
        );
        assert_eq!(
            efi.memory_map().type_of(base..base + 4 * PAGE),
            Some(EFI_LOADER_DATA)
        );
        assert_eq!(free_pages(&bs, base, 4), Status::EFI_SUCCESS);
    }
}

/// AllocateMaxAddress requests fail if there are no free pages below the given address.
#[test]
fn allocate_max_address_below_available_memory() {
    let efi = setup();
    let bs = efi.bs();

    // There is no memory below the start of RAM
    let result = allocate_pages(
        &bs,
        ALLOCATE_MAX_ADDRESS,
        EFI_LOADER_DATA,
        1,
        efi.ram().start - 1,
    );
    assert!(is_unavailable(result), "{result:x?}");
}

/// "Allocation requests of Type AllocateAddress allocate pages at the address pointed to by Memory
/// on input."
#[test]
fn allocate_address() {
    let efi = setup();
    let bs = efi.bs();

    let addr = efi.memory_map().find_free_pages(4).unwrap();
    assert_eq!(
        allocate_pages(&bs, ALLOCATE_ADDRESS, EFI_BOOT_SERVICES_DATA, 4, addr),
        Ok(addr)
    );
    assert_eq!(
        efi.memory_map().type_of(addr..addr + 4 * PAGE),
        Some(EFI_BOOT_SERVICES_DATA)
    );

    // The pages are no longer available, so neither they nor any range that overlaps with them can
    // be allocated again.
    for (memory, pages) in [
        (addr, 4),
        (addr + PAGE, 1),
        (addr - PAGE, 2),
        (addr + 3 * PAGE, 2),
    ] {
        let result = allocate_pages(&bs, ALLOCATE_ADDRESS, EFI_BOOT_SERVICES_DATA, pages, memory);
        assert!(is_unavailable(result), "{memory:#x} {pages}: {result:x?}");
    }

    assert_eq!(free_pages(&bs, addr, 4), Status::EFI_SUCCESS);
}

/// AllocateAddress requests for memory that is not described by the memory map fail.
#[test]
fn allocate_address_outside_of_memory_map() {
    let efi = setup();
    let bs = efi.bs();
    let ram = efi.ram();

    for (memory, pages) in [
        (0, 1),
        (ram.start - PAGE, 1),
        (ram.start - PAGE, 2),
        (ram.end - PAGE, 2),
        (ram.end, 1),
    ] {
        let result = allocate_pages(&bs, ALLOCATE_ADDRESS, EFI_LOADER_DATA, pages, memory);
        assert!(is_unavailable(result), "{memory:#x} {pages}: {result:x?}");
    }
}

/// AllocatePages() allocates whole pages, and so AllocateAddress requests for an address that is
/// not page aligned cannot be honoured.
#[test]
fn allocate_address_rejects_unaligned_address() {
    let efi = setup();
    let bs = efi.bs();

    let addr = efi.memory_map().find_free_pages(2).unwrap();
    for memory in [addr + 1, addr + 0x800, addr + PAGE - 8] {
        let result = allocate_pages(&bs, ALLOCATE_ADDRESS, EFI_LOADER_DATA, 1, memory);
        assert!(result.is_err(), "{memory:#x}: {result:x?}");
    }
    assert_eq!(
        efi.memory_map().type_of(addr..addr + 2 * PAGE),
        Some(EFI_CONVENTIONAL_MEMORY)
    );
}

/// AllocatePages() returns EFI_OUT_OF_RESOURCES if "The pages could not be allocated".
#[test]
fn allocate_pages_out_of_resources() {
    let efi = setup();
    let bs = efi.bs();

    for pages in [
        RAM_SIZE / EFI_PAGE_SIZE + 1,
        usize::MAX / EFI_PAGE_SIZE,
        usize::MAX,
    ] {
        for (allocation_type, memory) in [(ALLOCATE_ANY_PAGES, 0), (ALLOCATE_MAX_ADDRESS, u64::MAX)]
        {
            assert_eq!(
                allocate_pages(&bs, allocation_type, EFI_LOADER_DATA, pages, memory),
                Err(Status::EFI_OUT_OF_RESOURCES),
                "Type {allocation_type} Pages {pages:#x}"
            );
        }
    }
}

/// FreePages() "returns memory allocated by AllocatePages() to the firmware".
#[test]
fn free_pages_returns_memory_to_firmware() {
    let efi = setup();
    let bs = efi.bs();

    let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 4, 0).unwrap();
    assert_eq!(free_pages(&bs, base, 4), Status::EFI_SUCCESS);
    assert_eq!(
        efi.memory_map().type_of(base..base + 4 * PAGE),
        Some(EFI_CONVENTIONAL_MEMORY)
    );

    // The pages are available again
    assert_eq!(
        allocate_pages(&bs, ALLOCATE_ADDRESS, EFI_LOADER_DATA, 4, base),
        Ok(base)
    );
    assert_eq!(free_pages(&bs, base, 4), Status::EFI_SUCCESS);
}

/// FreePages() returns EFI_INVALID_PARAMETER if "Memory is not a page-aligned address".
#[test]
fn free_pages_rejects_unaligned_address() {
    let efi = setup();
    let bs = efi.bs();

    let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 2, 0).unwrap();
    for memory in [base + 1, base + 0x800, base + PAGE - 8] {
        assert_eq!(
            free_pages(&bs, memory, 1),
            Status::EFI_INVALID_PARAMETER,
            "{memory:#x}"
        );
    }

    // The pages are still allocated
    assert_eq!(
        efi.memory_map().type_of(base..base + 2 * PAGE),
        Some(EFI_LOADER_DATA)
    );
    assert_eq!(free_pages(&bs, base, 2), Status::EFI_SUCCESS);
}

/// FreePages() returns EFI_NOT_FOUND if "The requested memory pages were not allocated with
/// AllocatePages()", e.g., because they are free.
#[test]
fn free_pages_rejects_free_pages() {
    let efi = setup();
    let bs = efi.bs();

    let free = efi.memory_map().find_free_pages(2).unwrap();
    assert_eq!(free_pages(&bs, free, 1), Status::EFI_NOT_FOUND);
    assert_eq!(free_pages(&bs, free, 2), Status::EFI_NOT_FOUND);

    // Pages cannot be freed twice
    let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 1, 0).unwrap();
    assert_eq!(free_pages(&bs, base, 1), Status::EFI_SUCCESS);
    assert_eq!(free_pages(&bs, base, 1), Status::EFI_NOT_FOUND);
}

/// FreePages() returns EFI_NOT_FOUND if "The requested memory pages were not allocated with
/// AllocatePages()", even if they are in use.
#[test]
fn free_pages_rejects_memory_not_allocated_by_allocate_pages() {
    let efi = setup();
    let bs = efi.bs();

    // Memory backing a pool allocation
    let pool = allocate_pool(&bs, EFI_LOADER_DATA, 64).unwrap();
    assert_eq!(
        free_pages(&bs, pool as u64 & !(PAGE - 1), 1),
        Status::EFI_NOT_FOUND
    );
    assert_eq!(free_pool(&bs, pool), Status::EFI_SUCCESS);

    // Memory used by the firmware, e.g., to hold the EFI system table
    let system_table = efi.system_table_ptr() as u64 & !(PAGE - 1);
    assert_eq!(free_pages(&bs, system_table, 1), Status::EFI_NOT_FOUND);
}

/// FreePages() can return part of the pages that were allocated by an AllocatePages() call.
#[test]
fn free_pages_partially() {
    let efi = setup();
    let bs = efi.bs();

    let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 4, 0).unwrap();
    assert_eq!(free_pages(&bs, base + PAGE, 2), Status::EFI_SUCCESS);

    let map = efi.memory_map();
    assert_eq!(map.type_of(base..base + PAGE), Some(EFI_LOADER_DATA));
    assert_eq!(
        map.type_of(base + PAGE..base + 3 * PAGE),
        Some(EFI_CONVENTIONAL_MEMORY)
    );
    assert_eq!(
        map.type_of(base + 3 * PAGE..base + 4 * PAGE),
        Some(EFI_LOADER_DATA)
    );

    // The pages that were freed can no longer be freed, but the remaining ones can
    assert_eq!(free_pages(&bs, base + PAGE, 1), Status::EFI_NOT_FOUND);
    assert_eq!(free_pages(&bs, base, 2), Status::EFI_NOT_FOUND);
    assert_eq!(free_pages(&bs, base, 1), Status::EFI_SUCCESS);
    assert_eq!(free_pages(&bs, base + 3 * PAGE, 1), Status::EFI_SUCCESS);
}

/// FreePages() fails without freeing anything if the range covers pages that were not allocated
/// with AllocatePages().
#[test]
fn free_pages_rejects_range_exceeding_allocation() {
    let efi = setup();
    let bs = efi.bs();

    let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 3, 0).unwrap();
    assert_eq!(free_pages(&bs, base + 2 * PAGE, 1), Status::EFI_SUCCESS);

    assert_eq!(free_pages(&bs, base, 3), Status::EFI_NOT_FOUND);
    assert_eq!(
        efi.memory_map().type_of(base..base + 2 * PAGE),
        Some(EFI_LOADER_DATA)
    );
    assert_eq!(free_pages(&bs, base, 2), Status::EFI_SUCCESS);
}

/// GetMemoryMap() returns EFI_INVALID_PARAMETER if "MemoryMapSize is NULL".
#[test]
fn get_memory_map_rejects_null_memory_map_size() {
    let efi = setup();
    let bs = efi.bs();

    let mut buffer = [0u64; 1024];
    let (mut map_key, mut descriptor_size, mut descriptor_version) = (0, 0, 0);
    // SAFETY: All pointers except MemoryMapSize are valid.
    let status = unsafe {
        (bs.get_memory_map)(
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
}

/// "If the MemoryMap buffer is too small, the EFI_BUFFER_TOO_SMALL error code is returned and the
/// MemoryMapSize value contains the size of the buffer needed to contain the current memory map."
#[test]
fn get_memory_map_returns_required_size() {
    let efi = setup();
    let bs = efi.bs();

    let map = efi.memory_map();
    let required = map.descriptors.len() * map.descriptor_size;

    let mut size = 0;
    let (mut map_key, mut descriptor_size, mut descriptor_version) = (0, 0, 0);
    // SAFETY: All pointers are valid, and no buffer is passed as its size is 0.
    let status = unsafe {
        (bs.get_memory_map)(
            &mut size,
            ptr::null_mut(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    assert_eq!(status, Status::EFI_BUFFER_TOO_SMALL);
    assert_eq!(size, required);
}

/// GetMemoryMap() does not write beyond the end of a buffer that is too small to hold the memory
/// map: on input, MemoryMapSize is "the size of the buffer allocated by the caller".
#[test]
fn get_memory_map_buffer_too_small() {
    let efi = setup();
    let bs = efi.bs();

    let map = efi.memory_map();
    let required = map.descriptors.len() * map.descriptor_size;

    for short in [1, map.descriptor_size] {
        let mut buffer = vec![0x5a5a_5a5a_5a5a_5a5au64; required / 8 + 64];
        let mut size = required - short;
        let (mut map_key, mut descriptor_size, mut descriptor_version) = (0, 0, 0);
        // SAFETY: All pointers are valid, and `buffer` is larger than `size` bytes.
        let status = unsafe {
            (bs.get_memory_map)(
                &mut size,
                buffer.as_mut_ptr().cast(),
                &mut map_key,
                &mut descriptor_size,
                &mut descriptor_version,
            )
        };
        assert_eq!(status, Status::EFI_BUFFER_TOO_SMALL);
        assert_eq!(size, required);

        // SAFETY: `buffer` covers its size in bytes, all of which are initialized.
        let bytes =
            unsafe { slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), buffer.len() * 8) };
        assert!(bytes[required - short..].iter().all(|&b| b == 0x5a));
    }
}

/// GetMemoryMap() returns EFI_INVALID_PARAMETER if "The MemoryMap buffer is not too small and
/// MemoryMap is NULL".
#[test]
fn get_memory_map_rejects_null_memory_map() {
    let efi = setup();
    let bs = efi.bs();

    let mut size = 1 << 20;
    let (mut map_key, mut descriptor_size, mut descriptor_version) = (0, 0, 0);
    // SAFETY: All pointers except MemoryMap are valid.
    let status = unsafe {
        (bs.get_memory_map)(
            &mut size,
            ptr::null_mut(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
}

/// "On output, [MemoryMapSize] is the size of the buffer returned by the firmware if the buffer was
/// large enough", which is a multiple of DescriptorSize, i.e., "the size in bytes of an
/// EFI_MEMORY_DESCRIPTOR array element returned in MemoryMap".
#[test]
fn get_memory_map_returns_size_of_memory_map() {
    let efi = setup();
    let bs = efi.bs();

    let mut buffer = vec![0u64; 1 << 16];
    let mut size = buffer.len() * 8;
    let (mut map_key, mut descriptor_size, mut descriptor_version) = (0, 0, 0);
    // SAFETY: All pointers are valid, and `buffer` is a buffer of `size` bytes.
    let status = unsafe {
        (bs.get_memory_map)(
            &mut size,
            buffer.as_mut_ptr().cast(),
            &mut map_key,
            &mut descriptor_size,
            &mut descriptor_version,
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert!(descriptor_size >= size_of::<MemoryDescriptor>());
    assert!(size > 0);
    assert_eq!(size % descriptor_size, 0);
    assert_eq!(size, efi.memory_map().descriptors.len() * descriptor_size);
}

/// The memory map consists of DescriptorSize sized elements of version
/// EFI_MEMORY_DESCRIPTOR_VERSION, each describing a block of memory: "PhysicalStart must be aligned
/// on a 4 KiB boundary", "NumberOfPages must not be 0", and the blocks do not overlap.
#[test]
fn get_memory_map_returns_valid_descriptors() {
    let efi = setup();

    let map = efi.memory_map();
    assert_eq!(map.descriptor_version, EFI_MEMORY_DESCRIPTOR_VERSION);
    assert!(map.descriptor_size >= size_of::<MemoryDescriptor>());
    assert!(!map.descriptors.is_empty());

    for d in &map.descriptors {
        assert!(
            d.r#type < EFI_MAX_MEMORY_TYPE || d.r#type >= 0x7000_0000,
            "{d:x?}"
        );
        assert_eq!(d.physical_start % PAGE, 0, "{d:x?}");
        assert_ne!(d.number_of_pages, 0, "{d:x?}");
        assert!(d.physical_start <= 0xffff_ffff_ffff_f000, "{d:x?}");
        assert!(
            d.number_of_pages <= (0xffff_ffff_ffff_f000 - d.physical_start) / PAGE + 1,
            "{d:x?}"
        );
    }

    for pair in map.sorted().windows(2) {
        assert!(pair[0].end() <= pair[1].start(), "{pair:x?}");
    }
}

/// "The map describes all of memory, no matter how it is being used."
#[test]
fn get_memory_map_describes_all_memory() {
    let efi = setup();
    let bs = efi.bs();
    let ram = efi.ram();

    // Make sure the memory map covers memory of various types
    let page = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_RUNTIME_SERVICES_CODE, 1, 0).unwrap();
    let pool = allocate_pool(&bs, EFI_LOADER_DATA, 64).unwrap();

    // System RAM is the only memory that was declared to the EFI runtime, and so the memory map
    // should describe exactly that.
    let mut next = ram.start;
    for d in efi.memory_map().sorted() {
        assert_eq!(d.start(), next, "{d:x?}");
        next = d.end();
    }
    assert_eq!(next, ram.end);

    assert_eq!(free_pool(&bs, pool), Status::EFI_SUCCESS);
    assert_eq!(free_pages(&bs, page, 1), Status::EFI_SUCCESS);
}

/// "The firmware's key is changed every time something in the memory map changes."
#[test]
fn get_memory_map_key_changes_when_memory_map_changes() {
    let efi = setup();
    let bs = efi.bs();

    let initial = efi.memory_map().map_key;
    let base = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 1, 0).unwrap();
    let allocated = efi.memory_map().map_key;
    assert_ne!(allocated, initial);

    assert_eq!(free_pages(&bs, base, 1), Status::EFI_SUCCESS);
    let freed = efi.memory_map().map_key;
    assert_ne!(freed, allocated);
}

/// "On success a MapKey is returned that identifies the current memory map", and so as long as the
/// memory map does not change, the same key and memory map are returned.
#[test]
fn get_memory_map_key_identifies_memory_map() {
    let efi = setup();

    let first = efi.memory_map();
    let second = efi.memory_map();
    assert_eq!(second.map_key, first.map_key);
    assert_eq!(second.descriptors, first.descriptors);
}

/// AllocatePool() returns EFI_INVALID_PARAMETER if "Buffer is NULL".
#[test]
fn allocate_pool_rejects_null_buffer() {
    let efi = setup();
    let bs = efi.bs();

    // SAFETY: AllocatePool() must not dereference a NULL Buffer pointer.
    let status = unsafe { (bs.allocate_pool)(EFI_LOADER_DATA, 16, ptr::null_mut()) };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
}

/// AllocatePool() returns EFI_INVALID_PARAMETER if "PoolType is in the range
/// EfiMaxMemoryType..0x6FFFFFFF".
#[test]
fn allocate_pool_rejects_invalid_pool_type() {
    let efi = setup();
    let bs = efi.bs();

    for pool_type in [EFI_MAX_MEMORY_TYPE, 0x1000, 0x6fff_ffff] {
        assert_eq!(
            allocate_pool(&bs, pool_type, 16),
            Err(Status::EFI_INVALID_PARAMETER),
            "PoolType {pool_type:#x}"
        );
    }
}

/// AllocatePool() returns EFI_INVALID_PARAMETER if "PoolType is EfiPersistentMemory", and
/// EfiUnacceptedMemoryType cannot be allocated either.
#[test]
fn allocate_pool_rejects_persistent_and_unaccepted_memory() {
    let efi = setup();
    let bs = efi.bs();

    for pool_type in [EFI_PERSISTENT_MEMORY, EFI_UNACCEPTED_MEMORY_TYPE] {
        assert_eq!(
            allocate_pool(&bs, pool_type, 16),
            Err(Status::EFI_INVALID_PARAMETER),
            "PoolType {pool_type}"
        );
    }
}

/// AllocatePool() "allocates a memory region of Size bytes", and "All allocations are eight-byte
/// aligned".
#[test]
fn allocate_pool_returns_aligned_buffers() {
    let efi = setup();
    let bs = efi.bs();

    let buffers: Vec<_> = [1, 7, 8, 9, 63, 100, 4095, 4096, 4097, 65536]
        .into_iter()
        .enumerate()
        .map(|(i, size)| {
            let buffer = allocate_pool(&bs, EFI_LOADER_DATA, size).unwrap();
            assert_eq!(buffer as usize % 8, 0, "{buffer:?}");
            // SAFETY: `buffer` was allocated with a size of `size` bytes.
            unsafe { ptr::write_bytes(buffer.cast::<u8>(), i as u8, size) };
            (buffer, size)
        })
        .collect();

    // The allocations don't overlap, i.e., each buffer still holds the value it was filled with
    for (i, &(buffer, size)) in buffers.iter().enumerate() {
        // SAFETY: `buffer` was allocated with a size of `size` bytes, and initialized above.
        let bytes = unsafe { slice::from_raw_parts(buffer.cast::<u8>(), size) };
        assert!(bytes.iter().all(|&b| b == i as u8), "{buffer:?}");
    }

    for (buffer, _) in buffers {
        assert_eq!(free_pool(&bs, buffer), Status::EFI_SUCCESS);
    }
}

/// AllocatePool() "allocates a memory region of Size bytes from memory of type PoolType".
#[test]
fn allocate_pool_allocates_memory_of_pool_type() {
    let efi = setup();
    let bs = efi.bs();

    for pool_type in [
        EFI_LOADER_DATA,
        EFI_BOOT_SERVICES_DATA,
        EFI_RUNTIME_SERVICES_DATA,
        EFI_ACPI_RECLAIM_MEMORY,
    ] {
        let buffer = allocate_pool(&bs, pool_type, 256)
            .unwrap_or_else(|status| panic!("PoolType {pool_type}: {status:?}"));
        let start = buffer as u64;
        assert_eq!(
            efi.memory_map().type_of(start..start + 256),
            Some(pool_type),
            "PoolType {pool_type}"
        );
        assert_eq!(free_pool(&bs, buffer), Status::EFI_SUCCESS);
    }
}

/// AllocatePool() supports all memory types that UEFI images are permitted to allocate, e.g.,
/// "UEFI boot service drivers must allocate memory (and pool) of type EfiBootServicesData".
#[test]
fn allocate_pool_of_each_memory_type() {
    let efi = setup();
    let bs = efi.bs();

    for pool_type in ALLOCATABLE_MEMORY_TYPES {
        let buffer = allocate_pool(&bs, pool_type, 256)
            .unwrap_or_else(|status| panic!("PoolType {pool_type}: {status:?}"));
        let start = buffer as u64;
        assert_eq!(
            efi.memory_map().type_of(start..start + 256),
            Some(pool_type),
            "PoolType {pool_type}"
        );
        assert_eq!(free_pool(&bs, buffer), Status::EFI_SUCCESS);
    }
}

/// AllocatePool() "allocates pages from EfiConventionalMemory as needed to grow the requested pool
/// type", and so allocations succeed as long as sufficient free memory is available, regardless of
/// whether that memory is requested by a single large allocation or by many small ones.
#[test]
fn allocate_pool_grows_pool() {
    let efi = setup();
    let bs = efi.bs();

    for pool_type in [
        EFI_LOADER_DATA,
        EFI_BOOT_SERVICES_DATA,
        EFI_RUNTIME_SERVICES_DATA,
        EFI_ACPI_RECLAIM_MEMORY,
    ] {
        for (count, size) in [(1, 4 << 20), (128, 24 << 10)] {
            let buffers: Vec<_> = (0..count)
                .map(|i| {
                    let buffer = allocate_pool(&bs, pool_type, size)
                        .unwrap_or_else(|status| panic!("PoolType {pool_type}: {status:?}"));
                    // SAFETY: `buffer` was allocated with a size of `size` bytes.
                    unsafe { ptr::write_bytes(buffer.cast::<u8>(), i as u8, size) };
                    buffer
                })
                .collect();

            let map = efi.memory_map();
            for (i, &buffer) in buffers.iter().enumerate() {
                let start = buffer as u64;
                assert_eq!(
                    map.type_of(start..start + size as u64),
                    Some(pool_type),
                    "PoolType {pool_type}"
                );
                // The allocations don't overlap, so each one still holds what it was filled with
                // SAFETY: `buffer` was allocated with a size of `size` bytes, and initialized above.
                let bytes = unsafe { slice::from_raw_parts(buffer.cast::<u8>(), size) };
                assert!(bytes.iter().all(|&b| b == i as u8), "{buffer:?}");
            }

            for buffer in buffers {
                assert_eq!(free_pool(&bs, buffer), Status::EFI_SUCCESS);
            }
        }
    }
}

/// AllocatePool() returns EFI_OUT_OF_RESOURCES if "The pool requested could not be allocated".
#[test]
fn allocate_pool_out_of_resources() {
    let efi = setup();
    let bs = efi.bs();

    for size in [2 * RAM_SIZE, usize::MAX - EFI_PAGE_SIZE, usize::MAX] {
        assert_eq!(
            allocate_pool(&bs, EFI_LOADER_DATA, size),
            Err(Status::EFI_OUT_OF_RESOURCES),
            "Size {size:#x}"
        );
    }
}

/// FreePool() "returns pool memory to the system", and so it can be allocated again. This
/// allocates and frees much more memory than exists in total.
#[test]
fn free_pool_returns_memory_to_system() {
    let efi = setup();
    let bs = efi.bs();

    for i in 0..4 * RAM_SIZE / (8 << 20) {
        let buffer = allocate_pool(&bs, EFI_LOADER_DATA, 8 << 20)
            .unwrap_or_else(|status| panic!("iteration {i}: {status:?}"));
        assert_eq!(free_pool(&bs, buffer), Status::EFI_SUCCESS);
    }
}

/// FreePool() "returns pool memory to the system", after which it is no longer valid:
/// "EFI_INVALID_PARAMETER: Buffer was invalid".
#[test]
fn free_pool_frees_buffer() {
    let efi = setup();
    let bs = efi.bs();

    let buffer = allocate_pool(&bs, EFI_BOOT_SERVICES_DATA, 128).unwrap();
    assert_eq!(free_pool(&bs, buffer), Status::EFI_SUCCESS);
    assert_eq!(free_pool(&bs, buffer), Status::EFI_INVALID_PARAMETER);
}

/// FreePool() returns EFI_INVALID_PARAMETER if "Buffer was invalid", i.e., if it was not returned
/// by AllocatePool().
#[test]
fn free_pool_rejects_invalid_buffers() {
    let efi = setup();
    let bs = efi.bs();

    let pool = allocate_pool(&bs, EFI_LOADER_DATA, 128).unwrap();
    let page = allocate_pages(&bs, ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 1, 0).unwrap();
    let mut local = 0u64;

    for buffer in [
        ptr::null_mut(),
        pool.cast::<u8>().wrapping_add(1).cast(),
        pool.cast::<u8>().wrapping_add(8).cast(),
        page as *mut c_void,
        &raw mut local as *mut c_void,
        // The EFI system table is allocated from pool memory by the firmware
        efi.system_table_ptr().cast(),
    ] {
        assert_eq!(
            free_pool(&bs, buffer),
            Status::EFI_INVALID_PARAMETER,
            "{buffer:?}"
        );
    }

    // The valid allocations were not affected
    assert_eq!(free_pool(&bs, pool), Status::EFI_SUCCESS);
    assert_eq!(free_pages(&bs, page, 1), Status::EFI_SUCCESS);
}
