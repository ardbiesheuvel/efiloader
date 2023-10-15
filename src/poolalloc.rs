// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::memmap;
use crate::MemoryMap;
use crate::EfiMemoryType;
use crate::Placement;
use crate::EFI_MEMORY_XP;

use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use linked_list_allocator::Heap;

pub(crate) struct PoolAllocator {
    memtype: EfiMemoryType,
    heap: Heap,
    granularity: usize,
    allocated: usize,
}

/// The size of the region reserved by a pool allocator
const ARENA_SIZE: usize = 0x10_0000; // 1 MiB

impl PoolAllocator {
    fn extend<'a>(&mut self, bytes: usize, mm: &'a MemoryMap) -> Result<(), ()> {
        let grow = align_up!(bytes, self.granularity);
        if self.allocated + grow > ARENA_SIZE {
            return Err(());
        }
        self.grow_region(grow, mm)?;
        unsafe { Ok(self.heap.extend(grow)) }
    }

    fn grow_region<'a>(&mut self, bytes: usize, mm: &'a MemoryMap) -> Result<(), ()> {
        if self.granularity < ARENA_SIZE {
            let base = self.heap.bottom() as usize + self.allocated;
            mm.convert_region(
                base as u64,
                bytes,
                Some(EfiMemoryType::EfiBootServicesData),
                self.memtype,
                EFI_MEMORY_XP,
            )?;
        }
        Ok(self.allocated += bytes)
    }

    pub(crate) fn new<'a>(memtype: EfiMemoryType, mm: &'a MemoryMap) -> Result<Self, ()> {
        let granularity = match memtype {
            EfiMemoryType::EfiLoaderData | EfiMemoryType::EfiBootServicesData => ARENA_SIZE,
            EfiMemoryType::EfiRuntimeServicesData => 0x1_0000,
            EfiMemoryType::EfiACPIReclaimMemory => 0x1000,
            _ => {
                return Err(());
            }
        };

        let (typ, pl) = if granularity < ARENA_SIZE {
            (
                EfiMemoryType::EfiBootServicesData,
                Placement::Aligned(granularity as u64),
            )
        } else {
            (memtype, Placement::Anywhere)
        };

        let arena = mm
            .allocate_pages(memmap::size_to_pages(ARENA_SIZE), typ, pl)
            .ok_or(())?;

        let mut p = PoolAllocator {
            memtype: memtype,
            heap: Heap::from_slice(&mut arena[..granularity]),
            granularity: granularity,
            allocated: 0,
        };
        p.grow_region(granularity, mm)?;
        Ok(p)
    }

    pub(crate) fn from_slice(memtype: EfiMemoryType, buf: &'static mut [MaybeUninit<u8>]) -> Self {
        let len = buf.len();
        PoolAllocator {
            memtype: memtype,
            heap: Heap::from_slice(buf),
            granularity: len,
            allocated: len,
        }
    }

    pub(crate) fn allocate<'a>(
        &mut self,
        layout: Layout,
        mm: &'a MemoryMap,
    ) -> Result<NonNull<u8>, ()> {
        self.heap.allocate_first_fit(layout).or_else(|_| {
            self.extend(layout.size(), mm)?;
            self.heap.allocate_first_fit(layout)
        })
    }

    pub(crate) fn deallocate(&mut self, buffer: *const u8, layout: Layout) {
        unsafe {
            self.heap
                .deallocate(NonNull::new_unchecked(buffer as _), layout)
        }
    }
}
