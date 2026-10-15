// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::memmap;
use crate::EfiMemoryType;
use crate::MemoryMap;
use crate::Placement;
use crate::EFI_MEMORY_XP;
use crate::EFI_PAGE_SIZE;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use linked_list_allocator::Heap;

/// The size of the region reserved for an arena
const ARENA_SIZE: usize = 0x10_0000; // 1 MiB

/// Allocations of at least this size are not served from an arena, but from a page allocation of
/// their own, which is returned to the page allocator when the allocation is freed.
const LARGE_ALLOCATION_SIZE: usize = 0x1_0000; // 64 KiB

/// A region of memory reserved for a pool, from which the pool serves allocations
struct Arena {
    heap: Heap,
    /// The number of bytes at the start of the arena that have been handed to the heap
    allocated: usize,
    /// The size of the arena, which the heap must never grow beyond
    limit: usize,
}

impl Arena {
    /// Returns whether `buffer` points into the part of the arena that was handed to the heap
    fn contains(&self, buffer: *const u8) -> bool {
        let base = self.heap.bottom() as usize;
        (base..base + self.allocated).contains(&(buffer as usize))
    }
}

/// A pool of memory of a single memory type, which grows as needed, unless it was declared by the
/// embedder. Small allocations are served from arenas, and large ones from page allocations of
/// their own.
pub(crate) struct PoolAllocator {
    memtype: EfiMemoryType,
    /// The granularity at which memory is assigned to the pool
    granularity: usize,
    /// Whether arenas are reserved as EfiBootServicesData, and assigned to the pool in
    /// increments of `granularity` as they fill up, rather than all at once
    incremental: bool,
    /// Whether the pool was declared by the embedder, and must not grow beyond the region it was
    /// given
    fixed: bool,
    /// The arenas reserved for the pool, in the order they were created
    arenas: Vec<Arena>,
    /// The allocations that were served from page allocations of their own, as a map of base
    /// addresses to sizes
    large: BTreeMap<usize, usize>,
}

impl PoolAllocator {
    pub(crate) fn new(memtype: EfiMemoryType) -> Self {
        let (granularity, incremental) = match memtype {
            // Memory that the OS must preserve, or map during runtime services calls, is assigned
            // in 64 KiB increments, so that an OS using 64 KiB pages can do so without covering
            // unrelated memory. Pools of these types, as well as of EfiACPIReclaimMemory, are
            // only assigned memory as they need it, to avoid tying up memory that the OS cannot
            // use freely.
            EfiMemoryType::EfiReservedEfiMemoryType
            | EfiMemoryType::EfiRuntimeServicesCode
            | EfiMemoryType::EfiRuntimeServicesData
            | EfiMemoryType::EfiACPIMemoryNVS => (0x1_0000, true),
            EfiMemoryType::EfiACPIReclaimMemory => (EFI_PAGE_SIZE, true),
            _ => (EFI_PAGE_SIZE, false),
        };

        PoolAllocator {
            memtype,
            granularity,
            incremental,
            fixed: false,
            arenas: Vec::new(),
            large: BTreeMap::new(),
        }
    }

    pub(crate) fn from_slice(memtype: EfiMemoryType, buf: &'static mut [MaybeUninit<u8>]) -> Self {
        let len = buf.len();
        let arena = Arena {
            heap: Heap::from_slice(buf),
            allocated: len,
            limit: len,
        };

        PoolAllocator {
            memtype,
            granularity: EFI_PAGE_SIZE,
            incremental: false,
            fixed: true,
            arenas: vec![arena],
            large: BTreeMap::new(),
        }
    }

    /// Reserves `size` bytes of memory aligned to `align` for the pool, as memory of the pool's
    /// type, or as EfiBootServicesData if the pool is assigned memory incrementally.
    fn reserve(
        &self,
        size: usize,
        align: usize,
        mm: &MemoryMap,
    ) -> Result<&'static mut [MaybeUninit<u8>], ()> {
        let memtype = if self.incremental {
            EfiMemoryType::EfiBootServicesData
        } else {
            self.memtype
        };
        mm.allocate_pages(
            memmap::size_to_pages(size),
            memtype,
            Placement::Aligned(align as u64),
        )
        .ok_or(())
    }

    /// Assigns `size` bytes at `base` that were reserved by reserve() to the pool, by converting
    /// them to the pool's memory type if the pool is assigned memory incrementally.
    fn assign(&self, base: usize, size: usize, mm: &MemoryMap) -> Result<(), ()> {
        if !self.incremental {
            return Ok(());
        }
        // Runtime code pool memory may be used to hold code
        let rtattr = if self.memtype == EfiMemoryType::EfiRuntimeServicesCode {
            0
        } else {
            EFI_MEMORY_XP
        };
        mm.convert_region(
            base as u64,
            size,
            Some(EfiMemoryType::EfiBootServicesData),
            self.memtype,
            rtattr,
        )
    }

    /// Reserves `size` bytes of memory aligned to `align`, and assigns them to the pool.
    fn reserve_and_assign(
        &self,
        size: usize,
        align: usize,
        mm: &MemoryMap,
    ) -> Result<&'static mut [MaybeUninit<u8>], ()> {
        let region = self.reserve(size, align, mm)?;
        let base = region.as_ptr() as usize;
        if self.assign(base, size, mm).is_err() {
            // This cannot fail, given that the pages were just allocated
            mm.free_pages(base as u64, memmap::size_to_pages(size)).ok();
            return Err(());
        }
        Ok(region)
    }

    /// Reserves a new arena, and hands enough of it to a new heap to serve an allocation of
    /// `bytes` bytes, or all of it if the pool is not assigned memory incrementally.
    fn add_arena(&mut self, bytes: usize, mm: &MemoryMap) -> Result<(), ()> {
        let arena = self.reserve(ARENA_SIZE, self.granularity, mm)?;
        let size = if self.incremental {
            align_up!(bytes.max(1), self.granularity).min(ARENA_SIZE)
        } else {
            ARENA_SIZE
        };
        let base = arena.as_ptr() as usize;
        if self.assign(base, size, mm).is_err() {
            // This cannot fail, given that the pages were just allocated
            mm.free_pages(base as u64, memmap::size_to_pages(ARENA_SIZE))
                .ok();
            return Err(());
        }
        self.arenas.push(Arena {
            heap: Heap::from_slice(&mut arena[..size]),
            allocated: size,
            limit: ARENA_SIZE,
        });
        Ok(())
    }

    /// Hands enough of the remainder of the most recent arena to its heap to serve an allocation
    /// of `bytes` bytes. Fails if the arena does not have enough memory left.
    fn grow_arena(&mut self, bytes: usize, mm: &MemoryMap) -> Result<(), ()> {
        let grow = align_up!(bytes.max(1), self.granularity);
        let arena = self.arenas.last().ok_or(())?;
        if grow > arena.limit - arena.allocated {
            return Err(());
        }
        self.assign(arena.heap.bottom() as usize + arena.allocated, grow, mm)?;

        let arena = self.arenas.last_mut().ok_or(())?;
        arena.allocated += grow;
        // SAFETY: The heap covers the first `allocated` bytes of an arena of `limit` bytes that is
        // reserved for the pool and never freed (an arena allocated by add_arena(), or the slice
        // passed to from_slice()), and the check above ensures that it is only extended into the
        // remainder of that arena, which assign() has just assigned to the pool.
        unsafe { arena.heap.extend(grow) };
        Ok(())
    }

    /// Serves an allocation from a page allocation of its own
    fn allocate_large(&mut self, layout: Layout, mm: &MemoryMap) -> Result<NonNull<u8>, ()> {
        // This cannot overflow, as the size of a Layout does not exceed isize::MAX
        let size = align_up!(layout.size(), self.granularity);
        let region = self.reserve_and_assign(size, self.granularity.max(layout.align()), mm)?;
        self.large.insert(region.as_ptr() as usize, size);
        Ok(NonNull::from(region).cast())
    }

    pub(crate) fn allocate(&mut self, layout: Layout, mm: &MemoryMap) -> Result<NonNull<u8>, ()> {
        if layout.size() >= LARGE_ALLOCATION_SIZE && !self.fixed {
            return self.allocate_large(layout, mm);
        }

        // Try the most recent arenas first, as the older ones are more likely to be full
        if let Some(p) = self
            .arenas
            .iter_mut()
            .rev()
            .find_map(|a| a.heap.allocate_first_fit(layout).ok())
        {
            return Ok(p);
        }
        if self.fixed {
            return Err(());
        }

        // Grow the most recent arena, or add a new one if that is not possible
        if self.grow_arena(layout.size(), mm).is_ok() {
            let arena = self.arenas.last_mut().unwrap();
            if let Ok(p) = arena.heap.allocate_first_fit(layout) {
                return Ok(p);
            }
        }
        self.add_arena(layout.size(), mm)?;
        let arena = self.arenas.last_mut().unwrap();
        arena.heap.allocate_first_fit(layout)
    }

    pub(crate) fn deallocate(&mut self, buffer: *const u8, layout: Layout, mm: &MemoryMap) {
        if let Some(size) = self.large.remove(&(buffer as usize)) {
            // Return the pages to the page allocator. This cannot fail, given that they were
            // allocated and assigned to the pool by allocate_large().
            mm.free_pages(buffer as u64, memmap::size_to_pages(size))
                .ok();
            return;
        }

        if let Some(arena) = self.arenas.iter_mut().find(|a| a.contains(buffer)) {
            // SAFETY: This is only called by MemoryMap::free_pool_for(), for allocations that
            // allocate() returned, and that were recorded along with their layout. This means
            // `buffer` is a non-NULL pointer that was returned by the heap of this arena for the
            // same layout, given that the arenas never overlap.
            unsafe {
                arena
                    .heap
                    .deallocate(NonNull::new_unchecked(buffer as _), layout)
            }
        }
    }
}
