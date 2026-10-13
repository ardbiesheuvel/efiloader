// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::configtable::ConfigurationTablePointer;
use crate::memorytype::*;
use crate::poolalloc::PoolAllocator;
use crate::EfiMemoryType::*;
use crate::PhysicalAddress;
use crate::Placement::*;
use crate::{guid, Guid};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::cell::RefCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut, Range};
use core::ptr::*;
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Requested placement for page allocations. The variants `Max`, `Fixed` and `Anywhere` are 1:1
/// equivalents of the EFI AllocatePages() boot service's `Type` argument.
pub enum Placement {
    /// Placement below a certain address
    Max(u64),
    /// Placement at a fixed address
    Fixed(u64),
    /// Unrestricted placement
    Anywhere,

    /// Random placement using a `u32` seed with alignment
    Random(u32, u64),
    /// Arbitrary placement with alignment
    Aligned(u64),
    /// Placement with upper limit and alignment
    MaxAlignMask(u64, u64),
}

pub fn size_to_pages(size: usize) -> usize {
    (size + EFI_PAGE_MASK) >> EFI_PAGE_SHIFT
}

const EFI_MEMORY_ATTRIBUTES_FLAGS_RT_FORWARD_CONTROL_FLOW_GUARD: u32 = 0x1;

const EFI_MEMORY_ATTRIBUTES_TABLE_GUID: Guid = guid!(
    0xdcfa911d,
    0x26eb,
    0x469f,
    [0xa2, 0x20, 0x38, 0xb7, 0xdc, 0x46, 0x12, 0x20]
);

/// The EFI Memory Attributes Table, which is followed by `number_of_entries` entries of
/// `descriptor_size` bytes each
#[repr(C)]
struct MemoryAttributesTable {
    version: u32,
    number_of_entries: u32,
    descriptor_size: u32,
    flags: u32,
    entry: [EfiMemoryDescriptor; 0],
}

type MemMap = BTreeMap<PhysicalAddress, EfiMemoryDescriptor>;

struct PoolAllocation {
    pool_type: EfiMemoryType,
    layout: Layout,
    /// Whether the allocation was made on behalf of an EFI image, which may free it via FreePool()
    image: bool,
}

struct PoolAllocDb {
    allocators: BTreeMap<EfiMemoryType, PoolAllocator>,
    allocations: BTreeMap<*const u8, PoolAllocation>,
}

pub struct MemoryMap {
    memmap: RefCell<MemMap>,
    pool_alloc_db: RefCell<PoolAllocDb>,
    /// The page allocations made on behalf of EFI images, as a map of start to end addresses
    image_pages: RefCell<BTreeMap<u64, u64>>,
    mapkey: AtomicUsize,
    mem_attr_mapkey: AtomicUsize,
    mem_attr_disabled: AtomicBool,
}

impl MemoryMap {
    /// Create a new empty MemoryMap object
    pub fn new() -> Self {
        let alloc_db = PoolAllocDb {
            allocators: BTreeMap::new(),
            allocations: BTreeMap::new(),
        };
        MemoryMap {
            memmap: RefCell::new(BTreeMap::new()),
            pool_alloc_db: RefCell::new(alloc_db),
            image_pages: RefCell::new(BTreeMap::new()),
            mapkey: AtomicUsize::new(1),
            mem_attr_mapkey: AtomicUsize::new(0),
            mem_attr_disabled: AtomicBool::new(false),
        }
    }

    /// Don't generate an EFI Memory Attributes Table describing the runtime regions in the memory
    /// map, and don't install it as a configuration table. This permits the embedder to install
    /// a Memory Attributes Table of its own using
    /// [`EfiContext::install_configtable`](crate::EfiContext::install_configtable), e.g., the one
    /// provided by the underlying firmware, if the firmware's runtime regions are declared
    /// unchanged. Such a table can describe those regions more accurately than the single set of
    /// permissions per region that is passed to
    /// [`declare_runtime_region`](Self::declare_runtime_region). Note that it will not describe
    /// any runtime regions that are allocated by the EFI runtime itself.
    pub fn disable_memattr_table(&self) {
        self.mem_attr_disabled.store(true, Ordering::Relaxed);
    }

    pub(crate) fn allocate_pool<T>(
        &self,
        pool_type: EfiMemoryType,
        count: usize,
    ) -> Result<NonNull<T>, &'static str> {
        self.allocate_pool_for(pool_type, count, false)
    }

    /// Allocates pool memory on behalf of an EFI image, which may free it via FreePool().
    pub(crate) fn allocate_image_pool<T>(
        &self,
        pool_type: EfiMemoryType,
        count: usize,
    ) -> Result<NonNull<T>, &'static str> {
        self.allocate_pool_for(pool_type, count, true)
    }

    fn allocate_pool_for<T>(
        &self,
        pool_type: EfiMemoryType,
        count: usize,
        image: bool,
    ) -> Result<NonNull<T>, &'static str> {
        let size = count * core::mem::size_of::<T>();
        let align = core::mem::align_of::<T>().max(16);
        let layout = Layout::from_size_align(size, align).or(Err("Layout error"))?;
        let mut db = self.pool_alloc_db.borrow_mut();
        let p = db
            .allocators
            .entry(pool_type)
            .or_insert_with(|| PoolAllocator::new(pool_type))
            .allocate(layout, self)
            .or(Err("Failed to allocate from pool"))?;
        let a = PoolAllocation {
            pool_type,
            layout,
            image,
        };
        db.allocations.insert(p.as_ptr(), a);
        // SAFETY: NonNull<u8> and NonNull<T> have the same layout, and the allocation was created
        // with the size and alignment of `count` instances of T.
        unsafe { Ok(core::mem::transmute::<NonNull<u8>, NonNull<T>>(p)) }
    }

    pub(crate) fn free_pool(&self, buffer: *const u8) -> Result<(), ()> {
        self.free_pool_for(buffer, false)
    }

    /// Frees pool memory on behalf of an EFI image. Only allocations made via
    /// allocate_image_pool() can be freed this way.
    pub(crate) fn free_image_pool(&self, buffer: *const u8) -> Result<(), ()> {
        self.free_pool_for(buffer, true)
    }

    fn free_pool_for(&self, buffer: *const u8, image: bool) -> Result<(), ()> {
        let mut db = self.pool_alloc_db.borrow_mut();

        match db.allocations.get(&buffer) {
            Some(a) if a.image || !image => {}
            _ => return Err(()),
        }
        let a = db.allocations.remove(&buffer).unwrap();
        db.allocators
            .get_mut(&a.pool_type)
            .unwrap()
            .deallocate(buffer, a.layout, self);
        Ok(())
    }

    /// Declare a memory region `pool` as the region to be used for pool allocations of
    /// type `pool_type`. The region in question must already be accounted for in the
    /// memory map by a region of the same type. Pool allocations of this type will be
    /// served from this region only, and fail if it is exhausted. This fails if a pool
    /// of type `pool_type` exists already.
    pub fn declare_pool(
        &self,
        pool_type: EfiMemoryType,
        pool: &'static mut [MaybeUninit<u8>],
    ) -> Result<(), ()> {
        if pool.is_empty() {
            return Err(());
        }

        // Double check that the region is covered by the correct memory type
        let phys = pool.as_ptr() as u64;
        let num_pages = pool.len() >> EFI_PAGE_SHIFT;
        let memmap = self.memmap.borrow();
        memmap
            .values()
            .find(|&d| d.encompasses(phys, num_pages as u64) && d.r#type == pool_type)
            .map_or(Err(()), |_| Ok(()))?;

        let mut db = self.pool_alloc_db.borrow_mut();
        let alloc = &mut db.allocators;
        // Replacing an existing pool would result in its outstanding allocations being freed
        // into the new one
        if alloc.contains_key(&pool_type) {
            return Err(());
        }
        alloc.insert(pool_type, PoolAllocator::from_slice(pool_type, pool));
        Ok(())
    }

    fn inc_map_key(&self) {
        self.mapkey.fetch_add(1, Ordering::Release);
    }

    fn get_memattr_entries(&self, mm: &MemMap, mapkey: usize) -> Option<Vec<EfiMemoryDescriptor>> {
        if self.mem_attr_disabled.load(Ordering::Relaxed) {
            return None;
        }
        if self.mem_attr_mapkey.swap(mapkey, Ordering::Acquire) == mapkey {
            return None;
        }
        Some(
            mm.values()
                .filter_map(|desc| desc.to_memattr_table_entry())
                .collect(),
        )
    }

    /// Allocates a Memory Attributes Table describing `entries` from the EfiACPIReclaimMemory
    /// pool.
    fn new_memattr_table(
        &self,
        entries: &[EfiMemoryDescriptor],
    ) -> Result<ConfigurationTablePointer, &'static str> {
        let size = core::mem::size_of::<MemoryAttributesTable>() + core::mem::size_of_val(entries);
        let table = self
            .allocate_pool::<u8>(EfiACPIReclaimMemory, size)?
            .cast::<MemoryAttributesTable>();

        // SAFETY: `table` points to a pool allocation of `size` bytes, which is not shared with
        // anyone else yet. This covers the table and its entries, and pool allocations are at
        // least 16 byte aligned, which is sufficient for both.
        unsafe {
            table.write(MemoryAttributesTable {
                version: 2,
                number_of_entries: entries.len() as u32,
                descriptor_size: core::mem::size_of::<EfiMemoryDescriptor>() as u32,
                flags: 0 & EFI_MEMORY_ATTRIBUTES_FLAGS_RT_FORWARD_CONTROL_FLOW_GUARD,
                entry: [],
            });
            (&raw mut (*table.as_ptr()).entry)
                .cast::<EfiMemoryDescriptor>()
                .copy_from_nonoverlapping(entries.as_ptr(), entries.len());
        }
        Ok(ConfigurationTablePointer::Managed(table.cast()))
    }

    fn insert_region(&self, mm: &mut MemMap, desc: &EfiMemoryDescriptor) {
        debug_assert!(desc.physical_start as usize & EFI_PAGE_MASK == 0);

        // If insert() returns an existing item, something went really wrong and the memory
        // map will be in an inconsistent state.
        if let Some(_) = mm.insert(desc.physical_start, *desc) {
            panic!("Conflicting entries in memory map!\n");
        }
    }

    fn declare_region(
        &self,
        mm: &mut MemMap,
        phys: u64,
        num_pages: u64,
        _type: EfiMemoryType,
        attr: u64,
        rtattr: u64,
    ) -> Result<(), ()> {
        if phys & EFI_PAGE_MASK as u64 != 0 {
            return Err(());
        }

        // Check for overlap
        mm.values()
            .find(|&d| d.intersects(phys, num_pages))
            .map_or(Ok(()), |_| Err(()))?;

        // Entries can only be merged if they have the same type and attributes, and in the case
        // of runtime regions, the same permissions, as these are described individually in the
        // Memory Attributes Table.
        let mergeable = |d: &EfiMemoryDescriptor| {
            d.r#type == _type
                && d.attribute == attr
                && (attr & EFI_MEMORY_RUNTIME == 0 || d.rt_attribute == rtattr)
        };

        // Check whether the created/updated entry ends right where a
        // mergeable entry starts. If so, remove it and add its page count
        // to the new entry.
        let num_pages = {
            let mut l = num_pages;
            mm.retain(|p, d| {
                if *p == phys + (num_pages << EFI_PAGE_SHIFT) && mergeable(d) {
                    l += d.number_of_pages;
                    false
                } else {
                    true
                }
            });
            l
        };

        // Check if a mergeable entry exists that ends right where this
        // one starts. If so, update it to cover the newly declared region
        // instead of creating a new entry.
        if let Some(desc) = mm.values_mut().find(|d| {
            d.physical_start + (d.number_of_pages << EFI_PAGE_SHIFT) == phys && mergeable(d)
        }) {
            desc.number_of_pages += num_pages;
        } else {
            let d = EfiMemoryDescriptor {
                r#type: _type,
                physical_start: phys,
                virtual_start: 0,
                number_of_pages: num_pages,
                attribute: attr,
                rt_attribute: rtattr,
            };
            self.insert_region(mm, &d);
        }
        self.inc_map_key();
        Ok(())
    }

    /// Declare `range` as a region of available system memory in the EFI memory map.
    /// Page and pool allocations may be served from memory declared in this manner.
    /// The region must not exist yet in the memory map.
    ///
    /// # Safety
    ///
    /// The memory covered by `range` must be valid for reads and writes, and must be owned
    /// exclusively by this memory map for the remaining lifetime of the program, given that it
    /// will be handed out to the EFI runtime, to EFI images and to the embedder, e.g., as
    /// `&'static mut` slices returned by [`EfiContext::allocate_pages`](crate::EfiContext::allocate_pages).
    pub unsafe fn declare_memory_region(&self, range: &Range<usize>) -> Result<(), ()> {
        let mut mm = self.memmap.borrow_mut();
        let phys = range.start as PhysicalAddress;
        let pages = (range.end - range.start) as u64 >> EFI_PAGE_SHIFT;
        self.declare_region(
            &mut mm,
            phys,
            pages,
            EfiConventionalMemory,
            EFI_MEMORY_WB,
            0,
        )
    }

    /// Declare `range` as a EFI_MEMORY_RUNTIME region in the EFI memory map. This means that the
    /// region will be described to the OS as a region that needs to be mapped during calls to EFI
    /// runtime services.
    /// The region must not exist yet in the memory map, and must not be of type
    /// EfiConventionalMemory: use [`declare_memory_region`](Self::declare_memory_region) to
    /// declare memory that may be allocated from.
    pub fn declare_runtime_region(
        &self,
        range: &Range<usize>,
        _type: EfiMemoryType,
        attr: u64,
        rtattr: u64,
    ) -> Result<(), ()> {
        // Page allocations are served from EfiConventionalMemory regions, and so declaring such
        // a region here would circumvent the safety requirements of declare_memory_region()
        if _type == EfiConventionalMemory {
            return Err(());
        }
        let mut mm = self.memmap.borrow_mut();
        let phys = range.start as PhysicalAddress;
        let pages = (range.end - range.start) as u64 >> EFI_PAGE_SHIFT;
        self.declare_region(
            &mut mm,
            phys,
            pages,
            _type,
            attr | EFI_MEMORY_RUNTIME,
            rtattr | EFI_MEMORY_RUNTIME,
        )?;
        Ok(())
    }

    fn split_region(
        &self,
        mm: &mut MemMap,
        phys: PhysicalAddress,
        size: usize,
        _type: Option<EfiMemoryType>,
    ) -> Result<(), ()> {
        let desc = mm
            .values_mut()
            .find(|d| {
                d.r#type == _type.unwrap_or(d.r#type)
                    && d.physical_start < phys
                    && d.physical_start + (d.number_of_pages << EFI_PAGE_SHIFT)
                        >= phys + size as u64
            })
            .ok_or(())?;
        let num_pages = (phys - desc.physical_start) >> EFI_PAGE_SHIFT;
        let d = EfiMemoryDescriptor {
            r#type: desc.r#type,
            physical_start: phys,
            virtual_start: 0,
            number_of_pages: desc.number_of_pages - num_pages,
            attribute: desc.attribute,
            rt_attribute: desc.rt_attribute,
        };
        desc.number_of_pages = num_pages;
        self.insert_region(mm, &d);
        self.inc_map_key();
        Ok(())
    }

    pub(crate) fn convert_region(
        &self,
        phys: PhysicalAddress,
        size: usize,
        from: Option<EfiMemoryType>,
        to: EfiMemoryType,
        rtattr: u64,
    ) -> Result<(), ()> {
        let pages = size as u64 >> EFI_PAGE_SHIFT;
        let (attr, rtattr) = if to == EfiRuntimeServicesCode || to == EfiRuntimeServicesData {
            (
                EFI_MEMORY_RUNTIME | EFI_MEMORY_WB,
                EFI_MEMORY_RUNTIME | rtattr,
            )
        } else {
            (EFI_MEMORY_WB, rtattr)
        };

        if phys & EFI_PAGE_MASK as u64 != 0 {
            return Err(());
        }

        let mut mm = self.memmap.borrow_mut();

        // If the start address does not appear in the map yet, find the
        // entry that covers the range and split it in two.
        if !mm.contains_key(&phys) {
            self.split_region(&mut mm, phys, size, from)?;
        }

        // Take the entry that starts at the right address. This cannot fail as
        // split_region() will have created the entry if it did not exist before
        let mut desc = mm.remove(&phys).unwrap();

        // If such an entry exists, check whether it is of the
        // expected size and type. If not, put it back into the
        // map and return an error.
        if desc.r#type != from.unwrap_or(desc.r#type) || pages > desc.number_of_pages {
            self.insert_region(&mut mm, &desc);
            return Err(());
        }

        // Shrink the entry and increase its start address
        // accordingly. If it ends up empty, drop it.
        desc.number_of_pages -= pages;
        desc.physical_start += size as u64;
        if desc.number_of_pages > 0 {
            self.insert_region(&mut mm, &desc);
        }

        // Create a new entry for the freed up region
        self.declare_region(&mut mm, phys, pages, to, attr, rtattr)
    }

    /// Declare a region `range` as being allocated as a certain type. The region in question must
    /// already exist as available system RAM in the EFI memory map, and will be marked as being
    /// allocated as a region of `_type`.
    pub fn allocate_region(
        &self,
        range: &Range<usize>,
        _type: EfiMemoryType,
        rtattr: u64,
    ) -> Result<(), ()> {
        self.convert_region(
            range.start as PhysicalAddress,
            range.end - range.start,
            Some(EfiConventionalMemory),
            _type,
            rtattr,
        )
    }

    pub(crate) fn free_pages(&self, base: u64, pages: usize) -> Result<(), ()> {
        let size = pages << EFI_PAGE_SHIFT;
        self.convert_region(base, size, None, EfiConventionalMemory, 0)
    }

    /// Allocates pages on behalf of an EFI image, which may free them via FreePages(). Returns the
    /// base address of the allocation.
    pub(crate) fn allocate_image_pages(
        &self,
        pages: usize,
        _type: EfiMemoryType,
        placement: Placement,
    ) -> Option<u64> {
        let size = pages.checked_mul(EFI_PAGE_SIZE).filter(|&s| s > 0)?;
        let base = self.allocate_pages(pages, _type, placement)?.as_ptr() as u64;
        self.image_pages
            .borrow_mut()
            .insert(base, base + size as u64);
        Some(base)
    }

    /// Frees pages on behalf of an EFI image. Only allocations made via allocate_image_pages(), or
    /// parts thereof, can be freed this way.
    pub(crate) fn free_image_pages(&self, base: u64, pages: usize) -> Result<(), ()> {
        let end = (pages as u64)
            .checked_mul(EFI_PAGE_SIZE as u64)
            .and_then(|size| base.checked_add(size))
            .filter(|&end| end > base)
            .ok_or(())?;

        // Find the allocation that covers the range, if any
        let mut allocs = self.image_pages.borrow_mut();
        let (start, alloc_end) = allocs
            .range(..=base)
            .next_back()
            .map(|(&s, &e)| (s, e))
            .filter(|&(_, e)| e >= end)
            .ok_or(())?;

        self.free_pages(base, pages)?;

        // Retain the parts of the allocation that were not freed
        allocs.remove(&start);
        if start < base {
            allocs.insert(start, base);
        }
        if end < alloc_end {
            allocs.insert(end, alloc_end);
        }
        Ok(())
    }

    pub(crate) fn allocate_pages(
        &self,
        pages: usize,
        _type: EfiMemoryType,
        placement: Placement,
    ) -> Option<&'static mut [MaybeUninit<u8>]> {
        let mm = self.memmap.borrow();
        let p = pages as u64;

        // Narrow down the placement
        let placement = match placement {
            Max(max) => MaxAlignMask(max, EFI_PAGE_MASK as u64),
            Anywhere => MaxAlignMask(u64::MAX, EFI_PAGE_MASK as u64),
            Aligned(align) => MaxAlignMask(u64::MAX, align - 1),
            pl => pl,
        };

        let base = match placement {
            // Look for the descriptor that is the highest up in memory
            // that covers a sufficient number of pages below 'max' from
            // its started address aligned up to the requested alignment
            MaxAlignMask(max, mask) => {
                if let Some(desc) = mm
                    .values()
                    .take_while(|d| {
                        ((d.physical_start.wrapping_sub(1)) | mask)
                            .wrapping_add(p << EFI_PAGE_SHIFT)
                            <= max
                    })
                    .filter(|d| {
                        let num_pages = p
                            + (mask.wrapping_sub((d.physical_start.wrapping_sub(1)) & mask)
                                >> EFI_PAGE_SHIFT);
                        d.r#type == EfiConventionalMemory && d.number_of_pages >= num_pages
                    })
                    .last()
                {
                    // Find the highest possible base resulting from the limit in 'max'
                    let highest_base = max - (p << EFI_PAGE_SHIFT) + 1;

                    // Allocate from the top down
                    let offset = (desc.number_of_pages - p) << EFI_PAGE_SHIFT;
                    highest_base.min(desc.physical_start + offset) & !mask as u64
                } else {
                    return None;
                }
            }

            Placement::Random(seed, align) => {
                let mask = align - 1;

                // Get a list of (Range<u64>, descriptor) tuples describing all regions
                // that the randomized allocation may be served from.
                let mut slots: u64 = 0;
                let descs: Vec<(Range<u64>, &EfiMemoryDescriptor)> = mm
                    .values()
                    .filter_map(|d| {
                        // Include the number of pages lost to alignment in the page count
                        let num_pages = p
                            + (mask.wrapping_sub((d.physical_start.wrapping_sub(1)) & mask)
                                >> EFI_PAGE_SHIFT);
                        if d.r#type == EfiConventionalMemory && d.number_of_pages >= num_pages {
                            let sl =
                                1 + ((d.number_of_pages - num_pages) << EFI_PAGE_SHIFT) / align;
                            let end = slots + sl;
                            let r = slots..end;
                            slots = end;
                            Some((r, d))
                        } else {
                            None
                        }
                    })
                    .collect();

                // Use the seed to generate a random index into the slot list
                let index = (slots * seed as u64) >> 32;
                if let Some(entry) = descs
                    .into_iter()
                    .find(|e: &(Range<u64>, &EfiMemoryDescriptor)| e.0.contains(&index))
                {
                    let offset = (index - entry.0.start) * align;
                    ((entry.1.physical_start.wrapping_sub(1)) | mask).wrapping_add(1) + offset
                } else {
                    return None;
                }
            }

            Placement::Fixed(base) => base,

            _ => {
                return None; // unreachable
            }
        };
        drop(mm);

        let size = pages << EFI_PAGE_SHIFT;
        self.convert_region(base, size, Some(EfiConventionalMemory), _type, 0)
            .ok()?;

        // SAFETY: convert_region() succeeded, which means that the region was entirely covered by
        // EfiConventionalMemory, i.e., memory that the embedder declared as available, and that
        // it has now been assigned to the caller, until it is freed again via free_pages().
        unsafe {
            Some(slice::from_raw_parts_mut(
                base as *mut MaybeUninit<u8>,
                size,
            ))
        }
    }

    /// Copies the memory map into `tbl`, and returns the map key and the number of descriptors.
    /// Returns `None` if `tbl` is too small, in which case len() returns the number of descriptors
    /// that it needs to be able to hold.
    pub(crate) fn get_memory_map(
        &self,
        tbl: &mut [MaybeUninit<EfiMemoryDescriptor>],
    ) -> Option<(usize, usize)> {
        let (mm, key) = {
            let mm = self.memmap.borrow();
            let key = self.mapkey.load(Ordering::Acquire);

            if let Some(entries) = self.get_memattr_entries(&mm, key) {
                drop(mm);

                let table = self.new_memattr_table(&entries).ok()?;
                EFI.install_configtable(&EFI_MEMORY_ATTRIBUTES_TABLE_GUID, table);

                // We have updated the memory attributes tables, which itself may have caused changes
                // to the memory map. However, such changes should not affect the memory attributes
                // table itself, given that it only contains runtime regions.
                (self.memmap.borrow(), self.mapkey.load(Ordering::Acquire))
            } else {
                (mm, key)
            }
        };

        if tbl.len() < mm.len() {
            return None;
        }

        for (d, s) in tbl.iter_mut().zip(mm.values()) {
            d.write(*s);
        }
        Some((key, mm.len()))
    }

    pub(crate) fn len(&self) -> usize {
        self.memmap.borrow().len()
    }

    pub(crate) fn key(&self) -> usize {
        self.mapkey.load(Ordering::Relaxed)
    }

    pub(crate) fn box_new<T>(&self, memtype: EfiMemoryType, value: T) -> Result<PoolBox<T>, &str> {
        let p = self.allocate_pool::<T>(memtype, 1)?;

        // SAFETY: `p` was allocated above with the size and alignment of T, and is not shared with
        // anyone else yet. Initializing it via a raw pointer write avoids creating a reference to
        // the uninitialized allocation, and dropping its previous contents.
        unsafe { p.as_ptr().write(value) };
        Ok(PoolBox(Some(p)))
    }
}

use crate::EFI;

pub(crate) struct PoolBox<T: ?Sized>(Option<NonNull<T>>);
impl<T> PoolBox<T> {
    pub(crate) fn take(mut self) -> NonNull<T> {
        self.0.take().unwrap()
    }
}

impl<T: ?Sized> Drop for PoolBox<T> {
    fn drop(&mut self) {
        self.0.map(|p| {
            EFI.memmap.free_pool(p.as_ptr() as *const u8).ok();
        });
    }
}

impl<T: ?Sized> Deref for PoolBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: PoolBox instances are only created by box_new(), and own the initialized pool
        // allocation they point to until they are dropped or taken.
        unsafe { self.0.unwrap().as_ref() }
    }
}

impl<T: ?Sized> DerefMut for PoolBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: PoolBox instances are only created by box_new(), and own the initialized pool
        // allocation they point to until they are dropped or taken. Exclusive access is ensured by
        // `&mut self`.
        unsafe { self.0.unwrap().as_mut() }
    }
}
