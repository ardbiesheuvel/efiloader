// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::memmap;
use crate::memorytype::*;
use crate::EfiContext;
use crate::MemoryMapper;
use crate::EFI_PAGE_MASK;
use crate::{EfiMemoryType, FileLoader, Placement};

use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::{size_of, MaybeUninit};
use core::ops::Range;
use core::slice;
use core::str::from_utf8;
use log::{debug, trace};

#[cfg(target_arch = "aarch64")]
use crate::cmo;

#[derive(Copy, Clone)]
#[repr(C)]
struct DosHeader {
    magic: [u8; 2],
    dontcare: [u8; 58],
    pe_offset: u32,
}

#[cfg(target_arch = "x86_64")]
const ARCH_MACHINE_ID: u16 = 0x8664;

#[cfg(target_arch = "aarch64")]
const ARCH_MACHINE_ID: u16 = 0xaa64;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct PeHeader {
    signature: [u8; 4],
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,

    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entrypoint: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsys_version: u16,
    minor_subsys_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct PeSection {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

const EFI_IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
//const EFI_IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const EFI_IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

impl PeSection {
    fn get_name(&self) -> &str {
        from_utf8(&self.name).unwrap()
    }
}

const BASE_RELOC_TABLE_IDX: usize = 5;

#[repr(C)]
struct BaseRelocationBlock {
    rva: u32,
    size: u32,
}

const IMAGE_REL_BASED_ABSOLUTE: u16 = 0x0;
const IMAGE_REL_BASED_DIR64: u16 = 0xa000;
const IMAGE_REL_BASED_MASK: u16 = 0xf000;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct PeTable {
    rva: u32,
    size: u32,
}

pub(crate) struct PeLoader<'a> {
    pe_header: PeHeader,
    sections: Vec<PeSection>,
    table_directory: Vec<PeTable>,
    file_loader: &'a dyn FileLoader,
    efi: &'a EfiContext,
}

impl<'a> PeLoader<'a> {
    pub(crate) fn new(
        loader: &'a dyn FileLoader,
        efi: &'static EfiContext,
    ) -> Option<PeLoader<'a>> {
        let doshdr = {
            let mut h = MaybeUninit::<DosHeader>::uninit();
            unsafe {
                loader
                    .load_range(h.as_mut_ptr().cast(), 0, size_of::<DosHeader>())
                    .ok()?;
                h.assume_init()
            }
        };

        if doshdr.magic != ['M' as u8, 'Z' as u8] {
            debug!("Invalid DOS magic 0x{:x?}", doshdr.magic);
            return None;
        }

        if (doshdr.pe_offset as usize) < size_of::<DosHeader>()
            || (doshdr.pe_offset as usize) + size_of::<PeHeader>() > loader.get_size()
        {
            debug!("Invalid PE header offset 0x{:x?}", doshdr.pe_offset);
            return None;
        }

        let pehdr = {
            let mut h = MaybeUninit::<PeHeader>::uninit();
            unsafe {
                loader
                    .load_range(
                        h.as_mut_ptr().cast(),
                        doshdr.pe_offset as usize,
                        size_of::<PeHeader>(),
                    )
                    .ok()?;
                h.assume_init()
            }
        };

        if pehdr.signature != ['P' as u8, 'E' as u8, 0u8, 0u8] {
            debug!("Invalid PE magic 0x{:x?}", pehdr.signature);
            return None;
        }

        trace!(
            "PE header at offset 0x{:x?}: {:x?}",
            doshdr.pe_offset,
            pehdr
        );

        if pehdr.machine != ARCH_MACHINE_ID {
            debug!("Unsupported machine type 0x{:x?}", pehdr.machine);
            return None;
        }

        let petable_offset = doshdr.pe_offset + size_of::<PeHeader>() as u32;
        let petable_count = pehdr.number_of_rva_and_sizes as usize;
        let petable_size = size_of::<PeTable>() * petable_count;
        if petable_offset as usize + petable_size > loader.get_size() {
            debug!("PE table array runs past the end of the image");
            return None;
        }
        let petable_directory = {
            let mut v = Vec::<PeTable>::with_capacity(petable_count);
            unsafe {
                loader
                    .load_range(v.as_mut_ptr().cast(), petable_offset as usize, petable_size)
                    .ok()?;
                v.set_len(petable_count);
            }
            v
        };
        trace!("PE table directory: {:x?}", petable_directory);

        let section_offset = doshdr.pe_offset + 24 + pehdr.size_of_optional_header as u32;
        let section_count = pehdr.number_of_sections as usize;
        let sections_size = size_of::<PeSection>() * section_count;
        if section_offset as usize + sections_size > loader.get_size() {
            debug!("Section array runs past the end of the image");
            return None;
        }
        let sections = {
            let mut v = Vec::<PeSection>::with_capacity(section_count);
            unsafe {
                loader
                    .load_range(
                        v.as_mut_ptr().cast(),
                        section_offset as usize,
                        sections_size,
                    )
                    .ok()?;
                v.set_len(section_count);
            }
            v
        };
        trace!("Section headers: {:x?}", sections);

        for s in sections.iter() {
            if (s.pointer_to_raw_data | s.size_of_raw_data) & (pehdr.file_alignment - 1) != 0 {
                debug!(
                    "Section {} violates file alignment {:x}",
                    s.get_name(),
                    pehdr.file_alignment
                );
                return None;
            }

            if s.virtual_address & (pehdr.section_alignment - 1) != 0 {
                debug!(
                    "Section {} violates section alignment {:x}",
                    s.get_name(),
                    pehdr.section_alignment
                );
                return None;
            }

            if s.virtual_address + s.virtual_size > pehdr.size_of_image {
                debug!(
                    "Section {} exceeds image size {:x}",
                    s.get_name(),
                    pehdr.size_of_image
                );
                return None;
            }
        }

        Some(PeLoader {
            pe_header: pehdr,
            sections: sections,
            table_directory: petable_directory,
            file_loader: loader,
            efi: efi,
        })
    }

    unsafe fn apply_relocations(buf: &mut [MaybeUninit<u8>], tbl: &PeTable) -> Result<(), ()> {
        let (base, limit) = {
            let l = buf.len() as isize;
            let base = buf.as_mut_ptr() as *mut u8;
            (base, base.offset(l))
        };

        let mut reloc = base.offset(tbl.rva as isize);
        let reloc_end = reloc.offset(tbl.size as isize);

        if reloc > limit || reloc_end > limit {
            return Err(());
        }

        while reloc < reloc_end {
            const BSIZE: usize = size_of::<BaseRelocationBlock>();
            let block = &*(reloc as *const BaseRelocationBlock);
            reloc = reloc.offset(BSIZE as isize);
            if reloc > reloc_end || (block.size as usize) < BSIZE {
                return Err(());
            }

            let block_size = block.size as usize - BSIZE;
            let block_len = block_size / size_of::<u16>();
            let entries: &[u16] = slice::from_raw_parts(reloc as _, block_len);
            reloc = reloc.offset(block_size as isize);
            if reloc > reloc_end {
                return Err(());
            }

            for e in entries {
                let offset = block.rva + (*e as u32 % 0x1000);
                let p = base.offset(offset as isize);
                if p.offset(size_of::<u64>() as isize) > limit {
                    return Err(());
                }

                // Don't bother with all the different relocation types
                // Only the ones below are relevant for 64-bit architectures
                match *e & IMAGE_REL_BASED_MASK {
                    IMAGE_REL_BASED_ABSOLUTE => (),
                    IMAGE_REL_BASED_DIR64 => {
                        let p = p as *mut u64;
                        p.write_unaligned(p.read_unaligned() + base as u64);
                    }
                    _ => {
                        return Err(());
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn load(
        self,
        memory_type: EfiMemoryType,
        placement: Placement,
        mapper: &dyn MemoryMapper,
    ) -> Option<PeImage<'a>> {
        let buf = self.efi.allocate_pages(
            memmap::size_to_pages(self.pe_header.size_of_image as usize),
            memory_type,
            placement,
        )?;

        buf.fill(MaybeUninit::zeroed());
        // Load the PE header - some programs (such as GRUB or ACPI PRM runtime drivers)
        // rely on this even if the PE spec does not require it.
        unsafe {
            self.file_loader
                .load_range(
                    buf.as_mut_ptr().cast(),
                    0,
                    self.pe_header.size_of_headers as usize,
                )
                .ok()?;
        }

        for s in self.sections.iter() {
            let (va, vs, ra, rs) = (
                s.virtual_address as usize,
                s.virtual_size as usize,
                s.pointer_to_raw_data as usize,
                s.size_of_raw_data as usize,
            );
            unsafe {
                self.file_loader
                    .load_range(buf[va].as_mut_ptr().cast(), ra, vs.min(rs))
                    .ok()?;
            }
            if vs > rs {
                // Zero init remaining space
                buf[va + rs..va + vs].fill(MaybeUninit::zeroed());
            }
        }

        if let Some(dir) = self.table_directory.get(BASE_RELOC_TABLE_IDX) {
            log::trace!("Applying PE relocations");
            unsafe { Self::apply_relocations(buf, dir) }.ok()?;
        }

        // TODO free pages on failure

        let pe_image = PeImage {
            pe_loader: self,
            loaded_image: buf,
        };
        pe_image.remap(mapper).or_else(|| {
            log::warn!("Failed to map image with strict permissions!");

            #[cfg(feature = "strict_nx")]
            return None;

            #[cfg(not(feature = "strict_nx"))]
            {
                let start = buf.as_ptr() as usize;
                let end = start + buf.len();
                let range = start..end;
                mapper
                    .remap_range(&range, 0, EFI_MEMORY_RO | EFI_MEMORY_XP)
                    .ok()?;
                #[cfg(target_arch = "aarch64")]
                cmo::dcache_clean_to_pou(&range);
                Some(())
            }
        })?;
        Some(pe_image)
    }

    pub(crate) fn section_alignment(&self) -> usize {
        self.pe_header.section_alignment as _
    }
}

pub(crate) struct PeImage<'a> {
    pe_loader: PeLoader<'a>,
    loaded_image: &'a [MaybeUninit<u8>],
}

impl PeImage<'_> {
    fn remap(&self, mapper: &dyn MemoryMapper) -> Option<()> {
        if self.section_alignment() & EFI_PAGE_MASK != 0 {
            return None;
        }

        for s in self.sections() {
            let (set, clr) = match s.1 & (EFI_IMAGE_SCN_MEM_WRITE | EFI_IMAGE_SCN_MEM_EXECUTE) {
                0 => (EFI_MEMORY_RO | EFI_MEMORY_XP, 0),
                EFI_IMAGE_SCN_MEM_WRITE => (EFI_MEMORY_XP, EFI_MEMORY_RO),
                EFI_IMAGE_SCN_MEM_EXECUTE => (EFI_MEMORY_RO, EFI_MEMORY_XP),
                _ => {
                    return None;
                }
            };

            if clr & EFI_MEMORY_XP != 0 {
                // Clean the code regions of the loaded image to the PoU so we
                // can safely fetch instructions from them once the PXN/UXN
                // attributes are cleared
                #[cfg(target_arch = "aarch64")]
                cmo::dcache_clean_to_pou(&s.0);
            };

            let r = {
                let end = align_up!(s.0.end, self.section_alignment());
                s.0.start..end
            };
            mapper.remap_range(&r, set, clr).ok()?;
        }
        Some(())
    }

    pub(crate) fn image_base(&self) -> *const c_void {
        self.loaded_image.as_ptr().cast()
    }

    pub(crate) fn image_size(&self) -> u64 {
        self.pe_loader.pe_header.size_of_image as _
    }

    pub(crate) fn section_alignment(&self) -> usize {
        self.pe_loader.pe_header.section_alignment as _
    }

    pub(crate) fn entry_point(&self) -> *const u8 {
        self.loaded_image[self.pe_loader.pe_header.address_of_entrypoint as usize].as_ptr() as _
    }

    pub(crate) fn sections(&self) -> PeImageSectionIterator {
        PeImageSectionIterator {
            index: 0,
            pe_image: self,
        }
    }
}

pub(crate) struct PeImageSectionIterator<'a> {
    index: usize,
    pe_image: &'a PeImage<'a>,
}

impl Iterator for PeImageSectionIterator<'_> {
    type Item = (Range<usize>, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.pe_image.pe_loader.sections.len() {
            return None;
        }
        let s = &self.pe_image.pe_loader.sections[self.index];
        let start = self.pe_image.loaded_image[s.virtual_address as usize].as_ptr() as usize;
        let end = start + s.virtual_size as usize;
        self.index += 1;
        Some((start..end, s.characteristics))
    }
}
