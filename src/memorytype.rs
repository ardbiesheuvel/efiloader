// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::EfiMemoryType::EfiRuntimeServicesCode;
use crate::EfiMemoryType::EfiRuntimeServicesData;
use crate::{PhysicalAddress, VirtualAddress};

pub const EFI_PAGE_SHIFT: usize = 12;
pub const EFI_PAGE_SIZE: usize = 1 << EFI_PAGE_SHIFT;
pub const EFI_PAGE_MASK: usize = EFI_PAGE_SIZE - 1;

pub const EFI_MEMORY_UC: u64 = 0x1;
pub const EFI_MEMORY_WT: u64 = 0x4;
pub const EFI_MEMORY_WB: u64 = 0x8;

pub const EFI_MEMORY_RO: u64 = 0x20000;
pub const EFI_MEMORY_XP: u64 = 0x4000;

pub const EFI_MEMORY_RUNTIME: u64 = 0x8000_0000_0000_0000;

/// EFI memory types - refer to the UEFI specification for details.
#[allow(dead_code)]
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Debug)]
#[repr(u32)]
pub enum EfiMemoryType {
    EfiReservedEfiMemoryType,
    EfiLoaderCode,
    EfiLoaderData,
    EfiBootServicesCode,
    EfiBootServicesData,
    EfiRuntimeServicesCode,
    EfiRuntimeServicesData,
    EfiConventionalMemory,
    EfiUnusableMemory,
    EfiACPIReclaimMemory,
    EfiACPIMemoryNVS,
    EfiMemoryMappedIO,
    EfiMemoryMappedIOPortSpace,
    EfiPalCode,
    EfiPersistentMemory,
    EfiUnacceptedMemory,
}

/// EFI_MEMORY_DESCRIPTOR - refer to the UEFI specification for details
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EfiMemoryDescriptor {
    pub r#type: EfiMemoryType,
    pub physical_start: PhysicalAddress,
    pub virtual_start: VirtualAddress,
    pub number_of_pages: u64,
    pub attribute: u64,
    pub rt_attribute: u64,
}

impl EfiMemoryDescriptor {
    pub(crate) const fn zeroed() -> Self {
        EfiMemoryDescriptor {
            r#type: EfiMemoryType::EfiReservedEfiMemoryType,
            physical_start: 0,
            virtual_start: 0,
            number_of_pages: 0,
            attribute: 0,
            rt_attribute: 0,
        }
    }

    /// Returns whether the descriptor covers part of the range described by `phys`
    /// and `num_pages`
    pub(crate) fn intersects(&self, phys: u64, num_pages: u64) -> bool {
        let end1 = self.physical_start + (self.number_of_pages << EFI_PAGE_SHIFT);
        let end2 = phys + (num_pages << EFI_PAGE_SHIFT);

        phys < end1 && self.physical_start < end2
    }

    /// Returns whether the descriptor covers all of the range described by `phys`
    /// and `num_pages`
    pub(crate) fn encompasses(&self, phys: u64, num_pages: u64) -> bool {
        let end1 = self.physical_start + (self.number_of_pages << EFI_PAGE_SHIFT);
        let end2 = phys + (num_pages << EFI_PAGE_SHIFT);

        phys >= self.physical_start && end1 >= end2
    }

    pub(crate) fn to_memattr_table_entry(&self) -> Option<Self> {
        if self.attribute & EFI_MEMORY_RUNTIME != 0
            && (self.r#type == EfiRuntimeServicesCode || self.r#type == EfiRuntimeServicesData)
        {
            let mut ret = *self;
            ret.attribute = self.rt_attribute;
            Some(ret)
        } else {
            None
        }
    }
}
