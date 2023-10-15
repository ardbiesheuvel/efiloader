// SPDX-License-Identifier: GPL-2.0
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::*;
use crate::{status::*, Guid};

pub const EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID: Guid = guid!(
    0xf4560cf6,
    0x40ec,
    0x4b4a,
    [0xa1, 0x92, 0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89]
);

#[repr(C)]
pub struct EfiMemoryAttribute {
    get_memory_attributes: GetMemoryAttributes,
    set_memory_attributes: SetClearMemoryAttributes,
    clear_memory_attributes: SetClearMemoryAttributes,
}

type GetMemoryAttributes =
    extern "efiapi" fn(*mut EfiMemoryAttribute, PhysicalAddress, u64, *mut u64) -> Status;

type SetClearMemoryAttributes =
    extern "efiapi" fn(*mut EfiMemoryAttribute, PhysicalAddress, u64, u64) -> Status;

extern "efiapi" fn get_memory_attributes(
    _this: *mut EfiMemoryAttribute,
    base_address: PhysicalAddress,
    length: u64,
    attributes: *mut u64,
) -> Status {
    let mm = &EFI.mapper;

    let start = base_address as usize;
    let end = start + length as usize;

    if let Some(a) = mm.query_range(&(start..end)) {
        unsafe {
            *attributes = a;
        }
        Status::EFI_SUCCESS
    } else {
        Status::EFI_NO_MAPPING
    }
}

extern "efiapi" fn set_memory_attributes(
    _this: *mut EfiMemoryAttribute,
    base_address: PhysicalAddress,
    length: u64,
    attributes: u64,
) -> Status {
    let mm = &EFI.mapper;

    let start = base_address as usize;
    let end = start + length as usize;

    if let Ok(_) = mm.remap_range(&(start..end), attributes, 0) {
        Status::EFI_SUCCESS
    } else {
        Status::EFI_UNSUPPORTED
    }
}

extern "efiapi" fn clear_memory_attributes(
    _this: *mut EfiMemoryAttribute,
    base_address: PhysicalAddress,
    length: u64,
    attributes: u64,
) -> Status {
    let mm = &EFI.mapper;

    let start = base_address as usize;
    let end = start + length as usize;

    if let Ok(_) = mm.remap_range(&(start..end), 0, attributes) {
        Status::EFI_SUCCESS
    } else {
        Status::EFI_UNSUPPORTED
    }
}

impl EfiMemoryAttribute {
    pub fn new() -> EfiMemoryAttribute {
        EfiMemoryAttribute {
            get_memory_attributes: get_memory_attributes,
            set_memory_attributes: set_memory_attributes,
            clear_memory_attributes: clear_memory_attributes,
        }
    }
}

impl EfiProtocol for EfiMemoryAttribute {
    fn guid(&self) -> &'static Guid {
        &EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID
    }
}
