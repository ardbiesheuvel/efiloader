// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::UEFI_REVISION;
use crate::{memorytype::*, status::*, tableheader::*};
use crate::{Bool, Char16, Guid, PhysicalAddress};

#[derive(Debug)]
#[repr(C)]
pub struct Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub timezone: u16,
    pub daylight: u8,
    pub pad2: u8,
}

#[repr(C)]
pub struct TimeCapabilities {
    resolution: u32,
    accuracy: u32,
    sets_to_zero: Bool,
}

#[allow(dead_code)]
#[repr(C)]
pub enum ResetType {
    EfiResetCold,
    EfiResetWarm,
    EfiResetShutdown,
    EfiResetPlatformSpecific,
}

#[repr(C)]
struct CapsuleHeader {
    capsule_guid: Guid,
    header_size: u32,
    flags: u32,
    capsule_image_size: u32,
}

pub type GetTime =
    extern "efiapi" fn(_time: *mut Time, _capabilities: *mut TimeCapabilities) -> Status;

pub type SetTime = extern "efiapi" fn(_time: *const Time) -> Status;

type GetWakeupTime =
    extern "efiapi" fn(_enabled: *mut Bool, _pending: *mut Bool, _time: *mut Time) -> Status;

type SetWakeupTime = extern "efiapi" fn(_enable: Bool, _time: *const Time) -> Status;

type SetVirtualAddressMap = extern "efiapi" fn(
    _memory_map_size: usize,
    _descriptor_size: usize,
    _descriptor_version: u32,
    _virtual_map: *const EfiMemoryDescriptor,
) -> Status;

type ConvertPointer =
    extern "efiapi" fn(_debug_disposition: usize, _address: *const *mut ()) -> Status;

pub type GetVariable = extern "efiapi" fn(
    _variable_name: *const Char16,
    _vendor_guid: *const Guid,
    _attributes: *mut u32,
    _data_size: *mut usize,
    _data: *mut (),
) -> Status;

pub type GetNextVariableName = extern "efiapi" fn(
    _variable_name_size: *mut usize,
    _variable_name: *mut Char16,
    _vendor_guid: *mut Guid,
) -> Status;

pub type SetVariable = extern "efiapi" fn(
    _variable_name: *const Char16,
    _vendor_guid: *const Guid,
    _attributes: u32,
    _data_size: usize,
    _data: *const (),
) -> Status;

type GetNextHighMonotonicCount = extern "efiapi" fn(_high_count: *mut u32) -> Status;

pub type ResetSystem = extern "efiapi" fn(
    _reset_type: ResetType,
    _reset_status: Status,
    _data_size: usize,
    _reset_data: *const (),
) -> Status;

type UpdateCapsule = extern "efiapi" fn(
    _capsule_header_array: *const *const CapsuleHeader,
    _capsule_count: usize,
    _scatter_gather_list: PhysicalAddress,
) -> Status;

type QueryCapsuleCapabilities = extern "efiapi" fn(
    _capsule_header_array: *const *const CapsuleHeader,
    _capsule_count: usize,
    _maximum_capsule_size: *mut u64,
    _reset_type: *mut ResetType,
) -> Status;

type QueryVariableInfo = extern "efiapi" fn(
    _attributes: u32,
    _maximum_variable_storage_size: *mut u64,
    _remaining_variable_storage_size: *mut u64,
    _maximum_variable_size: *mut u64,
) -> Status;

#[repr(C)]
pub(crate) struct RuntimeServices {
    pub(crate) hdr: TableHeader,
    pub(crate) get_time: GetTime,
    pub(crate) set_time: SetTime,
    get_wakeup_time: GetWakeupTime,
    set_wakeup_time: SetWakeupTime,

    set_virtual_address_map: SetVirtualAddressMap,
    convert_pointer: ConvertPointer,

    pub(crate) get_variable: GetVariable,
    pub(crate) get_next_variable_name: GetNextVariableName,
    pub(crate) set_variable: SetVariable,

    get_next_high_mono_count: GetNextHighMonotonicCount,
    pub(crate) reset_system: ResetSystem,

    update_capsule: UpdateCapsule,
    query_capsule_capabilities: QueryCapsuleCapabilities,

    query_variable_info: QueryVariableInfo,
}

extern "efiapi" fn get_time(_time: *mut Time, _capabilities: *mut TimeCapabilities) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn set_time(_time: *const Time) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn get_wakeup_time(
    _enabled: *mut Bool,
    _pending: *mut Bool,
    _time: *mut Time,
) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn set_wakeup_time(_enable: Bool, _time: *const Time) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn set_virtual_address_map(
    _memory_map_size: usize,
    _descriptor_size: usize,
    _descriptor_version: u32,
    _virtual_map: *const EfiMemoryDescriptor,
) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn convert_pointer(_debug_disposition: usize, _address: *const *mut ()) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn get_variable(
    _variable_name: *const Char16,
    _vendor_guid: *const Guid,
    _attributes: *mut u32,
    _data_size: *mut usize,
    _data: *mut (),
) -> Status {
    Status::EFI_NOT_FOUND
}

extern "efiapi" fn get_next_variable_name(
    _variable_name_size: *mut usize,
    _variable_name: *mut Char16,
    _vendor_guid: *mut Guid,
) -> Status {
    Status::EFI_NOT_FOUND
}

extern "efiapi" fn set_variable(
    _variable_name: *const Char16,
    _vendor_guid: *const Guid,
    _attributes: u32,
    _data_size: usize,
    _data: *const (),
) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn get_next_high_monotonic_count(_high_count: *mut u32) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn reset_system(
    _reset_type: ResetType,
    _reset_status: Status,
    _data_size: usize,
    _reset_data: *const (),
) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn update_capsule(
    _capsule_header_array: *const *const CapsuleHeader,
    _capsule_count: usize,
    _scatter_gather_list: PhysicalAddress,
) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn query_capsule_capabilities(
    _capsule_header_array: *const *const CapsuleHeader,
    _capsule_count: usize,
    _maximum_capsule_size: *mut u64,
    _reset_type: *mut ResetType,
) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn query_variable_info(
    _attributes: u32,
    _maximum_variable_storage_size: *mut u64,
    _remaining_variable_storage_size: *mut u64,
    _maximum_variable_size: *mut u64,
) -> Status {
    Status::EFI_UNSUPPORTED
}

impl RuntimeServices {
    pub fn new() -> RuntimeServices {
        let mut rt = RuntimeServices {
            hdr: TableHeader {
                signature: [b'R', b'U', b'N', b'T', b'S', b'E', b'R', b'V'],
                revision: UEFI_REVISION,
                header_size: core::mem::size_of::<RuntimeServices>() as u32,
                crc32: 0,
                reserved: 0,
            },

            get_time: get_time,
            set_time: set_time,
            get_wakeup_time: get_wakeup_time,
            set_wakeup_time: set_wakeup_time,

            set_virtual_address_map: set_virtual_address_map,
            convert_pointer: convert_pointer,

            get_variable: get_variable,
            get_next_variable_name: get_next_variable_name,
            set_variable: set_variable,

            get_next_high_mono_count: get_next_high_monotonic_count,
            reset_system: reset_system,

            update_capsule: update_capsule,
            query_capsule_capabilities: query_capsule_capabilities,

            query_variable_info: query_variable_info,
        };
        rt.hdr.update_crc();
        rt
    }
}
