// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::UEFI_REVISION;
use crate::{
    bootservices::*, configtable, runtimeservices::*, simpletext::*, tableheader::*, Char16, Handle,
};

use const_utf16::encode_null_terminated;
use core::ptr;

#[repr(C)]
pub struct SystemTable {
    pub(super) hdr: TableHeader,
    firmware_vendor: *const Char16,
    firmware_revision: u32,
    console_in_handle: Handle,
    con_in: *const EfiSimpleTextInput,
    console_out_handle: Handle,
    con_out: *const EfiSimpleTextOutput,
    standard_error_handle: Handle,
    stderr: *const EfiSimpleTextOutput,
    runtime_services: *const RuntimeServices,
    boot_services: *const BootServices,
    pub(super) number_of_table_entries: usize,
    pub(super) configuration_table: *mut configtable::Tuple,
}

impl SystemTable {
    pub(super) fn new(
        bs: *const BootServices,
        rt: *const RuntimeServices,
        conin: *const EfiSimpleTextInput,
        conout: *const EfiSimpleTextOutput,
        conhandle: Handle,
    ) -> SystemTable {
        let mut st = SystemTable {
            hdr: TableHeader {
                signature: [b'I', b'B', b'I', b' ', b'S', b'Y', b'S', b'T'],
                revision: UEFI_REVISION,
                header_size: core::mem::size_of::<SystemTable>() as u32,
                crc32: 0,
                reserved: 0,
            },
            firmware_vendor: encode_null_terminated!("Google").as_ptr(),
            firmware_revision: UEFI_REVISION,
            console_in_handle: conhandle,
            con_in: conin,
            console_out_handle: conhandle,
            con_out: conout,
            standard_error_handle: conhandle,
            stderr: conout,
            runtime_services: rt,
            boot_services: bs,
            number_of_table_entries: 0,
            configuration_table: ptr::null_mut(),
        };
        st.hdr.update_crc();
        st
    }
}
