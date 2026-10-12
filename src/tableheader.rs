// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use core::slice;
use core::sync::atomic::{compiler_fence, Ordering};
use crc::{Crc, CRC_32_ISO_HDLC};

#[repr(C)]
pub struct TableHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

impl TableHeader {
    pub fn update_crc(&mut self) {
        self.crc32 = 0;
        compiler_fence(Ordering::Release);

        // SAFETY: TableHeader is only used as the first field of repr(C) EFI tables, whose size is
        // recorded in `header_size`, and so `header_size` bytes can be read starting at `self`.
        // Note that this includes padding, which is not guaranteed to be initialized (e.g., after
        // the system table's FirmwareRevision field).
        let s = unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, self.header_size as usize)
        };
        self.crc32 = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(s);
    }
}
