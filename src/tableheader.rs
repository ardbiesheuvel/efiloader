// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use core::slice;
use core::sync::atomic::{compiler_fence, Ordering};
use crc::{Crc, CRC_32_CKSUM};

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

        let s = unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, self.header_size as usize)
        };
        self.crc32 = Crc::<u32>::new(&CRC_32_CKSUM).checksum(s);
    }
}
