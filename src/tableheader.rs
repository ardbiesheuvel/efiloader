// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use core::mem::size_of;
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

/// EFI tables that start with a TableHeader, which carries a CRC32 of the entire table.
///
/// Implementations should be `repr(C)` structs whose first field is the TableHeader returned by
/// `header()`, and whose size is recorded in its `header_size` field.
///
/// # Safety
///
/// Implementations must not contain any padding, as update_crc() reads the entire table as a byte
/// slice.
pub(crate) unsafe trait EfiTable: Sized {
    fn header(&mut self) -> &mut TableHeader;

    /// Recomputes the CRC32 of the table, e.g., after it has been modified.
    fn update_crc(&mut self) {
        self.header().crc32 = 0;
        compiler_fence(Ordering::Release);

        // SAFETY: `self` covers size_of::<Self>() bytes, all of which are initialized, given that
        // implementations of this trait have no padding.
        let s =
            unsafe { slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) };
        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(s);
        self.header().crc32 = crc;
    }
}
