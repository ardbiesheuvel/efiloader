// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Small helpers for the UTF-16 strings that EFI uses.

use alloc::string::String;

/// Encode an ASCII string literal as a NUL terminated UTF-16 array at compile time.
macro_rules! utf16_lit {
    ($s:literal) => {{
        const S: &str = $s;
        const N: usize = S.len() + 1;
        const A: [u16; N] = {
            let b = S.as_bytes();
            let mut a = [0u16; N];
            let mut i = 0;
            while i < b.len() {
                assert!(b[i].is_ascii());
                a[i] = b[i] as u16;
                i += 1;
            }
            a
        };
        &A
    }};
}
pub(crate) use utf16_lit;

/// Convert a NUL terminated UTF-16 string to a `String`, replacing invalid code units with
/// U+FFFD.
///
/// # Safety
///
/// `p` must point to a NUL terminated array of `u16`.
pub(crate) unsafe fn from_ptr_lossy(p: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the caller guarantees NUL termination
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: we just established that `len` code units are readable
    let s = unsafe { core::slice::from_raw_parts(p, len) };
    char::decode_utf16(s.iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}
