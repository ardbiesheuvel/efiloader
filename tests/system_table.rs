// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the strings that EFI images exchange with efiloader via the system table: the firmware
//! vendor string, and the strings that EFI images write via the console output protocol, which
//! efiloader passes on to the console of the embedder.

mod common;
use common::*;

/// Returns the NUL terminated string at `s`, without the terminator
///
/// # Safety
///
/// `s` must point to a NUL terminated array of UTF-16 code units.
unsafe fn read_string(s: *const Char16) -> Vec<Char16> {
    let mut v = Vec::new();
    // SAFETY: The caller guarantees that `s` is NUL terminated, and so every code unit up to and
    // including the terminator is readable.
    unsafe {
        while *s.add(v.len()) != 0 {
            v.push(*s.add(v.len()));
        }
    }
    v
}

/// "FirmwareVendor: A pointer to a null terminated string that identifies the vendor that produces
/// the system firmware for the platform."
#[test]
fn the_firmware_vendor_is_a_nul_terminated_string() {
    let efi = setup();
    let vendor = efi.system_table().firmware_vendor;
    assert!(!vendor.is_null());
    // SAFETY: The firmware vendor string is NUL terminated, as checked by this test.
    let vendor = unsafe { read_string(vendor) };
    assert_eq!(String::from_utf16(&vendor).unwrap(), "Google");
}

/// Writes `string`, which need not be valid UTF-16, to the console via ConOut->OutputString(), and
/// returns the status along with the output that the console of the embedder received
fn output_string(efi: &Efi, string: &[Char16]) -> (Status, String) {
    assert_eq!(string.last(), Some(&0), "string must be NUL terminated");
    let con_out = efi.system_table().con_out as *mut SimpleTextOutputProtocol;
    efi.take_console_output();
    // SAFETY: ConOut points to the console output protocol instance, which remains valid, and
    // `string` is NUL terminated.
    let status = unsafe { ((*con_out).output_string)(con_out, string.as_ptr()) };
    (status, efi.take_console_output())
}

/// "OutputString(): Writes a string to the output device." efiloader writes it to the console of
/// the embedder.
#[test]
fn output_string_writes_to_the_console() {
    let efi = setup();
    let (status, output) = output_string(&efi, &utf16z("Hello, world!\r\n"));
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(output, "Hello, world!\r\n");
}

/// The string is decoded as UTF-16, which UCS-2 is a subset of, and so characters outside the BMP
/// are passed on if they are encoded as surrogate pairs. Unpaired surrogates, which are not valid
/// UTF-16, are passed on as U+FFFD instead.
#[test]
fn output_string_decodes_utf16() {
    let efi = setup();
    let string = [0xd83d, 0xde00, 0x20, 0xd800, 0x41, 0xdc00, 0];
    let (status, output) = output_string(&efi, &string);
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(output, "\u{1f600} \u{fffd}A\u{fffd}");
}
