// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the logging facade, via which efiloader passes its diagnostic messages to the function
//! that the embedder registered via efiloader::logger::set_logger(). These live in a separate test
//! binary, given that the logger applies to the entire process.

mod common;
use common::*;

use core::ffi::c_void;
use core::fmt;
use core::ptr;
use efiloader::logger::Level;
use std::sync::Mutex;

/// The messages that the logger received, along with their levels
static MESSAGES: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());

fn logger(level: Level, args: fmt::Arguments<'_>) {
    MESSAGES.lock().unwrap().push((level, args.to_string()));
}

/// Returns whether the logger received a message at `level` that contains `text`
fn logged(level: Level, text: &str) -> bool {
    MESSAGES
        .lock()
        .unwrap()
        .iter()
        .any(|(l, m)| *l == level && m.contains(text))
}

/// Diagnostic messages are passed to the registered logger, along with their level.
#[test]
fn messages_are_passed_to_the_logger() {
    let efi = setup();
    efiloader::logger::set_logger(logger);

    // GetNextMonotonicCount() is not implemented, which efiloader warns about
    let mut count = 0;
    // SAFETY: `count` is a valid pointer.
    unsafe { (efi.bs().get_next_monotonic_count)(&mut count) };
    assert!(logged(Level::Warn, "get_next_monotonic_count()"));

    // AllocatePool() traces its calls
    let mut buffer = ptr::null_mut::<c_void>();
    // SAFETY: `buffer` is a valid pointer, and the allocation is freed again before returning.
    unsafe {
        let status = (efi.bs().allocate_pool)(EFI_LOADER_DATA, 123, &mut buffer);
        assert_eq!(status, Status::EFI_SUCCESS);
        assert_eq!((efi.bs().free_pool)(buffer), Status::EFI_SUCCESS);
    }
    assert!(logged(Level::Trace, "AllocatePool() 123"));
}
