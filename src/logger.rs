// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! A minimal logging facade.
//!
//! efiloader emits its diagnostic messages via the macros in this module, which pass them to the
//! function that the embedder registered via [`set_logger`], if any.

use core::fmt;
use core::sync::atomic::{AtomicPtr, Ordering};

/// The severity of a diagnostic message. The values match the corresponding syslog severities.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum Level {
    Error = 3,
    Warn = 4,
    Info = 6,
    Debug = 7,
    Trace = 8,
}

/// Signature of the logging callback: receives the level and the formatted message.
pub type LogFn = fn(Level, fmt::Arguments<'_>);

static LOGGER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register the function that receives all diagnostic output.
pub fn set_logger(f: LogFn) {
    LOGGER.store(f as *mut (), Ordering::Release);
}

#[doc(hidden)]
pub fn __log(level: Level, args: fmt::Arguments<'_>) {
    let p = LOGGER.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: only ever set from a `LogFn` in `set_logger()`
        let f: LogFn = unsafe { core::mem::transmute(p) };
        f(level, args);
    }
}

macro_rules! __log_at {
    ($lvl:ident, $($arg:tt)+) => {
        $crate::logger::__log($crate::logger::Level::$lvl, format_args!($($arg)+))
    };
}

// Not all levels are used by the crate at all times
#[allow(unused_macros)]
macro_rules! log_error { ($($arg:tt)+) => { __log_at!(Error, $($arg)+) }; }
#[allow(unused_macros)]
macro_rules! log_warn { ($($arg:tt)+) => { __log_at!(Warn, $($arg)+) }; }
#[allow(unused_macros)]
macro_rules! log_info { ($($arg:tt)+) => { __log_at!(Info, $($arg)+) }; }
#[allow(unused_macros)]
macro_rules! log_debug { ($($arg:tt)+) => { __log_at!(Debug, $($arg)+) }; }
#[allow(unused_macros)]
macro_rules! log_trace { ($($arg:tt)+) => { __log_at!(Trace, $($arg)+) }; }

#[allow(unused_imports)]
pub(crate) use {
    log_debug as debug, log_error as error, log_info as info, log_trace as trace, log_warn as warn,
};
