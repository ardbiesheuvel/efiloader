// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the task priority services described in section 7.1 of the UEFI specification. The
//! event and timer services described in the same section are not implemented by efiloader.

mod common;
use common::*;

/// RaiseTPL() "raises the priority of the currently executing task and returns its previous
/// priority level", and TPL_APPLICATION is the level at which all normal execution occurs.
#[test]
fn raise_tpl_returns_previous_tpl() {
    let efi = setup();
    let bs = efi.bs();

    // SAFETY: Each RaiseTPL() call passes a TPL that is above the current one, and the TPL is
    // restored in reverse order.
    unsafe {
        let application = (bs.raise_tpl)(TPL_CALLBACK);
        assert_eq!(application, TPL_APPLICATION);
        let callback = (bs.raise_tpl)(TPL_NOTIFY);
        assert_eq!(callback, TPL_CALLBACK);
        let notify = (bs.raise_tpl)(TPL_HIGH_LEVEL);
        assert_eq!(notify, TPL_NOTIFY);

        (bs.restore_tpl)(notify);
        (bs.restore_tpl)(callback);
        (bs.restore_tpl)(application);
    }
}

/// The TPL passed to RaiseTPL() must not be below the current TPL, but it may be equal to it.
#[test]
fn raise_tpl_to_current_tpl() {
    let efi = setup();
    let bs = efi.bs();

    // SAFETY: Each RaiseTPL() call passes a TPL that is not below the current one, and the TPL is
    // restored in reverse order.
    unsafe {
        let application = (bs.raise_tpl)(TPL_APPLICATION);
        assert_eq!(application, TPL_APPLICATION);
        (bs.restore_tpl)(application);

        let application = (bs.raise_tpl)(TPL_NOTIFY);
        assert_eq!(application, TPL_APPLICATION);
        let notify = (bs.raise_tpl)(TPL_NOTIFY);
        assert_eq!(notify, TPL_NOTIFY);
        (bs.restore_tpl)(notify);
        (bs.restore_tpl)(application);
    }
}

/// RestoreTPL() "restores a task's priority level to its previous value", and so subsequent
/// RaiseTPL() calls report the restored TPL as the previous one.
#[test]
fn restore_tpl_restores_previous_tpl() {
    let efi = setup();
    let bs = efi.bs();

    // SAFETY: Each RaiseTPL() call passes a TPL that is above the current one, and each
    // RestoreTPL() call passes the TPL returned by the matching RaiseTPL() call.
    unsafe {
        let application = (bs.raise_tpl)(TPL_HIGH_LEVEL);
        (bs.restore_tpl)(application);

        let application = (bs.raise_tpl)(TPL_CALLBACK);
        assert_eq!(application, TPL_APPLICATION);
        let callback = (bs.raise_tpl)(TPL_HIGH_LEVEL);
        assert_eq!(callback, TPL_CALLBACK);
        (bs.restore_tpl)(callback);

        let callback = (bs.raise_tpl)(TPL_NOTIFY);
        assert_eq!(callback, TPL_CALLBACK);
        (bs.restore_tpl)(callback);
        (bs.restore_tpl)(application);

        let application = (bs.raise_tpl)(TPL_NOTIFY);
        assert_eq!(application, TPL_APPLICATION);
        (bs.restore_tpl)(application);
    }
}
