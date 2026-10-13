// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use core::fmt;

const EFI_ERROR_BASE: usize = isize::MAX as usize + 1;

/// EFI_STATUS - refer to the UEFI specification for details. This is not a Rust enum, given that
/// EFI images may pass or return any value, e.g., via Exit() or by returning from their entry
/// point.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct Status(pub usize);

impl Status {
    pub const EFI_SUCCESS: Status = Status(0);
    pub const EFI_LOAD_ERROR: Status = Status(1 + EFI_ERROR_BASE);
    pub const EFI_INVALID_PARAMETER: Status = Status(2 + EFI_ERROR_BASE);
    pub const EFI_UNSUPPORTED: Status = Status(3 + EFI_ERROR_BASE);
    pub const EFI_BAD_BUFFER_SIZE: Status = Status(4 + EFI_ERROR_BASE);
    pub const EFI_BUFFER_TOO_SMALL: Status = Status(5 + EFI_ERROR_BASE);
    pub const EFI_NOT_READY: Status = Status(6 + EFI_ERROR_BASE);
    pub const EFI_DEVICE_ERROR: Status = Status(7 + EFI_ERROR_BASE);
    pub const EFI_WRITE_PROTECTED: Status = Status(8 + EFI_ERROR_BASE);
    pub const EFI_OUT_OF_RESOURCES: Status = Status(9 + EFI_ERROR_BASE);
    pub const EFI_MEDIA_CHANGED: Status = Status(13 + EFI_ERROR_BASE);
    pub const EFI_NOT_FOUND: Status = Status(14 + EFI_ERROR_BASE);
    pub const EFI_ACCESS_DENIED: Status = Status(15 + EFI_ERROR_BASE);
    pub const EFI_NO_MAPPING: Status = Status(17 + EFI_ERROR_BASE);
    pub const EFI_TIMEOUT: Status = Status(18 + EFI_ERROR_BASE);
    pub const EFI_ABORTED: Status = Status(21 + EFI_ERROR_BASE);
    pub const EFI_SECURITY_VIOLATION: Status = Status(26 + EFI_ERROR_BASE);
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Status::EFI_SUCCESS => "EFI_SUCCESS",
            Status::EFI_LOAD_ERROR => "EFI_LOAD_ERROR",
            Status::EFI_INVALID_PARAMETER => "EFI_INVALID_PARAMETER",
            Status::EFI_UNSUPPORTED => "EFI_UNSUPPORTED",
            Status::EFI_BAD_BUFFER_SIZE => "EFI_BAD_BUFFER_SIZE",
            Status::EFI_BUFFER_TOO_SMALL => "EFI_BUFFER_TOO_SMALL",
            Status::EFI_NOT_READY => "EFI_NOT_READY",
            Status::EFI_DEVICE_ERROR => "EFI_DEVICE_ERROR",
            Status::EFI_WRITE_PROTECTED => "EFI_WRITE_PROTECTED",
            Status::EFI_OUT_OF_RESOURCES => "EFI_OUT_OF_RESOURCES",
            Status::EFI_MEDIA_CHANGED => "EFI_MEDIA_CHANGED",
            Status::EFI_NOT_FOUND => "EFI_NOT_FOUND",
            Status::EFI_ACCESS_DENIED => "EFI_ACCESS_DENIED",
            Status::EFI_NO_MAPPING => "EFI_NO_MAPPING",
            Status::EFI_TIMEOUT => "EFI_TIMEOUT",
            Status::EFI_ABORTED => "EFI_ABORTED",
            Status::EFI_SECURITY_VIOLATION => "EFI_SECURITY_VIOLATION",
            Status(s) => return write!(f, "Status({s:#x})"),
        };
        f.write_str(name)
    }
}
