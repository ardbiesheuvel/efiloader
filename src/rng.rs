// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Authors: Ilias Apalodimas <ilias.apalodimas@linaro.org>
//          Ard Biesheuvel <ardb@google.com>

use crate::guid;
use crate::*;
use crate::{status::*, Guid};

use core::mem::size_of_val;
use core::{ptr, slice};

pub const EFI_RNG_PROTOCOL_GUID: Guid = guid!(
    0x3152bca5,
    0xeade,
    0x433d,
    [0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44]
);

type EfiRngAlgo = Guid;

// Don't describe the raw algorithm as the default, so that we can serve
// calls to the default RNG from RNDR as well, without knowing or having
// to specify what RNDR is backed by
const RNG_ALGORITHM_DEFAULT: EfiRngAlgo = guid!(
    0xb65fc704,
    0x93b4,
    0x4301,
    [0x90, 0xea, 0xa7, 0x5c, 0x33, 0x93, 0xb5, 0xe9]
);

const EFI_RNG_ALGORITHM_RAW: EfiRngAlgo = guid!(
    0xe43176d7,
    0xb6e8,
    0x4827,
    [0xb7, 0x84, 0x7f, 0xfd, 0xc4, 0xb6, 0x85, 0x61]
);

/// The algorithms reported by GetInfo()
const RNG_ALGORITHMS: [EfiRngAlgo; 2] = [RNG_ALGORITHM_DEFAULT, EFI_RNG_ALGORITHM_RAW];

#[derive(Debug)]
#[repr(C)]
pub struct EfiRng {
    get_info: GetInfo<Self>,
    get_rng: GetRNG<Self>,
}

type GetInfo<T> = extern "efiapi" fn(*mut T, *mut usize, *mut EfiRngAlgo) -> Status;

type GetRNG<T> = extern "efiapi" fn(*mut T, *const EfiRngAlgo, usize, *mut u8) -> Status;

extern "efiapi" fn get_info<T>(
    _this: *mut T,
    rng_algorithm_list_size: *mut usize,
    rng_algorithm_list: *mut EfiRngAlgo,
) -> Status {
    if rng_algorithm_list_size.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `rng_algorithm_list_size` is not NULL, and the UEFI spec requires it to point to a
    // valid UINTN.
    let size = unsafe { &mut *rng_algorithm_list_size };

    // The list size is in bytes, not in entries
    let required = size_of_val(&RNG_ALGORITHMS);
    if *size < required {
        *size = required;
        return Status::EFI_BUFFER_TOO_SMALL;
    }
    if rng_algorithm_list.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `rng_algorithm_list` is not NULL, and the UEFI spec requires it to be valid for writes
    // of `*size` bytes, which is sufficient to hold RNG_ALGORITHMS. The copy is performed bytewise,
    // and so it does not rely on the buffer being suitably aligned.
    unsafe {
        ptr::copy_nonoverlapping(
            RNG_ALGORITHMS.as_ptr() as *const u8,
            rng_algorithm_list as *mut u8,
            required,
        );
    }
    *size = required;
    Status::EFI_SUCCESS
}

extern "efiapi" fn get_rng<T>(
    _this: *mut T,
    rng_algorithm: *const EfiRngAlgo,
    rng_value_length: usize,
    rng_value: *mut u8,
) -> Status {
    if rng_value.is_null() || rng_value_length == 0 {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `rng_value` is not NULL, and the UEFI spec requires it to be valid for writes of
    // `rng_value_length` bytes. Its contents may be uninitialized, and so it is cleared before it
    // is turned into a [u8] slice.
    let output = unsafe {
        ptr::write_bytes(rng_value, 0, rng_value_length);
        slice::from_raw_parts_mut(rng_value, rng_value_length)
    };
    // SAFETY: `rng_algorithm` is only dereferenced if it is not NULL, in which case the UEFI spec
    // requires it to point to a valid EFI_RNG_ALGORITHM GUID.
    let use_raw = !rng_algorithm.is_null()
        && match unsafe { *rng_algorithm } {
            RNG_ALGORITHM_DEFAULT => false,
            EFI_RNG_ALGORITHM_RAW => true,
            _ => {
                return Status::EFI_UNSUPPORTED;
            }
        };

    if EFI.get_entropy(output, use_raw) {
        Status::EFI_SUCCESS
    } else {
        Status::EFI_UNSUPPORTED
    }
}

impl EfiRng {
    pub fn new() -> EfiRng {
        EfiRng {
            get_info: get_info::<EfiRng>,
            get_rng: get_rng::<EfiRng>,
        }
    }
}

impl EfiProtocol for EfiRng {
    fn guid(&self) -> &'static Guid {
        &EFI_RNG_PROTOCOL_GUID
    }
}
