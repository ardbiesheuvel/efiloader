// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Authors: Ilias Apalodimas <ilias.apalodimas@linaro.org>
//          Ard Biesheuvel <ardb@google.com>

use crate::guid;
use crate::*;
use crate::{status::*, Guid};

use core::slice;

pub const EFI_RNG_PROTOCOL_GUID: Guid = guid!("3152bca5-eade-433d-862e-c01cdc291f44");

type EfiRngAlgo = Guid;

// Don't describe the raw algorithm as the default, so that we can serve
// calls to the default RNG from RNDR as well, without knowing or having
// to specify what RNDR is backed by
const RNG_ALGORITHM_DEFAULT: EfiRngAlgo = guid!("b65fc704-93b4-4301-90ea-a75c3393b5e9");

const EFI_RNG_ALGORITHM_RAW: EfiRngAlgo = guid!("e43176d7-b6e8-4827-b784-7ffdc4b68561");

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
    let len = unsafe { &mut *rng_algorithm_list_size };
    if *len < 2 {
        *len = 2;
        return Status::EFI_BUFFER_TOO_SMALL;
    }
    let guids = unsafe { slice::from_raw_parts_mut(rng_algorithm_list, 2) };
    guids[0] = RNG_ALGORITHM_DEFAULT;
    guids[1] = EFI_RNG_ALGORITHM_RAW;
    *len = 2;
    Status::EFI_SUCCESS
}

extern "efiapi" fn get_rng<T>(
    _this: *mut T,
    rng_algorithm: *const EfiRngAlgo,
    rng_value_length: usize,
    rng_value: *mut u8,
) -> Status {
    let output = unsafe { slice::from_raw_parts_mut(rng_value, rng_value_length) };
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
