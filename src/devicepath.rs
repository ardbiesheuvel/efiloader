// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::{guid, Guid};

pub const EFI_DEVICE_PATH_PROTOCOL_GUID: Guid = guid!("09576e91-6d3f-11d2-8e39-00a0c969723b");

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug)]
#[repr(u8)]
pub enum DevicePathType {
    EFI_DEV_MEDIA = 4,
    EFI_DEV_END_PATH = 0x7f,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug)]
#[repr(u8)]
pub enum DevicePathSubtype {
    EFI_DEV_MEDIA_VENDOR = 3,
    EFI_DEV_END_ENTIRE = 0xff,
}

#[derive(Clone, PartialEq, Debug)]
#[repr(C, packed)]
pub struct DevicePath {
    pub _type: DevicePathType,
    pub subtype: DevicePathSubtype,
    pub size: u16,
}
impl Copy for DevicePath {}

#[repr(C)]
pub struct VendorMedia {
    pub header: DevicePath,
    pub vendor_guid: Guid,
}

impl DevicePath {
    // Check whether this device path is a prefix of `other`
    // If so, return the number of bytes matched
    pub(crate) fn is_prefix_of(&self, other: &DevicePath) -> Option<isize> {
        let mut ret = 0;
        let mut l = self;
        let mut r = other;

        while *l == *r {
            if l._type == DevicePathType::EFI_DEV_END_PATH || l.size != r.size {
                break;
            }

            let p1 = l as *const _ as *const u8;
            let p2 = r as *const _ as *const u8;
            let s = l.size as isize;
            let (s1, s2) = unsafe {
                (
                    core::slice::from_raw_parts(p1, s as usize),
                    core::slice::from_raw_parts(p2, s as usize),
                )
            };
            if s1 != s2 {
                return None;
            }

            // Advance to the next node
            l = unsafe { &*(p1.offset(s) as *const DevicePath) };
            r = unsafe { &*(p2.offset(s) as *const DevicePath) };
            ret += s;
        }

        // Return a positive number iff we matched the prefix
        // until the end node
        if l._type == DevicePathType::EFI_DEV_END_PATH {
            Some(ret)
        } else {
            None
        }
    }

    // Quick 'n' dirty equality test
    pub(crate) fn equals(&self, other: &DevicePath) -> bool {
        self.is_prefix_of(other).is_some() && other.is_prefix_of(self).is_some()
    }
}
