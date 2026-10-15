// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::EfiProtocol;
use crate::{guid, Guid};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::size_of;

pub const EFI_DEVICE_PATH_PROTOCOL_GUID: Guid = guid!(
    0x9576e91,
    0x6d3f,
    0x11d2,
    [0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b]
);

/// The type of a device path node. This is not an enum, as device paths provided by EFI images may
/// contain any value, rather than only the ones that this crate uses.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DevicePathType(pub u8);

impl DevicePathType {
    pub const EFI_DEV_MEDIA: Self = Self(4);
    pub const EFI_DEV_END_PATH: Self = Self(0x7f);
}

/// The subtype of a device path node. This is not an enum, as device paths provided by EFI images
/// may contain any value, rather than only the ones that this crate uses.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DevicePathSubtype(pub u8);

impl DevicePathSubtype {
    pub const EFI_DEV_MEDIA_VENDOR: Self = Self(3);
    pub const EFI_DEV_MEDIA_FILE_PATH: Self = Self(4);
    pub const EFI_DEV_END_ENTIRE: Self = Self(0xff);
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

/// A device path that consists of a single vendor defined media device path node, which identifies
/// the device by means of a GUID
#[repr(C)]
pub(crate) struct VendorMediaDevicePath {
    vendor: VendorMedia,
    end: DevicePath,
}

impl VendorMediaDevicePath {
    pub(crate) fn new(vendor_guid: &Guid) -> Self {
        VendorMediaDevicePath {
            vendor: VendorMedia {
                header: DevicePath {
                    _type: DevicePathType::EFI_DEV_MEDIA,
                    subtype: DevicePathSubtype::EFI_DEV_MEDIA_VENDOR,
                    size: size_of::<VendorMedia>() as u16,
                },
                vendor_guid: *vendor_guid,
            },
            end: DevicePath {
                _type: DevicePathType::EFI_DEV_END_PATH,
                subtype: DevicePathSubtype::EFI_DEV_END_ENTIRE,
                size: size_of::<DevicePath>() as u16,
            },
        }
    }
}

impl EfiProtocol for VendorMediaDevicePath {
    fn guid(&self) -> &'static Guid {
        &EFI_DEVICE_PATH_PROTOCOL_GUID
    }
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

            // A node that does not cover its own header is malformed, and a node size of 0 would
            // make this loop forever
            if (l.size as usize) < size_of::<DevicePath>() {
                return None;
            }

            let p1 = l as *const _ as *const u8;
            let p2 = r as *const _ as *const u8;
            let s = l.size as isize;
            // SAFETY: `l` and `r` point to nodes of well formed device paths, and the size fields
            // in their headers are both equal to `s`, and so each node covers `s` bytes.
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
            // SAFETY: `l` is not an end node, and so it is followed by another node at offset `s`.
            l = unsafe { &*(p1.offset(s) as *const DevicePath) };
            // SAFETY: `r` has the same header as `l`, and so it is followed by another node too.
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

    /// Returns the size of the device path, including its end node, or None if it contains a node
    /// that does not cover its own header.
    pub(crate) fn size(&self) -> Option<usize> {
        let mut size = 0;
        let mut node = self;
        loop {
            let len = node.size as usize;
            if len < size_of::<DevicePath>() {
                return None;
            }
            size += len;
            if node._type == DevicePathType::EFI_DEV_END_PATH
                && node.subtype == DevicePathSubtype::EFI_DEV_END_ENTIRE
            {
                return Some(size);
            }
            // SAFETY: `node` is not the end node of the device path, and so it is followed by
            // another node at offset `len`.
            node = unsafe { &*((node as *const Self as *const u8).add(len) as *const Self) };
        }
    }

    /// Returns a copy of the device path, including its end node, or None if it contains a node
    /// that does not cover its own header.
    pub(crate) fn duplicate(&self) -> Option<Box<[u8]>> {
        let size = self.size()?;
        // SAFETY: size() returns the size of the entire device path, which covers `size` bytes.
        let bytes = unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size) };
        Some(Box::from(bytes))
    }

    /// Returns the node that follows this one.
    ///
    /// # Safety
    ///
    /// This node must not be an end node, and it must be part of a well formed device path, i.e.,
    /// one for which size() returns a value.
    pub(crate) unsafe fn next(&self) -> &DevicePath {
        // SAFETY: The caller guarantees that this node is followed by another node, at the offset
        // given by its size field.
        unsafe { &*((self as *const Self as *const u8).add(self.size as usize) as *const Self) }
    }

    /// Returns the path name of a file path media device path node, as a NUL terminated string.
    /// The path name may not be aligned, and so it is returned as a copy.
    pub(crate) fn file_path_name(&self) -> Vec<u16> {
        let len = (self.size as usize).saturating_sub(size_of::<DevicePath>()) / 2;
        let name = (self as *const Self as *const u8).wrapping_add(size_of::<DevicePath>());
        let mut path: Vec<u16> = (0..len)
            // SAFETY: The node covers `len` characters following its header.
            .map(|i| unsafe { (name as *const u16).add(i).read_unaligned() })
            .take_while(|&c| c != 0)
            .collect();
        path.push(0);
        path
    }
}
