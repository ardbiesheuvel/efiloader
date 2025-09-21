// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::ConfigurationTablePointer::*;
use crate::EfiContext;
use crate::EfiMemoryType::EfiRuntimeServicesData;
use crate::Guid;
use crate::PoolBox;
use crate::EFI;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ptr::NonNull;
use core::slice;

#[derive(Copy, Clone)]
#[repr(C)]
pub(crate) struct Tuple(Guid, *const ());

pub enum ConfigurationTablePointer {
    Managed(NonNull<u8>),
    Raw(*const ()),
}

pub(crate) struct ConfigurationTable {
    guid: Guid,
    p: ConfigurationTablePointer,
}

impl ConfigurationTable {
    fn as_tuple(&self) -> Tuple {
        let p = match self.p {
            Managed(p) => p.as_ptr() as *const (),
            Raw(p) => p,
        };
        Tuple(self.guid, p)
    }
}

impl From<*const ()> for ConfigurationTablePointer {
    fn from(p: *const ()) -> Self {
        Raw(p)
    }
}

impl<T> From<PoolBox<T>> for ConfigurationTablePointer {
    fn from(p: PoolBox<T>) -> Self {
        Managed(p.take().cast())
    }
}

impl Drop for ConfigurationTable {
    fn drop(&mut self) {
        if let Managed(p) = self.p {
            EFI.memmap.free_pool(p.as_ptr() as *const u8).ok();
        }
    }
}

pub(crate) struct ConfigTableDb {
    db: RefCell<(BTreeMap<Guid, ConfigurationTable>, &'static mut [Tuple])>,
}

impl ConfigTableDb {
    pub(crate) fn new() -> Self {
        ConfigTableDb {
            db: RefCell::new((BTreeMap::new(), &mut [])),
        }
    }

    pub(crate) fn install<T>(&self, guid: &Guid, p: T, efi: &EfiContext)
    where
        T: Into<ConfigurationTablePointer>,
    {
        let mut db = self.db.borrow_mut();
        let (map, slice) = &mut *db;

        let p = p.into();
        match p {
            Raw(p) if p.is_null() => map.remove(guid),
            _ => map.insert(*guid, ConfigurationTable { guid: *guid, p }),
        };

        let mut st = efi.st.borrow_mut();
        if slice.len() < map.len() {
            if slice.len() > 0 {
                efi.memmap.free_pool(slice.as_ptr() as *const u8).ok();
            }

            // Allocate in powers of two, and at least 8 entries, so that this code runs only once
            // or twice rather than every time the number of entries changes.
            let len = map.len().next_power_of_two().max(8);
            let c = efi
                .memmap
                .allocate_pool::<Tuple>(EfiRuntimeServicesData, len)
                .unwrap();

            *slice = unsafe { slice::from_raw_parts_mut(c.as_ptr(), len) };

            st.configuration_table = slice.as_ptr() as *mut _;

            // We need to update the CRC when changing the pointer but this only happens when the
            // number of entries changes, in which case the conditional below will take care of it.
            assert!(st.number_of_table_entries != map.len());
        }

        if st.number_of_table_entries != map.len() {
            st.number_of_table_entries = map.len();
            st.hdr.update_crc();
        }

        slice[..map.len()].copy_from_slice(
            map.values()
                .map(|b| b.as_tuple())
                .collect::<Vec<_>>()
                .as_slice(),
        );
    }
}
