// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::devicepath::*;
use crate::memmap::Placement;
use crate::EfiProtocol;
use crate::FileLoader;
use crate::{memorytype::*, status::*, tableheader::*};
use crate::{Bool, Char16, Event, EventNotify, Guid, Handle, PhysicalAddress, Tpl};
use crate::{ProtocolDb, TPL_APPLICATION, UEFI_REVISION};

use crate::bootservices::AllocateType::*;
use crate::devicepath::EFI_DEVICE_PATH_PROTOCOL_GUID;
use crate::loadedimage::exit_image;
use crate::new_handle;
use crate::EfiLoadedImage;
use crate::EFI;
use crate::EFI_LOADED_IMAGE_PROTOCOL_GUID;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::mem::{size_of, MaybeUninit};
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{ptr, slice};
use crc::{Crc, CRC_32_CKSUM};

const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;

#[allow(dead_code)]
#[derive(PartialEq)]
#[repr(C)]
enum AllocateType {
    AllocateAnyPages,
    AllocateMaxAddress,
    AllocateAddress,
}

#[allow(dead_code)]
#[repr(C)]
enum TimerDelay {
    TimerCancel,
    TimerPeriodic,
    TimerRelative,
}

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(PartialEq)]
#[repr(C)]
enum InterfaceType {
    EFI_NATIVE_INTERFACE,
}

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
#[repr(C)]
enum LocateSearchType {
    AllHandles,
    ByRegisterNotify,
    ByProtocol,
}

const EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL: u32 = 0x00000001;
//const EFI_OPEN_PROTOCOL_GET_PROTOCOL: u32 = 0x00000002;
const EFI_OPEN_PROTOCOL_TEST_PROTOCOL: u32 = 0x00000004;
//const EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER: u32 = 0x00000008;
//const EFI_OPEN_PROTOCOL_BY_DRIVER: u32 = 0x00000010;
//const EFI_OPEN_PROTOCOL_EXCLUSIVE: u32 = 0x00000020;

#[repr(C)]
struct OpenProtocolInformationEntry {
    _agent_handle: Handle,
    _controller_handle: Handle,
    _attributes: u32,
    _open_count: u32,
}

type RaiseTpl = extern "efiapi" fn(Tpl) -> Tpl;
type RestoreTpl = extern "efiapi" fn(Tpl);

type AllocatePages =
    extern "efiapi" fn(AllocateType, EfiMemoryType, usize, *mut PhysicalAddress) -> Status;
type FreePages = extern "efiapi" fn(PhysicalAddress, usize) -> Status;
type GetMemoryMap = extern "efiapi" fn(
    *mut usize,
    *mut EfiMemoryDescriptor,
    *mut usize,
    *mut usize,
    *mut u32,
) -> Status;
type AllocatePool = extern "efiapi" fn(EfiMemoryType, usize, *mut *mut c_void) -> Status;
type FreePool = extern "efiapi" fn(*mut c_void) -> Status;

type CreateEvent = extern "efiapi" fn(u32, Tpl, EventNotify, *const c_void, *mut Event) -> Status;
type SetTimer = extern "efiapi" fn(Event, TimerDelay, u64) -> Status;
type WaitForEvent = extern "efiapi" fn(usize, *const Event, *mut usize) -> Status;
type SignalOrCheckOrCloseEvent = extern "efiapi" fn(Event) -> Status;

type InstallProtocolInterface =
    extern "efiapi" fn(*mut Handle, *const Guid, InterfaceType, *const c_void) -> Status;
type ReinstallProtocolInterface =
    extern "efiapi" fn(Handle, *const Guid, *const c_void, *const c_void) -> Status;
type UninstallProtocolInterface = extern "efiapi" fn(Handle, *const Guid, *const c_void) -> Status;
type HandleProtocol = extern "efiapi" fn(Handle, *const Guid, *mut *const c_void) -> Status;
type RegisterProtocolNotify = extern "efiapi" fn(*const Guid, Event, *mut *const c_void) -> Status;
type LocateHandle = extern "efiapi" fn(
    LocateSearchType,
    *const Guid,
    *const c_void,
    *mut usize,
    *mut Handle,
) -> Status;
type LocateDevicePath =
    extern "efiapi" fn(*const Guid, *mut *const DevicePath, *mut Handle) -> Status;
type InstallConfigurationTable = extern "efiapi" fn(*const Guid, *const c_void) -> Status;

type LoadImage = extern "efiapi" fn(
    Bool,
    Handle,
    *const DevicePath,
    *const c_void,
    usize,
    *mut Handle,
) -> Status;
type StartImage = extern "efiapi" fn(Handle, *mut usize, *mut Char16) -> Status;
type Exit = extern "efiapi" fn(Handle, Status, usize, *const Char16) -> Status;
type UnloadImage = extern "efiapi" fn(Handle) -> Status;
type ExitBootServices = extern "efiapi" fn(Handle, usize) -> Status;

type GetNextMonotonicCount = extern "efiapi" fn(*mut u64) -> Status;
pub type Stall = extern "efiapi" fn(usize) -> Status;
type SetWatchdogTimer = extern "efiapi" fn(usize, u64, usize, *const Char16) -> Status;

type ConnectController = extern "efiapi" fn(Handle, Handle, *const DevicePath, Bool) -> Status;
type DisconnectController = extern "efiapi" fn(Handle, Handle, Handle) -> Status;

type OpenProtocol =
    extern "efiapi" fn(Handle, *const Guid, *mut *const c_void, Handle, Handle, u32) -> Status;
type CloseProtocol = extern "efiapi" fn(Handle, *const Guid, Handle, Handle) -> Status;
type OpenProtocolInformation = extern "efiapi" fn(
    Handle,
    *const Guid,
    *mut *const OpenProtocolInformationEntry,
    *mut usize,
) -> Status;

type ProtocolPerHandle = extern "efiapi" fn(Handle, *mut *const *const Guid, *mut usize) -> Status;
type LocateHandleBuffer = extern "efiapi" fn(
    LocateSearchType,
    *const Guid,
    *const c_void,
    *mut usize,
    *mut *const Handle,
) -> Status;
type LocateProtocol = extern "efiapi" fn(*const Guid, *const c_void, *mut *const c_void) -> Status;

type InstallMultipleProtocolInterfaces = unsafe extern "efiapi" fn(*mut Handle) -> Status;
type UninstallMultipleProtocolInterfaces = unsafe extern "efiapi" fn(Handle) -> Status;

type CalculateCrc32 = extern "efiapi" fn(*const c_void, usize, *mut u32) -> Status;

type CopyMem = extern "efiapi" fn(*mut u8, *const u8, usize) -> *mut u8;
type SetMem = extern "efiapi" fn(*mut u8, usize, u8) -> *mut u8;

#[repr(C)]
pub(crate) struct BootServices {
    pub(crate) hdr: TableHeader,

    raise_tpl: RaiseTpl,
    restore_tpl: RestoreTpl,

    allocate_pages: AllocatePages,
    free_pages: FreePages,
    get_memory_map: GetMemoryMap,
    allocate_pool: AllocatePool,
    free_pool: FreePool,

    create_event: CreateEvent,
    set_timer: SetTimer,
    wait_for_event: WaitForEvent,
    signal_event: SignalOrCheckOrCloseEvent,
    close_event: SignalOrCheckOrCloseEvent,
    check_event: SignalOrCheckOrCloseEvent,

    install_protocol_interface: InstallProtocolInterface,
    reinstall_protocol_interface: ReinstallProtocolInterface,
    uninstall_protocol_interface: UninstallProtocolInterface,
    handle_protocol: HandleProtocol,
    reserved: usize,
    register_protocol_notify: RegisterProtocolNotify,
    locate_handle: LocateHandle,
    locate_device_path: LocateDevicePath,
    install_configuration_table: InstallConfigurationTable,

    load_image: LoadImage,
    start_image: StartImage,
    exit: Exit,
    unload_image: UnloadImage,
    exit_boot_services: ExitBootServices,

    get_next_monotonic_count: GetNextMonotonicCount,
    pub(crate) stall: Stall,
    set_watchdog_timer: SetWatchdogTimer,

    connect_controller: ConnectController,
    disconnect_controller: DisconnectController,

    open_protocol: OpenProtocol,
    close_protocol: CloseProtocol,
    open_protocol_information: OpenProtocolInformation,

    protocols_per_handle: ProtocolPerHandle,
    locate_handle_buffer: LocateHandleBuffer,
    locate_protocol: LocateProtocol,
    install_multiple_protocol_interfaces: InstallMultipleProtocolInterfaces,
    uninstall_multiple_protocol_interfaces: UninstallMultipleProtocolInterfaces,

    calculate_crc32: CalculateCrc32,

    copy_mem: CopyMem,
    set_mem: SetMem,
}

impl BootServices {
    pub fn new() -> BootServices {
        let mut bs = BootServices {
            hdr: TableHeader {
                signature: [b'B', b'O', b'O', b'T', b'S', b'E', b'R', b'V'],
                revision: UEFI_REVISION,
                header_size: size_of::<BootServices>() as u32,
                crc32: 0,
                reserved: 0,
            },
            raise_tpl: raise_tpl,
            restore_tpl: restore_tpl,

            allocate_pages: allocate_pages,
            free_pages: free_pages,
            get_memory_map: get_memory_map,
            allocate_pool: allocate_pool,
            free_pool: free_pool,

            create_event: create_event,
            set_timer: set_timer,
            wait_for_event: wait_for_event,
            signal_event: signal_event,
            close_event: close_event,
            check_event: check_event,

            install_protocol_interface: install_protocol_interface,
            reinstall_protocol_interface: reinstall_protocol_interface,
            uninstall_protocol_interface: uninstall_protocol_interface,
            handle_protocol: handle_protocol,
            reserved: 0,
            register_protocol_notify: register_protocol_notify,
            locate_handle: locate_handle,
            locate_device_path: locate_device_path,
            install_configuration_table: install_configuration_table,

            load_image: load_image,
            start_image: start_image,
            exit: exit,
            unload_image: unload_image,
            exit_boot_services: exit_boot_services,

            get_next_monotonic_count: get_next_monotonic_count,
            stall: stall,
            set_watchdog_timer: set_watchdog_timer,

            connect_controller: connect_controller,
            disconnect_controller: disconnect_controller,

            open_protocol: open_protocol,
            close_protocol: close_protocol,
            open_protocol_information: open_protocol_information,

            protocols_per_handle: protocols_per_handle,
            locate_handle_buffer: locate_handle_buffer,
            locate_protocol: locate_protocol,
            install_multiple_protocol_interfaces: install_multiple_protocol_interfaces_wrapper,
            uninstall_multiple_protocol_interfaces: uninstall_multiple_protocol_interfaces_wrapper,

            calculate_crc32: calculate_crc32,

            copy_mem: copy_mem,
            set_mem: set_mem,
            //create_event_ex: create_event_ex,
        };
        bs.hdr.update_crc();
        bs
    }
}

static CURRENT_TPL: AtomicUsize = AtomicUsize::new(TPL_APPLICATION);

extern "efiapi" fn raise_tpl(new_tpl: Tpl) -> Tpl {
    CURRENT_TPL.swap(new_tpl, Ordering::AcqRel)
}

extern "efiapi" fn restore_tpl(old_tpl: Tpl) {
    CURRENT_TPL.store(old_tpl, Ordering::Release);
}

extern "efiapi" fn allocate_pages(
    _type: AllocateType,
    memory_type: EfiMemoryType,
    pages: usize,
    memory: *mut PhysicalAddress,
) -> Status {
    let m = unsafe { &mut *memory };

    let placement: Placement = match _type {
        AllocateAnyPages => Placement::Anywhere,
        AllocateMaxAddress => Placement::Max(*m),
        AllocateAddress => Placement::Fixed(*m),
    };

    let ret = if let Some(region) = EFI.allocate_pages(pages, memory_type, placement) {
        *m = region.as_ptr() as PhysicalAddress;
        Status::EFI_SUCCESS
    } else {
        Status::EFI_OUT_OF_RESOURCES
    };
    log::trace!("AllocatePages() {pages} {memory_type:?} -> {ret:?}");
    ret
}

extern "efiapi" fn free_pages(memory: PhysicalAddress, pages: usize) -> Status {
    if (memory as usize & EFI_PAGE_MASK) != 0 {
        return Status::EFI_INVALID_PARAMETER;
    }
    let ret = if let Ok(_) = EFI.free_pages(memory, pages) {
        Status::EFI_SUCCESS
    } else {
        Status::EFI_NOT_FOUND
    };
    log::trace!("FreePages() {memory:x?} {pages} -> {ret:?}");
    ret
}

extern "efiapi" fn get_memory_map(
    memory_map_size: *mut usize,
    memory_map: *mut EfiMemoryDescriptor,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> Status {
    log::trace!("GetMemoryMap()");
    let desc_size = size_of::<EfiMemoryDescriptor>();
    unsafe {
        *descriptor_size = desc_size;
        *descriptor_version = EFI_MEMORY_DESCRIPTOR_VERSION;
    }

    let map_size = unsafe { &mut *memory_map_size };
    if *map_size == 0 {
        *map_size = EFI.memmap.len() * desc_size;
        return Status::EFI_BUFFER_TOO_SMALL;
    }

    let buffer = unsafe { &mut slice::from_raw_parts_mut(memory_map, *map_size / desc_size) };

    if let Some((key, len)) = EFI.memmap.get_memory_map(buffer) {
        *map_size = len * desc_size;
        unsafe {
            *map_key = key;
        }
        Status::EFI_SUCCESS
    } else {
        Status::EFI_BUFFER_TOO_SMALL
    }
}

extern "efiapi" fn allocate_pool(
    pool_type: EfiMemoryType,
    size: usize,
    buffer: *mut *mut c_void,
) -> Status {
    log::trace!("AllocatePool() {size}");
    if buffer.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    if let Ok(buf) = EFI.allocate_pool(pool_type, size) {
        unsafe { *buffer = buf.as_ptr() as _ };
        Status::EFI_SUCCESS
    } else {
        Status::EFI_OUT_OF_RESOURCES
    }
}

extern "efiapi" fn free_pool(buffer: *mut c_void) -> Status {
    if EFI.free_pool(buffer as _).is_ok() {
        return Status::EFI_SUCCESS;
    }
    Status::EFI_INVALID_PARAMETER
}

extern "efiapi" fn create_event(
    _type: u32,
    _notify_tpl: Tpl,
    _notify_function: EventNotify,
    _notify_context: *const c_void,
    _event: *mut Event,
) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_OUT_OF_RESOURCES
}

extern "efiapi" fn set_timer(_event: Event, _type: TimerDelay, _trigger_time: u64) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_INVALID_PARAMETER
}

extern "efiapi" fn wait_for_event(
    _number_of_events: usize,
    _event: *const Event,
    _index: *mut usize,
) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn signal_event(_event: Event) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_SUCCESS
}

extern "efiapi" fn close_event(_event: Event) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_SUCCESS
}

extern "efiapi" fn check_event(_event: Event) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_NOT_READY
}

struct ExternalEfiProtocol {
    protocol: Guid,
    interface: *const c_void,
}
unsafe impl Send for ExternalEfiProtocol {}

impl EfiProtocol for ExternalEfiProtocol {
    fn as_proto_ptr(&self) -> *const c_void {
        self.interface
    }
    fn guid(&self) -> &Guid {
        &self.protocol
    }
}

extern "efiapi" fn install_protocol_interface(
    handle: *mut Handle,
    protocol: *const Guid,
    interface_type: InterfaceType,
    interface: *const c_void,
) -> Status {
    if handle.is_null()
        || protocol.is_null()
        || interface_type != InterfaceType::EFI_NATIVE_INTERFACE
    {
        return Status::EFI_INVALID_PARAMETER;
    }

    let (handle, protocol) = unsafe { (&mut *handle, &*protocol) };
    if *protocol == EFI_DEVICE_PATH_PROTOCOL_GUID {
        if interface.is_null() {
            return Status::EFI_INVALID_PARAMETER;
        }
        let dp = unsafe { &*(interface as *const DevicePath) };
        if dp._type == DevicePathType::EFI_DEV_END_PATH {
            return Status::EFI_INVALID_PARAMETER;
        }
    }

    let mut db = EFI.protocol_db.borrow_mut();
    if *handle != 0 && db.contains_key(&(*handle, *protocol)) {
        return Status::EFI_INVALID_PARAMETER;
    }

    let p = ExternalEfiProtocol {
        protocol: *protocol,
        interface: interface,
    };

    if *handle == 0 {
        *handle = new_handle();
    }
    db.insert((*handle, *protocol), Box::pin(p));
    Status::EFI_SUCCESS
}

extern "efiapi" fn uninstall_protocol_interface(
    handle: Handle,
    protocol: *const Guid,
    interface: *const c_void,
) -> Status {
    if handle == 0 || protocol.is_null() {
        return Status::EFI_UNSUPPORTED;
    }

    let protocol = unsafe { &*protocol };

    let mut found = false;
    EFI.protocol_db.borrow_mut().retain(
        |k: &(Handle, Guid), v: &mut Pin<Box<dyn EfiProtocol + Send>>| {
            let f = k.0 == handle && k.1 == *protocol && v.as_proto_ptr() == interface;
            found |= f;
            !f
        },
    );

    if found {
        Status::EFI_SUCCESS
    } else {
        Status::EFI_NOT_FOUND
    }
}

extern "efiapi" fn reinstall_protocol_interface(
    handle: Handle,
    protocol: *const Guid,
    old_interface: *const c_void,
    new_interface: *const c_void,
) -> Status {
    if handle == 0 || protocol.is_null() {
        return Status::EFI_UNSUPPORTED;
    }

    let protocol = unsafe { &*protocol };

    let mut db = EFI.protocol_db.borrow_mut();
    let mut found = false;
    db.retain(
        |k: &(Handle, Guid), v: &mut Pin<Box<dyn EfiProtocol + Send>>| {
            let f = k.0 == handle && k.1 == *protocol && v.as_proto_ptr() == old_interface;
            found |= f;
            !f
        },
    );

    if found {
        let p = ExternalEfiProtocol {
            protocol: *protocol,
            interface: new_interface,
        };

        db.insert((handle, *protocol), Box::pin(p));
        Status::EFI_SUCCESS
    } else {
        Status::EFI_NOT_FOUND
    }
}

extern "efiapi" fn handle_protocol(
    handle: Handle,
    protocol: *const Guid,
    interface: *mut *const c_void,
) -> Status {
    open_protocol(
        handle,
        protocol,
        interface,
        0,
        0,
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
    )
}

extern "efiapi" fn register_protocol_notify(
    _protocol: *const Guid,
    _event: Event,
    _registration: *mut *const c_void,
) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_OUT_OF_RESOURCES
}

fn get_handle_vec(search_type: &LocateSearchType, protocol: *const Guid) -> Vec<Handle> {
    let protocol = if !protocol.is_null() {
        Some(unsafe { &*protocol })
    } else {
        None
    };
    let mut v: Vec<_> = EFI
        .protocol_db
        .borrow()
        .keys()
        .filter_map(|k: &(Handle, Guid)| {
            if *search_type == LocateSearchType::AllHandles || k.1 == *protocol? {
                Some(k.0)
            } else {
                None
            }
        })
        .collect();

    if *search_type == LocateSearchType::AllHandles {
        v.dedup();
    }
    v
}

extern "efiapi" fn locate_handle(
    search_type: LocateSearchType,
    protocol: *const Guid,
    _search_key: *const c_void,
    buffer_size: *mut usize,
    buffer: *mut Handle,
) -> Status {
    if buffer.is_null() || buffer_size.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let handles = get_handle_vec(&search_type, protocol);

    let ret = if handles.len() == 0 {
        Status::EFI_NOT_FOUND
    } else {
        let size = handles.len() * size_of::<Handle>();

        let buffer_size = unsafe { &mut *buffer_size };
        if size > *buffer_size {
            *buffer_size = size;
            Status::EFI_BUFFER_TOO_SMALL
        } else {
            // SAFETY: we honour the caller's buffer and size arguments,
            // and don't exceed the size of the vector
            unsafe {
                ptr::copy(handles.as_ptr(), buffer, handles.len());
            }
            *buffer_size = size;
            Status::EFI_SUCCESS
        }
    };
    log::trace!("LocateHandle({search_type:?}) -> {ret:?}");
    ret
}

fn compare_device_path(
    entry: (&(usize, Guid), &Pin<Box<dyn EfiProtocol + Send>>),
    protocol: &Guid,
    device_path: &DevicePath,
    db: &ProtocolDb,
) -> Option<(isize, (Handle, *const c_void))> {
    // Check if this handle implements both the device path protocol
    // and the requested protocol
    let guid = &entry.0 .1;
    let key = (entry.0 .0, *protocol);
    if *guid != EFI_DEVICE_PATH_PROTOCOL_GUID || !db.contains_key(&key) {
        return None;
    }

    // Check whether the provided device path is a prefix
    // of the device path in the protocol database
    let dp = unsafe { &*((*entry.1).as_proto_ptr() as *const DevicePath) };
    let bytes_equal = device_path.is_prefix_of(dp)?;

    let devpathptr = unsafe { (device_path as *const _ as *const u8).offset(bytes_equal) };
    Some((bytes_equal, (entry.0 .0, devpathptr as *const c_void)))
}

extern "efiapi" fn locate_device_path(
    protocol: *const Guid,
    device_path: *mut *const DevicePath,
    device: *mut Handle,
) -> Status {
    if protocol.is_null() || device_path.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let (protocol, devpath) = unsafe { (&*protocol, &**device_path) };

    // Find all handles that have both the given protocol and
    // the DevicePath protocol installed, and classify them by
    // how many bytes the device path has in common with the
    // provided one, if any
    let db = EFI.protocol_db.borrow();
    let ret = if let Some(entry) = db
        .iter()
        .filter_map(
            |entry: (&(Handle, Guid), &Pin<Box<dyn EfiProtocol + Send>>)| {
                compare_device_path(entry, protocol, devpath, &db)
            },
        )
        .max_by(|a, b| a.0.cmp(&b.0))
    {
        if !device.is_null() {
            unsafe {
                *device = entry.1 .0;
                *device_path = entry.1 .1 as _;
            }
            Status::EFI_SUCCESS
        } else {
            Status::EFI_INVALID_PARAMETER
        }
    } else {
        Status::EFI_NOT_FOUND
    };
    log::trace!("LocateDevicePath() {protocol:02x?} {ret:?}");
    ret
}

extern "efiapi" fn install_configuration_table(guid: *const Guid, table: *const c_void) -> Status {
    if guid.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    EFI.install_configtable(unsafe { &*guid }, table);
    Status::EFI_SUCCESS
}

struct LoadImageFileLoader {
    source_buffer: *const c_void,
    source_size: usize,
}

impl FileLoader for LoadImageFileLoader {
    fn get_size(&self) -> usize {
        self.source_size
    }

    fn load_file<'a>(&self, loadbuffer: &'a mut [MaybeUninit<u8>]) -> Result<&'a [u8], &str> {
        if loadbuffer.len() < self.source_size {
            return Err("Buffer too small");
        }
        unsafe {
            self.load_range(loadbuffer.as_mut_ptr() as _, 0, loadbuffer.len())?;
            Ok(slice::from_raw_parts(
                loadbuffer.as_ptr() as *const _,
                loadbuffer.len(),
            ))
        }
    }

    unsafe fn load_range<'a>(
        &self,
        loadbuffer: *mut c_void,
        offset: usize,
        size: usize,
    ) -> Result<(), &str> {
        if offset > self.source_size {
            return Err("Offset out of range");
        }

        let dst = loadbuffer as *mut u8;
        let src = self.source_buffer as *const u8;
        let len = size.min(self.source_size - offset);
        ptr::copy(src.offset(offset as isize), dst, len);
        if len < size {
            ptr::write_bytes(dst.offset(len as isize), 0, size - len);
        }
        Ok(())
    }
}

extern "efiapi" fn load_image(
    _boot_policy: Bool,
    _parent_image_handle: Handle,
    _device_path: *const DevicePath,
    source_buffer: *const c_void,
    source_size: usize,
    image_handle: *mut Handle,
) -> Status {
    log::trace!("LoadImage()");
    if source_buffer.is_null() || source_size == 0 {
        return Status::EFI_UNSUPPORTED;
    }

    let ldr = LoadImageFileLoader {
        source_buffer,
        source_size,
    };

    if let Some(li) = EFI.load_image(&ldr) {
        unsafe {
            *image_handle = li.image_handle;
        }
        Status::EFI_SUCCESS
    } else {
        Status::EFI_LOAD_ERROR
    }
}

extern "efiapi" fn start_image(
    handle: Handle,
    _exit_data_size: *mut usize,
    _exit_data: *mut Char16,
) -> Status {
    log::trace!("StartImage()");
    let db = EFI.protocol_db.borrow();
    let key = (handle, EFI_LOADED_IMAGE_PROTOCOL_GUID);
    if let Some(proto) = db.get(&key) {
        let li = unsafe { &*(proto.as_proto_ptr() as *const EfiLoadedImage) };
        drop(db);
        let ret = li.start_image();
        // TODO ensure that we cannot start the same image twice
        ret
    } else {
        Status::EFI_INVALID_PARAMETER
    }
}

extern "efiapi" fn exit(
    image_handle: Handle,
    exit_status: Status,
    _exit_data_size: usize,
    _exit_data: *const Char16,
) -> Status {
    log::trace!("Exit()");
    let db = EFI.protocol_db.borrow();
    let key = (image_handle, EFI_LOADED_IMAGE_PROTOCOL_GUID);
    if let Some(proto) = db.get(&key) {
        unsafe {
            let li = &*(proto.as_proto_ptr() as *const EfiLoadedImage);
            // exit_image does not return, so we need to release
            // the db spinlock explicitly
            drop(db);
            if li.reserved != 0 {
                let sp = li.reserved;
                exit_image(exit_status, sp);
            }
        }
    }
    Status::EFI_INVALID_PARAMETER
}

extern "efiapi" fn unload_image(_image_handle: Handle) -> Status {
    Status::EFI_UNSUPPORTED
}

extern "efiapi" fn exit_boot_services(_image_handle: Handle, map_key: usize) -> Status {
    if map_key != EFI.memmap.key() {
        return Status::EFI_INVALID_PARAMETER;
    }
    log::trace!("ExitBootServices()");
    Status::EFI_SUCCESS
}

extern "efiapi" fn get_next_monotonic_count(_count: *mut u64) -> Status {
    log::warn!("UNIMPLEMENTED - get_next_monotonic_count()");
    Status::EFI_SUCCESS
}

extern "efiapi" fn stall(_micro_seconds: usize) -> Status {
    Status::EFI_SUCCESS
}

extern "efiapi" fn set_watchdog_timer(
    _timeout: usize,
    _watchdog_code: u64,
    _data_size: usize,
    _watchdog_data: *const Char16,
) -> Status {
    log::warn!("UNIMPLEMENTED - set_watchdog_timer()");
    Status::EFI_SUCCESS
}

extern "efiapi" fn connect_controller(
    _controller_handle: Handle,
    _driver_image_handle: Handle,
    _remaining_device_path: *const DevicePath,
    _recursive: Bool,
) -> Status {
    log::warn!("UNIMPLEMENTED - connect_controller()");
    Status::EFI_NOT_FOUND
}

extern "efiapi" fn disconnect_controller(
    _controller_handle: Handle,
    _driver_image_handle: Handle,
    _child_handle: Handle,
) -> Status {
    log::warn!("UNIMPLEMENTED - disconnect_controller()");
    Status::EFI_SUCCESS
}

extern "efiapi" fn open_protocol(
    handle: Handle,
    protocol: *const Guid,
    interface: *mut *const c_void,
    _agent_handle: Handle,
    _controller_handle: Handle,
    attributes: u32,
) -> Status {
    if protocol.is_null() || (interface.is_null() && attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL)
    {
        return Status::EFI_INVALID_PARAMETER;
    }

    let protocol = unsafe { &*protocol };
    let key = (handle, *protocol);
    let ret = if let Some(proto) = EFI.protocol_db.borrow().get(&key) {
        if attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL {
            let interface = unsafe { &mut *interface };
            *interface = proto.as_proto_ptr();
        }
        Status::EFI_SUCCESS
    } else {
        Status::EFI_UNSUPPORTED
    };
    log::trace!("OpenProtocol() {handle} {protocol:02x?} -> {ret:?}");
    ret
}

extern "efiapi" fn close_protocol(
    handle: Handle,
    protocol: *const Guid,
    _agent_handle: Handle,
    _controller_handle: Handle,
) -> Status {
    if handle == 0 || protocol.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    Status::EFI_SUCCESS
}

extern "efiapi" fn open_protocol_information(
    _handle: Handle,
    _protocol: *const Guid,
    _entry_buffer: *mut *const OpenProtocolInformationEntry,
    _entry_count: *mut usize,
) -> Status {
    log::warn!("UNIMPLEMENTED - open_protocol_information()");
    Status::EFI_OUT_OF_RESOURCES
}

extern "efiapi" fn protocols_per_handle(
    handle: Handle,
    protocol_buffer: *mut *const *const Guid,
    protocol_buffer_count: *mut usize,
) -> Status {
    if protocol_buffer.is_null() || protocol_buffer_count.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let (buffer, count) = unsafe { (&mut *protocol_buffer, &mut *protocol_buffer_count) };

    let guids: Vec<_> = EFI
        .protocol_db
        .borrow()
        .keys()
        .filter_map(|k: &(Handle, Guid)| {
            if k.0 == handle {
                Some(&k.1 as *const Guid)
            } else {
                None
            }
        })
        .collect();

    let ret = if let Ok(buf) = EFI
        .memmap
        .allocate_pool::<*const Guid>(EfiMemoryType::EfiLoaderData, guids.len())
    {
        unsafe {
            ptr::copy(guids.as_ptr(), buf.as_ptr(), guids.len());
        }
        *buffer = buf.as_ptr();
        *count = guids.len();
        Status::EFI_SUCCESS
    } else {
        Status::EFI_OUT_OF_RESOURCES
    };
    log::trace!("ProtocolsPerHandle() handle:{handle} -> {ret:?}");
    ret
}

extern "efiapi" fn locate_handle_buffer(
    search_type: LocateSearchType,
    protocol: *const Guid,
    _search_key: *const c_void,
    no_handles: *mut usize,
    buffer: *mut *const Handle,
) -> Status {
    if buffer.is_null() || no_handles.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let handles = get_handle_vec(&search_type, protocol);

    let ret = if handles.len() == 0 {
        Status::EFI_NOT_FOUND
    } else {
        let (buffer, count) = unsafe { (&mut *buffer, &mut *no_handles) };

        if let Ok(buf) = EFI
            .memmap
            .allocate_pool::<Handle>(EfiMemoryType::EfiLoaderData, handles.len())
        {
            unsafe {
                ptr::copy(handles.as_ptr(), buf.as_ptr(), handles.len());
            }
            *buffer = buf.as_ptr();
            *count = handles.len();
            Status::EFI_SUCCESS
        } else {
            Status::EFI_OUT_OF_RESOURCES
        }
    };
    log::trace!("LocateHandleBuffer() {protocol:x?} -> {ret:?}");
    ret
}

extern "efiapi" fn locate_protocol(
    protocol: *const Guid,
    _registration: *const c_void,
    interface: *mut *const c_void,
) -> Status {
    if protocol.is_null() || interface.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let (protocol, interface) = unsafe { (*protocol, &mut *interface) };

    let ret = if let Some(entry) = EFI
        .protocol_db
        .borrow()
        .iter()
        .find(|e: &(&(usize, Guid), &Pin<Box<dyn EfiProtocol + Send>>)| e.0 .1 == protocol)
    {
        *interface = entry.1.as_proto_ptr();
        Status::EFI_SUCCESS
    } else {
        *interface = ptr::null();
        Status::EFI_NOT_FOUND
    };
    log::trace!("LocateProtocol() {protocol:02x?} {ret:?}");
    ret
}

// Implementing the below functions properly in pure Rust needs c_variadic to stabilize for efiapi
// For the time being, use a helper in asm to convert the varargs to an array of pointers
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("multiprotocol_aarch64.s"));
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("multiprotocol_x86_64.s"));

extern "efiapi" {
    fn install_multiple_protocol_interfaces_wrapper(handle: *mut Handle) -> Status;
    fn uninstall_multiple_protocol_interfaces_wrapper(handle: Handle) -> Status;
}

unsafe fn parse_multiproto_varargs(
    p: *const *const c_void,
) -> Option<BTreeMap<Guid, *const c_void>> {
    let mut m: BTreeMap<Guid, *const c_void> = BTreeMap::new();
    let mut p = p;
    while !(*p).is_null() {
        let g = &*(*p as *const Guid);
        if m.insert(*g, *p.offset(1)).is_some() {
            // Cannot install the same protocol twice
            return None;
        }
        p = p.offset(2);
    }
    if m.len() == 0 {
        None
    } else {
        Some(m)
    }
}

#[no_mangle]
extern "efiapi" fn install_multiple_protocol_interfaces(
    handle: *mut Handle,
    p: *const *const c_void,
) -> Status {
    if handle.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let (handle, protocols) = unsafe {
        if let Some(m) = parse_multiproto_varargs(p) {
            (&mut *handle, m)
        } else {
            return Status::EFI_INVALID_PARAMETER;
        }
    };

    let mut db = EFI.protocol_db.borrow_mut();

    // Check whether a device path protocol is being installed that already exists in the database
    if let Some(devpath) = protocols.get(&EFI_DEVICE_PATH_PROTOCOL_GUID) {
        if devpath.is_null() {
            return Status::EFI_INVALID_PARAMETER;
        }

        let devpath = unsafe { &*(*devpath as *const DevicePath) };
        if devpath._type == DevicePathType::EFI_DEV_END_PATH {
            return Status::EFI_INVALID_PARAMETER;
        }

        if let Some(_) = db.iter().find(|e| {
            let p = e.1.as_proto_ptr();
            !p.is_null() && e.0 .1 == EFI_DEVICE_PATH_PROTOCOL_GUID && {
                let dp = unsafe { &*(p as *const DevicePath) };
                devpath.equals(dp)
            }
        }) {
            return Status::EFI_INVALID_PARAMETER;
        }
    }

    // If the handle is not NULL, check whether any of the protocols already exist on this handle
    if *handle != 0 {
        for g in protocols.keys() {
            if db.contains_key(&(*handle, *g)) {
                return Status::EFI_INVALID_PARAMETER;
            }
        }
    } else {
        *handle = new_handle();
    }

    for (guid, interface) in protocols.iter() {
        let p = ExternalEfiProtocol {
            protocol: *guid,
            interface: *interface,
        };
        db.insert((*handle, *guid), Box::pin(p));
    }
    Status::EFI_SUCCESS
}

#[no_mangle]
extern "efiapi" fn uninstall_multiple_protocol_interfaces(
    handle: Handle,
    p: *const *const c_void,
) -> Status {
    if handle == 0 {
        return Status::EFI_INVALID_PARAMETER;
    }

    let protocols = unsafe {
        if let Some(m) = parse_multiproto_varargs(p) {
            m
        } else {
            return Status::EFI_INVALID_PARAMETER;
        }
    };

    let mut db = EFI.protocol_db.borrow_mut();

    // Check whether all protocol/interface tuples are installed on the handle
    for (guid, interface) in protocols.iter() {
        if let Some(p) = db.get(&(handle, *guid)) {
            if p.as_proto_ptr() == *interface {
                continue;
            }
        }
        return Status::EFI_INVALID_PARAMETER;
    }

    for guid in protocols.keys() {
        db.remove(&(handle, *guid));
    }
    Status::EFI_SUCCESS
}

extern "efiapi" fn calculate_crc32(
    data: *const c_void,
    datasize: usize,
    crc32: *mut u32,
) -> Status {
    let (crc, slice) = unsafe {
        (
            &mut *crc32,
            slice::from_raw_parts(data as *const u8, datasize),
        )
    };
    *crc = Crc::<u32>::new(&CRC_32_CKSUM).checksum(slice);
    Status::EFI_SUCCESS
}

extern "efiapi" fn copy_mem(destination: *mut u8, source: *const u8, length: usize) -> *mut u8 {
    unsafe { ptr::copy(source, destination, length) }
    destination
}

extern "efiapi" fn set_mem(buffer: *mut u8, size: usize, value: u8) -> *mut u8 {
    unsafe { ptr::write_bytes(buffer, value, size) }
    buffer
}
