// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::devicepath::*;
use crate::memmap::Placement;
use crate::EfiProtocol;
use crate::FileLoader;
use crate::{memorytype::*, status::*, tableheader::*};
use crate::{Bool, Char16, Event, EventNotify, Guid, Handle, PhysicalAddress, Tpl};
use crate::{ProtocolDb, ProtocolEntry, ProtocolOwner, TPL_APPLICATION, UEFI_REVISION};

use crate::devicepath::EFI_DEVICE_PATH_PROTOCOL_GUID;
use crate::initrdloadfile2::EFI_LOAD_FILE2_PROTOCOL_GUID;
use crate::loadedimage::{current_image, exit_image, find_loaded_image};
use crate::loadedimage::{ImageOrigin, LoadedImageDevicePath};
use crate::new_handle;
use crate::simplefilesystem::{EfiFileProtocol, EfiSimpleFileSystemProtocol};
use crate::simplefilesystem::{EFI_FILE_DIRECTORY, EFI_FILE_INFO_ID, EFI_FILE_MODE_READ};
use crate::simplefilesystem::{EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID, SIZE_OF_EFI_FILE_INFO};
use crate::EFI;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem::{size_of, MaybeUninit};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{ptr, slice};
use crc::{Crc, CRC_32_ISO_HDLC};

const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;

// Values of EFI_ALLOCATE_TYPE. Arguments of enumerated types are passed as plain integers rather
// than Rust enums, given that EFI images may pass any value.
const ALLOCATE_ANY_PAGES: u32 = 0;
const ALLOCATE_MAX_ADDRESS: u32 = 1;
const ALLOCATE_ADDRESS: u32 = 2;

// Values of EFI_INTERFACE_TYPE
const EFI_NATIVE_INTERFACE: u32 = 0;

#[derive(Debug, PartialEq)]
enum LocateSearchType {
    AllHandles,
    ByRegisterNotify,
    ByProtocol,
}

impl LocateSearchType {
    fn from_raw(search_type: u32) -> Option<Self> {
        match search_type {
            0 => Some(LocateSearchType::AllHandles),
            1 => Some(LocateSearchType::ByRegisterNotify),
            2 => Some(LocateSearchType::ByProtocol),
            _ => None,
        }
    }
}

const EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL: u32 = 0x00000001;
const EFI_OPEN_PROTOCOL_GET_PROTOCOL: u32 = 0x00000002;
const EFI_OPEN_PROTOCOL_TEST_PROTOCOL: u32 = 0x00000004;
const EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER: u32 = 0x00000008;
const EFI_OPEN_PROTOCOL_BY_DRIVER: u32 = 0x00000010;
const EFI_OPEN_PROTOCOL_EXCLUSIVE: u32 = 0x00000020;
const EFI_OPEN_PROTOCOL_BY_DRIVER_EXCLUSIVE: u32 =
    EFI_OPEN_PROTOCOL_BY_DRIVER | EFI_OPEN_PROTOCOL_EXCLUSIVE;

#[repr(C)]
struct OpenProtocolInformationEntry {
    _agent_handle: Handle,
    _controller_handle: Handle,
    _attributes: u32,
    _open_count: u32,
}

type RaiseTpl = extern "efiapi" fn(Tpl) -> Tpl;
type RestoreTpl = extern "efiapi" fn(Tpl);

type AllocatePages = extern "efiapi" fn(u32, u32, usize, *mut PhysicalAddress) -> Status;
type FreePages = extern "efiapi" fn(PhysicalAddress, usize) -> Status;
type GetMemoryMap = extern "efiapi" fn(
    *mut usize,
    *mut EfiMemoryDescriptor,
    *mut usize,
    *mut usize,
    *mut u32,
) -> Status;
type AllocatePool = extern "efiapi" fn(u32, usize, *mut *mut ()) -> Status;
type FreePool = extern "efiapi" fn(*mut ()) -> Status;

type CreateEvent =
    extern "efiapi" fn(u32, Tpl, Option<EventNotify>, *const (), *mut Event) -> Status;
type SetTimer = extern "efiapi" fn(Event, u32, u64) -> Status;
type WaitForEvent = extern "efiapi" fn(usize, *const Event, *mut usize) -> Status;
type SignalOrCheckOrCloseEvent = extern "efiapi" fn(Event) -> Status;

type InstallProtocolInterface =
    extern "efiapi" fn(*mut Handle, *const Guid, u32, *const ()) -> Status;
type ReinstallProtocolInterface =
    extern "efiapi" fn(Handle, *const Guid, *const (), *const ()) -> Status;
type UninstallProtocolInterface = extern "efiapi" fn(Handle, *const Guid, *const ()) -> Status;
type HandleProtocol = extern "efiapi" fn(Handle, *const Guid, *mut *const ()) -> Status;
type RegisterProtocolNotify = extern "efiapi" fn(*const Guid, Event, *mut *const ()) -> Status;
type LocateHandle =
    extern "efiapi" fn(u32, *const Guid, *const (), *mut usize, *mut Handle) -> Status;
type LocateDevicePath =
    extern "efiapi" fn(*const Guid, *mut *const DevicePath, *mut Handle) -> Status;
type InstallConfigurationTable = extern "efiapi" fn(*const Guid, *const ()) -> Status;

type LoadImage =
    extern "efiapi" fn(Bool, Handle, *const DevicePath, *const (), usize, *mut Handle) -> Status;
type StartImage = extern "efiapi" fn(Handle, *mut usize, *mut *mut Char16) -> Status;
type Exit = extern "efiapi" fn(Handle, Status, usize, *const Char16) -> Status;
type UnloadImage = extern "efiapi" fn(Handle) -> Status;
type ExitBootServices = extern "efiapi" fn(Handle, usize) -> Status;

type GetNextMonotonicCount = extern "efiapi" fn(*mut u64) -> Status;
pub type Stall = extern "efiapi" fn(usize) -> Status;
type SetWatchdogTimer = extern "efiapi" fn(usize, u64, usize, *const Char16) -> Status;

type ConnectController = extern "efiapi" fn(Handle, Handle, *const DevicePath, Bool) -> Status;
type DisconnectController = extern "efiapi" fn(Handle, Handle, Handle) -> Status;

type OpenProtocol =
    extern "efiapi" fn(Handle, *const Guid, *mut *const (), Handle, Handle, u32) -> Status;
type CloseProtocol = extern "efiapi" fn(Handle, *const Guid, Handle, Handle) -> Status;
type OpenProtocolInformation = extern "efiapi" fn(
    Handle,
    *const Guid,
    *mut *const OpenProtocolInformationEntry,
    *mut usize,
) -> Status;

type ProtocolPerHandle = extern "efiapi" fn(Handle, *mut *const *const Guid, *mut usize) -> Status;
type LocateHandleBuffer =
    extern "efiapi" fn(u32, *const Guid, *const (), *mut usize, *mut *const Handle) -> Status;
type LocateProtocol = extern "efiapi" fn(*const Guid, *const (), *mut *const ()) -> Status;

type InstallMultipleProtocolInterfaces = unsafe extern "efiapi" fn(*mut Handle) -> Status;
type UninstallMultipleProtocolInterfaces = unsafe extern "efiapi" fn(Handle) -> Status;

type CalculateCrc32 = extern "efiapi" fn(*const (), usize, *mut u32) -> Status;

type CopyMem = extern "efiapi" fn(*mut u8, *const u8, usize) -> *mut u8;
type SetMem = extern "efiapi" fn(*mut u8, usize, u8) -> *mut u8;

type CreateEventEx =
    extern "efiapi" fn(u32, Tpl, Option<EventNotify>, *const (), *const Guid, *mut Event) -> Status;

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

    create_event_ex: CreateEventEx,
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

            create_event_ex: create_event_ex,
        };
        bs.update_crc();
        bs
    }
}

// SAFETY: BootServices consists of a TableHeader followed by pointer sized fields only, and so it
// has no padding, as checked below.
unsafe impl EfiTable for BootServices {
    fn header(&mut self) -> &mut TableHeader {
        &mut self.hdr
    }
}

const _: () =
    assert!(size_of::<BootServices>() == size_of::<TableHeader>() + 44 * size_of::<usize>());

static CURRENT_TPL: AtomicUsize = AtomicUsize::new(TPL_APPLICATION);

extern "efiapi" fn raise_tpl(new_tpl: Tpl) -> Tpl {
    CURRENT_TPL.swap(new_tpl, Ordering::AcqRel)
}

extern "efiapi" fn restore_tpl(old_tpl: Tpl) {
    CURRENT_TPL.store(old_tpl, Ordering::Release);
}

extern "efiapi" fn allocate_pages(
    alloc_type: u32,
    memory_type: u32,
    pages: usize,
    memory: *mut PhysicalAddress,
) -> Status {
    let Some(memory_type) = allocation_type(memory_type) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    if memory.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `memory` is not NULL, and the UEFI spec requires it to point to a valid
    // EFI_PHYSICAL_ADDRESS, which serves as an input for AllocateMaxAddress and AllocateAddress
    // allocations, and receives the address of the allocated pages.
    let m = unsafe { &mut *memory };

    let placement: Placement = match alloc_type {
        ALLOCATE_ANY_PAGES => Placement::Anywhere,
        ALLOCATE_MAX_ADDRESS => Placement::Max(*m),
        ALLOCATE_ADDRESS => Placement::Fixed(*m),
        _ => {
            return Status::EFI_INVALID_PARAMETER;
        }
    };

    let ret = if let Some(base) = EFI
        .memmap
        .allocate_image_pages(pages, memory_type, placement)
    {
        *m = base;
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
    // Only pages allocated via AllocatePages() may be freed
    let ret = if let Ok(_) = EFI.memmap.free_image_pages(memory, pages) {
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
    if memory_map_size.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let desc_size = size_of::<EfiMemoryDescriptor>();
    if !descriptor_size.is_null() {
        // SAFETY: `descriptor_size` is not NULL, and the UEFI spec requires it to point to a
        // writable UINTN.
        unsafe { *descriptor_size = desc_size };
    }
    if !descriptor_version.is_null() {
        // SAFETY: `descriptor_version` is not NULL, and the UEFI spec requires it to point to a
        // writable UINT32.
        unsafe { *descriptor_version = EFI_MEMORY_DESCRIPTOR_VERSION };
    }

    // SAFETY: `memory_map_size` is not NULL, and the UEFI spec requires it to point to a valid UINTN
    // that holds the size of the buffer at `memory_map`, and receives the size of the memory map.
    let map_size = unsafe { &mut *memory_map_size };

    let buffer: &mut [MaybeUninit<EfiMemoryDescriptor>] = if memory_map.is_null() {
        &mut []
    } else {
        // SAFETY: `memory_map` is not NULL, and the UEFI spec requires it to point to a writable
        // buffer of `*map_size` bytes, suitably aligned for EFI memory descriptors, which the
        // caller does not access while this call is in progress. Its contents may be
        // uninitialized, which is why it is accessed via MaybeUninit.
        unsafe { slice::from_raw_parts_mut(memory_map as *mut _, *map_size / desc_size) }
    };

    if let Some((key, len)) = EFI.memmap.get_memory_map(buffer) {
        *map_size = len * desc_size;
        if !map_key.is_null() {
            // SAFETY: `map_key` is not NULL, and the UEFI spec requires it to point to a writable
            // UINTN.
            unsafe { *map_key = key };
        }
        Status::EFI_SUCCESS
    } else {
        // Report the size of the buffer that is needed to hold the memory map
        let size = EFI.memmap.len() * desc_size;
        let ret = if memory_map.is_null() && *map_size >= size {
            Status::EFI_INVALID_PARAMETER
        } else {
            Status::EFI_BUFFER_TOO_SMALL
        };
        *map_size = size;
        ret
    }
}

/// Converts a memory type passed by an EFI image into an EfiMemoryType that may be allocated.
/// Memory types that are reserved, or defined by the OEM or the OS, are not supported.
fn allocation_type(memory_type: u32) -> Option<EfiMemoryType> {
    match EfiMemoryType::try_from(memory_type).ok()? {
        EfiMemoryType::EfiConventionalMemory
        | EfiMemoryType::EfiPersistentMemory
        | EfiMemoryType::EfiUnacceptedMemory => None,
        t => Some(t),
    }
}

extern "efiapi" fn allocate_pool(pool_type: u32, size: usize, buffer: *mut *mut ()) -> Status {
    log::trace!("AllocatePool() {size}");
    let Some(pool_type) = allocation_type(pool_type) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    if buffer.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    if let Ok(buf) = EFI.memmap.allocate_image_pool::<u8>(pool_type, size) {
        // SAFETY: `buffer` is not NULL, and the UEFI spec requires it to point to a writable
        // pointer sized location.
        unsafe { *buffer = buf.as_ptr() as _ };
        Status::EFI_SUCCESS
    } else {
        Status::EFI_OUT_OF_RESOURCES
    }
}

extern "efiapi" fn free_pool(buffer: *mut ()) -> Status {
    // Only memory allocated via AllocatePool(), or returned by other boot services that allocate
    // pool memory on behalf of the caller, may be freed
    if EFI.memmap.free_image_pool(buffer as _).is_ok() {
        return Status::EFI_SUCCESS;
    }
    Status::EFI_INVALID_PARAMETER
}

extern "efiapi" fn create_event(
    _type: u32,
    _notify_tpl: Tpl,
    _notify_function: Option<EventNotify>,
    _notify_context: *const (),
    _event: *mut Event,
) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_OUT_OF_RESOURCES
}

extern "efiapi" fn create_event_ex(
    _type: u32,
    _notify_tpl: Tpl,
    _notify_function: Option<EventNotify>,
    _notify_context: *const (),
    _event_group: *const Guid,
    _event: *mut Event,
) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_OUT_OF_RESOURCES
}

extern "efiapi" fn set_timer(_event: Event, _type: u32, _trigger_time: u64) -> Status {
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
    interface: *const (),
}

// SAFETY: `interface` points to a protocol interface that is owned by the EFI image that installed
// it. It is only dereferenced (to inspect device paths) by boot services, which are single threaded
// and only invoked by EFI images, and so sending it to another thread cannot result in data races.
unsafe impl Send for ExternalEfiProtocol {}

impl EfiProtocol for ExternalEfiProtocol {
    fn as_proto_ptr(&self) -> *const () {
        self.interface
    }
    fn guid(&self) -> &Guid {
        &self.protocol
    }
}

impl ExternalEfiProtocol {
    /// Returns a protocol database entry for `interface`, installed by an EFI image as an
    /// instance of `protocol`.
    fn entry(protocol: Guid, interface: *const ()) -> ProtocolEntry {
        ProtocolEntry::new(
            ProtocolOwner::Image,
            Box::pin(ExternalEfiProtocol {
                protocol,
                interface,
            }),
        )
    }
}

/// Returns whether `handle` exists, i.e., whether any protocols are installed on it.
fn handle_exists(db: &ProtocolDb, handle: Handle) -> bool {
    db.keys().any(|k| k.0 == handle)
}

/// Returns whether `handle` is the handle of an image that was loaded by the EFI runtime. (Loaded
/// image protocols installed by EFI images do not count.)
fn is_image_handle(db: &ProtocolDb, handle: Handle) -> bool {
    find_loaded_image(db, handle).is_some()
}

/// Returns whether `interface` may be installed by an EFI image as a device path protocol
/// instance: it must not be NULL, and it must not be an empty device path.
///
/// # Safety
///
/// `interface` must either be NULL or point to a device path.
unsafe fn is_valid_device_path(interface: *const ()) -> bool {
    !interface.is_null() && {
        // SAFETY: `interface` is not NULL, and so the caller guarantees that it points to a
        // device path.
        let dp = unsafe { &*(interface as *const DevicePath) };
        dp._type != DevicePathType::EFI_DEV_END_PATH
    }
}

extern "efiapi" fn install_protocol_interface(
    handle: *mut Handle,
    protocol: *const Guid,
    interface_type: u32,
    interface: *const (),
) -> Status {
    if handle.is_null() || protocol.is_null() || interface_type != EFI_NATIVE_INTERFACE {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: Both pointers were checked for NULL above, and the UEFI spec requires them to point to
    // a valid EFI_HANDLE and EFI_GUID, respectively.
    let (handle, protocol) = unsafe { (&mut *handle, &*protocol) };
    // SAFETY: The UEFI spec requires device path protocol interfaces to point to a device path.
    if *protocol == EFI_DEVICE_PATH_PROTOCOL_GUID && !unsafe { is_valid_device_path(interface) } {
        return Status::EFI_INVALID_PARAMETER;
    }

    let mut db = EFI.protocol_db.borrow_mut();
    // A handle that is passed in must exist, and must not carry this protocol already
    if *handle != 0 && (!handle_exists(&db, *handle) || db.contains_key(&(*handle, *protocol))) {
        return Status::EFI_INVALID_PARAMETER;
    }

    if *handle == 0 {
        *handle = new_handle();
    }
    db.insert(
        (*handle, *protocol),
        ExternalEfiProtocol::entry(*protocol, interface),
    );
    Status::EFI_SUCCESS
}

extern "efiapi" fn uninstall_protocol_interface(
    handle: Handle,
    protocol: *const Guid,
    interface: *const (),
) -> Status {
    if handle == 0 || protocol.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `protocol` is not NULL, and the UEFI spec requires it to point to a valid EFI_GUID.
    let protocol = unsafe { &*protocol };

    let mut db = EFI.protocol_db.borrow_mut();
    let key = (handle, *protocol);
    match db.get(&key) {
        Some(e) if e.as_proto_ptr() == interface => {
            // Protocols installed by the runtime or the embedder cannot be uninstalled by images
            if e.owner != ProtocolOwner::Image {
                return Status::EFI_ACCESS_DENIED;
            }
            db.remove(&key);
            Status::EFI_SUCCESS
        }
        _ => Status::EFI_NOT_FOUND,
    }
}

extern "efiapi" fn reinstall_protocol_interface(
    handle: Handle,
    protocol: *const Guid,
    old_interface: *const (),
    new_interface: *const (),
) -> Status {
    if handle == 0 || protocol.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `protocol` is not NULL, and the UEFI spec requires it to point to a valid EFI_GUID.
    let protocol = unsafe { &*protocol };
    // SAFETY: The UEFI spec requires device path protocol interfaces to point to a device path.
    if *protocol == EFI_DEVICE_PATH_PROTOCOL_GUID && !unsafe { is_valid_device_path(new_interface) }
    {
        return Status::EFI_INVALID_PARAMETER;
    }

    let mut db = EFI.protocol_db.borrow_mut();
    let key = (handle, *protocol);
    match db.get(&key) {
        Some(e) if e.as_proto_ptr() == old_interface => {
            // Protocols installed by the runtime or the embedder cannot be replaced by images
            if e.owner != ProtocolOwner::Image {
                return Status::EFI_ACCESS_DENIED;
            }
            db.insert(key, ExternalEfiProtocol::entry(*protocol, new_interface));
            Status::EFI_SUCCESS
        }
        _ => Status::EFI_NOT_FOUND,
    }
}

extern "efiapi" fn handle_protocol(
    handle: Handle,
    protocol: *const Guid,
    interface: *mut *const (),
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
    _registration: *mut *const (),
) -> Status {
    log::warn!("UNIMPLEMENTED");
    Status::EFI_OUT_OF_RESOURCES
}

/// Returns the handles matching the search criteria passed to LocateHandle() or
/// LocateHandleBuffer(), or the status code to return if the search criteria are invalid.
fn get_handle_vec(
    search_type: u32,
    protocol: *const Guid,
    search_key: *const (),
) -> Result<Vec<Handle>, Status> {
    let protocol = match LocateSearchType::from_raw(search_type) {
        Some(LocateSearchType::AllHandles) => None,
        Some(LocateSearchType::ByProtocol) => {
            if protocol.is_null() {
                return Err(Status::EFI_INVALID_PARAMETER);
            }
            // SAFETY: `protocol` is not NULL, and the UEFI spec requires it to point to a valid
            // EFI_GUID when searching by protocol. It is not dereferenced otherwise.
            Some(unsafe { *protocol })
        }
        Some(LocateSearchType::ByRegisterNotify) => {
            if search_key.is_null() {
                return Err(Status::EFI_INVALID_PARAMETER);
            }
            // RegisterProtocolNotify() is not implemented, so there are no registrations
            // that could match.
            return Err(Status::EFI_NOT_FOUND);
        }
        None => return Err(Status::EFI_INVALID_PARAMETER),
    };
    let mut v: Vec<_> = EFI
        .protocol_db
        .borrow()
        .keys()
        .filter_map(|k: &(Handle, Guid)| match protocol {
            Some(p) if k.1 != p => None,
            _ => Some(k.0),
        })
        .collect();

    if protocol.is_none() {
        v.dedup();
    }
    Ok(v)
}

extern "efiapi" fn locate_handle(
    search_type: u32,
    protocol: *const Guid,
    search_key: *const (),
    buffer_size: *mut usize,
    buffer: *mut Handle,
) -> Status {
    if buffer_size.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let ret = match get_handle_vec(search_type, protocol, search_key) {
        Err(status) => status,
        Ok(handles) if handles.len() == 0 => Status::EFI_NOT_FOUND,
        Ok(handles) => {
            let size = handles.len() * size_of::<Handle>();

            // SAFETY: `buffer_size` is not NULL, and the UEFI spec requires it to point to a valid
            // UINTN.
            let buffer_size = unsafe { &mut *buffer_size };
            if size > *buffer_size {
                // `buffer` may be NULL in this case, which is how the caller can query the size
                *buffer_size = size;
                Status::EFI_BUFFER_TOO_SMALL
            } else if buffer.is_null() {
                Status::EFI_INVALID_PARAMETER
            } else {
                // SAFETY: `buffer` is not NULL, and the UEFI spec requires it to point to a buffer
                // of `*buffer_size` bytes, which was checked above to be sufficient.
                unsafe {
                    ptr::copy(handles.as_ptr(), buffer, handles.len());
                }
                *buffer_size = size;
                Status::EFI_SUCCESS
            }
        }
    };
    log::trace!("LocateHandle({search_type}) -> {ret:?}");
    ret
}

fn compare_device_path(
    entry: (&(Handle, Guid), &ProtocolEntry),
    protocol: &Guid,
    device_path: &DevicePath,
    db: &ProtocolDb,
) -> Option<(isize, Handle)> {
    // Check if this handle implements both the device path protocol
    // and the requested protocol
    let guid = &entry.0 .1;
    let key = (entry.0 .0, *protocol);
    let p = entry.1.as_proto_ptr();
    if *guid != EFI_DEVICE_PATH_PROTOCOL_GUID || p.is_null() || !db.contains_key(&key) {
        return None;
    }

    // Check whether the device path in the protocol database is a prefix of the provided device
    // path, i.e., whether the handle is a device on that device path
    // SAFETY: `entry` is a device path protocol instance, and so its non-NULL interface pointer
    // points to a device path, which remains valid for as long as the protocol is installed.
    let dp = unsafe { &*(p as *const DevicePath) };
    Some((dp.is_prefix_of(device_path)?, entry.0 .0))
}

/// Finds the handle that has both `protocol` and the device path protocol installed, and whose
/// device path has the most bytes in common with `device_path`, if any. Returns the handle along
/// with the remaining part of `device_path`, i.e., the part that follows the matching nodes.
fn find_device<'a>(
    db: &ProtocolDb,
    protocol: &Guid,
    device_path: &'a DevicePath,
) -> Option<(Handle, &'a DevicePath)> {
    let (bytes_equal, handle) = db
        .iter()
        .filter_map(|entry| compare_device_path(entry, protocol, device_path, db))
        .max_by(|a, b| a.0.cmp(&b.0))?;

    // SAFETY: is_prefix_of() returns the combined size of the nodes of the device path of `handle`
    // that precede its end node, which are equal to the leading nodes of `device_path`, and so the
    // resulting pointer points to the remaining part of `device_path`.
    let remaining = unsafe {
        &*((device_path as *const DevicePath as *const u8).offset(bytes_equal) as *const DevicePath)
    };
    Some((handle, remaining))
}

extern "efiapi" fn locate_device_path(
    protocol: *const Guid,
    device_path: *mut *const DevicePath,
    device: *mut Handle,
) -> Status {
    if protocol.is_null() || device_path.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: Both pointers were checked for NULL above, and the UEFI spec requires them to point to
    // a valid EFI_GUID and to a pointer to a valid device path, respectively.
    let (protocol, devpath) = unsafe { (&*protocol, &**device_path) };

    let found = find_device(&EFI.protocol_db.borrow(), protocol, devpath);
    let ret = match found {
        Some((handle, remaining)) if !device.is_null() => {
            // SAFETY: Neither `device` nor `device_path` are NULL, and the UEFI spec requires them
            // to point to writable locations of the appropriate types.
            unsafe {
                *device = handle;
                *device_path = remaining;
            }
            Status::EFI_SUCCESS
        }
        Some(_) => Status::EFI_INVALID_PARAMETER,
        None => Status::EFI_NOT_FOUND,
    };
    log::trace!("LocateDevicePath() {protocol:02x?} {ret:?}");
    ret
}

extern "efiapi" fn install_configuration_table(guid: *const Guid, table: *const ()) -> Status {
    if guid.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // SAFETY: `guid` is not NULL, and the UEFI spec requires it to point to a valid EFI_GUID.
    let guid = unsafe { &*guid };

    // A NULL table removes the entry identified by `guid`, which must exist
    if table.is_null() && !EFI.cfgtable.contains(guid) {
        return Status::EFI_NOT_FOUND;
    }
    EFI.install_configtable(guid, table);
    Status::EFI_SUCCESS
}

struct LoadImageFileLoader {
    source_buffer: *const (),
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
        // SAFETY: `loadbuffer` is valid for writes of `loadbuffer.len()` bytes, all of which have
        // been initialized, either with file contents or with zeroes, if load_range() returns
        // successfully. This means they can be reinterpreted as a [u8] slice of the same size and
        // lifetime.
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
        loadbuffer: *mut (),
        offset: usize,
        size: usize,
    ) -> Result<(), &str> {
        if offset > self.source_size {
            return Err("Offset out of range");
        }

        let dst = loadbuffer as *mut u8;
        let src = self.source_buffer as *const u8;
        let len = size.min(self.source_size - offset);
        // SAFETY: `offset` and `len` were sanitized so that the source range is covered by the
        // buffer passed to LoadImage(), which the UEFI spec requires to be valid for reads of
        // `source_size` bytes. The caller guarantees that `loadbuffer` is valid for writes of
        // `size` bytes, and `len` does not exceed `size`.
        unsafe {
            ptr::copy(src.offset(offset as isize), dst, len);
            if len < size {
                ptr::write_bytes(dst.offset(len as isize), 0, size - len);
            }
        }
        Ok(())
    }
}

/// EFI_LOAD_FILE2_PROTOCOL, as installed by any party, e.g., by an EFI image. Only its LoadFile()
/// member is used.
#[repr(C)]
struct LoadFile2Protocol {
    load_file: Option<
        unsafe extern "efiapi" fn(
            *mut LoadFile2Protocol,
            *const DevicePath,
            Bool,
            *mut usize,
            *mut (),
        ) -> Status,
    >,
}

/// A file loaded via LoadFile2, which is held in a buffer of EfiBootServicesData pages that is
/// freed when the FileBuffer is dropped
struct FileBuffer {
    pages: &'static mut [MaybeUninit<u8>],
    size: usize,
}

impl FileBuffer {
    /// Allocates a buffer for a file of `size` bytes
    fn new(size: usize) -> Option<Self> {
        let pages = size.checked_add(EFI_PAGE_MASK)? >> EFI_PAGE_SHIFT;
        let pages = EFI.memmap.allocate_pages(
            pages,
            EfiMemoryType::EfiBootServicesData,
            Placement::Anywhere,
        )?;
        Some(FileBuffer { pages, size })
    }

    /// Returns a FileLoader that loads the file from the buffer
    fn loader(&self) -> LoadImageFileLoader {
        LoadImageFileLoader {
            source_buffer: self.pages.as_ptr() as *const (),
            source_size: self.size,
        }
    }
}

impl Drop for FileBuffer {
    fn drop(&mut self) {
        // This cannot fail, given that the pages were allocated by new()
        let pages = self.pages.len() >> EFI_PAGE_SHIFT;
        EFI.memmap
            .free_pages(self.pages.as_ptr() as u64, pages)
            .ok();
    }
}

/// Returns the status to pass on to the caller of LoadImage() if a file could not be loaded, given
/// the status returned by the protocol that was used to load it. Errors are passed on, but success
/// and warning codes are not, given that they are only returned here if no file was loaded.
fn file_error(status: Status) -> Status {
    if status.is_error() {
        status
    } else {
        Status::EFI_LOAD_ERROR
    }
}

/// Loads the file that `file_path` refers to into a FileBuffer, using the LoadFile2 protocol that
/// is installed on `handle`.
fn load_file2(handle: Handle, file_path: &DevicePath) -> Result<FileBuffer, Status> {
    let protocol = EFI
        .protocol_db
        .borrow()
        .get(&(handle, EFI_LOAD_FILE2_PROTOCOL_GUID))
        .map_or(ptr::null(), |p| p.as_proto_ptr()) as *mut LoadFile2Protocol;
    // SAFETY: The interface pointer of a LoadFile2 protocol is either NULL or points to an
    // EFI_LOAD_FILE2_PROTOCOL instance.
    let Some(load_file) = unsafe { protocol.as_ref() }.and_then(|p| p.load_file) else {
        return Err(Status::EFI_NOT_FOUND);
    };

    // Query the size of the file, which LoadFile() returns along with EFI_BUFFER_TOO_SMALL if it
    // is not passed a buffer. An empty file cannot be loaded as an image.
    let mut size = 0;
    // SAFETY: `load_file` is the LoadFile() member of `protocol`, which is passed a valid device
    // path, and a pointer to a valid UINTN that indicates that no buffer is provided.
    let status = unsafe { load_file(protocol, file_path, 0, &mut size, ptr::null_mut()) };
    if status != Status::EFI_BUFFER_TOO_SMALL {
        return Err(file_error(status));
    }
    if size == 0 {
        return Err(Status::EFI_LOAD_ERROR);
    }

    let mut file = FileBuffer::new(size).ok_or(Status::EFI_OUT_OF_RESOURCES)?;
    let buffer = file.pages.as_mut_ptr() as *mut ();
    // SAFETY: `load_file` is the LoadFile() member of `protocol`, which is passed a valid device
    // path, and a pointer to a valid UINTN that holds the size of `buffer`, which is valid for
    // writes of that many bytes.
    let status = unsafe { load_file(protocol, file_path, 0, &mut size, buffer) };
    if status != Status::EFI_SUCCESS {
        return Err(file_error(status));
    }
    // LoadFile() returns the number of bytes that it loaded into the buffer
    file.size = file.size.min(size);
    Ok(file)
}

/// A handle of a file that was opened via the file protocol, which is closed when dropped
struct OpenFile(*mut EfiFileProtocol);

impl OpenFile {
    fn protocol(&self) -> &EfiFileProtocol {
        // SAFETY: The handle was returned by OpenVolume() or Open(), and so it points to an
        // EFI_FILE_PROTOCOL instance, which remains valid until it is closed.
        unsafe { &*self.0 }
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        if let Some(close) = self.protocol().close {
            // SAFETY: `close` is the Close() member of the handle, which is not used again.
            unsafe { close(self.0) };
        }
    }
}

/// Loads the file that `file_path` refers to into a FileBuffer, using the simple file system
/// protocol that is installed on `handle`. `file_path` must consist of file path media device path
/// nodes, which are opened in turn, starting from the root directory of the volume.
fn load_file_from_volume(handle: Handle, file_path: &DevicePath) -> Result<FileBuffer, Status> {
    let interface = EFI
        .protocol_db
        .borrow()
        .get(&(handle, EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID))
        .map_or(ptr::null(), |p| p.as_proto_ptr());
    let volume = interface as *mut EfiSimpleFileSystemProtocol;
    // SAFETY: The interface pointer of a simple file system protocol is either NULL or points to an
    // EFI_SIMPLE_FILE_SYSTEM_PROTOCOL instance.
    let Some(open_volume) = unsafe { volume.as_ref() }.and_then(|v| v.open_volume) else {
        return Err(Status::EFI_NOT_FOUND);
    };
    let mut root = ptr::null_mut();
    // SAFETY: `open_volume` is the OpenVolume() member of `volume`, which is passed a pointer to a
    // writable location.
    let status = unsafe { open_volume(volume, &mut root) };
    if status != Status::EFI_SUCCESS || root.is_null() {
        return Err(file_error(status));
    }

    let mut file = OpenFile(root);
    let mut node = file_path;
    while node._type != DevicePathType::EFI_DEV_END_PATH {
        if node._type != DevicePathType::EFI_DEV_MEDIA
            || node.subtype != DevicePathSubtype::EFI_DEV_MEDIA_FILE_PATH
        {
            return Err(Status::EFI_NOT_FOUND);
        }
        let open = file.protocol().open.ok_or(Status::EFI_DEVICE_ERROR)?;
        let name = node.file_path_name();
        let mut next = ptr::null_mut();
        // SAFETY: `open` is the Open() member of the handle, which is passed a pointer to a
        // writable location, and a NUL terminated file name.
        let status = unsafe { open(file.0, &mut next, name.as_ptr(), EFI_FILE_MODE_READ, 0) };
        if status != Status::EFI_SUCCESS || next.is_null() {
            return Err(file_error(status));
        }
        // This closes the handle of the directory that the file was opened relative to
        file = OpenFile(next);
        // SAFETY: `node` is not an end node, and so it is followed by another node, given that
        // the caller checked that the device path that `file_path` is a part of is well formed.
        node = unsafe { node.next() };
    }

    // Query the size of the EFI_FILE_INFO structure first, and then retrieve it, to obtain the size
    // of the file, which must not be a directory
    let get_info = file.protocol().get_info.ok_or(Status::EFI_DEVICE_ERROR)?;
    let mut info_size = 0;
    // SAFETY: `get_info` is the GetInfo() member of the handle, which is passed a valid GUID, and a
    // pointer to a valid UINTN that indicates that no buffer is provided.
    let status = unsafe { get_info(file.0, &EFI_FILE_INFO_ID, &mut info_size, ptr::null_mut()) };
    if status != Status::EFI_BUFFER_TOO_SMALL {
        return Err(file_error(status));
    }
    if info_size < SIZE_OF_EFI_FILE_INFO {
        return Err(Status::EFI_DEVICE_ERROR);
    }
    // Use u64 words for the buffer, so that the UINT64 fields of the structure are aligned
    let mut info = alloc::vec![0u64; info_size.div_ceil(size_of::<u64>())];
    // SAFETY: `get_info` is the GetInfo() member of the handle, which is passed a valid GUID, and a
    // pointer to a valid UINTN that holds the size of `info`.
    let status = unsafe {
        get_info(
            file.0,
            &EFI_FILE_INFO_ID,
            &mut info_size,
            info.as_mut_ptr().cast(),
        )
    };
    if status != Status::EFI_SUCCESS {
        return Err(file_error(status));
    }
    // FileSize and Attribute are at offsets 8 and 72, respectively
    let (size, attribute) = (info[1], info[9]);
    if attribute & EFI_FILE_DIRECTORY != 0 {
        return Err(Status::EFI_NOT_FOUND);
    }
    // An empty file cannot be loaded as an image
    let size = usize::try_from(size).or(Err(Status::EFI_OUT_OF_RESOURCES))?;
    if size == 0 {
        return Err(Status::EFI_LOAD_ERROR);
    }

    let read = file.protocol().read.ok_or(Status::EFI_DEVICE_ERROR)?;
    let mut buffer = FileBuffer::new(size).ok_or(Status::EFI_OUT_OF_RESOURCES)?;
    let base = buffer.pages.as_mut_ptr();
    let mut done = 0;
    while done < size {
        let mut len = size - done;
        // SAFETY: `read` is the Read() member of the handle, which is passed a pointer to a valid
        // UINTN that holds the size of the remaining part of the buffer, which is valid for writes
        // of that many bytes.
        let status = unsafe { read(file.0, &mut len, base.add(done).cast()) };
        if status != Status::EFI_SUCCESS {
            return Err(file_error(status));
        }
        // Reading at the end of the file returns no data
        if len == 0 {
            break;
        }
        done += len.min(size - done);
    }
    buffer.size = done;
    Ok(buffer)
}

/// Loads the image file that `device_path` refers to into a FileBuffer. As the UEFI spec requires,
/// the simple file system protocol of the device that most closely matches `device_path` is used,
/// if there is one. Otherwise, the LoadFile2 protocol is used, but only if `boot_policy` is FALSE.
/// (The load file protocol, which the UEFI spec requires to be used in the other cases, is not
/// supported.) Returns the FileBuffer, along with the handle of the device that was used, and the
/// remaining part of `device_path`, which identifies the file on that device.
fn load_file(
    device_path: &DevicePath,
    boot_policy: Bool,
) -> Result<(FileBuffer, Handle, &DevicePath), Status> {
    let volume = find_device(
        &EFI.protocol_db.borrow(),
        &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
        device_path,
    );
    if let Some((handle, file_path)) = volume {
        return Ok((load_file_from_volume(handle, file_path)?, handle, file_path));
    }
    if boot_policy != 0 {
        return Err(Status::EFI_NOT_FOUND);
    }
    let found = find_device(
        &EFI.protocol_db.borrow(),
        &EFI_LOAD_FILE2_PROTOCOL_GUID,
        device_path,
    );
    let (handle, file_path) = found.ok_or(Status::EFI_NOT_FOUND)?;
    Ok((load_file2(handle, file_path)?, handle, file_path))
}

extern "efiapi" fn load_image(
    boot_policy: Bool,
    parent_image_handle: Handle,
    device_path: *const DevicePath,
    source_buffer: *const (),
    source_size: usize,
    image_handle: *mut Handle,
) -> Status {
    log::trace!("LoadImage()");
    // The parent image handle is the caller's image handle
    if image_handle.is_null() || !is_image_handle(&EFI.protocol_db.borrow(), parent_image_handle) {
        return Status::EFI_INVALID_PARAMETER;
    }
    if source_buffer.is_null() && device_path.is_null() {
        return Status::EFI_NOT_FOUND;
    }
    if !source_buffer.is_null() && source_size == 0 {
        return Status::EFI_UNSUPPORTED;
    }

    let mut origin = ImageOrigin {
        parent: parent_image_handle,
        ..Default::default()
    };
    let mut file = None;

    // Take a copy of the device path, if any, for the loaded image device path protocol
    // SAFETY: The UEFI spec requires `device_path` to be NULL or point to a valid device path.
    let device_path = match unsafe { device_path.as_ref() } {
        Some(dp) => {
            let Some(copy) = dp.duplicate() else {
                return Status::EFI_INVALID_PARAMETER;
            };

            let (device_handle, file_path) = if source_buffer.is_null() {
                // Load the image file from the device that the device path refers to
                match load_file(dp, boot_policy) {
                    Ok((f, device_handle, file_path)) => {
                        file = Some(f);
                        (device_handle, file_path)
                    }
                    Err(status) => return status,
                }
            } else {
                // If no device matches, the device path is recorded in its entirety
                let found = find_device(
                    &EFI.protocol_db.borrow(),
                    &EFI_DEVICE_PATH_PROTOCOL_GUID,
                    dp,
                );
                found.unwrap_or((0, dp))
            };

            // Record the device that the image was loaded from, if any, along with a copy of the
            // remaining part of the device path, which identifies the image file on that device.
            origin.device_handle = device_handle;
            origin.file_path = file_path.duplicate();
            Some(copy)
        }
        None => None,
    };

    let ldr = match &file {
        Some(file) => file.loader(),
        None => LoadImageFileLoader {
            source_buffer,
            source_size,
        },
    };

    if let Some(li) = EFI.load_image_with_origin(&ldr, origin) {
        // This cannot fail, given that the image handle is new
        let _ = EFI.install_pinned_protocol(
            li.image_handle,
            Box::pin(LoadedImageDevicePath(device_path)),
            ProtocolOwner::Runtime,
        );
        // SAFETY: `image_handle` is not NULL, and the UEFI spec requires it to point to a writable
        // EFI_HANDLE.
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
    exit_data_size: *mut usize,
    exit_data: *mut *mut Char16,
) -> Status {
    log::trace!("StartImage()");
    let Some(li) = find_loaded_image(&EFI.protocol_db.borrow(), handle) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    // SAFETY: `li` points to the EfiLoadedImage instance of the image, which remains valid until
    // the image is unloaded. EfiLoadedImage::start_image() marks the image as started before
    // running it, after which it can no longer be unloaded.
    let li = unsafe { &*li };
    let ret = li.start_image();

    // Pass back the exit data that the image passed to Exit(), if any. The caller is
    // responsible for freeing it.
    let (size, data) = li.exit_data.replace((0, ptr::null_mut()));
    // SAFETY: The UEFI spec requires `exit_data_size` and `exit_data` to point to writable
    // locations of the appropriate types, or to be NULL in the case of `exit_data`. Check both
    // for NULL, as callers that are not interested in the exit data may pass NULL for both.
    unsafe {
        if !exit_data_size.is_null() {
            *exit_data_size = size;
        }
        if !exit_data.is_null() {
            *exit_data = data;
        }
    }
    ret
}

extern "efiapi" fn exit(
    image_handle: Handle,
    exit_status: Status,
    exit_data_size: usize,
    exit_data: *const Char16,
) -> Status {
    log::trace!("Exit()");

    // Images that have not been started yet are unloaded
    if EFI.unload_image(image_handle).is_ok() {
        return Status::EFI_SUCCESS;
    }

    // Otherwise, only the image that is currently running may exit
    if image_handle != current_image() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // Note that exit_image() does not return, so the protocol database must not remain borrowed
    let Some(li) = find_loaded_image(&EFI.protocol_db.borrow(), image_handle) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    // SAFETY: `li` points to the EfiLoadedImage instance of the image, which remains valid until
    // the image is unloaded. It is the image that is currently running, and images that have been
    // started are never unloaded.
    let li = unsafe { &*li };
    // Clear the recorded stack pointer, as exit_image() bypasses the code in start_image() that
    // does so when the image returns normally
    let sp = li.reserved.replace(0);
    if sp != 0 {
        // Record the exit data for StartImage() to pass back to its caller. The exit data is only
        // valid if the exit status is not EFI_SUCCESS.
        if exit_status != Status::EFI_SUCCESS && !exit_data.is_null() {
            li.exit_data.set((exit_data_size, exit_data as *mut Char16));
        }
        // SAFETY: `sp` is the stack pointer that start_image() recorded when it entered the image,
        // which is the one that is currently running, as checked above. exit_image() switches back
        // to that stack, and returns `exit_status` from start_image().
        unsafe { exit_image(exit_status, sp) };
    }
    Status::EFI_INVALID_PARAMETER
}

extern "efiapi" fn unload_image(image_handle: Handle) -> Status {
    // Only images that have not been started yet can be unloaded, given that invoking the Unload()
    // functions of images that have been started is not supported
    match EFI.unload_image(image_handle) {
        Ok(()) => Status::EFI_SUCCESS,
        Err(status) => status,
    }
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
    interface: *mut *const (),
    agent_handle: Handle,
    controller_handle: Handle,
    attributes: u32,
) -> Status {
    if handle == 0
        || protocol.is_null()
        || (interface.is_null() && attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL)
    {
        return Status::EFI_INVALID_PARAMETER;
    }

    // Only certain combinations of attributes are permitted, some of which require an agent handle
    // and/or a controller handle. Note that open protocol information is not tracked, and so the
    // attributes have no further effect.
    let valid = match attributes {
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
        | EFI_OPEN_PROTOCOL_GET_PROTOCOL
        | EFI_OPEN_PROTOCOL_TEST_PROTOCOL => true,
        EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER => {
            agent_handle != 0 && controller_handle != 0 && controller_handle != handle
        }
        EFI_OPEN_PROTOCOL_BY_DRIVER | EFI_OPEN_PROTOCOL_BY_DRIVER_EXCLUSIVE => {
            agent_handle != 0 && controller_handle != 0
        }
        EFI_OPEN_PROTOCOL_EXCLUSIVE => agent_handle != 0,
        _ => false,
    };
    if !valid {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `protocol` is not NULL, and the UEFI spec requires it to point to a valid EFI_GUID.
    let protocol = unsafe { &*protocol };
    let key = (handle, *protocol);
    let ret = if let Some(proto) = EFI.protocol_db.borrow().get(&key) {
        if attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL {
            // SAFETY: `interface` was checked for NULL above unless `attributes` equals
            // EFI_OPEN_PROTOCOL_TEST_PROTOCOL, and the UEFI spec requires it to point to a
            // writable pointer sized location.
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
    agent_handle: Handle,
    controller_handle: Handle,
) -> Status {
    if handle == 0 || agent_handle == 0 || protocol.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `protocol` is not NULL, and the UEFI spec requires it to point to a valid EFI_GUID.
    let protocol = unsafe { &*protocol };
    let db = EFI.protocol_db.borrow();
    if controller_handle != 0 && !handle_exists(&db, controller_handle) {
        return Status::EFI_INVALID_PARAMETER;
    }

    // Open protocol information is not tracked, and so protocols that are installed are assumed to
    // have been opened by the caller.
    if !db.contains_key(&(handle, *protocol)) {
        return Status::EFI_NOT_FOUND;
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
    if handle == 0 || protocol_buffer.is_null() || protocol_buffer_count.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: Both pointers were checked for NULL above, and the UEFI spec requires them to point to
    // writable locations of the appropriate types.
    let (buffer, count) = unsafe { (&mut *protocol_buffer, &mut *protocol_buffer_count) };

    // The keys of the protocol database move around in memory when entries are added or removed,
    // so return pointers to persistent copies of the GUIDs instead. This permits the caller to
    // modify the protocol database while still using the GUID pointers, e.g., to uninstall all
    // protocols from the handle.
    let guids: Vec<_> = EFI
        .protocol_db
        .borrow()
        .keys()
        .filter(|k| k.0 == handle)
        .map(|k| EFI.persistent_guid(&k.1))
        .collect();

    // Handles only exist for as long as they carry at least one protocol
    if guids.is_empty() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let ret = if let Ok(buf) = EFI
        .memmap
        .allocate_image_pool::<*const Guid>(EfiMemoryType::EfiLoaderData, guids.len())
    {
        // SAFETY: `buf` was allocated with the size and alignment of `guids.len()` GUID pointers,
        // and so it can hold a copy of the contents of `guids`.
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
    search_type: u32,
    protocol: *const Guid,
    search_key: *const (),
    no_handles: *mut usize,
    buffer: *mut *const Handle,
) -> Status {
    if buffer.is_null() || no_handles.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let ret = match get_handle_vec(search_type, protocol, search_key) {
        Err(status) => status,
        Ok(handles) if handles.len() == 0 => Status::EFI_NOT_FOUND,
        Ok(handles) => {
            // SAFETY: Both pointers were checked for NULL above, and the UEFI spec requires them
            // to point to writable locations of the appropriate types.
            let (buffer, count) = unsafe { (&mut *buffer, &mut *no_handles) };

            if let Ok(buf) = EFI
                .memmap
                .allocate_image_pool::<Handle>(EfiMemoryType::EfiLoaderData, handles.len())
            {
                // SAFETY: `buf` was allocated with the size and alignment of `handles.len()`
                // handles, and so it can hold a copy of the contents of `handles`.
                unsafe {
                    ptr::copy(handles.as_ptr(), buf.as_ptr(), handles.len());
                }
                *buffer = buf.as_ptr();
                *count = handles.len();
                Status::EFI_SUCCESS
            } else {
                Status::EFI_OUT_OF_RESOURCES
            }
        }
    };
    log::trace!("LocateHandleBuffer({search_type}) {protocol:x?} -> {ret:?}");
    ret
}

extern "efiapi" fn locate_protocol(
    protocol: *const Guid,
    _registration: *const (),
    interface: *mut *const (),
) -> Status {
    if protocol.is_null() || interface.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: Both pointers were checked for NULL above, and the UEFI spec requires them to point to
    // a valid EFI_GUID and a writable pointer sized location, respectively.
    let (protocol, interface) = unsafe { (*protocol, &mut *interface) };

    let ret = if let Some(entry) = EFI
        .protocol_db
        .borrow()
        .iter()
        .find(|e: &(&(Handle, Guid), &ProtocolEntry)| e.0 .1 == protocol)
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

unsafe extern "efiapi" {
    fn install_multiple_protocol_interfaces_wrapper(handle: *mut Handle) -> Status;
    fn uninstall_multiple_protocol_interfaces_wrapper(handle: Handle) -> Status;
}

/// Collects the protocol GUID and interface pointer pairs from the NULL terminated list at `p`.
/// Returns `None` if the list is empty or contains duplicate GUIDs.
///
/// # Safety
///
/// `p` must point to a list of pairs of pointers that is terminated by a NULL pointer, where the
/// first pointer of each pair points to a valid EFI_GUID.
unsafe fn parse_multiproto_varargs(p: *const *const ()) -> Option<BTreeMap<Guid, *const ()>> {
    let mut m: BTreeMap<Guid, *const ()> = BTreeMap::new();
    let mut p = p;
    // SAFETY: The caller guarantees that `p` points to a NULL terminated list of GUID pointer and
    // interface pointer pairs, and the loop stops at the NULL terminator.
    unsafe {
        while !(*p).is_null() {
            let g = &*(*p as *const Guid);
            if m.insert(*g, *p.offset(1)).is_some() {
                // Cannot install the same protocol twice
                return None;
            }
            p = p.offset(2);
        }
    }
    if m.len() == 0 {
        None
    } else {
        Some(m)
    }
}

#[unsafe(no_mangle)]
extern "efiapi" fn install_multiple_protocol_interfaces(
    handle: *mut Handle,
    p: *const *const (),
) -> Status {
    if handle.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: `handle` is not NULL, and the UEFI spec requires it to point to a valid EFI_HANDLE.
    // The assembler wrapper passes the variadic arguments via `p`, which the UEFI spec requires to
    // be a NULL terminated list of protocol GUID and interface pointer pairs.
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
        // SAFETY: The UEFI spec requires device path protocol interfaces to point to a device
        // path.
        if !unsafe { is_valid_device_path(*devpath) } {
            return Status::EFI_INVALID_PARAMETER;
        }

        // SAFETY: `devpath` was checked above to be a non-NULL pointer to a device path.
        let devpath = unsafe { &*(*devpath as *const DevicePath) };

        if let Some(_) = db.iter().find(|e| {
            let p = e.1.as_proto_ptr();
            !p.is_null() && e.0 .1 == EFI_DEVICE_PATH_PROTOCOL_GUID && {
                // SAFETY: `p` is the non-NULL interface pointer of a device path protocol
                // instance, and so it points to a device path.
                let dp = unsafe { &*(p as *const DevicePath) };
                devpath.equals(dp)
            }
        }) {
            return Status::EFI_ALREADY_STARTED;
        }
    }

    // If the handle is not NULL, check whether it exists, and whether any of the protocols already
    // exist on this handle
    if *handle != 0 {
        if !handle_exists(&db, *handle) {
            return Status::EFI_INVALID_PARAMETER;
        }
        for g in protocols.keys() {
            if db.contains_key(&(*handle, *g)) {
                return Status::EFI_INVALID_PARAMETER;
            }
        }
    } else {
        *handle = new_handle();
    }

    for (guid, interface) in protocols.iter() {
        db.insert(
            (*handle, *guid),
            ExternalEfiProtocol::entry(*guid, *interface),
        );
    }
    Status::EFI_SUCCESS
}

#[unsafe(no_mangle)]
extern "efiapi" fn uninstall_multiple_protocol_interfaces(
    handle: Handle,
    p: *const *const (),
) -> Status {
    if handle == 0 {
        return Status::EFI_INVALID_PARAMETER;
    }

    // SAFETY: The assembler wrapper passes the variadic arguments via `p`, which the UEFI spec
    // requires to be a NULL terminated list of protocol GUID and interface pointer pairs.
    let protocols = unsafe {
        if let Some(m) = parse_multiproto_varargs(p) {
            m
        } else {
            return Status::EFI_INVALID_PARAMETER;
        }
    };

    let mut db = EFI.protocol_db.borrow_mut();

    // Check whether all protocol/interface tuples are installed on the handle, and whether they
    // were installed by an EFI image (as opposed to the runtime or the embedder)
    for (guid, interface) in protocols.iter() {
        if let Some(p) = db.get(&(handle, *guid)) {
            if p.as_proto_ptr() == *interface && p.owner == ProtocolOwner::Image {
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

extern "efiapi" fn calculate_crc32(data: *const (), datasize: usize, crc32: *mut u32) -> Status {
    if data.is_null() || datasize == 0 || crc32.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // SAFETY: Neither pointer is NULL, and the UEFI spec requires `crc32` to point to a writable
    // UINT32, and `data` to point to a buffer of `datasize` bytes.
    let (crc, slice) = unsafe {
        (
            &mut *crc32,
            slice::from_raw_parts(data as *const u8, datasize),
        )
    };
    *crc = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(slice);
    Status::EFI_SUCCESS
}

extern "efiapi" fn copy_mem(destination: *mut u8, source: *const u8, length: usize) -> *mut u8 {
    // SAFETY: The UEFI spec requires `source` and `destination` to be valid for reads and writes of
    // `length` bytes, respectively. Like CopyMem(), ptr::copy() permits the buffers to overlap.
    unsafe { ptr::copy(source, destination, length) }
    destination
}

extern "efiapi" fn set_mem(buffer: *mut u8, size: usize, value: u8) -> *mut u8 {
    // SAFETY: The UEFI spec requires `buffer` to be valid for writes of `size` bytes.
    unsafe { ptr::write_bytes(buffer, value, size) }
    buffer
}
