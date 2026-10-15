// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Shared harness for the boot services tests.
//!
//! The tests exercise the boot services the way EFI images do: via the EFI system table that is
//! passed to the entry point of an image. To obtain it, the harness initializes the EFI runtime
//! with a chunk of anonymous memory as system RAM, and loads and starts a minimal PE/COFF image
//! whose entry point records the system table pointer it is passed.
//!
//! The tables, data structures and constants below are transcribed from the UEFI specification
//! rather than taken from the efiloader implementation, so that the tests also cover the layout of
//! the tables that are exposed to EFI images. The only efiloader types that are used are part of
//! its public API: the ones that represent the primitive EFI types EFI_GUID, EFI_HANDLE and
//! EFI_STATUS, and the ones used to initialize the EFI runtime.
//!
//! The EFI runtime is a process wide singleton, and so all tests in a test binary share the same
//! instance. [`setup`] serializes the tests, and each test should only rely on state that it
//! creates itself, e.g., protocols with unique GUIDs that it installs onto new handles.
//!
//! Tests for behavior that the spec mandates but that efiloader does not implement are marked
//! `#[ignore]`, with a reason describing the discrepancy. They can be run using
//! `cargo test -- --ignored`.

#![allow(dead_code)]

use core::ffi::c_void;
use core::mem::{MaybeUninit, size_of};
use core::ops::Range;
use core::ptr;
use core::slice;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use efiloader::memorytype::{EFI_MEMORY_RO, EFI_MEMORY_XP};
pub use efiloader::status::Status;
pub use efiloader::{Guid, Handle};

pub type Boolean = u8;
pub type Char16 = u16;
pub type PhysicalAddress = u64;
pub type Event = *mut c_void;
pub type EventNotify = unsafe extern "efiapi" fn(Event, *mut c_void);

pub const EFI_PAGE_SIZE: usize = 4096;
pub const PAGE: u64 = EFI_PAGE_SIZE as u64;

// EFI_TPL
pub type Tpl = usize;
pub const TPL_APPLICATION: Tpl = 4;
pub const TPL_CALLBACK: Tpl = 8;
pub const TPL_NOTIFY: Tpl = 16;
pub const TPL_HIGH_LEVEL: Tpl = 31;

// EFI_ALLOCATE_TYPE
pub const ALLOCATE_ANY_PAGES: u32 = 0;
pub const ALLOCATE_MAX_ADDRESS: u32 = 1;
pub const ALLOCATE_ADDRESS: u32 = 2;
pub const MAX_ALLOCATE_TYPE: u32 = 3;

// EFI_MEMORY_TYPE
pub const EFI_RESERVED_MEMORY_TYPE: u32 = 0;
pub const EFI_LOADER_CODE: u32 = 1;
pub const EFI_LOADER_DATA: u32 = 2;
pub const EFI_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
pub const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
pub const EFI_UNUSABLE_MEMORY: u32 = 8;
pub const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;
pub const EFI_ACPI_MEMORY_NVS: u32 = 10;
pub const EFI_MEMORY_MAPPED_IO: u32 = 11;
pub const EFI_MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
pub const EFI_PAL_CODE: u32 = 13;
pub const EFI_PERSISTENT_MEMORY: u32 = 14;
pub const EFI_UNACCEPTED_MEMORY_TYPE: u32 = 15;
pub const EFI_MAX_MEMORY_TYPE: u32 = 16;

/// The memory types that UEFI images may allocate pages or pool of. (They must not allocate
/// EfiReservedMemoryType, EfiMemoryMappedIO or EfiUnacceptedMemoryType, and EfiConventionalMemory
/// and EfiPersistentMemory are rejected by AllocatePages() and AllocatePool().)
pub const ALLOCATABLE_MEMORY_TYPES: [u32; 8] = [
    EFI_LOADER_CODE,
    EFI_LOADER_DATA,
    EFI_BOOT_SERVICES_CODE,
    EFI_BOOT_SERVICES_DATA,
    EFI_RUNTIME_SERVICES_CODE,
    EFI_RUNTIME_SERVICES_DATA,
    EFI_ACPI_RECLAIM_MEMORY,
    EFI_ACPI_MEMORY_NVS,
];

pub const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;

// EFI_INTERFACE_TYPE
pub const EFI_NATIVE_INTERFACE: u32 = 0;

// EFI_LOCATE_SEARCH_TYPE
pub const ALL_HANDLES: u32 = 0;
pub const BY_REGISTER_NOTIFY: u32 = 1;
pub const BY_PROTOCOL: u32 = 2;

// Attributes of OpenProtocol()
pub const EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL: u32 = 0x01;
pub const EFI_OPEN_PROTOCOL_GET_PROTOCOL: u32 = 0x02;
pub const EFI_OPEN_PROTOCOL_TEST_PROTOCOL: u32 = 0x04;
pub const EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER: u32 = 0x08;
pub const EFI_OPEN_PROTOCOL_BY_DRIVER: u32 = 0x10;
pub const EFI_OPEN_PROTOCOL_EXCLUSIVE: u32 = 0x20;

pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249; // "IBI SYST"
pub const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x5652_4553_544f_4f42; // "BOOTSERV"

pub const EFI_LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid {
    data1: 0x5b1b31a1,
    data2: 0x9562,
    data3: 0x11d2,
    data4: [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const EFI_LOADED_IMAGE_PROTOCOL_REVISION: u32 = 0x1000;

pub const EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID: Guid = Guid {
    data1: 0xbc62157e,
    data2: 0x3e33,
    data3: 0x4fec,
    data4: [0x99, 0x20, 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf],
};

pub const EFI_DEVICE_PATH_PROTOCOL_GUID: Guid = Guid {
    data1: 0x09576e91,
    data2: 0x6d3f,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const EFI_LOAD_FILE2_PROTOCOL_GUID: Guid = Guid {
    data1: 0x4006c0c1,
    data2: 0xfcb3,
    data3: 0x403e,
    data4: [0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d],
};

pub const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: Guid = Guid {
    data1: 0x964e5b22,
    data2: 0x6459,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION: u64 = 0x00010000;

pub const EFI_FILE_PROTOCOL_REVISION: u64 = 0x00010000;

pub const EFI_FILE_MODE_READ: u64 = 0x0000000000000001;
pub const EFI_FILE_MODE_WRITE: u64 = 0x0000000000000002;
pub const EFI_FILE_MODE_CREATE: u64 = 0x8000000000000000;

pub const EFI_FILE_READ_ONLY: u64 = 0x0000000000000001;
pub const EFI_FILE_DIRECTORY: u64 = 0x0000000000000010;

pub const EFI_FILE_INFO_ID: Guid = Guid {
    data1: 0x09576e92,
    data2: 0x6d3f,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const SIZE_OF_EFI_FILE_INFO: usize = 80;

pub const EFI_FILE_SYSTEM_INFO_ID: Guid = Guid {
    data1: 0x09576e93,
    data2: 0x6d3f,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};
pub const SIZE_OF_EFI_FILE_SYSTEM_INFO: usize = 36;

pub const EFI_FILE_SYSTEM_VOLUME_LABEL_ID: Guid = Guid {
    data1: 0xdb47d7d3,
    data2: 0xfe81,
    data3: 0x11d3,
    data4: [0x9a, 0x35, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
};

pub const EFI_UNSPECIFIED_TIMEZONE: i16 = 0x07ff;

pub const EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID: Guid = Guid {
    data1: 0x387477c1,
    data2: 0x69c7,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

pub const EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID: Guid = Guid {
    data1: 0x387477c2,
    data2: 0x69c7,
    data3: 0x11d2,
    data4: [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
};

/// EFI_TABLE_HEADER
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// EFI_CONFIGURATION_TABLE
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

/// EFI_SYSTEM_TABLE
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *mut Char16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut c_void,
    pub console_out_handle: Handle,
    pub con_out: *mut c_void,
    pub standard_error_handle: Handle,
    pub std_err: *mut c_void,
    pub runtime_services: *mut c_void,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut ConfigurationTable,
}

/// EFI_MEMORY_DESCRIPTOR
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct MemoryDescriptor {
    pub r#type: u32,
    pub physical_start: PhysicalAddress,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

/// EFI_DEVICE_PATH_PROTOCOL, i.e., the header of a device path node
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DevicePathProtocol {
    pub r#type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
}

/// EFI_OPEN_PROTOCOL_INFORMATION_ENTRY
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct OpenProtocolInformationEntry {
    pub agent_handle: Handle,
    pub controller_handle: Handle,
    pub attributes: u32,
    pub open_count: u32,
}

/// EFI_LOADED_IMAGE_PROTOCOL
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *mut DevicePathProtocol,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: Option<unsafe extern "efiapi" fn(Handle) -> Status>,
}

/// EFI_LOAD_FILE2_PROTOCOL
#[derive(Clone, Copy)]
#[repr(C)]
pub struct LoadFile2Protocol {
    pub load_file: unsafe extern "efiapi" fn(
        *mut LoadFile2Protocol,
        *mut DevicePathProtocol,
        Boolean,
        *mut usize,
        *mut c_void,
    ) -> Status,
}

/// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SimpleFileSystemProtocol {
    pub revision: u64,
    pub open_volume:
        unsafe extern "efiapi" fn(*mut SimpleFileSystemProtocol, *mut *mut FileProtocol) -> Status,
}

/// EFI_FILE_PROTOCOL, revision 1
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FileProtocol {
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(
        *mut FileProtocol,
        *mut *mut FileProtocol,
        *const Char16,
        u64,
        u64,
    ) -> Status,
    pub close: unsafe extern "efiapi" fn(*mut FileProtocol) -> Status,
    pub delete: unsafe extern "efiapi" fn(*mut FileProtocol) -> Status,
    pub read: unsafe extern "efiapi" fn(*mut FileProtocol, *mut usize, *mut c_void) -> Status,
    pub write: unsafe extern "efiapi" fn(*mut FileProtocol, *mut usize, *const c_void) -> Status,
    pub get_position: unsafe extern "efiapi" fn(*mut FileProtocol, *mut u64) -> Status,
    pub set_position: unsafe extern "efiapi" fn(*mut FileProtocol, u64) -> Status,
    pub get_info: unsafe extern "efiapi" fn(
        *mut FileProtocol,
        *const Guid,
        *mut usize,
        *mut c_void,
    ) -> Status,
    pub set_info:
        unsafe extern "efiapi" fn(*mut FileProtocol, *const Guid, usize, *const c_void) -> Status,
    pub flush: unsafe extern "efiapi" fn(*mut FileProtocol) -> Status,
}

/// EFI_TIME
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub time_zone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

/// EFI_FILE_INFO, without the FileName that follows it
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FileInfo {
    pub size: u64,
    pub file_size: u64,
    pub physical_size: u64,
    pub create_time: EfiTime,
    pub last_access_time: EfiTime,
    pub modification_time: EfiTime,
    pub attribute: u64,
}

/// Parses the EFI_FILE_INFO structure in `buf`, and returns it along with the FileName
pub fn parse_file_info(buf: &[u8]) -> (FileInfo, String) {
    assert!(buf.len() >= SIZE_OF_EFI_FILE_INFO);
    // SAFETY: `buf` covers an EFI_FILE_INFO structure.
    let info: FileInfo = unsafe { ptr::read_unaligned(buf.as_ptr().cast()) };
    assert_eq!(info.size as usize, buf.len());
    (info, utf16_to_string(&buf[SIZE_OF_EFI_FILE_INFO..]))
}

/// Returns the NUL terminated UTF-16LE string at the start of `buf`
pub fn utf16_to_string(buf: &[u8]) -> String {
    let chars: Vec<u16> = (0..buf.len() / 2)
        .map(|i| u16::from_le_bytes([buf[2 * i], buf[2 * i + 1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16(&chars).unwrap()
}

/// Returns `s` as a NUL terminated UTF-16 string
pub fn utf16z(s: &str) -> Vec<Char16> {
    s.encode_utf16().chain([0]).collect()
}

pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

/// A writer of cpio archives in the "newc" format of the Linux initramfs, as described in the
/// cpio(5) man page
#[derive(Default)]
pub struct Cpio(pub Vec<u8>);

impl Cpio {
    /// Appends an entry for `path` with the given mode, modification time and contents
    pub fn entry(mut self, path: &str, mode: u32, mtime: u32, data: &[u8]) -> Self {
        let name_size = path.len() as u32 + 1;
        let fields = [
            0,
            mode,
            0,
            0,
            1,
            mtime,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name_size,
            0,
        ];
        self.0.extend_from_slice(b"070701");
        for field in fields {
            self.0.extend_from_slice(format!("{field:08X}").as_bytes());
        }
        self.0.extend_from_slice(path.as_bytes());
        self.0.push(0);
        self.align();
        self.0.extend_from_slice(data);
        self.align();
        self
    }

    fn align(&mut self) {
        self.0.resize(self.0.len().next_multiple_of(4), 0);
    }

    /// Appends a regular file
    pub fn file(self, path: &str, data: &[u8]) -> Self {
        self.entry(path, S_IFREG | 0o644, 0, data)
    }

    /// Appends a directory
    pub fn dir(self, path: &str) -> Self {
        self.entry(path, S_IFDIR | 0o755, 0, &[])
    }

    /// Appends the trailer, and returns the archive
    pub fn finish(self) -> Vec<u8> {
        self.entry("TRAILER!!!", 0, 0, &[]).0
    }
}

/// EFI_BOOT_SERVICES
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,

    // Task Priority Services
    pub raise_tpl: unsafe extern "efiapi" fn(Tpl) -> Tpl,
    pub restore_tpl: unsafe extern "efiapi" fn(Tpl),

    // Memory Services
    pub allocate_pages: unsafe extern "efiapi" fn(u32, u32, usize, *mut PhysicalAddress) -> Status,
    pub free_pages: unsafe extern "efiapi" fn(PhysicalAddress, usize) -> Status,
    pub get_memory_map: unsafe extern "efiapi" fn(
        *mut usize,
        *mut MemoryDescriptor,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> Status,
    pub allocate_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut c_void) -> Status,
    pub free_pool: unsafe extern "efiapi" fn(*mut c_void) -> Status,

    // Event & Timer Services
    pub create_event:
        unsafe extern "efiapi" fn(u32, Tpl, Option<EventNotify>, *mut c_void, *mut Event) -> Status,
    pub set_timer: unsafe extern "efiapi" fn(Event, u32, u64) -> Status,
    pub wait_for_event: unsafe extern "efiapi" fn(usize, *mut Event, *mut usize) -> Status,
    pub signal_event: unsafe extern "efiapi" fn(Event) -> Status,
    pub close_event: unsafe extern "efiapi" fn(Event) -> Status,
    pub check_event: unsafe extern "efiapi" fn(Event) -> Status,

    // Protocol Handler Services
    pub install_protocol_interface:
        unsafe extern "efiapi" fn(*mut Handle, *const Guid, u32, *mut c_void) -> Status,
    pub reinstall_protocol_interface:
        unsafe extern "efiapi" fn(Handle, *const Guid, *mut c_void, *mut c_void) -> Status,
    pub uninstall_protocol_interface:
        unsafe extern "efiapi" fn(Handle, *const Guid, *mut c_void) -> Status,
    pub handle_protocol: unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    pub reserved: *mut c_void,
    pub register_protocol_notify:
        unsafe extern "efiapi" fn(*const Guid, Event, *mut *mut c_void) -> Status,
    pub locate_handle:
        unsafe extern "efiapi" fn(u32, *const Guid, *mut c_void, *mut usize, *mut Handle) -> Status,
    pub locate_device_path:
        unsafe extern "efiapi" fn(*const Guid, *mut *mut DevicePathProtocol, *mut Handle) -> Status,
    pub install_configuration_table: unsafe extern "efiapi" fn(*const Guid, *mut c_void) -> Status,

    // Image Services
    pub load_image: unsafe extern "efiapi" fn(
        Boolean,
        Handle,
        *mut DevicePathProtocol,
        *mut c_void,
        usize,
        *mut Handle,
    ) -> Status,
    pub start_image: unsafe extern "efiapi" fn(Handle, *mut usize, *mut *mut Char16) -> Status,
    pub exit: unsafe extern "efiapi" fn(Handle, Status, usize, *mut Char16) -> Status,
    pub unload_image: unsafe extern "efiapi" fn(Handle) -> Status,
    pub exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,

    // Miscellaneous Services
    pub get_next_monotonic_count: unsafe extern "efiapi" fn(*mut u64) -> Status,
    pub stall: unsafe extern "efiapi" fn(usize) -> Status,
    pub set_watchdog_timer: unsafe extern "efiapi" fn(usize, u64, usize, *mut Char16) -> Status,

    // DriverSupport Services
    pub connect_controller:
        unsafe extern "efiapi" fn(Handle, *mut Handle, *mut DevicePathProtocol, Boolean) -> Status,
    pub disconnect_controller: unsafe extern "efiapi" fn(Handle, Handle, Handle) -> Status,

    // Open and Close Protocol Services
    pub open_protocol: unsafe extern "efiapi" fn(
        Handle,
        *const Guid,
        *mut *mut c_void,
        Handle,
        Handle,
        u32,
    ) -> Status,
    pub close_protocol: unsafe extern "efiapi" fn(Handle, *const Guid, Handle, Handle) -> Status,
    pub open_protocol_information: unsafe extern "efiapi" fn(
        Handle,
        *const Guid,
        *mut *mut OpenProtocolInformationEntry,
        *mut usize,
    ) -> Status,

    // Library Services
    pub protocols_per_handle:
        unsafe extern "efiapi" fn(Handle, *mut *mut *mut Guid, *mut usize) -> Status,
    pub locate_handle_buffer: unsafe extern "efiapi" fn(
        u32,
        *const Guid,
        *mut c_void,
        *mut usize,
        *mut *mut Handle,
    ) -> Status,
    pub locate_protocol:
        unsafe extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
    pub install_multiple_protocol_interfaces: unsafe extern "efiapi" fn(*mut Handle, ...) -> Status,
    pub uninstall_multiple_protocol_interfaces: unsafe extern "efiapi" fn(Handle, ...) -> Status,

    // 32-bit CRC Services
    pub calculate_crc32: unsafe extern "efiapi" fn(*const c_void, usize, *mut u32) -> Status,

    // Miscellaneous Services
    pub copy_mem: unsafe extern "efiapi" fn(*mut c_void, *const c_void, usize),
    pub set_mem: unsafe extern "efiapi" fn(*mut c_void, usize, u8),
    pub create_event_ex: unsafe extern "efiapi" fn(
        u32,
        Tpl,
        Option<EventNotify>,
        *const c_void,
        *const Guid,
        *mut Event,
    ) -> Status,
}

const _: () = assert!(size_of::<TableHeader>() == 24);
const _: () = assert!(size_of::<MemoryDescriptor>() == 40);
const _: () = assert!(size_of::<SystemTable>() == size_of::<TableHeader>() + 12 * 8);
const _: () = assert!(size_of::<BootServices>() == size_of::<TableHeader>() + 44 * 8);

/// The signature of the entry point of an EFI image (EFI_IMAGE_ENTRY_POINT)
pub type EntryPoint = extern "efiapi" fn(Handle, *mut SystemTable) -> Status;

/// The amount of memory that is declared to the EFI runtime as system RAM
pub const RAM_SIZE: usize = 64 << 20;

struct Context {
    efi: &'static efiloader::EfiContext,
    system_table: *mut SystemTable,
    image_handle: Handle,
    ram: Range<u64>,
}

// SAFETY: The system table pointer refers to memory that remains valid for the remaining lifetime
// of the process, and is only dereferenced by tests that hold the harness lock.
unsafe impl Send for Context {}
// SAFETY: See above.
unsafe impl Sync for Context {}

static LOCK: Mutex<()> = Mutex::new(());
static CONTEXT: OnceLock<Context> = OnceLock::new();

/// Provides access to the EFI runtime. Tests are serialized for as long as an instance exists.
pub struct Efi {
    ctx: &'static Context,
    _guard: MutexGuard<'static, ()>,
}

/// Initializes the EFI runtime when called for the first time, and returns an [`Efi`] instance that
/// grants exclusive access to it.
pub fn setup() -> Efi {
    // A test that fails while holding the lock poisons it, but this does not affect other tests
    let guard = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let ctx = CONTEXT.get_or_init(init);
    Efi { ctx, _guard: guard }
}

/// Implements the memory permission management needed by the PE/COFF loader using mprotect()
struct Mapper;

impl efiloader::MemoryMapper for Mapper {
    fn remap_range(&self, range: &Range<usize>, set: u64, clr: u64) -> Result<(), &str> {
        // System RAM is mapped read/write and non-executable by default
        let mut prot = libc::PROT_READ | libc::PROT_WRITE;
        if set & EFI_MEMORY_RO != 0 {
            prot &= !libc::PROT_WRITE;
        }
        if clr & EFI_MEMORY_XP != 0 {
            prot |= libc::PROT_EXEC;
        }
        // SAFETY: The PE/COFF loader only remaps memory that it allocated from system RAM, which is
        // part of the anonymous mapping created by init().
        let ret = unsafe { libc::mprotect(range.start as *mut c_void, range.len(), prot) };
        if ret == 0 {
            Ok(())
        } else {
            Err("mprotect() failed")
        }
    }

    fn query_range(&self, _range: &Range<usize>) -> Option<u64> {
        None
    }
}

/// Used as a type parameter only: no source of randomness is provided to the EFI runtime, so that
/// images are loaded at deterministic addresses.
struct NoRandom;

impl efiloader::Random for NoRandom {
    fn get_entropy(&self, _bytes: &mut [u8], _use_raw: bool) -> bool {
        false
    }
}

/// An in-memory file that the embedder can pass to the EFI runtime
pub struct MemFile(pub Vec<u8>);

impl efiloader::FileLoader for MemFile {
    fn get_size(&self) -> usize {
        self.0.len()
    }

    fn load_file<'a>(&self, loadbuffer: &'a mut [MaybeUninit<u8>]) -> Result<&'a [u8], &str> {
        // SAFETY: `loadbuffer` is valid for writes of its entire size, all of which load_range()
        // initializes when it succeeds.
        unsafe {
            self.load_range(loadbuffer.as_mut_ptr().cast(), 0, loadbuffer.len())?;
            Ok(slice::from_raw_parts(
                loadbuffer.as_ptr().cast(),
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
        let src = self.0.get(offset..).ok_or("offset out of range")?;
        let len = size.min(src.len());
        let dst = loadbuffer.cast::<u8>();
        // SAFETY: The caller guarantees that `loadbuffer` is valid for writes of `size` bytes.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
            ptr::write_bytes(dst.add(len), 0, size - len);
        }
        Ok(())
    }
}

static BOOTSTRAP_IMAGE_HANDLE: AtomicUsize = AtomicUsize::new(0);
static BOOTSTRAP_SYSTEM_TABLE: AtomicUsize = AtomicUsize::new(0);

extern "efiapi" fn bootstrap_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    BOOTSTRAP_IMAGE_HANDLE.store(image_handle, Ordering::Release);
    BOOTSTRAP_SYSTEM_TABLE.store(system_table as usize, Ordering::Release);
    Status::EFI_SUCCESS
}

fn init() -> Context {
    // SAFETY: This creates a new anonymous private mapping, which is not shared with anyone.
    let base = unsafe {
        libc::mmap(
            ptr::null_mut(),
            RAM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(
        base,
        libc::MAP_FAILED,
        "failed to allocate memory for the EFI runtime"
    );
    let ram = base as usize..base as usize + RAM_SIZE;

    let memmap = efiloader::memmap::MemoryMap::new();
    // SAFETY: The mapping is used exclusively as system RAM by the EFI runtime for the remaining
    // lifetime of the process.
    unsafe { memmap.declare_memory_region(&ram) }.expect("failed to declare system RAM");

    let efi = efiloader::init(None, memmap, Mapper, None::<NoRandom>)
        .expect("failed to initialize the EFI runtime");

    let image = MemFile(pe_image(bootstrap_entry));
    let mut loaded_image = efi
        .load_image(&image)
        .expect("failed to load the bootstrap image");
    assert_eq!(loaded_image.start_image(), Status::EFI_SUCCESS);
    assert_eq!(
        BOOTSTRAP_IMAGE_HANDLE.load(Ordering::Acquire),
        loaded_image.image_handle
    );
    let system_table = BOOTSTRAP_SYSTEM_TABLE.load(Ordering::Acquire) as *mut SystemTable;
    assert!(!system_table.is_null());

    Context {
        efi,
        system_table,
        image_handle: loaded_image.image_handle,
        ram: ram.start as u64..ram.end as u64,
    }
}

impl Efi {
    /// The efiloader context, which the tests use only to override the default implementations of
    /// boot services that efiloader leaves to the embedder.
    pub fn context(&self) -> &'static efiloader::EfiContext {
        self.ctx.efi
    }

    /// The EFI system table pointer that is passed to the entry point of EFI images
    pub fn system_table_ptr(&self) -> *mut SystemTable {
        self.ctx.system_table
    }

    /// Returns a snapshot of the EFI system table
    pub fn system_table(&self) -> SystemTable {
        // SAFETY: The system table pointer is valid, and the table is not modified while it is
        // being copied, given that tests are serialized.
        unsafe { ptr::read(self.ctx.system_table) }
    }

    /// Returns a copy of the EFI boot services table referenced by the system table
    pub fn bs(&self) -> BootServices {
        // SAFETY: The system table holds a valid pointer to the boot services table.
        unsafe { ptr::read(self.system_table().boot_services) }
    }

    /// The handle of an image that was loaded and started, which can be passed as the image handle
    /// of the caller, e.g., ParentImageHandle or AgentHandle
    pub fn image_handle(&self) -> Handle {
        self.ctx.image_handle
    }

    /// The physical address range of the system RAM declared to the EFI runtime
    pub fn ram(&self) -> Range<u64> {
        self.ctx.ram.clone()
    }

    /// Retrieves the current memory map using GetMemoryMap()
    pub fn memory_map(&self) -> MemoryMap {
        let bs = self.bs();
        let mut map_size = 0;
        let mut map_key = 0;
        let mut descriptor_size = 0;
        let mut descriptor_version = 0;
        loop {
            // The buffer is not allocated from EFI memory, so the memory map does not grow as a
            // result. Still, add some slack, as the spec recommends.
            let mut buffer = vec![0u64; map_size / 8 + 64];
            let mut size = buffer.len() * 8;
            // SAFETY: All pointers are valid, and `buffer` is a suitably aligned buffer of `size`
            // bytes.
            let status = unsafe {
                (bs.get_memory_map)(
                    &mut size,
                    buffer.as_mut_ptr().cast(),
                    &mut map_key,
                    &mut descriptor_size,
                    &mut descriptor_version,
                )
            };
            if status == Status::EFI_BUFFER_TOO_SMALL {
                map_size = size;
                continue;
            }
            assert_eq!(status, Status::EFI_SUCCESS);
            assert!(descriptor_size >= size_of::<MemoryDescriptor>());
            assert_eq!(size % descriptor_size, 0);
            let base = buffer.as_ptr().cast::<u8>();
            let descriptors = (0..size / descriptor_size)
                // SAFETY: Each descriptor starts with an EFI_MEMORY_DESCRIPTOR, and all of them
                // reside in the first `size` bytes of `buffer`.
                .map(|i| unsafe { ptr::read_unaligned(base.add(i * descriptor_size).cast()) })
                .collect();
            return MemoryMap {
                map_key,
                descriptor_size,
                descriptor_version,
                descriptors,
            };
        }
    }

    /// Returns the (VendorGuid, VendorTable) pairs in the EFI configuration table
    pub fn configuration_tables(&self) -> Vec<(Guid, *mut c_void)> {
        let st = self.system_table();
        (0..st.number_of_table_entries)
            .map(|i| {
                // SAFETY: The configuration table array holds NumberOfTableEntries entries.
                let entry = unsafe { ptr::read(st.configuration_table.add(i)) };
                (entry.vendor_guid, entry.vendor_table)
            })
            .collect()
    }

    /// Installs `interface` as an instance of `protocol` using InstallProtocolInterface(), onto
    /// `handle`, or onto a new handle if `handle` is NULL. Returns the handle on success.
    pub fn install_protocol(
        &self,
        handle: Handle,
        protocol: &Guid,
        interface: *mut c_void,
    ) -> Result<Handle, Status> {
        let mut handle = handle;
        // SAFETY: All pointers are valid.
        let status = unsafe {
            (self.bs().install_protocol_interface)(
                &mut handle,
                protocol,
                EFI_NATIVE_INTERFACE,
                interface,
            )
        };
        if status == Status::EFI_SUCCESS {
            assert_ne!(handle, 0);
            Ok(handle)
        } else {
            Err(status)
        }
    }

    /// Returns the instance of `protocol` installed on `handle` using HandleProtocol()
    pub fn handle_protocol(&self, handle: Handle, protocol: &Guid) -> Result<*mut c_void, Status> {
        let mut interface = ptr::null_mut();
        // SAFETY: All pointers are valid.
        let status = unsafe { (self.bs().handle_protocol)(handle, protocol, &mut interface) };
        if status == Status::EFI_SUCCESS {
            Ok(interface)
        } else {
            Err(status)
        }
    }

    /// Returns the handles matching the search criteria using LocateHandle(), sorted in ascending
    /// order.
    pub fn locate_handles(
        &self,
        search_type: u32,
        protocol: Option<&Guid>,
    ) -> Result<Vec<Handle>, Status> {
        let bs = self.bs();
        let protocol = protocol.map_or(ptr::null(), |p| p as *const Guid);
        let mut size = 0;
        // SAFETY: All pointers are valid, and no buffer is passed as its size is 0.
        let status = unsafe {
            (bs.locate_handle)(
                search_type,
                protocol,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
            )
        };
        if status != Status::EFI_BUFFER_TOO_SMALL {
            return Err(status);
        }
        assert_eq!(size % size_of::<Handle>(), 0);
        let mut handles = vec![0; size / size_of::<Handle>()];
        // SAFETY: All pointers are valid, and `handles` is a buffer of `size` bytes.
        let status = unsafe {
            (bs.locate_handle)(
                search_type,
                protocol,
                ptr::null_mut(),
                &mut size,
                handles.as_mut_ptr(),
            )
        };
        assert_eq!(status, Status::EFI_SUCCESS);
        handles.truncate(size / size_of::<Handle>());
        handles.sort();
        Ok(handles)
    }

    /// Loads `image` from memory using LoadImage(), passing the image handle of the bootstrap image
    /// as the parent image handle. Returns the handle of the loaded image on success.
    pub fn load_image(&self, image: &[u8]) -> Result<Handle, Status> {
        let mut handle = 0;
        // SAFETY: All pointers are valid, and `image` is a buffer of `image.len()` bytes.
        let status = unsafe {
            (self.bs().load_image)(
                0,
                self.image_handle(),
                ptr::null_mut(),
                image.as_ptr() as *mut c_void,
                image.len(),
                &mut handle,
            )
        };
        if status == Status::EFI_SUCCESS {
            assert_ne!(handle, 0);
            Ok(handle)
        } else {
            Err(status)
        }
    }

    /// Installs a volume that exposes the files and directories in the cpio archive `archive`, and
    /// returns its handle
    pub fn install_cpio_volume(&self, archive: Vec<u8>) -> Handle {
        self.context()
            .install_cpio_volume(MemFile(archive), &new_guid())
            .unwrap()
    }
}

/// A copy of the memory map as returned by GetMemoryMap()
#[derive(Clone, Debug)]
pub struct MemoryMap {
    pub map_key: usize,
    pub descriptor_size: usize,
    pub descriptor_version: u32,
    pub descriptors: Vec<MemoryDescriptor>,
}

impl MemoryDescriptor {
    pub fn start(&self) -> u64 {
        self.physical_start
    }

    pub fn end(&self) -> u64 {
        self.physical_start + self.number_of_pages * PAGE
    }
}

impl MemoryMap {
    /// Returns the descriptors sorted by physical address
    pub fn sorted(&self) -> Vec<MemoryDescriptor> {
        let mut descriptors = self.descriptors.clone();
        descriptors.sort_by_key(|d| d.physical_start);
        descriptors
    }

    /// Returns the memory type of `range` if it is described in its entirety by descriptors of the
    /// same type, and `None` otherwise.
    pub fn type_of(&self, range: Range<u64>) -> Option<u32> {
        let mut covered = range.start;
        let mut memory_type = None;
        for d in self
            .sorted()
            .iter()
            .filter(|d| d.start() < range.end && range.start < d.end())
        {
            if d.start() > covered || *memory_type.get_or_insert(d.r#type) != d.r#type {
                return None;
            }
            covered = d.end();
        }
        memory_type.filter(|_| covered >= range.end)
    }

    /// Returns the address of a range of `pages` free pages, i.e., EfiConventionalMemory, that is
    /// preceded and followed by at least one other free page.
    pub fn find_free_pages(&self, pages: u64) -> Option<u64> {
        self.descriptors
            .iter()
            .find(|d| d.r#type == EFI_CONVENTIONAL_MEMORY && d.number_of_pages >= pages + 2)
            .map(|d| d.start() + PAGE)
    }
}

/// Returns a new GUID, which is guaranteed to be unique within the test binary
pub fn new_guid() -> Guid {
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    Guid {
        data1: COUNTER.fetch_add(1, Ordering::Relaxed),
        data2: 0xe71f,
        data3: 0x4c0d,
        data4: [0x9a, 0x7e, 0x57, 0xb0, 0x07, 0x5e, 0x12, 0x34],
    }
}

/// Returns a new and unique protocol interface pointer. The protocol handler services do not
/// dereference protocol interfaces they don't know about, but it points to valid memory anyway.
pub fn new_interface() -> *mut c_void {
    Box::into_raw(Box::new(0u64)).cast()
}

pub const HARDWARE_DEVICE_PATH: u8 = 0x01;
pub const HW_VENDOR_DP: u8 = 0x04;
pub const MEDIA_DEVICE_PATH: u8 = 0x04;
pub const MEDIA_VENDOR_DP: u8 = 0x03;
pub const MEDIA_FILEPATH_DP: u8 = 0x04;
pub const END_DEVICE_PATH_TYPE: u8 = 0x7f;
pub const END_ENTIRE_DEVICE_PATH_SUBTYPE: u8 = 0xff;

/// The node that terminates a device path
pub const END_NODE: [u8; 4] = [END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, 4, 0];

/// Returns a vendor-defined hardware device path node identified by `guid`
pub fn vendor_node(guid: &Guid) -> Vec<u8> {
    let mut node = vec![HARDWARE_DEVICE_PATH, HW_VENDOR_DP];
    node.extend_from_slice(&20u16.to_le_bytes());
    node.extend_from_slice(&guid.data1.to_le_bytes());
    node.extend_from_slice(&guid.data2.to_le_bytes());
    node.extend_from_slice(&guid.data3.to_le_bytes());
    node.extend_from_slice(&guid.data4);
    node
}

/// Returns a file path media device path node for the file at `path`
pub fn file_path_node(path: &str) -> Vec<u8> {
    let mut node = vec![MEDIA_DEVICE_PATH, MEDIA_FILEPATH_DP, 0, 0];
    for c in path.encode_utf16().chain([0]) {
        node.extend_from_slice(&c.to_le_bytes());
    }
    let len = node.len() as u16;
    node[2..4].copy_from_slice(&len.to_le_bytes());
    node
}

/// Returns a pointer to a new device path consisting of `nodes` followed by an end node. The device
/// path is leaked, so that it remains valid for as long as protocol database entries may refer to
/// it.
pub fn device_path(nodes: &[&[u8]]) -> *mut DevicePathProtocol {
    let mut path = nodes.concat();
    path.extend_from_slice(&END_NODE);
    Box::leak(path.into_boxed_slice()).as_mut_ptr().cast()
}

/// Returns the device path at `path` as a byte slice, including its end node.
///
/// # Safety
///
/// `path` must point to a device path that remains valid and unmodified for the lifetime `'a`.
pub unsafe fn device_path_bytes<'a>(path: *const DevicePathProtocol) -> &'a [u8] {
    let mut size = 0;
    loop {
        // SAFETY: The caller guarantees that `path` points to a device path, and `size` is the
        // offset of one of its nodes, given that the previous one was not an end node.
        let node = unsafe { ptr::read(path.cast::<u8>().add(size).cast::<DevicePathProtocol>()) };
        let len = u16::from_le_bytes(node.length) as usize;
        assert!(
            len >= size_of::<DevicePathProtocol>(),
            "malformed device path"
        );
        size += len;
        if node.r#type == END_DEVICE_PATH_TYPE && node.sub_type == END_ENTIRE_DEVICE_PATH_SUBTYPE {
            break;
        }
    }
    // SAFETY: The device path covers `size` bytes, and the caller guarantees that it remains valid
    // and unmodified for the lifetime `'a`.
    unsafe { slice::from_raw_parts(path.cast(), size) }
}

/// Reference implementation of the 32-bit CRC used by UEFI (as used by Ethernet, zlib, etc)
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// Returns whether the CRC32 field of the table header at `table` matches the contents of the
/// table, which consists of HeaderSize bytes.
///
/// # Safety
///
/// `table` must point to an EFI table that starts with an EFI_TABLE_HEADER.
pub unsafe fn table_crc_is_valid(table: *const TableHeader) -> bool {
    // SAFETY: The caller guarantees that `table` points to a table of HeaderSize bytes.
    let (hdr, mut bytes) = unsafe {
        let hdr = ptr::read(table);
        let bytes = slice::from_raw_parts(table.cast::<u8>(), hdr.header_size as usize).to_vec();
        (hdr, bytes)
    };
    // The CRC is computed with the CRC32 field set to 0
    bytes[16..20].fill(0);
    crc32(&bytes) == hdr.crc32
}

#[cfg(target_arch = "x86_64")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0x8664;
#[cfg(target_arch = "aarch64")]
pub const IMAGE_FILE_MACHINE_NATIVE: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x14c;

/// The file offset of the PE header in images created by [`pe_image`]
pub const PE_HEADER_OFFSET: usize = 0x40;
/// The RVA of the code section, and the entry point, of images created by [`pe_image`]
pub const TEXT_RVA: u32 = 0x1000;
/// The SizeOfImage of images created by [`pe_image`]
pub const SIZE_OF_IMAGE: u32 = 0x2000;
const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const TEXT_FILE_OFFSET: u32 = 0x200;
const TEXT_SIZE: u32 = 0x200;
const NUMBER_OF_RVA_AND_SIZES: u32 = 16;
/// The size of the PE32+ optional header, including the data directory
const SIZE_OF_OPTIONAL_HEADER: u16 = 112 + 8 * NUMBER_OF_RVA_AND_SIZES as u16;

/// Returns the code that the entry point of images created by [`pe_image`] consists of, which
/// branches to the absolute address `target`.
pub fn trampoline(target: EntryPoint) -> Vec<u8> {
    let target = target as usize as u64;
    let mut code = vec![];
    #[cfg(target_arch = "x86_64")]
    {
        code.extend_from_slice(&[0x48, 0xb8]); // movabs rax, target
        code.extend_from_slice(&target.to_le_bytes());
        code.extend_from_slice(&[0xff, 0xe0]); // jmp rax
    }
    #[cfg(target_arch = "aarch64")]
    {
        code.extend_from_slice(&0x5800_0050u32.to_le_bytes()); // ldr x16, 0f
        code.extend_from_slice(&0xd61f_0200u32.to_le_bytes()); // br x16
        code.extend_from_slice(&target.to_le_bytes()); // 0: .quad target
    }
    code
}

/// Returns a minimal PE32+ EFI application image for the native architecture, consisting of the
/// headers and a single code section, whose entry point branches to `entry`.
pub fn pe_image(entry: EntryPoint) -> Vec<u8> {
    pe_image_for_machine(entry, IMAGE_FILE_MACHINE_NATIVE)
}

/// Like [`pe_image`], but with `machine` as the machine type in the COFF file header
pub fn pe_image_for_machine(entry: EntryPoint, machine: u16) -> Vec<u8> {
    let mut image = vec![0u8; (TEXT_FILE_OFFSET + TEXT_SIZE) as usize];

    // MS-DOS header: the magic number, and the file offset of the PE header
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(PE_HEADER_OFFSET as u32).to_le_bytes());

    let mut hdr = vec![];
    hdr.extend_from_slice(b"PE\0\0");

    // COFF file header
    hdr.extend_from_slice(&machine.to_le_bytes());
    hdr.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    hdr.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    hdr.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
    hdr.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
    hdr.extend_from_slice(&SIZE_OF_OPTIONAL_HEADER.to_le_bytes());
    hdr.extend_from_slice(&0x22u16.to_le_bytes()); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // PE32+ optional header
    hdr.extend_from_slice(&0x20bu16.to_le_bytes()); // Magic
    hdr.extend_from_slice(&[0, 0]); // Major/MinorLinkerVersion
    hdr.extend_from_slice(&TEXT_SIZE.to_le_bytes()); // SizeOfCode
    hdr.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
    hdr.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    hdr.extend_from_slice(&TEXT_RVA.to_le_bytes()); // AddressOfEntryPoint
    hdr.extend_from_slice(&TEXT_RVA.to_le_bytes()); // BaseOfCode
    hdr.extend_from_slice(&0u64.to_le_bytes()); // ImageBase
    hdr.extend_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    hdr.extend_from_slice(&FILE_ALIGNMENT.to_le_bytes());
    hdr.extend_from_slice(&[0; 12]); // OS, image and subsystem versions
    hdr.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    hdr.extend_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
    hdr.extend_from_slice(&TEXT_FILE_OFFSET.to_le_bytes()); // SizeOfHeaders
    hdr.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    hdr.extend_from_slice(&10u16.to_le_bytes()); // Subsystem: EFI application
    hdr.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
    hdr.extend_from_slice(&[0; 32]); // SizeOfStack/HeapReserve/Commit
    hdr.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    hdr.extend_from_slice(&NUMBER_OF_RVA_AND_SIZES.to_le_bytes());
    hdr.extend_from_slice(&[0; 8 * NUMBER_OF_RVA_AND_SIZES as usize]); // no relocations etc

    // Section table
    hdr.extend_from_slice(b".text\0\0\0");
    hdr.extend_from_slice(&TEXT_SIZE.to_le_bytes()); // VirtualSize
    hdr.extend_from_slice(&TEXT_RVA.to_le_bytes()); // VirtualAddress
    hdr.extend_from_slice(&TEXT_SIZE.to_le_bytes()); // SizeOfRawData
    hdr.extend_from_slice(&TEXT_FILE_OFFSET.to_le_bytes()); // PointerToRawData
    hdr.extend_from_slice(&[0; 12]); // relocations and line numbers
    hdr.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // CNT_CODE | MEM_EXECUTE | MEM_READ

    image[PE_HEADER_OFFSET..PE_HEADER_OFFSET + hdr.len()].copy_from_slice(&hdr);

    let code = trampoline(entry);
    let text = TEXT_FILE_OFFSET as usize;
    image[text..text + code.len()].copy_from_slice(&code);
    image
}
