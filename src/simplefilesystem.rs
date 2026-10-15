// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! The EFI simple file system and file protocols, along with an implementation of both that
//! exposes the files and directories in a cpio archive as a read-only volume.

use crate::cpio::{Index, NodeKind, ROOT};
use crate::{guid, status::*, Char16, EfiProtocol, FileLoader, Guid};

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomPinned;
use core::mem::size_of;
use core::ptr;

pub const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: Guid = guid!(
    0x964e5b22,
    0x6459,
    0x11d2,
    [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]
);

pub const EFI_FILE_INFO_ID: Guid = guid!(
    0x09576e92,
    0x6d3f,
    0x11d2,
    [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]
);

pub const EFI_FILE_SYSTEM_INFO_ID: Guid = guid!(
    0x09576e93,
    0x6d3f,
    0x11d2,
    [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]
);

pub const EFI_FILE_SYSTEM_VOLUME_LABEL_ID: Guid = guid!(
    0xdb47d7d3,
    0xfe81,
    0x11d3,
    [0x9a, 0x35, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d]
);

const EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION: u64 = 0x00010000;
const EFI_FILE_PROTOCOL_REVISION: u64 = 0x00010000;

pub(crate) const EFI_FILE_MODE_READ: u64 = 0x0000000000000001;
const EFI_FILE_MODE_WRITE: u64 = 0x0000000000000002;
const EFI_FILE_MODE_CREATE: u64 = 0x8000000000000000;

const EFI_FILE_READ_ONLY: u64 = 0x0000000000000001;
pub(crate) const EFI_FILE_DIRECTORY: u64 = 0x0000000000000010;

/// The size of EFI_FILE_INFO without the file name
pub(crate) const SIZE_OF_EFI_FILE_INFO: usize = 80;
/// The size of EFI_FILE_SYSTEM_INFO without the volume label
const SIZE_OF_EFI_FILE_SYSTEM_INFO: usize = 36;

const EFI_UNSPECIFIED_TIMEZONE: i16 = 0x07ff;

type FileOpen = unsafe extern "efiapi" fn(
    *mut EfiFileProtocol,
    *mut *mut EfiFileProtocol,
    *const Char16,
    u64,
    u64,
) -> Status;
type FileClose = unsafe extern "efiapi" fn(*mut EfiFileProtocol) -> Status;
type FileDelete = unsafe extern "efiapi" fn(*mut EfiFileProtocol) -> Status;
type FileRead = unsafe extern "efiapi" fn(*mut EfiFileProtocol, *mut usize, *mut ()) -> Status;
type FileWrite = unsafe extern "efiapi" fn(*mut EfiFileProtocol, *mut usize, *const ()) -> Status;
type FileGetPosition = unsafe extern "efiapi" fn(*mut EfiFileProtocol, *mut u64) -> Status;
type FileSetPosition = unsafe extern "efiapi" fn(*mut EfiFileProtocol, u64) -> Status;
type FileGetInfo =
    unsafe extern "efiapi" fn(*mut EfiFileProtocol, *const Guid, *mut usize, *mut ()) -> Status;
type FileSetInfo =
    unsafe extern "efiapi" fn(*mut EfiFileProtocol, *const Guid, usize, *const ()) -> Status;
type FileFlush = unsafe extern "efiapi" fn(*mut EfiFileProtocol) -> Status;

/// EFI_FILE_PROTOCOL, revision 1. The members are optional, as instances provided by EFI images
/// cannot be relied upon to populate all of them.
#[repr(C)]
pub(crate) struct EfiFileProtocol {
    pub(crate) revision: u64,
    pub(crate) open: Option<FileOpen>,
    pub(crate) close: Option<FileClose>,
    pub(crate) delete: Option<FileDelete>,
    pub(crate) read: Option<FileRead>,
    pub(crate) write: Option<FileWrite>,
    pub(crate) get_position: Option<FileGetPosition>,
    pub(crate) set_position: Option<FileSetPosition>,
    pub(crate) get_info: Option<FileGetInfo>,
    pub(crate) set_info: Option<FileSetInfo>,
    pub(crate) flush: Option<FileFlush>,
}

type OpenVolume = unsafe extern "efiapi" fn(
    *mut EfiSimpleFileSystemProtocol,
    *mut *mut EfiFileProtocol,
) -> Status;

/// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
#[repr(C)]
pub(crate) struct EfiSimpleFileSystemProtocol {
    pub(crate) revision: u64,
    pub(crate) open_volume: Option<OpenVolume>,
}

/// A read-only volume that exposes the files and directories in a cpio archive via the simple file
/// system protocol
#[repr(C)]
pub(crate) struct CpioVolume {
    /// The protocol interface, which must come first, given that OpenVolume() casts the pointer to
    /// it back to the CpioVolume that contains it
    protocol: EfiSimpleFileSystemProtocol,
    archive: Box<dyn FileLoader + Send>,
    index: Index,
    // The file handles that are opened on the volume refer to it, so it must not be moved
    pin: PhantomPinned,
}

impl EfiProtocol for CpioVolume {
    fn guid(&self) -> &'static Guid {
        &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID
    }
}

impl CpioVolume {
    /// Returns a volume that exposes the contents of the cpio archive provided by `archive`, or an
    /// error if the archive is malformed
    pub(crate) fn new(archive: impl FileLoader + Send + 'static) -> Result<Self, &'static str> {
        let index = Index::new(&archive)?;
        Ok(CpioVolume {
            protocol: EfiSimpleFileSystemProtocol {
                revision: EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION,
                open_volume: Some(open_volume),
            },
            archive: Box::new(archive),
            index,
            pin: PhantomPinned,
        })
    }

    /// Returns an EFI_FILE_INFO structure describing node `node`
    fn file_info(&self, node: usize) -> Vec<u8> {
        let node = &self.index.nodes[node];
        let (size, attribute) = match node.kind {
            NodeKind::File { size, .. } => (size as u64, EFI_FILE_READ_ONLY),
            NodeKind::Directory(_) => (0, EFI_FILE_READ_ONLY | EFI_FILE_DIRECTORY),
        };
        let info_size = SIZE_OF_EFI_FILE_INFO + (node.name.len() + 1) * size_of::<Char16>();
        let time = efi_time(node.mtime);

        let mut info = Vec::with_capacity(info_size);
        info.extend_from_slice(&(info_size as u64).to_le_bytes());
        // FileSize and PhysicalSize
        info.extend_from_slice(&size.to_le_bytes());
        info.extend_from_slice(&size.to_le_bytes());
        // CreateTime, LastAccessTime and ModificationTime
        for _ in 0..3 {
            info.extend_from_slice(&time);
        }
        info.extend_from_slice(&attribute.to_le_bytes());
        for c in node.name.iter().chain(&[0]) {
            info.extend_from_slice(&c.to_le_bytes());
        }
        info
    }

    /// Returns an EFI_FILE_SYSTEM_INFO structure describing the volume
    fn file_system_info(&self) -> Vec<u8> {
        // The volume has no label, and so it consists of only the terminating NUL character
        let info_size = SIZE_OF_EFI_FILE_SYSTEM_INFO + size_of::<Char16>();

        let mut info = Vec::with_capacity(info_size);
        info.extend_from_slice(&(info_size as u64).to_le_bytes());
        // ReadOnly, followed by padding
        info.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        // VolumeSize and FreeSpace
        info.extend_from_slice(&(self.archive.get_size() as u64).to_le_bytes());
        info.extend_from_slice(&0u64.to_le_bytes());
        // BlockSize
        info.extend_from_slice(&512u32.to_le_bytes());
        // VolumeLabel
        info.extend_from_slice(&[0, 0]);
        info
    }
}

/// Returns the EFI_TIME structure that represents `secs` seconds since the Unix epoch
fn efi_time(secs: u32) -> [u8; 16] {
    let (days, secs) = (secs / 86400, secs % 86400);

    // Convert the number of days since 1970-01-01 into a date in the Gregorian calendar, using the
    // algorithm described at https://howardhinnant.github.io/date_algorithms.html#civil_from_days,
    // simplified for dates that do not precede the epoch
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = era * 400 + yoe + (month <= 2) as u32;

    let mut time = [0; 16];
    time[0..2].copy_from_slice(&(year as u16).to_le_bytes());
    time[2] = month as u8;
    time[3] = day as u8;
    time[4] = (secs / 3600) as u8;
    time[5] = (secs / 60 % 60) as u8;
    time[6] = (secs % 60) as u8;
    // Pad1 and Nanosecond are 0, followed by TimeZone, and Daylight and Pad2, which are 0 too
    time[12..14].copy_from_slice(&EFI_UNSPECIFIED_TIMEZONE.to_le_bytes());
    time
}

/// An EFI_FILE_PROTOCOL instance that represents a file or directory on a CpioVolume
#[repr(C)]
struct FileHandle {
    /// The protocol interface, which must come first, given that the protocol functions cast the
    /// pointer to it back to the FileHandle that contains it
    protocol: EfiFileProtocol,
    volume: *const CpioVolume,
    node: usize,
    /// The current position in a file, or the index of the next entry to return of a directory
    position: u64,
}

const FILE_PROTOCOL: EfiFileProtocol = EfiFileProtocol {
    revision: EFI_FILE_PROTOCOL_REVISION,
    open: Some(open),
    close: Some(close),
    delete: Some(delete),
    read: Some(read),
    write: Some(write),
    get_position: Some(get_position),
    set_position: Some(set_position),
    get_info: Some(get_info),
    set_info: Some(set_info),
    flush: Some(flush),
};

impl FileHandle {
    /// Returns a new handle for node `node` of `volume`, which is freed again by Close()
    fn open(volume: &CpioVolume, node: usize) -> *mut EfiFileProtocol {
        let handle = Box::new(FileHandle {
            protocol: FILE_PROTOCOL,
            volume,
            node,
            position: 0,
        });
        Box::into_raw(handle) as *mut EfiFileProtocol
    }

    /// Returns the FileHandle that `this` points to, and the volume that it was opened on, or None
    /// if `this` is NULL
    ///
    /// # Safety
    ///
    /// `this` must be NULL or a pointer returned by [`FileHandle::open`] that has not been closed.
    unsafe fn from_ptr<'a>(this: *mut EfiFileProtocol) -> Option<(&'a mut Self, &'a CpioVolume)> {
        // SAFETY: The caller guarantees that `this` is NULL or points to a FileHandle, which holds a
        // pointer to the volume it was opened on. CpioVolume instances are owned by the EFI runtime
        // and never uninstalled, and so the volume remains valid indefinitely.
        unsafe {
            let handle = (this as *mut FileHandle).as_mut()?;
            let volume = &*handle.volume;
            Some((handle, volume))
        }
    }
}

// SAFETY for the functions below that call FileHandle::from_ptr(): the UEFI spec requires `this`
// to be the EFI_FILE_PROTOCOL instance that the function is called through, and these functions
// are only exposed via the FileHandle instances created by FileHandle::open().

extern "efiapi" fn open_volume(
    this: *mut EfiSimpleFileSystemProtocol,
    root: *mut *mut EfiFileProtocol,
) -> Status {
    if this.is_null() || root.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // SAFETY: The UEFI spec requires `this` to be the protocol instance that this function is
    // called through, and it is only exposed via CpioVolume instances. `root` is not NULL, and the
    // UEFI spec requires it to point to a writable location.
    unsafe {
        let volume = &*(this as *const CpioVolume);
        *root = FileHandle::open(volume, ROOT);
    }
    Status::EFI_SUCCESS
}

extern "efiapi" fn open(
    this: *mut EfiFileProtocol,
    new_handle: *mut *mut EfiFileProtocol,
    file_name: *const Char16,
    open_mode: u64,
    _attributes: u64,
) -> Status {
    // SAFETY: See above.
    let Some((handle, volume)) = (unsafe { FileHandle::from_ptr(this) }) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    if new_handle.is_null() || file_name.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // The volume is read-only
    match open_mode {
        EFI_FILE_MODE_READ => {}
        m if m == EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE
            || m == EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE =>
        {
            return Status::EFI_WRITE_PROTECTED;
        }
        _ => return Status::EFI_INVALID_PARAMETER,
    }

    let mut name = Vec::new();
    loop {
        // SAFETY: The UEFI spec requires `file_name` to point to a NUL terminated string, of which
        // all characters preceding the NUL character have been read already.
        let c = unsafe { ptr::read_unaligned(file_name.add(name.len())) };
        if c == 0 {
            break;
        }
        name.push(c);
    }
    let Some(node) = volume.index.lookup(handle.node, &name) else {
        return Status::EFI_NOT_FOUND;
    };
    // SAFETY: `new_handle` is not NULL, and the UEFI spec requires it to point to a writable
    // location.
    unsafe {
        *new_handle = FileHandle::open(volume, node);
    }
    Status::EFI_SUCCESS
}

extern "efiapi" fn close(this: *mut EfiFileProtocol) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // SAFETY: See above. The handle was allocated by FileHandle::open(), and is not used again.
    drop(unsafe { Box::from_raw(this as *mut FileHandle) });
    Status::EFI_SUCCESS
}

extern "efiapi" fn delete(this: *mut EfiFileProtocol) -> Status {
    // The volume is read-only, and so the handle is closed without deleting the file
    match close(this) {
        Status::EFI_SUCCESS => Status::EFI_WARN_DELETE_FAILURE,
        status => status,
    }
}

extern "efiapi" fn read(
    this: *mut EfiFileProtocol,
    buffer_size: *mut usize,
    buffer: *mut (),
) -> Status {
    // SAFETY: See above.
    let Some((handle, volume)) = (unsafe { FileHandle::from_ptr(this) }) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    // SAFETY: The UEFI spec requires `buffer_size` to be NULL or point to a valid UINTN.
    let Some(buffer_size) = (unsafe { buffer_size.as_mut() }) else {
        return Status::EFI_INVALID_PARAMETER;
    };

    match &volume.index.nodes[handle.node].kind {
        NodeKind::File { offset, size } => {
            // Reading at the end of the file returns no data, but reading beyond it is an error
            let Some(remaining) = (*size as u64).checked_sub(handle.position) else {
                return Status::EFI_DEVICE_ERROR;
            };
            let len = remaining.min(*buffer_size as u64) as usize;
            if len > 0 {
                if buffer.is_null() {
                    return Status::EFI_INVALID_PARAMETER;
                }
                // SAFETY: The UEFI spec requires `buffer` to be valid for writes of `*buffer_size`
                // bytes, which is at least `len`.
                let src = offset + handle.position as usize;
                if unsafe { volume.archive.load_range(buffer, src, len) }.is_err() {
                    return Status::EFI_DEVICE_ERROR;
                }
            }
            handle.position += len as u64;
            *buffer_size = len;
            Status::EFI_SUCCESS
        }
        NodeKind::Directory(entries) => {
            // Each read returns the EFI_FILE_INFO of the next directory entry, if any
            let Some(&entry) = entries.values().nth(handle.position as usize) else {
                *buffer_size = 0;
                return Status::EFI_SUCCESS;
            };
            let info = volume.file_info(entry);
            if *buffer_size < info.len() {
                *buffer_size = info.len();
                return Status::EFI_BUFFER_TOO_SMALL;
            }
            if buffer.is_null() {
                return Status::EFI_INVALID_PARAMETER;
            }
            // SAFETY: The UEFI spec requires `buffer` to be valid for writes of `*buffer_size`
            // bytes, which is at least `info.len()`.
            unsafe { ptr::copy_nonoverlapping(info.as_ptr(), buffer as *mut u8, info.len()) };
            handle.position += 1;
            *buffer_size = info.len();
            Status::EFI_SUCCESS
        }
    }
}

extern "efiapi" fn write(
    this: *mut EfiFileProtocol,
    buffer_size: *mut usize,
    _buffer: *const (),
) -> Status {
    // SAFETY: See above.
    let Some((handle, volume)) = (unsafe { FileHandle::from_ptr(this) }) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    if buffer_size.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // All files are opened read-only
    match volume.index.nodes[handle.node].kind {
        NodeKind::File { .. } => Status::EFI_ACCESS_DENIED,
        NodeKind::Directory(_) => Status::EFI_UNSUPPORTED,
    }
}

extern "efiapi" fn get_position(this: *mut EfiFileProtocol, position: *mut u64) -> Status {
    // SAFETY: See above.
    let Some((handle, volume)) = (unsafe { FileHandle::from_ptr(this) }) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    if position.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    match volume.index.nodes[handle.node].kind {
        NodeKind::File { .. } => {
            // SAFETY: `position` is not NULL, and the UEFI spec requires it to point to a writable
            // UINT64.
            unsafe { *position = handle.position };
            Status::EFI_SUCCESS
        }
        NodeKind::Directory(_) => Status::EFI_UNSUPPORTED,
    }
}

extern "efiapi" fn set_position(this: *mut EfiFileProtocol, position: u64) -> Status {
    // SAFETY: See above.
    let Some((handle, volume)) = (unsafe { FileHandle::from_ptr(this) }) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    match volume.index.nodes[handle.node].kind {
        // All ones moves the position to the end of the file
        NodeKind::File { size, .. } if position == u64::MAX => handle.position = size as u64,
        NodeKind::File { .. } => handle.position = position,
        // Directories can only be rewound
        NodeKind::Directory(_) if position == 0 => handle.position = 0,
        NodeKind::Directory(_) => return Status::EFI_UNSUPPORTED,
    }
    Status::EFI_SUCCESS
}

extern "efiapi" fn get_info(
    this: *mut EfiFileProtocol,
    information_type: *const Guid,
    buffer_size: *mut usize,
    buffer: *mut (),
) -> Status {
    // SAFETY: See above.
    let Some((handle, volume)) = (unsafe { FileHandle::from_ptr(this) }) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    // SAFETY: The UEFI spec requires `information_type` and `buffer_size` to be NULL or to point
    // to a valid EFI_GUID and a valid UINTN, respectively.
    let (Some(information_type), Some(buffer_size)) =
        (unsafe { (information_type.as_ref(), buffer_size.as_mut()) })
    else {
        return Status::EFI_INVALID_PARAMETER;
    };

    let info = if *information_type == EFI_FILE_INFO_ID {
        volume.file_info(handle.node)
    } else if *information_type == EFI_FILE_SYSTEM_INFO_ID {
        volume.file_system_info()
    } else if *information_type == EFI_FILE_SYSTEM_VOLUME_LABEL_ID {
        // The volume has no label
        vec![0, 0]
    } else {
        return Status::EFI_UNSUPPORTED;
    };
    if *buffer_size < info.len() {
        *buffer_size = info.len();
        return Status::EFI_BUFFER_TOO_SMALL;
    }
    if buffer.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // SAFETY: The UEFI spec requires `buffer` to be valid for writes of `*buffer_size` bytes, which
    // is at least `info.len()`.
    unsafe { ptr::copy_nonoverlapping(info.as_ptr(), buffer as *mut u8, info.len()) };
    *buffer_size = info.len();
    Status::EFI_SUCCESS
}

extern "efiapi" fn set_info(
    this: *mut EfiFileProtocol,
    information_type: *const Guid,
    _buffer_size: usize,
    buffer: *const (),
) -> Status {
    if this.is_null() || information_type.is_null() || buffer.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // The volume is read-only
    Status::EFI_WRITE_PROTECTED
}

extern "efiapi" fn flush(this: *mut EfiFileProtocol) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    // All files are opened read-only
    Status::EFI_ACCESS_DENIED
}
