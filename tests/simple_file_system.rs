// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the read-only volumes that the EFI runtime provides via the simple file system
//! protocol and the file protocol described in sections 13.4 and 13.5 of the UEFI specification,
//! which expose the files and directories in a cpio archive.

mod common;
use common::*;

use core::ffi::c_void;
use core::mem;
use core::ptr;

/// A file or directory opened via the file protocol, which is closed when dropped
struct File(*mut FileProtocol);

impl Drop for File {
    fn drop(&mut self) {
        // SAFETY: The handle is open.
        assert_eq!(
            unsafe { (self.protocol().close)(self.0) },
            Status::EFI_SUCCESS
        );
    }
}

impl File {
    /// Opens the root directory of the volume with handle `volume` using OpenVolume()
    fn open_volume(efi: &Efi, volume: Handle) -> File {
        let sfs = efi
            .handle_protocol(volume, &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID)
            .unwrap()
            .cast::<SimpleFileSystemProtocol>();
        let mut root = ptr::null_mut();
        // SAFETY: `sfs` points to a simple file system protocol instance, and `root` is writable.
        let status = unsafe { ((*sfs).open_volume)(sfs, &mut root) };
        assert_eq!(status, Status::EFI_SUCCESS);
        File(root)
    }

    fn protocol(&self) -> FileProtocol {
        // SAFETY: The handle points to a file protocol instance.
        unsafe { ptr::read(self.0) }
    }

    /// Opens `path` relative to this file using Open() with mode `mode`
    fn open_mode(&self, path: &str, mode: u64) -> Result<File, Status> {
        let path = utf16z(path);
        let mut file = ptr::null_mut();
        // SAFETY: All pointers are valid, and `path` is NUL terminated.
        let status = unsafe { (self.protocol().open)(self.0, &mut file, path.as_ptr(), mode, 0) };
        if status == Status::EFI_SUCCESS {
            assert!(!file.is_null());
            Ok(File(file))
        } else {
            Err(status)
        }
    }

    /// Opens `path` relative to this file for reading
    fn open(&self, path: &str) -> Result<File, Status> {
        self.open_mode(path, EFI_FILE_MODE_READ)
    }

    /// Reads up to `size` bytes using Read()
    fn read(&self, size: usize) -> Result<Vec<u8>, Status> {
        let mut buf = vec![0xaa; size];
        let mut len = size;
        // SAFETY: `buf` is valid for writes of `len` bytes.
        let status = unsafe { (self.protocol().read)(self.0, &mut len, buf.as_mut_ptr().cast()) };
        if status != Status::EFI_SUCCESS {
            assert_eq!(len, size, "BufferSize modified on failure");
            return Err(status);
        }
        assert!(len <= size);
        buf.truncate(len);
        Ok(buf)
    }

    /// Reads the next directory entry using Read(), or returns None at the end of the directory
    fn read_entry(&self) -> Option<(FileInfo, String)> {
        // Query the size of the entry first, which must not advance the position
        let mut size = 0;
        // SAFETY: No buffer is passed, as its size is 0.
        let status = unsafe { (self.protocol().read)(self.0, &mut size, ptr::null_mut()) };
        if status == Status::EFI_SUCCESS {
            assert_eq!(size, 0);
            return None;
        }
        assert_eq!(status, Status::EFI_BUFFER_TOO_SMALL);
        let buf = self.read(size).unwrap();
        Some(parse_file_info(&buf))
    }

    /// Returns the information of type `info_type` using GetInfo()
    fn get_info(&self, info_type: &Guid) -> Result<Vec<u8>, Status> {
        let mut size = 0;
        // SAFETY: No buffer is passed, as its size is 0.
        let status =
            unsafe { (self.protocol().get_info)(self.0, info_type, &mut size, ptr::null_mut()) };
        if status != Status::EFI_BUFFER_TOO_SMALL {
            return Err(status);
        }
        let mut buf = vec![0xaa; size + 16];
        let mut len = buf.len();
        // SAFETY: `buf` is valid for writes of `len` bytes.
        let status = unsafe {
            (self.protocol().get_info)(self.0, info_type, &mut len, buf.as_mut_ptr().cast())
        };
        assert_eq!(status, Status::EFI_SUCCESS);
        assert_eq!(len, size);
        buf.truncate(len);
        Ok(buf)
    }

    /// Returns the EFI_FILE_INFO of the file
    fn info(&self) -> (FileInfo, String) {
        parse_file_info(&self.get_info(&EFI_FILE_INFO_ID).unwrap())
    }

    fn position(&self) -> Result<u64, Status> {
        let mut position = 0;
        // SAFETY: `position` is writable.
        let status = unsafe { (self.protocol().get_position)(self.0, &mut position) };
        if status == Status::EFI_SUCCESS {
            Ok(position)
        } else {
            Err(status)
        }
    }

    fn set_position(&self, position: u64) -> Status {
        // SAFETY: The handle is open.
        unsafe { (self.protocol().set_position)(self.0, position) }
    }
}

/// Returns the names of the entries of `dir`, and whether they are directories
fn list(dir: &File) -> Vec<(String, bool)> {
    let mut entries = Vec::new();
    while let Some((info, name)) = dir.read_entry() {
        entries.push((name, info.attribute & EFI_FILE_DIRECTORY != 0));
    }
    entries
}

fn is_dir(file: &File) -> bool {
    file.info().0.attribute & EFI_FILE_DIRECTORY != 0
}

/// An archive with a few files and directories, each with distinct contents
fn sample_archive() -> Vec<u8> {
    Cpio::default()
        .dir("loader")
        .dir("loader/addons")
        .file("loader/addons/a.addon.efi", b"first addon")
        .file("loader/addons/b.addon.efi", b"second addon")
        .dir("EFI")
        .dir("EFI/Linux")
        .file("EFI/Linux/linux.efi", b"0123456789abcdef")
        .finish()
}

/// OpenVolume(): "Opens the root directory on a volume."
#[test]
fn open_volume_opens_root_directory() {
    let efi = setup();
    let volume = efi.install_cpio_volume(sample_archive());

    let sfs = efi
        .handle_protocol(volume, &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID)
        .unwrap()
        .cast::<SimpleFileSystemProtocol>();
    // SAFETY: The interface is a simple file system protocol instance.
    assert_eq!(
        unsafe { (*sfs).revision },
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION
    );

    let root = File::open_volume(&efi, volume);
    assert_eq!(root.protocol().revision, EFI_FILE_PROTOCOL_REVISION);
    let (info, name) = root.info();
    assert_ne!(info.attribute & EFI_FILE_DIRECTORY, 0);
    assert_eq!(name, "");
    assert_eq!(list(&root), [("EFI".into(), true), ("loader".into(), true)]);

    // Each call opens a new handle
    let root2 = File::open_volume(&efi, volume);
    assert_ne!(root.0, root2.0);
}

/// Open(): "Opens a new file relative to the source file's location." "If the filename starts
/// with a '\' the relative location is the root directory that This resides on; otherwise '\'
/// separates name components. Each name component is opened in turn, and the handle to the last
/// file opened is returned."
#[test]
fn open_opens_files_relative_to_source_file() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));

    let file = root.open("\\EFI\\Linux\\linux.efi").unwrap();
    assert_eq!(file.read(64).unwrap(), b"0123456789abcdef");
    let file = root.open("EFI\\Linux\\linux.efi").unwrap();
    assert_eq!(file.read(64).unwrap(), b"0123456789abcdef");

    let linux = root.open("EFI\\Linux").unwrap();
    assert!(is_dir(&linux));
    let file = linux.open("linux.efi").unwrap();
    assert_eq!(file.read(64).unwrap(), b"0123456789abcdef");
    let addon = linux.open("\\loader\\addons\\a.addon.efi").unwrap();
    assert_eq!(addon.read(64).unwrap(), b"first addon");
}

/// Open(): "'.' Opens the current location. '..' Opens the parent directory for the current
/// location. If the location is the root directory the request will return an error, as there is
/// no parent directory for the root directory."
#[test]
fn open_handles_path_modifiers() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));

    let addons = root.open("loader\\.\\addons\\").unwrap();
    assert_eq!(
        list(&addons),
        [("a.addon.efi".into(), false), ("b.addon.efi".into(), false)]
    );
    let file = addons.open("..\\..\\EFI\\Linux\\linux.efi").unwrap();
    assert_eq!(file.read(4).unwrap(), b"0123");
    assert_eq!(addons.open(".").unwrap().info().1, "addons");
    assert_eq!(addons.open("..").unwrap().info().1, "loader");
    assert_eq!(addons.open("\\").unwrap().info().1, "");

    assert!(root.open("..").is_err());
    assert!(root.open("loader\\..\\..").is_err());
}

/// Open() returns "EFI_NOT_FOUND: The specified file could not be found on the device."
#[test]
fn open_returns_not_found_for_missing_files() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));

    for path in [
        "missing.efi",
        "\\loader\\missing",
        "loader\\addons\\c.addon.efi",
        "EFI\\Linux\\linux.efi\\x",
    ] {
        assert_eq!(root.open(path).err(), Some(Status::EFI_NOT_FOUND), "{path}");
    }
}

/// File names are case insensitive, as they are on the FAT file systems that the UEFI
/// specification mandates for system partitions.
#[test]
fn open_ignores_case() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));

    let file = root.open("\\efi\\LINUX\\Linux.EFI").unwrap();
    assert_eq!(file.read(64).unwrap(), b"0123456789abcdef");
    // The names are reported as they appear in the archive
    assert_eq!(file.info().1, "linux.efi");
}

/// Open(): "The only valid combinations that the file may be opened with are: Read, Read/Write,
/// or Create/Read/Write." "EFI_WRITE_PROTECTED: An attempt was made to create a file, or open a
/// file for write when the media is write-protected."
#[test]
fn open_refuses_write_access() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));

    for mode in [
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
    ] {
        for path in ["EFI\\Linux\\linux.efi", "EFI\\Linux\\new.efi"] {
            assert_eq!(
                root.open_mode(path, mode).err(),
                Some(Status::EFI_WRITE_PROTECTED)
            );
        }
    }
    for mode in [
        0,
        EFI_FILE_MODE_WRITE,
        EFI_FILE_MODE_CREATE,
        EFI_FILE_MODE_READ | EFI_FILE_MODE_CREATE,
    ] {
        assert_eq!(
            root.open_mode("EFI\\Linux\\linux.efi", mode).err(),
            Some(Status::EFI_INVALID_PARAMETER)
        );
    }
}

/// Read(): "If This is a file handle, the function reads the requested number of bytes from the
/// file at the file's current position and returns them in Buffer. If the read goes beyond the end
/// of the file, the read length is truncated to the end of the file. The file's current position
/// is increased by the number of bytes returned." It returns "EFI_DEVICE_ERROR: On entry, the
/// current file position is beyond the end of the file."
#[test]
fn read_reads_from_current_position() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));
    let file = root.open("EFI\\Linux\\linux.efi").unwrap();

    assert_eq!(file.read(4).unwrap(), b"0123");
    assert_eq!(file.position(), Ok(4));
    assert_eq!(file.read(0).unwrap(), b"");
    assert_eq!(file.read(10).unwrap(), b"456789abcd");
    assert_eq!(file.read(10).unwrap(), b"ef");
    assert_eq!(file.position(), Ok(16));
    assert_eq!(file.read(10).unwrap(), b"");

    assert_eq!(file.set_position(17), Status::EFI_SUCCESS);
    assert_eq!(file.read(10).err(), Some(Status::EFI_DEVICE_ERROR));
}

/// SetPosition(): "This function sets the current file position for the handle to the position
/// supplied. With the exception of seeking to position 0xFFFFFFFFFFFFFFFF, only absolute
/// positioning is supported, and seeking past the end of the file is allowed (a subsequent write
/// would grow the file). Seeking to position 0xFFFFFFFFFFFFFFFF causes the current position to be
/// set to the end of the file."
#[test]
fn set_position_moves_current_position() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));
    let file = root.open("EFI\\Linux\\linux.efi").unwrap();

    assert_eq!(file.set_position(10), Status::EFI_SUCCESS);
    assert_eq!(file.position(), Ok(10));
    assert_eq!(file.read(3).unwrap(), b"abc");
    assert_eq!(
        file.set_position(0xffff_ffff_ffff_ffff),
        Status::EFI_SUCCESS
    );
    assert_eq!(file.position(), Ok(16));
    assert_eq!(file.read(3).unwrap(), b"");
    assert_eq!(file.set_position(100), Status::EFI_SUCCESS);
    assert_eq!(file.position(), Ok(100));
}

/// Read(): "If This is a directory, the function reads the directory entry at the file's current
/// position and returns the entry in Buffer. If the Buffer is not large enough to hold the current
/// directory entry, then EFI_BUFFER_TOO_SMALL is returned and the current file position is not
/// updated. BufferSize is set to be the size of the buffer needed to read the entry. On success,
/// the current position is updated to the next directory entry. If there are no more directory
/// entries, the read returns a zero-length buffer. EFI_FILE_INFO is the structure returned as the
/// directory entry."
#[test]
fn read_returns_directory_entries() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));
    let addons = root.open("loader\\addons").unwrap();

    let (info, name) = addons.read_entry().unwrap();
    assert_eq!(name, "a.addon.efi");
    assert_eq!(info.file_size, b"first addon".len() as u64);
    assert_eq!(info.attribute & EFI_FILE_DIRECTORY, 0);

    // A buffer that is too small does not advance the position
    let size = SIZE_OF_EFI_FILE_INFO + 2 * utf16z("b.addon.efi").len();
    let mut buf = vec![0u8; size];
    let mut len = size - 1;
    // SAFETY: `buf` is valid for writes of `len` bytes.
    let status = unsafe { (addons.protocol().read)(addons.0, &mut len, buf.as_mut_ptr().cast()) };
    assert_eq!(status, Status::EFI_BUFFER_TOO_SMALL);
    assert_eq!(len, size);

    let (info, name) = addons.read_entry().unwrap();
    assert_eq!(name, "b.addon.efi");
    assert_eq!(info.file_size, b"second addon".len() as u64);
    assert!(addons.read_entry().is_none());
    assert!(addons.read_entry().is_none());

    // Setting the position to 0 restarts the enumeration
    assert_eq!(addons.set_position(0), Status::EFI_SUCCESS);
    assert_eq!(addons.read_entry().unwrap().1, "a.addon.efi");
}

/// GetPosition() returns "EFI_UNSUPPORTED: The request is not valid on open directories."
/// SetPosition() returns "EFI_UNSUPPORTED: The seek request for nonzero is not valid on open
/// directories."
#[test]
fn directory_positions_are_not_supported() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));

    assert_eq!(root.position(), Err(Status::EFI_UNSUPPORTED));
    assert_eq!(root.set_position(1), Status::EFI_UNSUPPORTED);
    assert_eq!(root.set_position(0), Status::EFI_SUCCESS);
}

/// GetInfo() returns an EFI_FILE_INFO structure for EFI_FILE_INFO_ID, which describes the file,
/// with "Size: Size of the EFI_FILE_INFO structure, including the Null-terminated FileName
/// string."
#[test]
fn get_info_describes_file() {
    let efi = setup();
    // 2023-11-14 22:13:20 UTC
    let archive = Cpio::default()
        .entry("dir/file.txt", S_IFREG | 0o444, 1_700_000_000, b"some text")
        .finish();
    let root = File::open_volume(&efi, efi.install_cpio_volume(archive));

    let (info, name) = root.open("dir\\file.txt").unwrap().info();
    assert_eq!(name, "file.txt");
    assert_eq!(info.size as usize, SIZE_OF_EFI_FILE_INFO + 2 * 9);
    assert_eq!(info.file_size, 9);
    assert!(info.physical_size >= 9);
    assert_eq!(info.attribute & EFI_FILE_DIRECTORY, 0);
    assert_ne!(info.attribute & EFI_FILE_READ_ONLY, 0);
    let time = EfiTime {
        year: 2023,
        month: 11,
        day: 14,
        hour: 22,
        minute: 13,
        second: 20,
        time_zone: EFI_UNSPECIFIED_TIMEZONE,
        ..Default::default()
    };
    assert_eq!(info.modification_time, time);

    let (info, name) = root.open("dir").unwrap().info();
    assert_eq!(name, "dir");
    assert_ne!(info.attribute & EFI_FILE_DIRECTORY, 0);
}

/// GetInfo() returns an EFI_FILE_SYSTEM_INFO structure for EFI_FILE_SYSTEM_INFO_ID, and an
/// EFI_FILE_SYSTEM_VOLUME_LABEL structure for EFI_FILE_SYSTEM_VOLUME_LABEL_ID. It returns
/// "EFI_UNSUPPORTED: The InformationType is not known."
#[test]
fn get_info_describes_volume() {
    let efi = setup();
    let archive = sample_archive();
    let size = archive.len() as u64;
    let root = File::open_volume(&efi, efi.install_cpio_volume(archive));
    let file = root.open("EFI\\Linux\\linux.efi").unwrap();

    let info = file.get_info(&EFI_FILE_SYSTEM_INFO_ID).unwrap();
    let u64_at = |offset: usize| u64::from_le_bytes(info[offset..offset + 8].try_into().unwrap());
    assert_eq!(info.len(), SIZE_OF_EFI_FILE_SYSTEM_INFO + 2);
    assert_eq!(u64_at(0), info.len() as u64);
    // ReadOnly
    assert_eq!(info[8], 1);
    // VolumeSize and FreeSpace
    assert_eq!(u64_at(16), size);
    assert_eq!(u64_at(24), 0);
    // VolumeLabel
    assert_eq!(utf16_to_string(&info[SIZE_OF_EFI_FILE_SYSTEM_INFO..]), "");

    let label = file.get_info(&EFI_FILE_SYSTEM_VOLUME_LABEL_ID).unwrap();
    assert_eq!(utf16_to_string(&label), "");

    assert_eq!(file.get_info(&new_guid()), Err(Status::EFI_UNSUPPORTED));
}

/// The volume is read-only: Write() returns "EFI_ACCESS_DENIED: The file was opened read only."
/// and "EFI_UNSUPPORTED: Writes to open directory files are not supported.", SetInfo() returns
/// "EFI_WRITE_PROTECTED: InformationType is EFI_FILE_INFO_ID and the media is read-only.", and
/// Delete() returns "EFI_WARN_DELETE_FAILURE: The handle was closed, but the file was not deleted."
#[test]
fn volume_is_read_only() {
    let efi = setup();
    let root = File::open_volume(&efi, efi.install_cpio_volume(sample_archive()));
    let file = root.open("EFI\\Linux\\linux.efi").unwrap();

    let mut data = *b"data";
    for (handle, status) in [
        (&file, Status::EFI_ACCESS_DENIED),
        (&root, Status::EFI_UNSUPPORTED),
    ] {
        let mut len = data.len();
        // SAFETY: `data` is valid for reads of `len` bytes.
        let ret =
            unsafe { (handle.protocol().write)(handle.0, &mut len, data.as_mut_ptr().cast()) };
        assert_eq!(ret, status);
    }

    let info = file.get_info(&EFI_FILE_INFO_ID).unwrap();
    // SAFETY: `info` is a valid EFI_FILE_INFO structure of `info.len()` bytes.
    let status = unsafe {
        (file.protocol().set_info)(
            file.0,
            &EFI_FILE_INFO_ID,
            info.len(),
            info.as_ptr() as *const c_void,
        )
    };
    assert_eq!(status, Status::EFI_WRITE_PROTECTED);

    // SAFETY: The handle is open.
    assert_eq!(
        unsafe { (file.protocol().flush)(file.0) },
        Status::EFI_ACCESS_DENIED
    );

    // Delete() closes the handle
    let handle = file.0;
    mem::forget(file);
    // SAFETY: `handle` is open, and is not used again.
    let status = unsafe { ((*handle).delete)(handle) };
    assert_eq!(status, Status::EFI_WARN_DELETE_FAILURE);
    assert_eq!(
        root.open("EFI\\Linux\\linux.efi").unwrap().read(4).unwrap(),
        b"0123"
    );
}

/// The volume carries a device path that consists of a vendor defined media device path node,
/// which identifies the volume by the GUID that was passed when it was installed.
#[test]
fn volume_has_vendor_media_device_path() {
    let efi = setup();
    let guid = new_guid();
    let volume = efi
        .context()
        .install_cpio_volume(MemFile(sample_archive()), &guid)
        .unwrap();

    let dp = efi
        .handle_protocol(volume, &EFI_DEVICE_PATH_PROTOCOL_GUID)
        .unwrap();
    // SAFETY: The interface is a device path.
    let bytes = unsafe { device_path_bytes(dp.cast()) };
    let mut expected = vec![MEDIA_DEVICE_PATH, MEDIA_VENDOR_DP, 20, 0];
    expected.extend_from_slice(&guid.data1.to_le_bytes());
    expected.extend_from_slice(&guid.data2.to_le_bytes());
    expected.extend_from_slice(&guid.data3.to_le_bytes());
    expected.extend_from_slice(&guid.data4);
    expected.extend_from_slice(&END_NODE);
    assert_eq!(bytes, expected);
}

/// Directories that are missing from the archive are created implicitly, and leading "/" and
/// "./" are ignored.
#[test]
fn archive_may_omit_directories() {
    let efi = setup();
    let archive = Cpio::default()
        .file("./a/b/c.txt", b"c")
        .file("/a/d.txt", b"d")
        .finish();
    let root = File::open_volume(&efi, efi.install_cpio_volume(archive));

    assert_eq!(list(&root), [("a".into(), true)]);
    let a = root.open("a").unwrap();
    assert_eq!(list(&a), [("b".into(), true), ("d.txt".into(), false)]);
    assert_eq!(a.open("b\\c.txt").unwrap().read(2).unwrap(), b"c");
}

/// The archive may consist of several concatenated archives, which may be separated by zero
/// padding, and entries replace earlier entries with the same path.
#[test]
fn archive_may_be_concatenated() {
    let efi = setup();
    let mut archive = Cpio::default()
        .file("a.txt", b"old a")
        .file("b.txt", b"b")
        .finish();
    archive.resize(archive.len() + 512, 0);
    archive.extend(Cpio::default().file("A.TXT", b"new a").finish());
    let root = File::open_volume(&efi, efi.install_cpio_volume(archive));

    assert_eq!(root.open("a.txt").unwrap().read(16).unwrap(), b"new a");
    assert_eq!(root.open("b.txt").unwrap().read(16).unwrap(), b"b");
}

/// Entries other than regular files and directories are ignored, as are entries that refer to a
/// parent directory.
#[test]
fn archive_entries_may_be_ignored() {
    let efi = setup();
    let archive = Cpio::default()
        .entry("link", S_IFLNK | 0o777, 0, b"a.txt")
        .file("../escape.txt", b"x")
        .file("a/../b.txt", b"x")
        .file("a.txt", b"a")
        .finish();
    let root = File::open_volume(&efi, efi.install_cpio_volume(archive));

    assert_eq!(list(&root), [("a.txt".into(), false)]);
}

/// Malformed archives are rejected.
#[test]
fn malformed_archives_are_rejected() {
    let efi = setup();

    let archive = Cpio::default().file("a.txt", b"some text").finish();
    let mut bad_magic = archive.clone();
    bad_magic[0] = b'1';
    let mut bad_digit = archive.clone();
    // The first digit of the file size
    bad_digit[54] = b'x';
    let truncated = archive[..archive.len() - 130].to_vec();
    for archive in [bad_magic, bad_digit, truncated] {
        assert!(
            efi.context()
                .install_cpio_volume(MemFile(archive), &new_guid())
                .is_err()
        );
    }
}
