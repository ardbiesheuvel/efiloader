// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the image services described in section 7.4 of the UEFI specification: LoadImage(),
//! StartImage(), Exit() and UnloadImage(). ExitBootServices() is covered by a separate test
//! binary.
//!
//! The images that are loaded by these tests consist of a trampoline that branches into a Rust
//! function in this file, which runs on the stack provided by StartImage(). These functions report
//! their observations via static variables, rather than by asserting anything themselves, given
//! that panics cannot unwind out of an EFI image entry point.

mod common;
use common::*;

use core::cell::{Cell, RefCell};
use core::ffi::c_void;
use core::mem::size_of_val;
use core::ptr;
use std::panic;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

/// A handle value that is never allocated by the firmware
const BOGUS_HANDLE: Handle = 0xdead_0000_beef;

static ENTRY_COUNT: AtomicUsize = AtomicUsize::new(0);
static ENTRY_IMAGE_HANDLE: AtomicUsize = AtomicUsize::new(0);
static ENTRY_SYSTEM_TABLE: AtomicUsize = AtomicUsize::new(0);
/// The status that images return or pass to Exit()
static IMAGE_STATUS: AtomicUsize = AtomicUsize::new(0);
/// The image handle that images pass to Exit()
static EXIT_IMAGE_HANDLE: AtomicUsize = AtomicUsize::new(0);
/// The status returned by Exit(), if it returns
static EXIT_RETURNED: AtomicUsize = AtomicUsize::new(0);
/// Set by images when they continue after calling Exit()
static RESUMED_AFTER_EXIT: AtomicBool = AtomicBool::new(false);

/// Resets the state shared with the images
fn reset() {
    for v in [
        &ENTRY_COUNT,
        &ENTRY_IMAGE_HANDLE,
        &ENTRY_SYSTEM_TABLE,
        &IMAGE_STATUS,
        &EXIT_IMAGE_HANDLE,
        &EXIT_RETURNED,
    ] {
        v.store(0, SeqCst);
    }
    RESUMED_AFTER_EXIT.store(false, SeqCst);
}

fn record_entry(image_handle: Handle, system_table: *mut SystemTable) {
    ENTRY_COUNT.fetch_add(1, SeqCst);
    ENTRY_IMAGE_HANDLE.store(image_handle, SeqCst);
    ENTRY_SYSTEM_TABLE.store(system_table as usize, SeqCst);
}

/// An image entry point that returns IMAGE_STATUS
extern "efiapi" fn returning_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    record_entry(image_handle, system_table);
    Status(IMAGE_STATUS.load(SeqCst))
}

/// An image entry point that calls Exit() for EXIT_IMAGE_HANDLE, or for its own image handle if it
/// is NULL, passing IMAGE_STATUS. If Exit() returns, the image returns EFI_SUCCESS.
extern "efiapi" fn exiting_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    record_entry(image_handle, system_table);
    let handle = match EXIT_IMAGE_HANDLE.load(SeqCst) {
        0 => image_handle,
        handle => handle,
    };
    // SAFETY: The system table pointer passed to the entry point is valid, and so is the boot
    // services table pointer it holds. Exit() ignores ExitData if ExitStatus is EFI_SUCCESS, and
    // otherwise, it is NULL.
    let status = unsafe {
        let exit = (*(*system_table).boot_services).exit;
        let exit_status = Status(IMAGE_STATUS.load(SeqCst));
        let exit_data = if exit_status == Status::EFI_SUCCESS {
            // Garbage, which must be ignored
            ptr::dangling_mut::<u16>()
        } else {
            ptr::null_mut()
        };
        exit(handle, exit_status, 0x1000, exit_data)
    };
    EXIT_RETURNED.store(status.0, SeqCst);
    RESUMED_AFTER_EXIT.store(true, SeqCst);
    Status::EFI_SUCCESS
}

/// The exit data passed to Exit() by exit_data_entry()
static EXIT_DATA: AtomicUsize = AtomicUsize::new(0);
const EXIT_DATA_MESSAGE: [Char16; 5] = [b'O' as u16, b'o' as u16, b'p' as u16, b's' as u16, 0];
const EXIT_DATA_SIZE: usize = size_of_val(&EXIT_DATA_MESSAGE) + 4;

/// An image entry point that calls Exit() with EFI_ABORTED and exit data, which consists of a
/// Null-terminated string followed by binary data.
extern "efiapi" fn exit_data_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    record_entry(image_handle, system_table);
    // SAFETY: The system table pointer passed to the entry point is valid, and so is the boot
    // services table pointer it holds. The buffer allocated by AllocatePool() is large enough to
    // hold the exit data.
    unsafe {
        let bs = ptr::read((*system_table).boot_services);
        let mut data: *mut c_void = ptr::null_mut();
        let status = (bs.allocate_pool)(EFI_BOOT_SERVICES_DATA, EXIT_DATA_SIZE, &mut data);
        if status != Status::EFI_SUCCESS {
            return status;
        }
        let message = EXIT_DATA_MESSAGE.as_ptr().cast::<u8>();
        let len = size_of_val(&EXIT_DATA_MESSAGE);
        ptr::copy_nonoverlapping(message, data.cast(), len);
        ptr::copy_nonoverlapping(
            [0xde, 0xad, 0xbe, 0xef].as_ptr(),
            data.cast::<u8>().add(len),
            4,
        );
        EXIT_DATA.store(data as usize, SeqCst);
        (bs.exit)(
            image_handle,
            Status::EFI_ABORTED,
            EXIT_DATA_SIZE,
            data.cast(),
        );
    }
    RESUMED_AFTER_EXIT.store(true, SeqCst);
    Status::EFI_SUCCESS
}

fn start_image(efi: &Efi, image_handle: Handle) -> Status {
    let mut exit_data_size = 0;
    let mut exit_data = ptr::null_mut();
    // SAFETY: All pointers are valid.
    unsafe { (efi.bs().start_image)(image_handle, &mut exit_data_size, &mut exit_data) }
}

fn loaded_image(efi: &Efi, image_handle: Handle) -> LoadedImageProtocol {
    let li = efi
        .handle_protocol(image_handle, &EFI_LOADED_IMAGE_PROTOCOL_GUID)
        .expect("image handle does not carry a loaded image protocol");
    // SAFETY: The interface is an EFI_LOADED_IMAGE_PROTOCOL instance.
    unsafe { ptr::read(li.cast()) }
}

/// LoadImage(): "If SourceBuffer is not NULL, the function is a memory-to-memory load in which
/// SourceBuffer points to the image to be loaded and SourceSize indicates the image's size in
/// bytes." "Once the image is loaded, firmware creates and returns an EFI_HANDLE that identifies
/// the image and supports EFI Loaded Image Protocol".
#[test]
fn load_image_from_memory() {
    let efi = setup();

    let image = pe_image(returning_entry);
    let handle = efi.load_image(&image).unwrap();
    let li = loaded_image(&efi, handle);
    assert_eq!(li.revision, EFI_LOADED_IMAGE_PROTOCOL_REVISION);
    assert_eq!(li.system_table, efi.system_table_ptr());
    assert!(li.image_size >= SIZE_OF_IMAGE as u64);
    // An EFI application's code and data are loaded as EfiLoaderCode and EfiLoaderData
    assert_eq!(li.image_code_type, EFI_LOADER_CODE);
    assert_eq!(li.image_data_type, EFI_LOADER_DATA);

    // The image was loaded at ImageBase, honouring its section alignment
    let base = li.image_base as u64;
    assert_ne!(base, 0);
    assert_eq!(base % PAGE, 0);
    assert_eq!(
        efi.memory_map().type_of(base..base + li.image_size),
        Some(EFI_LOADER_CODE)
    );
    let code = trampoline(returning_entry);
    // SAFETY: The code section of the image is mapped at ImageBase + TEXT_RVA.
    let loaded =
        unsafe { core::slice::from_raw_parts((base + TEXT_RVA as u64) as *const u8, code.len()) };
    assert_eq!(loaded, &code[..]);
}

/// Each image that is loaded gets its own image handle and copy of the image.
#[test]
fn load_image_creates_new_image_handle() {
    let efi = setup();

    let image = pe_image(returning_entry);
    let handle1 = efi.load_image(&image).unwrap();
    let handle2 = efi.load_image(&image).unwrap();
    assert_ne!(handle1, handle2);
    assert_ne!(
        loaded_image(&efi, handle1).image_base,
        loaded_image(&efi, handle2).image_base
    );
}

/// LoadImage(): "the caller has copied the image into SourceBuffer and can free the buffer once
/// loading is complete."
#[test]
fn load_image_does_not_retain_source_buffer() {
    let efi = setup();
    reset();

    let mut image = pe_image(returning_entry);
    let handle = efi.load_image(&image).unwrap();
    image.fill(0);
    drop(image);

    assert_eq!(start_image(&efi, handle), Status::EFI_SUCCESS);
    assert_eq!(ENTRY_COUNT.load(SeqCst), 1);
}

/// "The caller's image handle" is passed as ParentImageHandle, and the loaded image protocol
/// records it: "ParentHandle: Parent image's image handle."
#[test]
fn load_image_records_parent_image_handle() {
    let efi = setup();

    let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
    assert_eq!(loaded_image(&efi, handle).parent_handle, efi.image_handle());
}

/// Loads an image from memory using LoadImage(), passing a device path consisting of `nodes`, and
/// returns its loaded image protocol. The device path is clobbered before returning, given that the
/// caller of LoadImage() is free to reuse it at that point.
fn load_image_with_device_path(efi: &Efi, nodes: &[&[u8]]) -> LoadedImageProtocol {
    let image = pe_image(returning_entry);
    let path = device_path(nodes);
    let mut handle = 0;
    // SAFETY: All pointers are valid, and `image` is a buffer of `image.len()` bytes.
    let status = unsafe {
        (efi.bs().load_image)(
            0,
            efi.image_handle(),
            path,
            image.as_ptr() as *mut c_void,
            image.len(),
            &mut handle,
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    // SAFETY: `path` points to a device path that was leaked by device_path().
    unsafe { ptr::write_bytes(path.cast::<u8>(), 0, device_path_bytes(path).len()) };
    loaded_image(efi, handle)
}

/// Returns a copy of the file path recorded in the loaded image protocol `li`, if any
fn recorded_file_path(li: &LoadedImageProtocol) -> Option<Vec<u8>> {
    // SAFETY: FilePath is either NULL or points to a device path that remains valid for as long as
    // the image is loaded.
    (!li.file_path.is_null()).then(|| unsafe { device_path_bytes(li.file_path) }.to_vec())
}

/// LoadImage() records the device that the image was loaded from in the loaded image protocol,
/// along with the remaining part of DevicePath: "DeviceHandle: The device handle that the EFI Image
/// was loaded from." "FilePath: A pointer to the file path portion specific to DeviceHandle that
/// the EFI Image was loaded from." As with LocateDevicePath(), the device is the one whose device
/// path matches the most leading nodes of DevicePath.
#[test]
fn load_image_records_device_handle_and_file_path() {
    let efi = setup();

    // A device, and a child device of that device
    let (a, b) = (vendor_node(&new_guid()), vendor_node(&new_guid()));
    let device_a = efi
        .install_protocol(0, &EFI_DEVICE_PATH_PROTOCOL_GUID, device_path(&[&a]).cast())
        .unwrap();
    let device_ab = efi
        .install_protocol(
            0,
            &EFI_DEVICE_PATH_PROTOCOL_GUID,
            device_path(&[&a, &b]).cast(),
        )
        .unwrap();

    let file = file_path_node("\\EFI\\BOOT\\IMAGE.EFI");
    let file_path = Some([&file[..], &END_NODE].concat());

    let li = load_image_with_device_path(&efi, &[&a, &b, &file]);
    assert_eq!(li.device_handle, device_ab);
    assert_eq!(recorded_file_path(&li), file_path);

    let li = load_image_with_device_path(&efi, &[&a, &file]);
    assert_eq!(li.device_handle, device_a);
    assert_eq!(recorded_file_path(&li), file_path);

    // If DevicePath is the device path of the device itself, only the end node remains
    let li = load_image_with_device_path(&efi, &[&a, &b]);
    assert_eq!(li.device_handle, device_ab);
    assert_eq!(recorded_file_path(&li), Some(END_NODE.to_vec()));
}

/// If no device matches DevicePath, LoadImage() records no device handle, and all of DevicePath as
/// the file path.
#[test]
fn load_image_records_entire_device_path_if_no_device_matches() {
    let efi = setup();

    let nodes = [vendor_node(&new_guid()), file_path_node("\\IMAGE.EFI")];
    let li = load_image_with_device_path(&efi, &[&nodes[0], &nodes[1]]);
    assert_eq!(li.device_handle, 0);
    assert_eq!(
        recorded_file_path(&li),
        Some([&nodes[0][..], &nodes[1], &END_NODE].concat())
    );
}

/// If no DevicePath is passed to LoadImage(), it records neither a device handle nor a file path.
#[test]
fn load_image_without_device_path_records_no_device_handle_or_file_path() {
    let efi = setup();

    let li = loaded_image(&efi, efi.load_image(&pe_image(returning_entry)).unwrap());
    assert_eq!(li.device_handle, 0);
    assert!(li.file_path.is_null());
}

/// LoadImage() installs the EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL onto the image handle, alongside
/// the loaded image protocol. If no device path was passed to LoadImage(), its interface is NULL.
#[test]
fn load_image_installs_loaded_image_device_path_protocol() {
    let efi = setup();

    let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
    assert_eq!(
        efi.handle_protocol(handle, &EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID),
        Ok(ptr::null_mut())
    );
}

/// LoadImage() initializes the EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL with a copy of the DevicePath
/// that was passed to it.
#[test]
fn load_image_installs_copy_of_device_path() {
    let efi = setup();
    let bs = efi.bs();

    let image = pe_image(returning_entry);
    let nodes = [vendor_node(&new_guid()), vendor_node(&new_guid())];
    let path = device_path(&[&nodes[0], &nodes[1]]);
    let mut handle = 0;
    // SAFETY: All pointers are valid, and `image` is a buffer of `image.len()` bytes.
    let status = unsafe {
        (bs.load_image)(
            0,
            efi.image_handle(),
            path,
            image.as_ptr() as *mut c_void,
            image.len(),
            &mut handle,
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);

    let copy = efi
        .handle_protocol(handle, &EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID)
        .unwrap();
    assert!(!copy.is_null());
    assert_ne!(copy, path.cast());
    // Two vendor-defined device path nodes of 20 bytes each, followed by the end node
    let size = 2 * 20 + 4;
    // SAFETY: Both device paths consist of `size` bytes.
    unsafe {
        assert_eq!(
            core::slice::from_raw_parts(copy.cast::<u8>(), size),
            core::slice::from_raw_parts(path.cast::<u8>(), size)
        );
    }
}

/// LoadImage() returns EFI_INVALID_PARAMETER if "One or more parametes are invalid", e.g., if
/// DevicePath contains a node whose length does not even cover its header.
#[test]
fn load_image_rejects_malformed_device_path() {
    let efi = setup();
    let bs = efi.bs();

    let image = pe_image(returning_entry);
    let malformed: &mut [u8] = Box::leak(Box::new([
        HARDWARE_DEVICE_PATH,
        HW_VENDOR_DP,
        0,
        0,
        END_DEVICE_PATH_TYPE,
        END_ENTIRE_DEVICE_PATH_SUBTYPE,
        4,
        0,
    ]));
    let mut handle = 0;
    // SAFETY: All pointers are valid, and `image` is a buffer of `image.len()` bytes.
    let status = unsafe {
        (bs.load_image)(
            0,
            efi.image_handle(),
            malformed.as_mut_ptr().cast(),
            image.as_ptr() as *mut c_void,
            image.len(),
            &mut handle,
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
}

/// LoadImage() returns EFI_INVALID_PARAMETER if "ImageHandle is NULL".
#[test]
fn load_image_rejects_null_image_handle() {
    let efi = setup();
    let bs = efi.bs();

    let image = pe_image(returning_entry);
    // SAFETY: All pointers except ImageHandle are valid, and `image` is a buffer of `image.len()`
    // bytes.
    let status = unsafe {
        (bs.load_image)(
            0,
            efi.image_handle(),
            ptr::null_mut(),
            image.as_ptr() as *mut c_void,
            image.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
}

/// LoadImage() returns EFI_INVALID_PARAMETER if "ParentImageHandle is NULL" or
/// "ParentImageHandle is not a valid EFI_HANDLE".
#[test]
fn load_image_rejects_invalid_parent_image_handle() {
    let efi = setup();
    let bs = efi.bs();

    let image = pe_image(returning_entry);
    for parent in [0, BOGUS_HANDLE] {
        let mut handle = 0;
        // SAFETY: All pointers are valid, and `image` is a buffer of `image.len()` bytes.
        let status = unsafe {
            (bs.load_image)(
                0,
                parent,
                ptr::null_mut(),
                image.as_ptr() as *mut c_void,
                image.len(),
                &mut handle,
            )
        };
        assert_eq!(status, Status::EFI_INVALID_PARAMETER, "{parent:#x}");
    }
}

/// LoadImage() returns EFI_NOT_FOUND if "Both SourceBuffer and DevicePath are NULL".
#[test]
fn load_image_rejects_null_source_buffer_and_device_path() {
    let efi = setup();
    let bs = efi.bs();

    let mut handle = 0;
    // SAFETY: All pointers are valid or NULL.
    let status = unsafe {
        (bs.load_image)(
            0,
            efi.image_handle(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &mut handle,
        )
    };
    assert_eq!(status, Status::EFI_NOT_FOUND);
}

/// The arguments that LoadFile() of a FileServer was called with
#[derive(Clone, Debug)]
struct LoadFileCall {
    /// The FilePath argument, or None if it was NULL or malformed
    file_path: Option<Vec<u8>>,
    boot_policy: Boolean,
    /// The value that the BufferSize argument pointed to
    buffer_size: usize,
    buffer: usize,
}

/// An EFI_LOAD_FILE2_PROTOCOL implementation that serves a single file from memory, and records
/// the calls that are made to it
#[repr(C)]
struct FileServer {
    protocol: LoadFile2Protocol,
    /// The device path of the file relative to the device, including the end node
    file_path: Vec<u8>,
    /// The contents of the file
    file: Vec<u8>,
    /// If not EFI_SUCCESS, the status that is returned instead of loading the file into a buffer
    /// that is large enough to hold it
    read_status: Cell<Status>,
    calls: RefCell<Vec<LoadFileCall>>,
}

/// The LoadFile() function of FileServer, which behaves as the UEFI specification describes. It
/// must not panic, given that panics cannot unwind out of it.
unsafe extern "efiapi" fn serve_file(
    this: *mut LoadFile2Protocol,
    file_path: *mut DevicePathProtocol,
    boot_policy: Boolean,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    // SAFETY: `this` points to the `protocol` field of a FileServer, which is its first field.
    let server = unsafe { &*this.cast::<FileServer>() };
    // Catch the panic that device_path_bytes() raises if the file path is malformed
    // SAFETY: `file_path` is not NULL, and points to a device path, malformed or not.
    let path = (!file_path.is_null())
        .then(|| panic::catch_unwind(|| unsafe { device_path_bytes(file_path) }.to_vec()).ok())
        .flatten();
    // SAFETY: `buffer_size` is either NULL or points to a valid UINTN.
    let Some(size) = (unsafe { buffer_size.as_mut() }) else {
        return Status::EFI_INVALID_PARAMETER;
    };
    server.calls.borrow_mut().push(LoadFileCall {
        file_path: path.clone(),
        boot_policy,
        buffer_size: *size,
        buffer: buffer as usize,
    });

    if boot_policy != 0 {
        return Status::EFI_UNSUPPORTED;
    }
    if path.as_ref() != Some(&server.file_path) {
        return Status::EFI_NOT_FOUND;
    }
    if buffer.is_null() || *size < server.file.len() {
        *size = server.file.len();
        return Status::EFI_BUFFER_TOO_SMALL;
    }
    if server.read_status.get() != Status::EFI_SUCCESS {
        return server.read_status.get();
    }
    // SAFETY: `buffer` is valid for writes of `*size` bytes, which is sufficient to hold the file.
    unsafe { ptr::copy_nonoverlapping(server.file.as_ptr(), buffer.cast(), server.file.len()) };
    *size = server.file.len();
    Status::EFI_SUCCESS
}

/// Installs a device path that consists of `device` onto a new handle, along with a FileServer that
/// serves `file` at the file path that consists of `file_path`. Returns the handle and the server.
fn install_file_server(
    efi: &Efi,
    device: &[&[u8]],
    file_path: &[&[u8]],
    file: Vec<u8>,
) -> (Handle, &'static FileServer) {
    let handle = efi
        .install_protocol(
            0,
            &EFI_DEVICE_PATH_PROTOCOL_GUID,
            device_path(device).cast(),
        )
        .unwrap();
    (handle, install_file_server_on(efi, handle, file_path, file))
}

/// Installs a FileServer that serves `file` at the file path that consists of `file_path` onto
/// `handle`, and returns it.
fn install_file_server_on(
    efi: &Efi,
    handle: Handle,
    file_path: &[&[u8]],
    file: Vec<u8>,
) -> &'static FileServer {
    let server: &'static FileServer = Box::leak(Box::new(FileServer {
        protocol: LoadFile2Protocol {
            load_file: serve_file,
        },
        file_path: [&file_path.concat()[..], &END_NODE].concat(),
        file,
        read_status: Cell::new(Status::EFI_SUCCESS),
        calls: RefCell::new(Vec::new()),
    }));
    let interface = server as *const FileServer as *mut c_void;
    efi.install_protocol(handle, &EFI_LOAD_FILE2_PROTOCOL_GUID, interface)
        .unwrap();
    server
}

/// Loads an image using LoadImage() without a source buffer, passing `boot_policy` as BootPolicy,
/// and a device path that consists of `nodes`. Returns the handle of the image on success.
fn load_image_from_device_path(
    efi: &Efi,
    boot_policy: Boolean,
    nodes: &[&[u8]],
) -> Result<Handle, Status> {
    let mut handle = 0;
    // SAFETY: All pointers are valid or NULL. SourceSize is ignored if SourceBuffer is NULL.
    let status = unsafe {
        (efi.bs().load_image)(
            boot_policy,
            efi.image_handle(),
            device_path(nodes),
            ptr::null_mut(),
            0,
            &mut handle,
        )
    };
    if status == Status::EFI_SUCCESS {
        Ok(handle)
    } else {
        Err(status)
    }
}

/// LoadImage(): "If SourceBuffer is NULL, the function is a file copy operation that uses the
/// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL. If there is no instance of EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
/// associated with file path, then this function will attempt to use EFI_LOAD_FILE_PROTOCOL
/// (BootPolicy is TRUE) or EFI_LOAD_FILE2_PROTOCOL, and then EFI_LOAD_FILE_PROTOCOL (BootPolicy is
/// FALSE)." "In the case of EFI_LOAD_FILE_PROTOCOL, the remaining device path nodes of DevicePath
/// and the BootPolicy flag are passed to the EFI_LOAD_FILE_PROTOCOL.LoadFile() function." "In the
/// case of EFI_LOAD_FILE2_PROTOCOL, the behavior is the same as above, except that it is only used
/// if BootPolicy is FALSE."
#[test]
fn load_image_from_load_file2() {
    let efi = setup();
    reset();

    let (device, file) = (vendor_node(&new_guid()), file_path_node("\\IMAGE.EFI"));
    let (handle, server) =
        install_file_server(&efi, &[&device], &[&file], pe_image(returning_entry));
    let image = load_image_from_device_path(&efi, 0, &[&device, &file]).unwrap();

    // LoadFile() was passed the file path relative to the device, and FALSE as BootPolicy
    let calls = server.calls.borrow().clone();
    assert!(!calls.is_empty());
    for call in calls {
        assert_eq!(call.file_path.as_ref(), Some(&server.file_path));
        assert_eq!(call.boot_policy, 0);
    }

    // The image handle carries the loaded image protocol, which records that the image was loaded
    // from the device, and the loaded image device path protocol
    let li = loaded_image(&efi, image);
    assert_eq!(li.device_handle, handle);
    assert_eq!(recorded_file_path(&li), Some(server.file_path.clone()));
    let path = efi
        .handle_protocol(image, &EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID)
        .unwrap();
    // SAFETY: The interface of the loaded image device path protocol is a device path.
    assert_eq!(
        unsafe { device_path_bytes(path.cast()) },
        [&device[..], &file, &END_NODE].concat()
    );

    assert_eq!(start_image(&efi, image), Status::EFI_SUCCESS);
    assert_eq!(ENTRY_COUNT.load(SeqCst), 1);
}

/// LoadImage(): "In all cases, this function will use the instance of these protocols associated
/// with the handle that most closely matches DevicePath will be used." Devices that do not
/// implement the LoadFile2 protocol do not qualify.
#[test]
fn load_image_uses_load_file2_of_closest_device() {
    let efi = setup();

    let [a, b, c] = [(); 3].map(|_| vendor_node(&new_guid()));
    let file = file_path_node("\\IMAGE.EFI");
    let image = pe_image(returning_entry);
    let (handle_a, server_a) = install_file_server(&efi, &[&a], &[&file], image.clone());
    let (handle_ab, server_ab) = install_file_server(&efi, &[&a, &b], &[&c, &file], image);
    // A child device of the latter that does not implement LoadFile2
    efi.install_protocol(
        0,
        &EFI_DEVICE_PATH_PROTOCOL_GUID,
        device_path(&[&a, &b, &c]).cast(),
    )
    .unwrap();

    let image = load_image_from_device_path(&efi, 0, &[&a, &b, &c, &file]).unwrap();
    assert!(server_a.calls.borrow().is_empty());
    let li = loaded_image(&efi, image);
    assert_eq!(li.device_handle, handle_ab);
    assert_eq!(recorded_file_path(&li), Some(server_ab.file_path.clone()));

    let image = load_image_from_device_path(&efi, 0, &[&a, &file]).unwrap();
    let li = loaded_image(&efi, image);
    assert_eq!(li.device_handle, handle_a);
    assert_eq!(recorded_file_path(&li), Some(server_a.file_path.clone()));
}

/// LoadImage(): EFI_LOAD_FILE2_PROTOCOL "is only used if BootPolicy is FALSE". As efiloader does
/// not support loading images via EFI_SIMPLE_FILE_SYSTEM_PROTOCOL or EFI_LOAD_FILE_PROTOCOL, it
/// returns EFI_NOT_FOUND instead, as EDK2 does if it finds neither.
#[test]
fn load_image_does_not_use_load_file2_if_boot_policy_is_true() {
    let efi = setup();

    let (device, file) = (vendor_node(&new_guid()), file_path_node("\\IMAGE.EFI"));
    let (_, server) = install_file_server(&efi, &[&device], &[&file], pe_image(returning_entry));
    assert_eq!(
        load_image_from_device_path(&efi, 1, &[&device, &file]),
        Err(Status::EFI_NOT_FOUND)
    );
    assert!(server.calls.borrow().is_empty());
}

/// If none of the devices that DevicePath refers to implements the LoadFile2 protocol, LoadImage()
/// returns EFI_NOT_FOUND, as EDK2 does.
#[test]
fn load_image_without_load_file2_returns_not_found() {
    let efi = setup();

    let (device, file) = (vendor_node(&new_guid()), file_path_node("\\IMAGE.EFI"));
    efi.install_protocol(
        0,
        &EFI_DEVICE_PATH_PROTOCOL_GUID,
        device_path(&[&device]).cast(),
    )
    .unwrap();
    assert_eq!(
        load_image_from_device_path(&efi, 0, &[&device, &file]),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// LoadImage() passes on the errors returned by LoadFile(), e.g., "EFI_NOT_FOUND: The file was not
/// found." and "EFI_DEVICE_ERROR: Image was not loaded because the device returned a read error."
#[test]
fn load_image_passes_on_load_file2_errors() {
    let efi = setup();

    let (device, file) = (vendor_node(&new_guid()), file_path_node("\\IMAGE.EFI"));
    let (_, server) = install_file_server(&efi, &[&device], &[&file], pe_image(returning_entry));
    let other_file = file_path_node("\\OTHER.EFI");
    assert_eq!(
        load_image_from_device_path(&efi, 0, &[&device, &other_file]),
        Err(Status::EFI_NOT_FOUND)
    );

    server.read_status.set(Status::EFI_DEVICE_ERROR);
    assert_eq!(
        load_image_from_device_path(&efi, 0, &[&device, &file]),
        Err(Status::EFI_DEVICE_ERROR)
    );
}

/// LoadImage() frees the buffer that it loads the file into via LoadFile2, regardless of whether
/// it manages to load the image from it.
#[test]
fn load_image_frees_file_loaded_via_load_file2() {
    let efi = setup();

    for (contents, read_status, result) in [
        (pe_image(returning_entry), Status::EFI_SUCCESS, None),
        // "EFI_LOAD_ERROR: Image was not loaded because the image format was corrupt or not
        // understood."
        (
            vec![0; SIZE_OF_IMAGE as usize],
            Status::EFI_SUCCESS,
            Some(Status::EFI_LOAD_ERROR),
        ),
        (
            pe_image(returning_entry),
            Status::EFI_DEVICE_ERROR,
            Some(Status::EFI_DEVICE_ERROR),
        ),
    ] {
        let (device, file) = (vendor_node(&new_guid()), file_path_node("\\IMAGE.EFI"));
        let (_, server) = install_file_server(&efi, &[&device], &[&file], contents);
        server.read_status.set(read_status);
        assert_eq!(
            load_image_from_device_path(&efi, 0, &[&device, &file]).err(),
            result
        );

        let calls = server.calls.borrow();
        let read = calls
            .iter()
            .find(|call| call.buffer != 0)
            .expect("LoadFile() was not passed a buffer");
        let buffer = read.buffer as u64..(read.buffer + read.buffer_size) as u64;
        assert_eq!(
            efi.memory_map().type_of(buffer),
            Some(EFI_CONVENTIONAL_MEMORY)
        );
    }
}

/// LoadImage(): "If SourceBuffer is NULL, the function is a file copy operation that uses the
/// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL." "In the case of EFI_SIMPLE_FILE_SYSTEM_PROTOCOL, the path name
/// from the File Path Media Device Path node(s) of DevicePath is used." Unlike the LoadFile2
/// protocol, it is used regardless of BootPolicy.
#[test]
fn load_image_from_simple_file_system() {
    let efi = setup();
    reset();

    let archive = Cpio::default()
        .file("EFI/BOOT/IMAGE.EFI", &pe_image(returning_entry))
        .finish();
    let volume = efi.install_cpio_volume(archive);
    let device = efi.device_nodes(volume);
    let file = file_path_node("\\EFI\\BOOT\\IMAGE.EFI");
    for boot_policy in [0, 1] {
        // The buffer that the file is loaded into is freed again
        let pages = efi.memory_map().pages_of_type(EFI_BOOT_SERVICES_DATA);
        let image = load_image_from_device_path(&efi, boot_policy, &[&device, &file]).unwrap();
        assert_eq!(
            efi.memory_map().pages_of_type(EFI_BOOT_SERVICES_DATA),
            pages
        );

        let li = loaded_image(&efi, image);
        assert_eq!(li.device_handle, volume);
        assert_eq!(
            recorded_file_path(&li),
            Some([&file[..], &END_NODE].concat())
        );
        assert_eq!(start_image(&efi, image), Status::EFI_SUCCESS);
    }
    assert_eq!(ENTRY_COUNT.load(SeqCst), 2);

    // The path name may be split over several file path nodes, which are opened in turn
    let dir = file_path_node("\\EFI\\BOOT");
    let name = file_path_node("IMAGE.EFI");
    let image = load_image_from_device_path(&efi, 0, &[&device, &dir, &name]).unwrap();
    assert_eq!(loaded_image(&efi, image).device_handle, volume);
}

/// LoadImage() only uses the LoadFile2 protocol "If there is no instance of
/// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL associated with file path".
#[test]
fn load_image_prefers_simple_file_system_to_load_file2() {
    let efi = setup();

    let archive = Cpio::default()
        .file("IMAGE.EFI", &pe_image(returning_entry))
        .finish();
    let volume = efi.install_cpio_volume(archive);
    let file = file_path_node("\\IMAGE.EFI");
    let server = install_file_server_on(&efi, volume, &[&file], pe_image(returning_entry));

    load_image_from_device_path(&efi, 0, &[&efi.device_nodes(volume), &file]).unwrap();
    assert!(server.calls.borrow().is_empty());
}

/// LoadImage() passes on the errors returned by the file protocol, e.g., "EFI_NOT_FOUND: The
/// specified file could not be found on the device." It also returns EFI_NOT_FOUND if DevicePath
/// refers to a directory, or if nodes other than file path nodes follow the device path of the
/// volume, as EDK2 does, and EFI_LOAD_ERROR if the file is not an image. The memory that the file
/// is loaded into is freed in all cases.
#[test]
fn load_image_from_simple_file_system_fails_gracefully() {
    let efi = setup();

    let archive = Cpio::default()
        .file("EFI/BOOT/IMAGE.EFI", &pe_image(returning_entry))
        .file("EFI/BOOT/TEXT.TXT", b"not an image")
        .finish();
    let volume = efi.install_cpio_volume(archive);
    let device = efi.device_nodes(volume);
    let pages = efi.memory_map().pages_of_type(EFI_BOOT_SERVICES_DATA);
    for (nodes, status) in [
        (
            vec![file_path_node("\\EFI\\BOOT\\MISSING.EFI")],
            Status::EFI_NOT_FOUND,
        ),
        (vec![file_path_node("\\EFI\\BOOT")], Status::EFI_NOT_FOUND),
        (
            vec![
                vendor_node(&new_guid()),
                file_path_node("\\EFI\\BOOT\\IMAGE.EFI"),
            ],
            Status::EFI_NOT_FOUND,
        ),
        (
            vec![file_path_node("\\EFI\\BOOT\\TEXT.TXT")],
            Status::EFI_LOAD_ERROR,
        ),
    ] {
        let mut path: Vec<&[u8]> = vec![&device];
        path.extend(nodes.iter().map(Vec::as_slice));
        assert_eq!(load_image_from_device_path(&efi, 0, &path), Err(status));
        assert_eq!(
            efi.memory_map().pages_of_type(EFI_BOOT_SERVICES_DATA),
            pages
        );
    }
}

/// The names of the addons that sidecar_entry() found, along with the status that LoadImage()
/// returned for each of them
static SIDECARS: Mutex<Vec<(String, Status)>> = Mutex::new(Vec::new());

/// An image entry point that loads the addons in the "<FilePath>.extra.d" directory on the device
/// that its loaded image protocol identifies, the way systemd-stub does: it opens the directory
/// using the simple file system protocol of the device, and loads each "*.addon.efi" file in it via
/// LoadImage(), passing a device path that consists of the device path of the device followed by a
/// file path node. It records the outcome in SIDECARS.
extern "efiapi" fn sidecar_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    record_entry(image_handle, system_table);
    // SAFETY: The system table pointer is the one passed to the entry point.
    match panic::catch_unwind(|| unsafe { load_sidecars(image_handle, system_table) }) {
        Ok(sidecars) => {
            if let Ok(mut s) = SIDECARS.lock() {
                *s = sidecars;
            }
            Status::EFI_SUCCESS
        }
        Err(_) => Status::EFI_ABORTED,
    }
}

/// See sidecar_entry()
///
/// # Safety
///
/// `system_table` must be the system table pointer passed to the entry point of the image with
/// handle `image_handle`.
unsafe fn load_sidecars(
    image_handle: Handle,
    system_table: *mut SystemTable,
) -> Vec<(String, Status)> {
    // SAFETY: The caller guarantees that the system table pointer is valid, and so is the boot
    // services table that it points to. All other pointers are either provided by the EFI runtime,
    // or point to local variables.
    unsafe {
        let bs = ptr::read((*system_table).boot_services);
        let protocol = |handle: Handle, guid: &Guid| {
            let mut interface = ptr::null_mut();
            let status = (bs.handle_protocol)(handle, guid, &mut interface);
            assert_eq!(status, Status::EFI_SUCCESS);
            interface
        };

        // The loaded image protocol identifies the device and the file path of the image
        let li = protocol(image_handle, &EFI_LOADED_IMAGE_PROTOCOL_GUID);
        let li = ptr::read(li.cast::<LoadedImageProtocol>());
        let file_path = device_path_bytes(li.file_path);
        assert_eq!(file_path[..2], [MEDIA_DEVICE_PATH, MEDIA_FILEPATH_DP]);
        let dir = format!("{}.extra.d", utf16_to_string(&file_path[4..]));

        // Collect the names of the addons in the directory
        let sfs = protocol(li.device_handle, &EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID);
        let sfs = sfs.cast::<SimpleFileSystemProtocol>();
        let mut root = ptr::null_mut();
        assert_eq!(((*sfs).open_volume)(sfs, &mut root), Status::EFI_SUCCESS);
        let mut handle = ptr::null_mut();
        let name = utf16z(&dir);
        let status = ((*root).open)(root, &mut handle, name.as_ptr(), EFI_FILE_MODE_READ, 0);
        assert_eq!(status, Status::EFI_SUCCESS);
        let mut addons = Vec::new();
        loop {
            let mut buf = [0u8; 1024];
            let mut size = buf.len();
            let status = ((*handle).read)(handle, &mut size, buf.as_mut_ptr().cast());
            assert_eq!(status, Status::EFI_SUCCESS);
            if size == 0 {
                break;
            }
            let (_, name) = parse_file_info(&buf[..size]);
            if name.ends_with(".addon.efi") {
                addons.push(name);
            }
        }
        ((*handle).close)(handle);
        ((*root).close)(root);

        // Load each of them via a device path
        let device = protocol(li.device_handle, &EFI_DEVICE_PATH_PROTOCOL_GUID);
        let device = device_path_bytes(device.cast());
        let device = &device[..device.len() - END_NODE.len()];
        addons
            .into_iter()
            .map(|name| {
                let file = file_path_node(&format!("{dir}\\{name}"));
                let path = [device, &file, &END_NODE].concat();
                let mut addon = 0;
                let status = (bs.load_image)(
                    0,
                    image_handle,
                    path.as_ptr().cast_mut().cast(),
                    ptr::null_mut(),
                    0,
                    &mut addon,
                );
                if status == Status::EFI_SUCCESS {
                    assert_eq!((bs.unload_image)(addon), Status::EFI_SUCCESS);
                }
                (name, status)
            })
            .collect()
    }
}

/// EfiContext::load_image_with_file_path() records the device and the file path that it is passed
/// in the loaded image protocol of the image, so that the image can load other files relative to
/// its own location, e.g., the addons that systemd-stub loads from its "<FilePath>.extra.d"
/// directory.
#[test]
fn image_can_load_files_relative_to_its_file_path() {
    let efi = setup();
    reset();

    let archive = Cpio::default()
        .file(
            "EFI/Linux/uki.efi.extra.d/a.addon.efi",
            &pe_image(returning_entry),
        )
        .file("EFI/Linux/uki.efi.extra.d/b.addon.efi", b"not an image")
        .file("EFI/Linux/uki.efi.extra.d/c.cred", b"credential")
        .finish();
    let volume = efi.install_cpio_volume(archive);
    let image = MemFile(pe_image(sidecar_entry));
    let mut li = efi
        .context()
        .load_image_with_file_path(&image, volume, "\\EFI\\Linux\\uki.efi")
        .unwrap();

    let info = loaded_image(&efi, li.image_handle);
    assert_eq!(info.parent_handle, 0);
    assert_eq!(info.device_handle, volume);
    assert_eq!(
        recorded_file_path(&info),
        Some([&file_path_node("\\EFI\\Linux\\uki.efi")[..], &END_NODE].concat())
    );

    assert_eq!(li.start_image(), Status::EFI_SUCCESS);
    assert_eq!(
        *SIDECARS.lock().unwrap(),
        [
            ("a.addon.efi".to_string(), Status::EFI_SUCCESS),
            ("b.addon.efi".to_string(), Status::EFI_LOAD_ERROR),
        ]
    );
}

/// LoadImage() returns EFI_LOAD_ERROR if the "Image was not loaded because the image format was
/// corrupt or not understood".
#[test]
fn load_image_rejects_corrupt_image() {
    let efi = setup();

    let image = pe_image(returning_entry);
    let corrupt = |offset: usize, bytes: &[u8]| {
        let mut image = image.clone();
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
        image
    };
    for (what, image) in [
        ("random data", vec![0xa5; image.len()]),
        ("truncated headers", image[..0x100].to_vec()),
        ("MS-DOS magic", corrupt(0, b"XZ")),
        ("PE header offset", corrupt(0x3c, &0xfff0u32.to_le_bytes())),
        ("PE signature", corrupt(PE_HEADER_OFFSET, b"PX\0\0")),
    ] {
        assert_eq!(
            efi.load_image(&image),
            Err(Status::EFI_LOAD_ERROR),
            "{what}"
        );
    }
}

/// LoadImage() refuses to load images for other architectures: "EFI_UNSUPPORTED: The image type is
/// not supported."
#[test]
fn load_image_rejects_foreign_machine_type() {
    let efi = setup();

    let image = pe_image_for_machine(returning_entry, IMAGE_FILE_MACHINE_I386);
    let result = efi.load_image(&image);
    assert!(
        matches!(
            result,
            Err(Status::EFI_UNSUPPORTED) | Err(Status::EFI_LOAD_ERROR)
        ),
        "{result:?}"
    );
}

/// StartImage() "transfers control to the entry point of an image that was loaded by
/// EFI_BOOT_SERVICES.LoadImage()", which takes "ImageHandle: The firmware allocated handle for the
/// UEFI image" and "SystemTable: A pointer to the EFI System Table".
#[test]
fn start_image_calls_entry_point() {
    let efi = setup();
    reset();

    let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
    assert_eq!(ENTRY_COUNT.load(SeqCst), 0);
    assert_eq!(start_image(&efi, handle), Status::EFI_SUCCESS);
    assert_eq!(ENTRY_COUNT.load(SeqCst), 1);
    assert_eq!(ENTRY_IMAGE_HANDLE.load(SeqCst), handle);
    assert_eq!(
        ENTRY_SYSTEM_TABLE.load(SeqCst),
        efi.system_table_ptr() as usize
    );
}

/// "Control returns from StartImage() when the loaded image's EFI_IMAGE_ENTRY_POINT returns", and
/// StartImage() returns the "Exit code from image".
#[test]
fn start_image_returns_exit_code() {
    let efi = setup();

    for status in [
        Status::EFI_SUCCESS,
        Status::EFI_ABORTED,
        Status::EFI_LOAD_ERROR,
        Status(1), // EFI_WARN_UNKNOWN_GLYPH
    ] {
        reset();
        IMAGE_STATUS.store(status.0, SeqCst);
        let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
        assert_eq!(start_image(&efi, handle), status);
    }
}

/// StartImage() returns EFI_INVALID_PARAMETER if "ImageHandle is either an invalid image handle
/// ...".
#[test]
fn start_image_rejects_invalid_image_handle() {
    let efi = setup();
    reset();

    let not_an_image = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    for handle in [0, BOGUS_HANDLE, not_an_image] {
        assert_eq!(
            start_image(&efi, handle),
            Status::EFI_INVALID_PARAMETER,
            "{handle:#x}"
        );
    }
    assert_eq!(ENTRY_COUNT.load(SeqCst), 0);
}

/// StartImage() returns EFI_INVALID_PARAMETER if "... the image has already been initialized with
/// StartImage": "The image may only be started one time."
#[test]
fn start_image_rejects_started_image() {
    let efi = setup();
    reset();

    let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
    assert_eq!(start_image(&efi, handle), Status::EFI_SUCCESS);
    assert_eq!(start_image(&efi, handle), Status::EFI_INVALID_PARAMETER);
    assert_eq!(ENTRY_COUNT.load(SeqCst), 1);
}

/// Exit() "terminates the image referenced by ImageHandle and returns control to boot services",
/// i.e., "Control is returned to the StartImage() call that invoked the image specified by
/// ImageHandle".
#[test]
fn exit_returns_to_start_image() {
    let efi = setup();

    for status in [Status::EFI_ABORTED, Status::EFI_SUCCESS] {
        reset();
        IMAGE_STATUS.store(status.0, SeqCst);
        let handle = efi.load_image(&pe_image(exiting_entry)).unwrap();
        assert_eq!(start_image(&efi, handle), status);
        assert_eq!(ENTRY_COUNT.load(SeqCst), 1);
        assert!(!RESUMED_AFTER_EXIT.load(SeqCst));
    }
}

/// StartImage(): "When that call is made, the ExitData buffer and ExitDataSize from Exit() are
/// passed back through the ExitData buffer and ExitDataSize in this function. The caller of this
/// function is responsible for returning the ExitData buffer to the pool by calling
/// EFI_BOOT_SERVICES.FreePool() when the buffer is no longer needed."
#[test]
fn exit_passes_exit_data_to_start_image() {
    let efi = setup();
    let bs = efi.bs();
    reset();

    let handle = efi.load_image(&pe_image(exit_data_entry)).unwrap();
    let mut exit_data_size = 0;
    let mut exit_data = ptr::null_mut();
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.start_image)(handle, &mut exit_data_size, &mut exit_data) };
    assert_eq!(status, Status::EFI_ABORTED);
    assert!(!RESUMED_AFTER_EXIT.load(SeqCst));

    assert_eq!(exit_data_size, EXIT_DATA_SIZE);
    assert_eq!(exit_data as usize, EXIT_DATA.load(SeqCst));
    // SAFETY: The exit data consists of EXIT_DATA_SIZE bytes.
    let data = unsafe { core::slice::from_raw_parts(exit_data.cast::<u8>(), EXIT_DATA_SIZE) };
    assert_eq!(&data[..10], b"O\0o\0p\0s\0\0\0");
    assert_eq!(&data[10..], &[0xde, 0xad, 0xbe, 0xef]);
    // SAFETY: The exit data was allocated using AllocatePool().
    assert_eq!(
        unsafe { (bs.free_pool)(exit_data.cast()) },
        Status::EFI_SUCCESS
    );
}

/// Exit() can only be called for images that are executing: it does not return when called by
/// the currently executing image, but fails for handles that do not belong to an image.
#[test]
fn exit_rejects_handle_that_is_not_an_image() {
    let efi = setup();
    reset();

    let not_an_image = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    EXIT_IMAGE_HANDLE.store(not_an_image, SeqCst);
    IMAGE_STATUS.store(Status::EFI_ABORTED.0, SeqCst);
    let handle = efi.load_image(&pe_image(exiting_entry)).unwrap();

    // Exit() returns to the image, which then returns EFI_SUCCESS
    assert_eq!(start_image(&efi, handle), Status::EFI_SUCCESS);
    assert!(RESUMED_AFTER_EXIT.load(SeqCst));
    assert_eq!(
        Status(EXIT_RETURNED.load(SeqCst)),
        Status::EFI_INVALID_PARAMETER
    );
}

/// Exit() returns "EFI_SUCCESS: The image specified by ImageHandle was unloaded. This condition
/// only occurs for images that have been loaded with LoadImage() but have not been started with
/// StartImage()." "It is valid to call Exit() or Unload() for an image that was loaded by
/// EFI_BOOT_SERVICES.LoadImage() before calling EFI_BOOT_SERVICES.StartImage(). This will free the
/// image from memory without having started it."
#[test]
fn exit_unloads_image_that_was_not_started() {
    let efi = setup();
    let bs = efi.bs();
    reset();

    let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
    let li = loaded_image(&efi, handle);
    // SAFETY: ExitData is NULL.
    let status = unsafe { (bs.exit)(handle, Status::EFI_ABORTED, 0, ptr::null_mut()) };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_unloaded(&efi, handle, &li);
}

/// Checks that the image with handle `handle` and loaded image protocol `li` was unloaded, i.e.,
/// that its handle is no longer valid, and that the memory it occupied was freed.
fn assert_unloaded(efi: &Efi, handle: Handle, li: &LoadedImageProtocol) {
    let bs = efi.bs();

    assert_eq!(start_image(efi, handle), Status::EFI_INVALID_PARAMETER);
    assert!(
        efi.handle_protocol(handle, &EFI_LOADED_IMAGE_PROTOCOL_GUID)
            .is_err()
    );
    assert!(
        !efi.locate_handles(ALL_HANDLES, None)
            .unwrap()
            .contains(&handle)
    );
    assert_eq!(ENTRY_COUNT.load(SeqCst), 0);

    // The memory can be allocated and written to again
    let base = li.image_base as u64;
    let pages = li.image_size.div_ceil(PAGE);
    assert_eq!(
        efi.memory_map().type_of(base..base + pages * PAGE),
        Some(EFI_CONVENTIONAL_MEMORY)
    );
    let mut memory = base;
    // SAFETY: `memory` is a valid EFI_PHYSICAL_ADDRESS.
    let status = unsafe {
        (bs.allocate_pages)(
            ALLOCATE_ADDRESS,
            EFI_LOADER_DATA,
            pages as usize,
            &mut memory,
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    // SAFETY: The pages were just allocated.
    unsafe { ptr::write_bytes(base as *mut u8, 0xaa, (pages * PAGE) as usize) };
    // SAFETY: The pages are no longer used.
    assert_eq!(
        unsafe { (bs.free_pages)(base, pages as usize) },
        Status::EFI_SUCCESS
    );
}

/// UnloadImage() returns "EFI_SUCCESS: The image has been unloaded" for images that have not been
/// started: "It is valid to call Exit() or Unload() for an image that was loaded by
/// EFI_BOOT_SERVICES.LoadImage() before calling EFI_BOOT_SERVICES.StartImage()."
#[test]
fn unload_image_unloads_image_that_was_not_started() {
    let efi = setup();
    let bs = efi.bs();
    reset();

    let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
    let li = loaded_image(&efi, handle);
    // SAFETY: UnloadImage() takes no pointer arguments.
    let status = unsafe { (bs.unload_image)(handle) };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_unloaded(&efi, handle, &li);
}

/// UnloadImage() returns "EFI_INVALID_PARAMETER: ImageHandle is not a valid image handle".
#[test]
fn unload_image_rejects_invalid_image_handle() {
    let efi = setup();
    let bs = efi.bs();

    let not_an_image = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    for handle in [0, BOGUS_HANDLE, not_an_image] {
        // SAFETY: UnloadImage() takes no pointer arguments.
        let status = unsafe { (bs.unload_image)(handle) };
        assert_eq!(status, Status::EFI_INVALID_PARAMETER, "{handle:#x}");
    }
}

/// An image entry point that calls UnloadImage() for its own image handle, and returns
/// EFI_SUCCESS.
extern "efiapi" fn unloading_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    record_entry(image_handle, system_table);
    // SAFETY: The system table pointer passed to the entry point is valid, and so is the boot
    // services table pointer it holds.
    let status = unsafe { ((*(*system_table).boot_services).unload_image)(image_handle) };
    EXIT_RETURNED.store(status.0, SeqCst);
    Status::EFI_SUCCESS
}

/// UnloadImage() returns "EFI_UNSUPPORTED: The image has been started, and does not support
/// unload", which applies to an image that is running and has not registered an Unload() function.
#[test]
fn unload_image_rejects_started_image() {
    let efi = setup();
    reset();

    let handle = efi.load_image(&pe_image(unloading_entry)).unwrap();
    assert_eq!(start_image(&efi, handle), Status::EFI_SUCCESS);
    assert_eq!(ENTRY_COUNT.load(SeqCst), 1);
    assert_eq!(Status(EXIT_RETURNED.load(SeqCst)), Status::EFI_UNSUPPORTED);
}

static PARENT_IMAGE_HANDLE: AtomicUsize = AtomicUsize::new(0);
static CHILD_IMAGE: AtomicUsize = AtomicUsize::new(0);
static CHILD_IMAGE_SIZE: AtomicUsize = AtomicUsize::new(0);
static CHILD_LOAD_STATUS: AtomicUsize = AtomicUsize::new(0);
static CHILD_START_STATUS: AtomicUsize = AtomicUsize::new(0);
static CHILD_EXIT_PARENT_STATUS: AtomicUsize = AtomicUsize::new(0);
static CHILD_RESUMED_AFTER_EXIT: AtomicBool = AtomicBool::new(false);
const CHILD_EXIT_STATUS: Status = Status::EFI_NOT_READY;
const PARENT_EXIT_STATUS: Status = Status::EFI_TIMEOUT;

/// An image entry point that loads and starts a child image from the buffer described by
/// CHILD_IMAGE and CHILD_IMAGE_SIZE, and calls Exit() with PARENT_EXIT_STATUS when it returns.
extern "efiapi" fn parent_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    record_entry(image_handle, system_table);
    PARENT_IMAGE_HANDLE.store(image_handle, SeqCst);
    // SAFETY: The system table pointer passed to the entry point is valid, and so is the boot
    // services table pointer it holds. CHILD_IMAGE points to a buffer of CHILD_IMAGE_SIZE bytes.
    unsafe {
        let bs = ptr::read((*system_table).boot_services);
        let mut child = 0;
        let status = (bs.load_image)(
            0,
            image_handle,
            ptr::null_mut(),
            CHILD_IMAGE.load(SeqCst) as *mut c_void,
            CHILD_IMAGE_SIZE.load(SeqCst),
            &mut child,
        );
        CHILD_LOAD_STATUS.store(status.0, SeqCst);
        if status != Status::EFI_SUCCESS {
            return status;
        }

        let mut exit_data_size = 0;
        let mut exit_data = ptr::null_mut();
        let status = (bs.start_image)(child, &mut exit_data_size, &mut exit_data);
        CHILD_START_STATUS.store(status.0, SeqCst);

        (bs.exit)(image_handle, PARENT_EXIT_STATUS, 0, ptr::null_mut());
    }
    RESUMED_AFTER_EXIT.store(true, SeqCst);
    Status::EFI_SUCCESS
}

/// An image entry point that calls Exit() for its parent image, which is not the currently
/// executing image, and then for itself with CHILD_EXIT_STATUS.
extern "efiapi" fn child_entry(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    // SAFETY: The system table pointer passed to the entry point is valid, and so is the boot
    // services table pointer it holds.
    unsafe {
        let bs = ptr::read((*system_table).boot_services);
        let parent = PARENT_IMAGE_HANDLE.load(SeqCst);
        let status = (bs.exit)(parent, Status::EFI_ABORTED, 0, ptr::null_mut());
        CHILD_EXIT_PARENT_STATUS.store(status.0, SeqCst);

        (bs.exit)(image_handle, CHILD_EXIT_STATUS, 0, ptr::null_mut());
    }
    CHILD_RESUMED_AFTER_EXIT.store(true, SeqCst);
    Status::EFI_SUCCESS
}

/// When images start other images, Exit() returns control to the StartImage() call that started
/// the image passed to it. It returns EFI_INVALID_PARAMETER if "The image specified by ImageHandle
/// has been loaded and started with LoadImage() and StartImage(), but the image is not the
/// currently executing image."
#[test]
fn exit_from_nested_images() {
    let efi = setup();
    reset();

    let child = pe_image(child_entry);
    CHILD_IMAGE.store(child.as_ptr() as usize, SeqCst);
    CHILD_IMAGE_SIZE.store(child.len(), SeqCst);
    CHILD_RESUMED_AFTER_EXIT.store(false, SeqCst);

    let parent = efi.load_image(&pe_image(parent_entry)).unwrap();
    let status = start_image(&efi, parent);
    assert_eq!(Status(CHILD_LOAD_STATUS.load(SeqCst)), Status::EFI_SUCCESS);

    // The child image's call to Exit() for the parent image returned an error
    assert_eq!(
        Status(CHILD_EXIT_PARENT_STATUS.load(SeqCst)),
        Status::EFI_INVALID_PARAMETER
    );

    // The child image's call to Exit() for itself returned to the parent image
    assert_eq!(Status(CHILD_START_STATUS.load(SeqCst)), CHILD_EXIT_STATUS);
    assert!(!CHILD_RESUMED_AFTER_EXIT.load(SeqCst));

    // The parent image's call to Exit() returned to us
    assert_eq!(status, PARENT_EXIT_STATUS);
    assert!(!RESUMED_AFTER_EXIT.load(SeqCst));
}
