// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the image services described in section 7.4 of the UEFI specification: LoadImage(),
//! StartImage() and Exit(). UnloadImage() is not covered, as efiloader does not implement it, and
//! ExitBootServices() is covered by a separate test binary.
//!
//! The images that are loaded by these tests consist of a trampoline that branches into a Rust
//! function in this file, which runs on the stack provided by StartImage(). These functions report
//! their observations via static variables, rather than by asserting anything themselves, given
//! that panics cannot unwind out of an EFI image entry point.

mod common;
use common::*;

use core::ffi::c_void;
use core::mem::size_of_val;
use core::ptr;
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
#[ignore = "efiloader permits images to be started more than once"]
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
#[ignore = "efiloader does not pass the exit data back to StartImage()"]
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
#[ignore = "efiloader does not support unloading images"]
fn exit_unloads_image_that_was_not_started() {
    let efi = setup();
    let bs = efi.bs();
    reset();

    let handle = efi.load_image(&pe_image(returning_entry)).unwrap();
    // SAFETY: ExitData is NULL.
    let status = unsafe { (bs.exit)(handle, Status::EFI_ABORTED, 0, ptr::null_mut()) };
    assert_eq!(status, Status::EFI_SUCCESS);

    // The image handle is no longer valid
    assert_eq!(start_image(&efi, handle), Status::EFI_INVALID_PARAMETER);
    assert!(
        efi.handle_protocol(handle, &EFI_LOADED_IMAGE_PROTOCOL_GUID)
            .is_err()
    );
    assert_eq!(ENTRY_COUNT.load(SeqCst), 0);
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
