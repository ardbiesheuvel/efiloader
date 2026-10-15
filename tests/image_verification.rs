// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the authentication of the image files that EFI images load via LoadImage() without
//! passing a source buffer, using the image verifier that the embedder may provide via
//! EfiContext::set_image_verifier(). These live in a separate test binary, given that the verifier
//! affects all subsequent calls to LoadImage().

mod common;
use common::*;

use core::ffi::c_void;
use core::ptr;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

/// Image files that contain this marker are rejected by the verifier
const MARKER: &[u8] = b"REJECT ME";

/// The number of image files that the verifier was asked to verify
static VERIFIED: AtomicUsize = AtomicUsize::new(0);

struct Verifier;

impl efiloader::ImageVerifier for Verifier {
    fn verify(&self, image: &[u8]) -> bool {
        VERIFIED.fetch_add(1, SeqCst);
        !image.windows(MARKER.len()).any(|w| w == MARKER)
    }
}

/// Returns an image file that the verifier rejects, but which is a valid image otherwise
fn rejected_image() -> Vec<u8> {
    let mut image = pe_image(returning_entry);
    image.extend_from_slice(MARKER);
    image
}

extern "efiapi" fn returning_entry(
    _image_handle: Handle,
    _system_table: *mut SystemTable,
) -> Status {
    Status::EFI_SUCCESS
}

/// Loads an image using LoadImage() without a source buffer, passing a device path that consists
/// of `nodes`. Returns the handle of the image on success.
fn load_image_from_device_path(efi: &Efi, nodes: &[&[u8]]) -> Result<Handle, Status> {
    let path = device_path(nodes);
    let mut handle = 0;
    // SAFETY: All pointers are valid or NULL. SourceSize is ignored if SourceBuffer is NULL.
    let status = unsafe {
        (efi.bs().load_image)(0, efi.image_handle(), path, ptr::null_mut(), 0, &mut handle)
    };
    if status == Status::EFI_SUCCESS {
        Ok(handle)
    } else {
        // LoadImage() returns "EFI_ACCESS_DENIED: Image was not loaded because the platform policy
        // prohibits the image from being loaded. NULL is returned in *ImageHandle."
        assert_eq!(handle, 0);
        Err(status)
    }
}

/// Image files that are loaded from a volume are passed to the verifier, and LoadImage() returns
/// EFI_ACCESS_DENIED for those it rejects, after freeing the memory it loaded them into.
#[test]
fn image_files_from_volumes_are_verified() {
    let efi = setup();
    efi.context().set_image_verifier(Verifier);

    let archive = Cpio::default()
        .file("GOOD.EFI", &pe_image(returning_entry))
        .file("BAD.EFI", &rejected_image())
        .finish();
    let volume = efi.install_cpio_volume(archive);
    let device = efi.device_nodes(volume);

    let verified = VERIFIED.load(SeqCst);
    load_image_from_device_path(&efi, &[&device, &file_path_node("\\GOOD.EFI")]).unwrap();
    assert_eq!(VERIFIED.load(SeqCst), verified + 1);

    let pages = efi.memory_map().pages_of_type(EFI_BOOT_SERVICES_DATA);
    assert_eq!(
        load_image_from_device_path(&efi, &[&device, &file_path_node("\\BAD.EFI")]),
        Err(Status::EFI_ACCESS_DENIED)
    );
    assert_eq!(VERIFIED.load(SeqCst), verified + 2);
    assert_eq!(
        efi.memory_map().pages_of_type(EFI_BOOT_SERVICES_DATA),
        pages
    );
}

/// The same applies to image files that are loaded via the LoadFile2 protocol.
#[test]
fn image_files_from_load_file2_are_verified() {
    let efi = setup();
    efi.context().set_image_verifier(Verifier);

    // The initrd LoadFile2 protocol that the EFI runtime provides, which serves a single file via
    // the LINUX_EFI_INITRD_MEDIA_GUID vendor media device path
    let initrd_media = Guid {
        data1: 0x5568e427,
        data2: 0x68fc,
        data3: 0x4f3d,
        data4: [0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68],
    };
    efi.context().set_initrd_loader(MemFile(rejected_image()));
    let mut node = vec![MEDIA_DEVICE_PATH, MEDIA_VENDOR_DP, 20, 0];
    node.extend_from_slice(&initrd_media.data1.to_le_bytes());
    node.extend_from_slice(&initrd_media.data2.to_le_bytes());
    node.extend_from_slice(&initrd_media.data3.to_le_bytes());
    node.extend_from_slice(&initrd_media.data4);

    let verified = VERIFIED.load(SeqCst);
    assert_eq!(
        load_image_from_device_path(&efi, &[&node]),
        Err(Status::EFI_ACCESS_DENIED)
    );
    assert_eq!(VERIFIED.load(SeqCst), verified + 1);
}

/// Images that EFI images load from memory are not verified.
#[test]
fn images_loaded_from_memory_are_not_verified() {
    let efi = setup();
    efi.context().set_image_verifier(Verifier);

    let verified = VERIFIED.load(SeqCst);
    let image = rejected_image();
    efi.load_image(&image).unwrap();

    // Not even if a device path is passed along with the image
    let path = device_path(&[&file_path_node("\\BAD.EFI")]);
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
    assert_eq!(VERIFIED.load(SeqCst), verified);
}
