// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 Google LLC

//! Tests for the protocol handler services described in section 7.3 of the UEFI specification.
//! RegisterProtocolNotify(), ConnectController(), DisconnectController() and
//! OpenProtocolInformation() are not covered, as efiloader does not implement them.

mod common;
use common::*;

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use core::slice;

/// A handle value that is never allocated by the firmware
const BOGUS_HANDLE: Handle = 0xdead_0000_beef;

fn uninstall(bs: &BootServices, handle: Handle, protocol: &Guid, interface: *mut c_void) -> Status {
    // SAFETY: All pointers are valid.
    unsafe { (bs.uninstall_protocol_interface)(handle, protocol, interface) }
}

fn reinstall(
    bs: &BootServices,
    handle: Handle,
    protocol: &Guid,
    old: *mut c_void,
    new: *mut c_void,
) -> Status {
    // SAFETY: All pointers are valid.
    unsafe { (bs.reinstall_protocol_interface)(handle, protocol, old, new) }
}

fn open_protocol(
    bs: &BootServices,
    handle: Handle,
    protocol: *const Guid,
    interface: *mut *mut c_void,
    agent: Handle,
    controller: Handle,
    attributes: u32,
) -> Status {
    // SAFETY: All pointers are valid or NULL.
    unsafe { (bs.open_protocol)(handle, protocol, interface, agent, controller, attributes) }
}

fn locate_handle_buffer(
    bs: &BootServices,
    search_type: u32,
    protocol: *const Guid,
) -> Result<Vec<Handle>, Status> {
    let mut count = 0;
    let mut buffer = ptr::null_mut();
    // SAFETY: All pointers are valid or NULL.
    let status = unsafe {
        (bs.locate_handle_buffer)(
            search_type,
            protocol,
            ptr::null_mut(),
            &mut count,
            &mut buffer,
        )
    };
    if status != Status::EFI_SUCCESS {
        return Err(status);
    }
    assert!(!buffer.is_null());
    // SAFETY: LocateHandleBuffer() returned a buffer holding `count` handles.
    let mut handles = unsafe { slice::from_raw_parts(buffer, count) }.to_vec();
    // SAFETY: The buffer was allocated from pool by LocateHandleBuffer().
    assert_eq!(
        unsafe { (bs.free_pool)(buffer.cast()) },
        Status::EFI_SUCCESS
    );
    handles.sort();
    Ok(handles)
}

/// Returns the protocol GUIDs installed on `handle`, as reported by ProtocolsPerHandle()
fn protocols_per_handle(bs: &BootServices, handle: Handle) -> Result<Vec<Guid>, Status> {
    let mut buffer = ptr::null_mut();
    let mut count = 0;
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.protocols_per_handle)(handle, &mut buffer, &mut count) };
    if status != Status::EFI_SUCCESS {
        return Err(status);
    }
    // SAFETY: ProtocolsPerHandle() returned a buffer holding `count` pointers to GUIDs.
    let mut guids: Vec<Guid> = unsafe { slice::from_raw_parts(buffer, count) }
        .iter()
        // SAFETY: Each GUID pointer is valid.
        .map(|&g| unsafe { ptr::read(g) })
        .collect();
    // SAFETY: The buffer was allocated from pool by ProtocolsPerHandle().
    assert_eq!(
        unsafe { (bs.free_pool)(buffer.cast()) },
        Status::EFI_SUCCESS
    );
    guids.sort();
    Ok(guids)
}

fn sorted(handles: &[Handle]) -> Vec<Handle> {
    let mut handles = handles.to_vec();
    handles.sort();
    handles
}

/// InstallProtocolInterface(): "If *Handle is NULL on input, a new handle is created and returned
/// on output."
#[test]
fn install_protocol_interface_creates_handle() {
    let efi = setup();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();
    assert_eq!(efi.handle_protocol(handle, &guid), Ok(interface));
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Ok(vec![handle])
    );
    assert!(
        efi.locate_handles(ALL_HANDLES, None)
            .unwrap()
            .contains(&handle)
    );
}

/// InstallProtocolInterface(): "If *Handle is not NULL on input, the protocol is added to the
/// handle, and the handle is returned unmodified."
#[test]
fn install_protocol_interface_on_existing_handle() {
    let efi = setup();
    let (guid1, guid2) = (new_guid(), new_guid());
    let (interface1, interface2) = (new_interface(), new_interface());

    let handle = efi.install_protocol(0, &guid1, interface1).unwrap();
    assert_eq!(efi.install_protocol(handle, &guid2, interface2), Ok(handle));
    assert_eq!(efi.handle_protocol(handle, &guid1), Ok(interface1));
    assert_eq!(efi.handle_protocol(handle, &guid2), Ok(interface2));
}

/// The same protocol may be installed onto multiple handles.
#[test]
fn install_protocol_interface_on_multiple_handles() {
    let efi = setup();
    let guid = new_guid();
    let (interface1, interface2) = (new_interface(), new_interface());

    let handle1 = efi.install_protocol(0, &guid, interface1).unwrap();
    let handle2 = efi.install_protocol(0, &guid, interface2).unwrap();
    assert_ne!(handle1, handle2);
    assert_eq!(efi.handle_protocol(handle1, &guid), Ok(interface1));
    assert_eq!(efi.handle_protocol(handle2, &guid), Ok(interface2));
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Ok(sorted(&[handle1, handle2]))
    );
}

/// InstallProtocolInterface(): "NULL can be used if a structure is not associated with
/// Protocol."
#[test]
fn install_protocol_interface_with_null_interface() {
    let efi = setup();
    let guid = new_guid();

    let handle = efi.install_protocol(0, &guid, ptr::null_mut()).unwrap();
    assert_eq!(efi.handle_protocol(handle, &guid), Ok(ptr::null_mut()));
}

/// InstallProtocolInterface() returns EFI_INVALID_PARAMETER if "Handle is NULL".
#[test]
fn install_protocol_interface_rejects_null_handle() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    // SAFETY: InstallProtocolInterface() must not dereference a NULL Handle pointer.
    let status = unsafe {
        (bs.install_protocol_interface)(
            ptr::null_mut(),
            &guid,
            EFI_NATIVE_INTERFACE,
            new_interface(),
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// InstallProtocolInterface() returns EFI_INVALID_PARAMETER if "Protocol is NULL".
#[test]
fn install_protocol_interface_rejects_null_protocol() {
    let efi = setup();
    let bs = efi.bs();

    let mut handle = 0;
    // SAFETY: InstallProtocolInterface() must not dereference a NULL Protocol pointer.
    let status = unsafe {
        (bs.install_protocol_interface)(
            &mut handle,
            ptr::null(),
            EFI_NATIVE_INTERFACE,
            new_interface(),
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
    assert_eq!(handle, 0);
}

/// InstallProtocolInterface() returns EFI_INVALID_PARAMETER if "InterfaceType is not
/// EFI_NATIVE_INTERFACE".
#[test]
fn install_protocol_interface_rejects_non_native_interface() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    for interface_type in [1, u32::MAX] {
        let mut handle = 0;
        // SAFETY: All pointers are valid.
        let status = unsafe {
            (bs.install_protocol_interface)(&mut handle, &guid, interface_type, new_interface())
        };
        assert_eq!(
            status,
            Status::EFI_INVALID_PARAMETER,
            "InterfaceType {interface_type:#x}"
        );
    }
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// InstallProtocolInterface() returns EFI_INVALID_PARAMETER if "Protocol is already installed on
/// the handle specified by Handle".
#[test]
fn install_protocol_interface_rejects_duplicate_protocol() {
    let efi = setup();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();
    for duplicate in [new_interface(), interface] {
        assert_eq!(
            efi.install_protocol(handle, &guid, duplicate),
            Err(Status::EFI_INVALID_PARAMETER)
        );
    }
    assert_eq!(efi.handle_protocol(handle, &guid), Ok(interface));
}

/// InstallProtocolInterface(): "If *Handle is not a valid handle, then EFI_INVALID_PARAMETER is
/// returned."
#[test]
fn install_protocol_interface_rejects_invalid_handle() {
    let efi = setup();
    let guid = new_guid();

    assert_eq!(
        efi.install_protocol(BOGUS_HANDLE, &guid, new_interface()),
        Err(Status::EFI_INVALID_PARAMETER)
    );
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// UninstallProtocolInterface() "removes a protocol interface from the handle on which it was
/// previously installed".
#[test]
fn uninstall_protocol_interface_removes_interface() {
    let efi = setup();
    let bs = efi.bs();
    let (guid1, guid2) = (new_guid(), new_guid());
    let (interface1, interface2) = (new_interface(), new_interface());

    let handle = efi.install_protocol(0, &guid1, interface1).unwrap();
    efi.install_protocol(handle, &guid2, interface2).unwrap();

    assert_eq!(
        uninstall(&bs, handle, &guid1, interface1),
        Status::EFI_SUCCESS
    );
    assert_eq!(
        efi.handle_protocol(handle, &guid1),
        Err(Status::EFI_UNSUPPORTED)
    );
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid1)),
        Err(Status::EFI_NOT_FOUND)
    );

    // The other protocol is unaffected, and so the handle remains valid
    assert_eq!(efi.handle_protocol(handle, &guid2), Ok(interface2));
    assert!(
        efi.locate_handles(ALL_HANDLES, None)
            .unwrap()
            .contains(&handle)
    );
}

/// UninstallProtocolInterface(): "If the last protocol interface is removed from a handle, the
/// handle is freed and is no longer valid."
#[test]
fn uninstall_protocol_interface_frees_handle() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();
    assert_eq!(
        uninstall(&bs, handle, &guid, interface),
        Status::EFI_SUCCESS
    );

    assert!(
        !efi.locate_handles(ALL_HANDLES, None)
            .unwrap()
            .contains(&handle)
    );
    assert_eq!(
        efi.install_protocol(handle, &new_guid(), new_interface()),
        Err(Status::EFI_INVALID_PARAMETER)
    );
}

/// UninstallProtocolInterface() returns EFI_NOT_FOUND if "The interface was not found".
#[test]
fn uninstall_protocol_interface_rejects_unknown_interface() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();

    // Wrong interface, protocol or handle
    assert_eq!(
        uninstall(&bs, handle, &guid, new_interface()),
        Status::EFI_NOT_FOUND
    );
    assert_eq!(
        uninstall(&bs, handle, &guid, ptr::null_mut()),
        Status::EFI_NOT_FOUND
    );
    assert_eq!(
        uninstall(&bs, handle, &new_guid(), interface),
        Status::EFI_NOT_FOUND
    );
    let other = efi.install_protocol(0, &new_guid(), interface).unwrap();
    assert_eq!(
        uninstall(&bs, other, &guid, interface),
        Status::EFI_NOT_FOUND
    );

    assert_eq!(efi.handle_protocol(handle, &guid), Ok(interface));
}

/// UninstallProtocolInterface() returns EFI_INVALID_PARAMETER if "Handle is NULL".
#[test]
fn uninstall_protocol_interface_rejects_null_handle() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    assert_eq!(
        uninstall(&bs, 0, &guid, new_interface()),
        Status::EFI_INVALID_PARAMETER
    );
}

/// UninstallProtocolInterface() returns EFI_INVALID_PARAMETER if "Protocol is NULL".
#[test]
fn uninstall_protocol_interface_rejects_null_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &new_guid(), interface).unwrap();
    // SAFETY: UninstallProtocolInterface() must not dereference a NULL Protocol pointer.
    let status = unsafe { (bs.uninstall_protocol_interface)(handle, ptr::null(), interface) };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
}

/// UninstallProtocolInterface(): "In some cases, outstanding reference information is not
/// available in the protocol, so the protocol, once added, cannot be removed. Examples include
/// Console I/O, ...". The console protocols referenced by the system table must not be removed.
#[test]
fn uninstall_protocol_interface_retains_console_protocols() {
    let efi = setup();
    let bs = efi.bs();
    let st = efi.system_table();

    for (handle, guid, interface) in [
        (
            st.console_in_handle,
            EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID,
            st.con_in,
        ),
        (
            st.console_out_handle,
            EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID,
            st.con_out,
        ),
    ] {
        assert_ne!(
            uninstall(&bs, handle, &guid, interface),
            Status::EFI_SUCCESS
        );
        assert_eq!(efi.handle_protocol(handle, &guid), Ok(interface));
    }
}

/// ReinstallProtocolInterface(): "The OldInterface for Protocol is replaced by the NewInterface."
#[test]
fn reinstall_protocol_interface_replaces_interface() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let (old, new) = (new_interface(), new_interface());

    let handle = efi.install_protocol(0, &guid, old).unwrap();
    assert_eq!(reinstall(&bs, handle, &guid, old, new), Status::EFI_SUCCESS);
    assert_eq!(efi.handle_protocol(handle, &guid), Ok(new));
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Ok(vec![handle])
    );

    // The old interface is gone
    assert_eq!(uninstall(&bs, handle, &guid, old), Status::EFI_NOT_FOUND);
    assert_eq!(uninstall(&bs, handle, &guid, new), Status::EFI_SUCCESS);
}

/// ReinstallProtocolInterface(): "NewInterface may be the same as OldInterface."
#[test]
fn reinstall_protocol_interface_with_same_interface() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();
    assert_eq!(
        reinstall(&bs, handle, &guid, interface, interface),
        Status::EFI_SUCCESS
    );
    assert_eq!(efi.handle_protocol(handle, &guid), Ok(interface));
}

/// ReinstallProtocolInterface() returns EFI_NOT_FOUND if "The OldInterface on the handle was not
/// found".
#[test]
fn reinstall_protocol_interface_rejects_unknown_interface() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();
    assert_eq!(
        reinstall(&bs, handle, &guid, new_interface(), new_interface()),
        Status::EFI_NOT_FOUND
    );
    assert_eq!(
        reinstall(&bs, handle, &new_guid(), interface, new_interface()),
        Status::EFI_NOT_FOUND
    );
    assert_eq!(efi.handle_protocol(handle, &guid), Ok(interface));
}

/// ReinstallProtocolInterface() returns EFI_INVALID_PARAMETER if "Handle is NULL".
#[test]
fn reinstall_protocol_interface_rejects_null_handle() {
    let efi = setup();
    let bs = efi.bs();

    assert_eq!(
        reinstall(&bs, 0, &new_guid(), new_interface(), new_interface()),
        Status::EFI_INVALID_PARAMETER
    );
}

/// ReinstallProtocolInterface() returns EFI_INVALID_PARAMETER if "Protocol is NULL".
#[test]
fn reinstall_protocol_interface_rejects_null_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &new_guid(), interface).unwrap();
    // SAFETY: ReinstallProtocolInterface() must not dereference a NULL Protocol pointer.
    let status = unsafe {
        (bs.reinstall_protocol_interface)(handle, ptr::null(), interface, new_interface())
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
}

/// HandleProtocol() returns "the interface information for the specified protocol".
#[test]
fn handle_protocol_returns_interface() {
    let efi = setup();
    let (guid1, guid2) = (new_guid(), new_guid());
    let (interface1, interface2) = (new_interface(), new_interface());

    let handle = efi.install_protocol(0, &guid1, interface1).unwrap();
    efi.install_protocol(handle, &guid2, interface2).unwrap();
    assert_eq!(efi.handle_protocol(handle, &guid1), Ok(interface1));
    assert_eq!(efi.handle_protocol(handle, &guid2), Ok(interface2));
}

/// The console handles in the system table support the protocols that the system table refers
/// to, e.g., "ConOut: A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL interface that is associated
/// with ConsoleOutHandle".
#[test]
fn handle_protocol_returns_console_protocols() {
    let efi = setup();
    let st = efi.system_table();

    assert_eq!(
        efi.handle_protocol(st.console_in_handle, &EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID),
        Ok(st.con_in)
    );
    assert_eq!(
        efi.handle_protocol(st.console_out_handle, &EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID),
        Ok(st.con_out)
    );
    assert_eq!(
        efi.handle_protocol(
            st.standard_error_handle,
            &EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID
        ),
        Ok(st.std_err)
    );
}

/// HandleProtocol() returns EFI_UNSUPPORTED if "The device does not support the specified
/// protocol".
#[test]
fn handle_protocol_rejects_unsupported_protocol() {
    let efi = setup();

    let handle = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    assert_eq!(
        efi.handle_protocol(handle, &new_guid()),
        Err(Status::EFI_UNSUPPORTED)
    );
}

/// HandleProtocol() returns EFI_INVALID_PARAMETER if "Handle is NULL".
#[test]
fn handle_protocol_rejects_null_handle() {
    let efi = setup();
    let guid = new_guid();

    assert_eq!(
        efi.handle_protocol(0, &guid),
        Err(Status::EFI_INVALID_PARAMETER)
    );
}

/// HandleProtocol() returns EFI_INVALID_PARAMETER if "Protocol is NULL" or "Interface is NULL".
#[test]
fn handle_protocol_rejects_null_pointers() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let mut interface = ptr::null_mut();
    // SAFETY: HandleProtocol() must not dereference NULL pointers.
    unsafe {
        assert_eq!(
            (bs.handle_protocol)(handle, ptr::null(), &mut interface),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.handle_protocol)(handle, &guid, ptr::null_mut()),
            Status::EFI_INVALID_PARAMETER
        );
    }
}

/// LocateHandle(): with SearchType ByProtocol, "All handles that support Protocol are returned".
/// "On output, [BufferSize is] the size in bytes of the array returned in Buffer".
#[test]
fn locate_handle_by_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    let handle1 = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let handle2 = efi.install_protocol(0, &guid, new_interface()).unwrap();
    // A handle that carries a different protocol
    efi.install_protocol(0, &new_guid(), new_interface())
        .unwrap();

    // A larger buffer than needed
    let mut buffer = [0usize; 8];
    let mut size = size_of::<[Handle; 8]>();
    // SAFETY: All pointers are valid, and `buffer` is a buffer of `size` bytes.
    let status = unsafe {
        (bs.locate_handle)(
            BY_PROTOCOL,
            &guid,
            ptr::null_mut(),
            &mut size,
            buffer.as_mut_ptr(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(size, 2 * size_of::<Handle>());
    assert_eq!(sorted(&buffer[..2]), sorted(&[handle1, handle2]));
}

/// LocateHandle() returns EFI_NOT_FOUND if "No handles match the search".
#[test]
fn locate_handle_by_protocol_not_found() {
    let efi = setup();
    let bs = efi.bs();

    let mut buffer = [0usize; 8];
    let mut size = size_of::<[Handle; 8]>();
    // SAFETY: All pointers are valid, and `buffer` is a buffer of `size` bytes.
    let status = unsafe {
        (bs.locate_handle)(
            BY_PROTOCOL,
            &new_guid(),
            ptr::null_mut(),
            &mut size,
            buffer.as_mut_ptr(),
        )
    };
    assert_eq!(status, Status::EFI_NOT_FOUND);
}

/// LocateHandle(): "If the input value of BufferSize is too small, the function returns
/// EFI_BUFFER_TOO_SMALL and updates BufferSize to the size of the buffer needed to obtain the
/// array."
#[test]
fn locate_handle_buffer_too_small() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    efi.install_protocol(0, &guid, new_interface()).unwrap();
    efi.install_protocol(0, &guid, new_interface()).unwrap();

    for handles in [0, 1] {
        let mut buffer = [BOGUS_HANDLE; 2];
        let mut size = handles * size_of::<Handle>();
        // SAFETY: All pointers are valid, and `buffer` is larger than `size` bytes.
        let status = unsafe {
            (bs.locate_handle)(
                BY_PROTOCOL,
                &guid,
                ptr::null_mut(),
                &mut size,
                buffer.as_mut_ptr(),
            )
        };
        assert_eq!(status, Status::EFI_BUFFER_TOO_SMALL);
        assert_eq!(size, 2 * size_of::<Handle>());
        // Nothing was written beyond the size of the buffer
        assert_eq!(buffer[1], BOGUS_HANDLE);
    }
}

/// LocateHandle() returns EFI_INVALID_PARAMETER if "One or more matches are found and BufferSize
/// is NULL" or "BufferSize is large enough for the result and Buffer is NULL".
#[test]
fn locate_handle_rejects_null_pointers() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    efi.install_protocol(0, &guid, new_interface()).unwrap();
    let mut buffer = [0usize; 1];
    let mut size = size_of::<Handle>();
    // SAFETY: LocateHandle() must not dereference NULL pointers.
    unsafe {
        assert_eq!(
            (bs.locate_handle)(
                BY_PROTOCOL,
                &guid,
                ptr::null_mut(),
                ptr::null_mut(),
                buffer.as_mut_ptr()
            ),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.locate_handle)(
                BY_PROTOCOL,
                &guid,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut()
            ),
            Status::EFI_INVALID_PARAMETER
        );
    }
}

/// LocateHandle() returns EFI_INVALID_PARAMETER if "SearchType is not a member of
/// EFI_LOCATE_SEARCH_TYPE", "SearchType is ByRegisterNotify and SearchKey is NULL" or "SearchType
/// is ByProtocol and Protocol is NULL".
#[test]
fn locate_handle_rejects_invalid_search() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    efi.install_protocol(0, &guid, new_interface()).unwrap();
    for (search_type, protocol) in [
        (3, &raw const guid),
        (u32::MAX, &raw const guid),
        (BY_REGISTER_NOTIFY, &raw const guid),
        (BY_PROTOCOL, ptr::null()),
    ] {
        let mut buffer = [0usize; 64];
        let mut size = size_of::<[Handle; 64]>();
        // SAFETY: All pointers are valid or NULL, and `buffer` is a buffer of `size` bytes.
        let status = unsafe {
            (bs.locate_handle)(
                search_type,
                protocol,
                ptr::null_mut(),
                &mut size,
                buffer.as_mut_ptr(),
            )
        };
        assert_eq!(
            status,
            Status::EFI_INVALID_PARAMETER,
            "SearchType {search_type:#x}"
        );
    }
}

/// LocateHandle(): with SearchType AllHandles, "Protocol and SearchKey are ignored and the function
/// returns an array of every handle in the system". With SearchType ByProtocol, "SearchKey is
/// ignored".
#[test]
fn locate_handle_all_handles() {
    let efi = setup();
    let bs = efi.bs();
    let st = efi.system_table();
    let (guid1, guid2) = (new_guid(), new_guid());

    // A handle that carries multiple protocols
    let handle1 = efi.install_protocol(0, &guid1, new_interface()).unwrap();
    efi.install_protocol(handle1, &guid2, new_interface())
        .unwrap();
    let handle2 = efi.install_protocol(0, &guid1, new_interface()).unwrap();

    let all = efi.locate_handles(ALL_HANDLES, None).unwrap();
    for handle in [
        handle1,
        handle2,
        st.console_in_handle,
        st.console_out_handle,
        efi.image_handle(),
    ] {
        assert_eq!(
            all.iter().filter(|&&h| h == handle).count(),
            1,
            "{handle:#x} in {all:x?}"
        );
    }

    let unknown = new_guid();
    let mut key = 0u64;
    for (search_type, protocol, expected) in [
        (ALL_HANDLES, &raw const unknown, all.clone()),
        (BY_PROTOCOL, &raw const guid1, sorted(&[handle1, handle2])),
    ] {
        let mut buffer = vec![0usize; all.len() + 1];
        let mut size = buffer.len() * size_of::<Handle>();
        // SAFETY: All pointers are valid, and `buffer` is a buffer of `size` bytes.
        let status = unsafe {
            (bs.locate_handle)(
                search_type,
                protocol,
                (&raw mut key).cast(),
                &mut size,
                buffer.as_mut_ptr(),
            )
        };
        assert_eq!(status, Status::EFI_SUCCESS, "SearchType {search_type}");
        assert_eq!(sorted(&buffer[..size / size_of::<Handle>()]), expected);
    }
}

/// LocateHandleBuffer() "returns one or more handles that match the SearchType request. Buffer is
/// allocated from pool, and the number of entries in Buffer is returned in NoHandles."
#[test]
fn locate_handle_buffer_by_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    let handle1 = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let handle2 = efi.install_protocol(0, &guid, new_interface()).unwrap();
    efi.install_protocol(0, &new_guid(), new_interface())
        .unwrap();

    // The buffer is freed using FreePool()
    assert_eq!(
        locate_handle_buffer(&bs, BY_PROTOCOL, &guid),
        Ok(sorted(&[handle1, handle2]))
    );
}

/// LocateHandleBuffer() with SearchType AllHandles returns every handle in the system.
#[test]
fn locate_handle_buffer_all_handles() {
    let efi = setup();
    let bs = efi.bs();

    let handle = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    let all = locate_handle_buffer(&bs, ALL_HANDLES, ptr::null()).unwrap();
    assert!(all.contains(&handle));
    assert_eq!(efi.locate_handles(ALL_HANDLES, None), Ok(all));
}

/// LocateHandleBuffer() returns EFI_NOT_FOUND if "No handles match the search".
#[test]
fn locate_handle_buffer_not_found() {
    let efi = setup();
    let bs = efi.bs();

    assert_eq!(
        locate_handle_buffer(&bs, BY_PROTOCOL, &new_guid()),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// LocateHandleBuffer() returns EFI_INVALID_PARAMETER if "NoHandles is NULL" or "Buffer is NULL".
#[test]
fn locate_handle_buffer_rejects_null_pointers() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    efi.install_protocol(0, &guid, new_interface()).unwrap();
    let mut count = 0;
    let mut buffer = ptr::null_mut();
    // SAFETY: LocateHandleBuffer() must not dereference NULL pointers.
    unsafe {
        assert_eq!(
            (bs.locate_handle_buffer)(
                BY_PROTOCOL,
                &guid,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut buffer
            ),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.locate_handle_buffer)(
                BY_PROTOCOL,
                &guid,
                ptr::null_mut(),
                &mut count,
                ptr::null_mut()
            ),
            Status::EFI_INVALID_PARAMETER
        );
    }
}

/// LocateHandleBuffer() uses the search types of LocateHandle(), and so it rejects invalid search
/// criteria in the same way.
#[test]
fn locate_handle_buffer_rejects_invalid_search() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    efi.install_protocol(0, &guid, new_interface()).unwrap();
    for (search_type, protocol) in [
        (3, &raw const guid),
        (BY_REGISTER_NOTIFY, &raw const guid),
        (BY_PROTOCOL, ptr::null()),
    ] {
        assert_eq!(
            locate_handle_buffer(&bs, search_type, protocol),
            Err(Status::EFI_INVALID_PARAMETER),
            "SearchType {search_type}"
        );
    }
}

/// LocateProtocol() "finds the first device handle that support Protocol, and returns a pointer to
/// the protocol interface from that handle in Interface."
#[test]
fn locate_protocol_returns_interface() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let interface = new_interface();

    efi.install_protocol(0, &guid, interface).unwrap();
    let mut found = ptr::null_mut();
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.locate_protocol)(&guid, ptr::null_mut(), &mut found) };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(found, interface);
}

/// LocateProtocol(): "If no protocol instances are found, then Interface is set to NULL", and
/// EFI_NOT_FOUND is returned.
#[test]
fn locate_protocol_not_found() {
    let efi = setup();
    let bs = efi.bs();

    let mut found = new_interface();
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.locate_protocol)(&new_guid(), ptr::null_mut(), &mut found) };
    assert_eq!(status, Status::EFI_NOT_FOUND);
    assert!(found.is_null());
}

/// LocateProtocol(): "If Interface is NULL, then EFI_INVALID_PARAMETER is returned. If Protocol is
/// NULL, then EFI_INVALID_PARAMETER is returned."
#[test]
fn locate_protocol_rejects_null_pointers() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    efi.install_protocol(0, &guid, new_interface()).unwrap();
    let mut found = ptr::null_mut();
    // SAFETY: LocateProtocol() must not dereference NULL pointers.
    unsafe {
        assert_eq!(
            (bs.locate_protocol)(&guid, ptr::null_mut(), ptr::null_mut()),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.locate_protocol)(ptr::null(), ptr::null_mut(), &mut found),
            Status::EFI_INVALID_PARAMETER
        );
    }
}

/// Calls LocateDevicePath() with `device_path`, and returns the handle and the remaining part of the
/// device path on success.
fn locate_device_path(
    bs: &BootServices,
    protocol: &Guid,
    device_path: *mut DevicePathProtocol,
) -> Result<(Handle, *mut DevicePathProtocol), Status> {
    let mut remaining = device_path;
    let mut device = 0;
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.locate_device_path)(protocol, &mut remaining, &mut device) };
    if status == Status::EFI_SUCCESS {
        Ok((device, remaining))
    } else {
        Err(status)
    }
}

/// Returns the address of the node at `offset` bytes into `device_path`
fn node_at(device_path: *mut DevicePathProtocol, offset: usize) -> *mut DevicePathProtocol {
    device_path.cast::<u8>().wrapping_add(offset).cast()
}

/// The size of the vendor-defined hardware device path nodes used by these tests
const VENDOR_NODE_SIZE: usize = 20;

/// LocateDevicePath(): "If the handle for DevicePath supports the protocol (a direct match), the
/// resulting device path is advanced to the device path terminator node."
#[test]
fn locate_device_path_direct_match() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let node = vendor_node(&new_guid());

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let path = device_path(&[&node]);
    efi.install_protocol(handle, &EFI_DEVICE_PATH_PROTOCOL_GUID, path.cast())
        .unwrap();

    // Use a copy of the device path
    let search = device_path(&[&node]);
    let (device, remaining) = locate_device_path(&bs, &guid, search).unwrap();
    assert_eq!(device, handle);
    assert_eq!(remaining, node_at(search, VENDOR_NODE_SIZE));
    // SAFETY: `remaining` points into the device path created above.
    assert_eq!(unsafe { (*remaining).r#type }, END_DEVICE_PATH_TYPE);
}

/// LocateDevicePath() "locates all devices on DevicePath that support Protocol and returns the
/// handle to the device that is closest to DevicePath. DevicePath is advanced over the device path
/// nodes that were matched."
#[test]
fn locate_device_path_closest_match() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let [a, b, c, x] = [(); 4].map(|_| vendor_node(&new_guid()));

    // Two handles supporting the protocol, with device paths A and A/B
    let handle_a = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let path_a = device_path(&[&a]);
    efi.install_protocol(handle_a, &EFI_DEVICE_PATH_PROTOCOL_GUID, path_a.cast())
        .unwrap();
    let handle_ab = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let path_ab = device_path(&[&a, &b]);
    efi.install_protocol(handle_ab, &EFI_DEVICE_PATH_PROTOCOL_GUID, path_ab.cast())
        .unwrap();

    // A/B/C is closest to A/B, leaving C
    let search = device_path(&[&a, &b, &c]);
    assert_eq!(
        locate_device_path(&bs, &guid, search),
        Ok((handle_ab, node_at(search, 2 * VENDOR_NODE_SIZE)))
    );

    // A/X is closest to A, leaving X
    let search = device_path(&[&a, &x]);
    assert_eq!(
        locate_device_path(&bs, &guid, search),
        Ok((handle_a, node_at(search, VENDOR_NODE_SIZE)))
    );
}

/// LocateDevicePath() only considers handles that support Protocol.
#[test]
fn locate_device_path_requires_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let [a, b] = [(); 2].map(|_| vendor_node(&new_guid()));

    // A supports the protocol, but A/B does not
    let handle_a = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let path_a = device_path(&[&a]);
    efi.install_protocol(handle_a, &EFI_DEVICE_PATH_PROTOCOL_GUID, path_a.cast())
        .unwrap();
    let path_ab = device_path(&[&a, &b]);
    let handle_ab = efi
        .install_protocol(0, &EFI_DEVICE_PATH_PROTOCOL_GUID, path_ab.cast())
        .unwrap();
    efi.install_protocol(handle_ab, &new_guid(), new_interface())
        .unwrap();

    let search = device_path(&[&a, &b]);
    assert_eq!(
        locate_device_path(&bs, &guid, search),
        Ok((handle_a, node_at(search, VENDOR_NODE_SIZE)))
    );

    // No handle with a device path supports this protocol
    assert_eq!(
        locate_device_path(&bs, &new_guid(), device_path(&[&a])),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// LocateDevicePath() returns EFI_NOT_FOUND if "No handles matched the search".
#[test]
fn locate_device_path_not_found() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let [a, b] = [(); 2].map(|_| vendor_node(&new_guid()));

    // A/B supports the protocol, but neither A, nor B, nor B/A match it
    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let path = device_path(&[&a, &b]);
    efi.install_protocol(handle, &EFI_DEVICE_PATH_PROTOCOL_GUID, path.cast())
        .unwrap();

    for search in [
        device_path(&[&a]),
        device_path(&[&b]),
        device_path(&[&b, &a]),
    ] {
        assert_eq!(
            locate_device_path(&bs, &guid, search),
            Err(Status::EFI_NOT_FOUND)
        );
    }
}

/// LocateDevicePath() returns EFI_INVALID_PARAMETER if "Protocol is NULL", "DevicePath is NULL" or
/// "A handle matched the search and Device is NULL".
#[test]
fn locate_device_path_rejects_null_pointers() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let node = vendor_node(&new_guid());

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let path = device_path(&[&node]);
    efi.install_protocol(handle, &EFI_DEVICE_PATH_PROTOCOL_GUID, path.cast())
        .unwrap();

    let mut remaining = path;
    let mut device = 0;
    // SAFETY: LocateDevicePath() must not dereference NULL pointers.
    unsafe {
        assert_eq!(
            (bs.locate_device_path)(ptr::null(), &mut remaining, &mut device),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.locate_device_path)(&guid, ptr::null_mut(), &mut device),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.locate_device_path)(&guid, &mut remaining, ptr::null_mut()),
            Status::EFI_INVALID_PARAMETER
        );
    }
}

/// OpenProtocol() "Queries a handle to determine if it supports a specified protocol. If the
/// protocol is supported by the handle, it opens the protocol on behalf of the calling agent."
#[test]
fn open_protocol_returns_interface() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();
    for attributes in [
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL,
    ] {
        let mut found = ptr::null_mut();
        assert_eq!(
            open_protocol(
                &bs,
                handle,
                &guid,
                &mut found,
                efi.image_handle(),
                0,
                attributes
            ),
            Status::EFI_SUCCESS,
            "Attributes {attributes:#x}"
        );
        assert_eq!(found, interface);
    }
}

/// OpenProtocol() with EFI_OPEN_PROTOCOL_TEST_PROTOCOL tests whether the protocol is supported:
/// Interface "is optional, and will be ignored if Attributes is EFI_OPEN_PROTOCOL_TEST_PROTOCOL."
#[test]
fn open_protocol_test_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let agent = efi.image_handle();
    let test = EFI_OPEN_PROTOCOL_TEST_PROTOCOL;
    assert_eq!(
        open_protocol(&bs, handle, &guid, ptr::null_mut(), agent, 0, test),
        Status::EFI_SUCCESS
    );
    assert_eq!(
        open_protocol(&bs, handle, &new_guid(), ptr::null_mut(), agent, 0, test),
        Status::EFI_UNSUPPORTED
    );

    let sentinel = new_interface();
    let mut found = sentinel;
    assert_eq!(
        open_protocol(&bs, handle, &guid, &mut found, agent, 0, test),
        Status::EFI_SUCCESS
    );
    assert_eq!(found, sentinel);
}

/// OpenProtocol() returns EFI_UNSUPPORTED if "Handle does not support Protocol".
#[test]
fn open_protocol_rejects_unsupported_protocol() {
    let efi = setup();
    let bs = efi.bs();

    let handle = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    let mut found = ptr::null_mut();
    assert_eq!(
        open_protocol(
            &bs,
            handle,
            &new_guid(),
            &mut found,
            efi.image_handle(),
            0,
            EFI_OPEN_PROTOCOL_GET_PROTOCOL
        ),
        Status::EFI_UNSUPPORTED
    );
}

/// OpenProtocol() returns EFI_INVALID_PARAMETER if "Protocol is NULL", or if "Interface is NULL,
/// and Attributes is not TEST_PROTOCOL".
#[test]
fn open_protocol_rejects_null_pointers() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let agent = efi.image_handle();

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let mut found = ptr::null_mut();
    for attributes in [
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL,
        EFI_OPEN_PROTOCOL_TEST_PROTOCOL,
    ] {
        assert_eq!(
            open_protocol(&bs, handle, ptr::null(), &mut found, agent, 0, attributes),
            Status::EFI_INVALID_PARAMETER,
            "Attributes {attributes:#x}"
        );
    }
    for attributes in [
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL,
    ] {
        assert_eq!(
            open_protocol(&bs, handle, &guid, ptr::null_mut(), agent, 0, attributes),
            Status::EFI_INVALID_PARAMETER,
            "Attributes {attributes:#x}"
        );
    }
}

/// OpenProtocol() returns EFI_INVALID_PARAMETER if "Handle is NULL".
#[test]
fn open_protocol_rejects_null_handle() {
    let efi = setup();
    let bs = efi.bs();

    let mut found = ptr::null_mut();
    assert_eq!(
        open_protocol(
            &bs,
            0,
            &new_guid(),
            &mut found,
            efi.image_handle(),
            0,
            EFI_OPEN_PROTOCOL_GET_PROTOCOL
        ),
        Status::EFI_INVALID_PARAMETER
    );
}

/// OpenProtocol() returns EFI_INVALID_PARAMETER if "Attributes is not a legal value".
#[test]
fn open_protocol_rejects_illegal_attributes() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    for attributes in [
        0,
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL | EFI_OPEN_PROTOCOL_GET_PROTOCOL,
        0x40,
        u32::MAX,
    ] {
        let mut found = ptr::null_mut();
        assert_eq!(
            open_protocol(
                &bs,
                handle,
                &guid,
                &mut found,
                efi.image_handle(),
                0,
                attributes
            ),
            Status::EFI_INVALID_PARAMETER,
            "Attributes {attributes:#x}"
        );
    }
}

/// The attributes used by drivers that follow the UEFI driver model require an AgentHandle, and
/// all but EXCLUSIVE also a ControllerHandle: OpenProtocol() returns EFI_INVALID_PARAMETER if, e.g.,
/// "Attributes is BY_DRIVER and AgentHandle is NULL", "Attributes is BY_CHILD_CONTROLLER and
/// ControllerHandle is NULL" or "Attributes is BY_CHILD_CONTROLLER and Handle is identical to
/// ControllerHandle".
#[test]
fn open_protocol_with_driver_model_attributes() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let interface = new_interface();

    let handle = efi.install_protocol(0, &guid, interface).unwrap();
    let controller = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    let agent = efi.image_handle();
    let by_child_controller = EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER;
    let by_driver = EFI_OPEN_PROTOCOL_BY_DRIVER;
    let exclusive = EFI_OPEN_PROTOCOL_EXCLUSIVE;

    for (attributes, agent, controller) in [
        (by_child_controller, 0, controller),
        (by_child_controller, agent, 0),
        (by_child_controller, agent, handle),
        (by_driver, 0, controller),
        (by_driver, agent, 0),
        (by_driver | exclusive, 0, controller),
        (by_driver | exclusive, agent, 0),
        (exclusive, 0, controller),
    ] {
        let mut found = ptr::null_mut();
        assert_eq!(
            open_protocol(
                &bs, handle, &guid, &mut found, agent, controller, attributes
            ),
            Status::EFI_INVALID_PARAMETER,
            "Attributes {attributes:#x} AgentHandle {agent:#x} ControllerHandle {controller:#x}"
        );
    }

    for (attributes, controller) in [
        (by_child_controller, controller),
        (by_driver, controller),
        (by_driver | exclusive, controller),
        (exclusive, 0),
    ] {
        let mut found = ptr::null_mut();
        assert_eq!(
            open_protocol(
                &bs, handle, &guid, &mut found, agent, controller, attributes
            ),
            Status::EFI_SUCCESS,
            "Attributes {attributes:#x}"
        );
        assert_eq!(found, interface);
    }
}

/// CloseProtocol() "Closes a protocol on a handle that was opened using OpenProtocol()."
#[test]
fn close_protocol_closes_open_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let agent = efi.image_handle();

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let mut found = ptr::null_mut();
    assert_eq!(
        open_protocol(
            &bs,
            handle,
            &guid,
            &mut found,
            agent,
            0,
            EFI_OPEN_PROTOCOL_GET_PROTOCOL
        ),
        Status::EFI_SUCCESS
    );
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.close_protocol)(handle, &guid, agent, 0) };
    assert_eq!(status, Status::EFI_SUCCESS);
}

/// CloseProtocol() returns EFI_INVALID_PARAMETER if "Handle is NULL", "AgentHandle is NULL",
/// "ControllerHandle is not NULL and ControllerHandle is not a valid EFI_HANDLE" or "Protocol is
/// NULL".
#[test]
fn close_protocol_rejects_invalid_parameters() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let agent = efi.image_handle();

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    let mut found = ptr::null_mut();
    assert_eq!(
        open_protocol(
            &bs,
            handle,
            &guid,
            &mut found,
            agent,
            0,
            EFI_OPEN_PROTOCOL_GET_PROTOCOL
        ),
        Status::EFI_SUCCESS
    );

    for (handle, protocol, agent, controller) in [
        (0, &raw const guid, agent, 0),
        (handle, ptr::null(), agent, 0),
        (handle, &raw const guid, 0, 0),
        (handle, &raw const guid, agent, BOGUS_HANDLE),
    ] {
        // SAFETY: All pointers are valid or NULL.
        let status = unsafe { (bs.close_protocol)(handle, protocol, agent, controller) };
        assert_eq!(
            status,
            Status::EFI_INVALID_PARAMETER,
            "{handle:#x} {protocol:?} {agent:#x} {controller:#x}"
        );
    }
}

/// CloseProtocol() returns EFI_NOT_FOUND if "Handle does not support the protocol specified by
/// Protocol".
#[test]
fn close_protocol_rejects_unsupported_protocol() {
    let efi = setup();
    let bs = efi.bs();

    let handle = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.close_protocol)(handle, &new_guid(), efi.image_handle(), 0) };
    assert_eq!(status, Status::EFI_NOT_FOUND);
}

/// CloseProtocol() returns EFI_NOT_FOUND if "The protocol interface specified by Handle and
/// Protocol is not currently open by AgentHandle and ControllerHandle".
#[test]
#[ignore = "efiloader does not keep track of open protocols"]
fn close_protocol_rejects_protocol_that_is_not_open() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    let handle = efi.install_protocol(0, &guid, new_interface()).unwrap();
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.close_protocol)(handle, &guid, efi.image_handle(), 0) };
    assert_eq!(status, Status::EFI_NOT_FOUND);
}

/// ProtocolsPerHandle() "retrieves the list of protocol interface GUIDs that are installed on
/// Handle", in a buffer that the caller frees using FreePool().
#[test]
fn protocols_per_handle_returns_protocols() {
    let efi = setup();
    let bs = efi.bs();
    let mut guids = [new_guid(), new_guid(), new_guid()];

    let handle = efi.install_protocol(0, &guids[0], new_interface()).unwrap();
    efi.install_protocol(handle, &guids[1], ptr::null_mut())
        .unwrap();
    efi.install_protocol(handle, &guids[2], new_interface())
        .unwrap();
    // A different handle carrying one of the same protocols
    efi.install_protocol(0, &guids[1], new_interface()).unwrap();

    guids.sort();
    assert_eq!(protocols_per_handle(&bs, handle), Ok(guids.to_vec()));
}

/// ProtocolsPerHandle() returns pointers to GUIDs that remain valid while the protocols are being
/// uninstalled, which is how callers typically use it to remove all protocols from a handle.
#[test]
fn protocols_per_handle_returns_stable_guid_pointers() {
    let efi = setup();
    let bs = efi.bs();
    let guids = [new_guid(), new_guid(), new_guid(), new_guid()];

    let handle = efi.install_protocol(0, &guids[0], new_interface()).unwrap();
    for guid in &guids[1..] {
        efi.install_protocol(handle, guid, new_interface()).unwrap();
    }

    let mut buffer = ptr::null_mut();
    let mut count = 0;
    // SAFETY: All pointers are valid.
    let status = unsafe { (bs.protocols_per_handle)(handle, &mut buffer, &mut count) };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(count, guids.len());

    let mut uninstalled = vec![];
    for i in 0..count {
        // SAFETY: ProtocolsPerHandle() returned a buffer holding `count` GUID pointers, which
        // should still point to the GUIDs of the protocols that have not been uninstalled yet.
        let guid = unsafe { ptr::read(*buffer.add(i)) };
        let interface = efi.handle_protocol(handle, &guid).unwrap();
        assert_eq!(
            uninstall(&bs, handle, &guid, interface),
            Status::EFI_SUCCESS
        );
        uninstalled.push(guid);
    }
    // SAFETY: The buffer was allocated from pool by ProtocolsPerHandle().
    assert_eq!(
        unsafe { (bs.free_pool)(buffer.cast()) },
        Status::EFI_SUCCESS
    );

    uninstalled.sort();
    assert_eq!(uninstalled, guids.to_vec());
    assert!(
        !efi.locate_handles(ALL_HANDLES, None)
            .unwrap()
            .contains(&handle)
    );
}

/// ProtocolsPerHandle() returns EFI_INVALID_PARAMETER if "ProtocolBuffer is NULL" or
/// "ProtocolBufferCount is NULL".
#[test]
fn protocols_per_handle_rejects_null_pointers() {
    let efi = setup();
    let bs = efi.bs();

    let handle = efi
        .install_protocol(0, &new_guid(), new_interface())
        .unwrap();
    let mut buffer = ptr::null_mut();
    let mut count = 0;
    // SAFETY: ProtocolsPerHandle() must not dereference NULL pointers.
    unsafe {
        assert_eq!(
            (bs.protocols_per_handle)(handle, ptr::null_mut(), &mut count),
            Status::EFI_INVALID_PARAMETER
        );
        assert_eq!(
            (bs.protocols_per_handle)(handle, &mut buffer, ptr::null_mut()),
            Status::EFI_INVALID_PARAMETER
        );
    }
}

/// ProtocolsPerHandle() returns EFI_INVALID_PARAMETER if "Handle is NULL" or "Handle is not a valid
/// EFI_HANDLE".
#[test]
fn protocols_per_handle_rejects_invalid_handle() {
    let efi = setup();
    let bs = efi.bs();

    for handle in [0, BOGUS_HANDLE] {
        assert_eq!(
            protocols_per_handle(&bs, handle),
            Err(Status::EFI_INVALID_PARAMETER),
            "{handle:#x}"
        );
    }
}

/// InstallMultipleProtocolInterfaces() "installs a set of protocol interfaces into the boot
/// services environment", where "If Handle is NULL on entry, then a new handle will be allocated."
#[test]
fn install_multiple_protocol_interfaces_creates_handle() {
    let efi = setup();
    let bs = efi.bs();
    let (guid1, guid2) = (new_guid(), new_guid());
    let (interface1, interface2) = (new_interface(), new_interface());

    let mut handle = 0;
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            &mut handle,
            &raw const guid1,
            interface1,
            &raw const guid2,
            interface2,
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_ne!(handle, 0);
    assert_eq!(efi.handle_protocol(handle, &guid1), Ok(interface1));
    assert_eq!(efi.handle_protocol(handle, &guid2), Ok(interface2));
}

/// InstallMultipleProtocolInterfaces() installs the protocols onto the handle passed in.
#[test]
fn install_multiple_protocol_interfaces_on_existing_handle() {
    let efi = setup();
    let bs = efi.bs();
    let (guid1, guid2, guid3) = (new_guid(), new_guid(), new_guid());
    let (interface1, interface2) = (new_interface(), new_interface());

    let mut handle = efi.install_protocol(0, &guid3, new_interface()).unwrap();
    let existing = handle;
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            &mut handle,
            &raw const guid1,
            interface1,
            &raw const guid2,
            interface2,
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(handle, existing);
    assert_eq!(efi.handle_protocol(handle, &guid1), Ok(interface1));
    assert_eq!(efi.handle_protocol(handle, &guid2), Ok(interface2));
}

/// InstallMultipleProtocolInterfaces() takes a variable number of arguments, which may exceed the
/// number that is passed in registers.
#[test]
fn install_multiple_protocol_interfaces_with_many_protocols() {
    let efi = setup();
    let bs = efi.bs();
    let g = [(); 6].map(|_| new_guid());
    let i = [(); 6].map(|_| new_interface());

    let mut handle = 0;
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            &mut handle,
            &raw const g[0],
            i[0],
            &raw const g[1],
            i[1],
            &raw const g[2],
            i[2],
            &raw const g[3],
            i[3],
            &raw const g[4],
            i[4],
            &raw const g[5],
            i[5],
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    for (guid, interface) in g.iter().zip(i) {
        assert_eq!(efi.handle_protocol(handle, guid), Ok(interface));
    }
}

/// InstallMultipleProtocolInterfaces() returns EFI_INVALID_PARAMETER if "Handle is NULL".
#[test]
fn install_multiple_protocol_interfaces_rejects_null_handle() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();

    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer. A NULL Handle pointer must not be dereferenced.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            ptr::null_mut(),
            &raw const guid,
            new_interface(),
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// InstallMultipleProtocolInterfaces() returns EFI_INVALID_PARAMETER if "Protocol is already
/// installed on the handle specified by Handle": "If any errors are generated while the protocol
/// interfaces are being installed, then all the protocols installed prior to the error will be
/// uninstalled".
#[test]
fn install_multiple_protocol_interfaces_rejects_installed_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let (guid1, guid2, guid3) = (new_guid(), new_guid(), new_guid());
    let interface = new_interface();

    let mut handle = efi.install_protocol(0, &guid2, interface).unwrap();
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            &mut handle,
            &raw const guid1,
            new_interface(),
            &raw const guid2,
            new_interface(),
            &raw const guid3,
            new_interface(),
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
    assert_eq!(protocols_per_handle(&bs, handle), Ok(vec![guid2]));
    assert_eq!(efi.handle_protocol(handle, &guid2), Ok(interface));
}

/// InstallMultipleProtocolInterfaces(): "The same GUID cannot be installed more than once onto the
/// same handle", and so a list containing the same GUID twice cannot be installed.
#[test]
fn install_multiple_protocol_interfaces_rejects_duplicate_protocol() {
    let efi = setup();
    let bs = efi.bs();
    let (guid1, guid2) = (new_guid(), new_guid());

    let mut handle = 0;
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            &mut handle,
            &raw const guid1,
            new_interface(),
            &raw const guid2,
            new_interface(),
            &raw const guid1,
            new_interface(),
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_INVALID_PARAMETER);
    for guid in [guid1, guid2] {
        assert_eq!(
            efi.locate_handles(BY_PROTOCOL, Some(&guid)),
            Err(Status::EFI_NOT_FOUND)
        );
    }
}

/// InstallMultipleProtocolInterfaces(): "If an identical Device Path Protocol instance is already
/// present in the handle database, then no protocols are installed onto Handle, and
/// EFI_ALREADY_STARTED is returned."
#[test]
fn install_multiple_protocol_interfaces_rejects_duplicate_device_path() {
    let efi = setup();
    let bs = efi.bs();
    let guid = new_guid();
    let node = vendor_node(&new_guid());

    let path = device_path(&[&node]);
    efi.install_protocol(0, &EFI_DEVICE_PATH_PROTOCOL_GUID, path.cast())
        .unwrap();

    // An identical copy of the device path
    let copy = device_path(&[&node]);
    let device_path_guid = EFI_DEVICE_PATH_PROTOCOL_GUID;
    let mut handle = 0;
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            &mut handle,
            &raw const guid,
            new_interface(),
            &raw const device_path_guid,
            copy,
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_ALREADY_STARTED);
    assert_eq!(
        efi.locate_handles(BY_PROTOCOL, Some(&guid)),
        Err(Status::EFI_NOT_FOUND)
    );
}

/// InstallMultipleProtocolInterfaces() only rejects device paths that are identical to one that is
/// already installed, not ones that share a prefix with it.
#[test]
fn install_multiple_protocol_interfaces_accepts_distinct_device_paths() {
    let efi = setup();
    let bs = efi.bs();
    let [a, b] = [(); 2].map(|_| vendor_node(&new_guid()));

    let path_ab = device_path(&[&a, &b]);
    efi.install_protocol(0, &EFI_DEVICE_PATH_PROTOCOL_GUID, path_ab.cast())
        .unwrap();

    let path_a = device_path(&[&a]);
    let device_path_guid = EFI_DEVICE_PATH_PROTOCOL_GUID;
    let mut handle = 0;
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.install_multiple_protocol_interfaces)(
            &mut handle,
            &raw const device_path_guid,
            path_a,
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(
        efi.handle_protocol(handle, &EFI_DEVICE_PATH_PROTOCOL_GUID),
        Ok(path_a.cast())
    );
}

/// UninstallMultipleProtocolInterfaces() "removes a set of protocol interfaces from the boot
/// services environment".
#[test]
fn uninstall_multiple_protocol_interfaces_removes_interfaces() {
    let efi = setup();
    let bs = efi.bs();
    let (guid1, guid2, guid3) = (new_guid(), new_guid(), new_guid());
    let (interface1, interface2, interface3) = (new_interface(), new_interface(), new_interface());

    let handle = efi.install_protocol(0, &guid1, interface1).unwrap();
    efi.install_protocol(handle, &guid2, interface2).unwrap();
    efi.install_protocol(handle, &guid3, interface3).unwrap();

    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.uninstall_multiple_protocol_interfaces)(
            handle,
            &raw const guid1,
            interface1,
            &raw const guid3,
            interface3,
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert_eq!(protocols_per_handle(&bs, handle), Ok(vec![guid2]));

    // Removing the remaining protocol frees the handle
    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.uninstall_multiple_protocol_interfaces)(
            handle,
            &raw const guid2,
            interface2,
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert!(
        !efi.locate_handles(ALL_HANDLES, None)
            .unwrap()
            .contains(&handle)
    );
}

/// UninstallMultipleProtocolInterfaces() takes a variable number of arguments, which may exceed the
/// number that is passed in registers.
#[test]
fn uninstall_multiple_protocol_interfaces_with_many_protocols() {
    let efi = setup();
    let bs = efi.bs();
    let g = [(); 6].map(|_| new_guid());
    let i = [(); 6].map(|_| new_interface());

    let handle = efi.install_protocol(0, &g[0], i[0]).unwrap();
    for (guid, interface) in g.iter().zip(i).skip(1) {
        efi.install_protocol(handle, guid, interface).unwrap();
    }

    // SAFETY: The variable argument list consists of GUID and interface pointer pairs, terminated
    // by a NULL GUID pointer.
    let status = unsafe {
        (bs.uninstall_multiple_protocol_interfaces)(
            handle,
            &raw const g[0],
            i[0],
            &raw const g[1],
            i[1],
            &raw const g[2],
            i[2],
            &raw const g[3],
            i[3],
            &raw const g[4],
            i[4],
            &raw const g[5],
            i[5],
            ptr::null::<Guid>(),
        )
    };
    assert_eq!(status, Status::EFI_SUCCESS);
    assert!(
        !efi.locate_handles(ALL_HANDLES, None)
            .unwrap()
            .contains(&handle)
    );
}

/// UninstallMultipleProtocolInterfaces(): "If any errors are generated while the protocol
/// interfaces are being uninstalled, then the protocols uninstalled prior to the error will be
/// reinstalled ... and the status code EFI_INVALID_PARAMETER is returned."
#[test]
fn uninstall_multiple_protocol_interfaces_rejects_unknown_interface() {
    let efi = setup();
    let bs = efi.bs();
    let (guid1, guid2) = (new_guid(), new_guid());
    let (interface1, interface2) = (new_interface(), new_interface());

    let handle = efi.install_protocol(0, &guid1, interface1).unwrap();
    efi.install_protocol(handle, &guid2, interface2).unwrap();

    for (protocol, interface) in [(guid2, new_interface()), (new_guid(), interface2)] {
        // SAFETY: The variable argument list consists of GUID and interface pointer pairs,
        // terminated by a NULL GUID pointer.
        let status = unsafe {
            (bs.uninstall_multiple_protocol_interfaces)(
                handle,
                &raw const guid1,
                interface1,
                &raw const protocol,
                interface,
                ptr::null::<Guid>(),
            )
        };
        assert_eq!(status, Status::EFI_INVALID_PARAMETER);
        assert_eq!(efi.handle_protocol(handle, &guid1), Ok(interface1));
        assert_eq!(efi.handle_protocol(handle, &guid2), Ok(interface2));
    }
}
