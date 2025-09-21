// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

use crate::guid;
use crate::EfiProtocol;
use crate::{status::*, Bool, Char16, Event, Guid};

use alloc::boxed::Box;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr;

const EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID: Guid = guid!("387477c1-69c7-11d2-8e39-00a0c969723b");

const EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID: Guid = guid!("387477c2-69c7-11d2-8e39-00a0c969723b");

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct KeyStroke(u16, Char16);

#[repr(C)]
pub struct EfiSimpleTextInput {
    reset: Reset<Self>,
    read_key_stroke: ReadKeyStroke,
    wait_for_key: Event,
}

#[repr(C)]
pub(crate) struct SimpleTextInput {
    pub(crate) text_input: EfiSimpleTextInput,
    conin: fn() -> Option<u8>,
}

type Reset<T> = extern "efiapi" fn(this: *mut T, extended_verification: Bool) -> Status;

type ReadKeyStroke =
    extern "efiapi" fn(this: *mut EfiSimpleTextInput, key: *mut KeyStroke) -> Status;

#[repr(C)]
pub struct EfiSimpleTextOutputMode {
    max_mode: i32,
    mode: i32,
    attribute: i32,
    cursor_column: i32,
    cursor_row: i32,
    cursor_visible: Bool,
}

#[repr(C)]
pub struct EfiSimpleTextOutput {
    reset: Reset<Self>,
    output_string: OutputString,
    test_string: OutputString,
    query_mode: QueryMode,
    set_mode: SetMode,
    set_attribute: SetAttribute,
    clear_screen: ClearScreen,
    set_cursor_position: SetCursorPosition,
    enable_cursor: EnableCursor,
    mode: *mut EfiSimpleTextOutputMode,
}

#[repr(C)]
pub struct SimpleTextOutput {
    pub(crate) text_output: EfiSimpleTextOutput,
    mode: EfiSimpleTextOutputMode,
    conout: fn(&str),
    pin: PhantomPinned,
}

type OutputString =
    extern "efiapi" fn(this: *mut EfiSimpleTextOutput, string: *const Char16) -> Status;

type QueryMode = extern "efiapi" fn(
    this: *mut EfiSimpleTextOutput,
    mode_number: usize,
    columns: *mut usize,
    rows: *mut usize,
) -> Status;

type SetMode = extern "efiapi" fn(this: *mut EfiSimpleTextOutput, mode_number: usize) -> Status;

type SetAttribute = extern "efiapi" fn(this: *mut EfiSimpleTextOutput, attribute: usize) -> Status;

type ClearScreen = extern "efiapi" fn(this: *mut EfiSimpleTextOutput) -> Status;

type SetCursorPosition =
    extern "efiapi" fn(this: *mut EfiSimpleTextOutput, column: usize, row: usize) -> Status;

type EnableCursor = extern "efiapi" fn(this: *mut EfiSimpleTextOutput, visible: Bool) -> Status;

extern "efiapi" fn reset<T>(this: *mut T, _extended_verification: Bool) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }
    Status::EFI_SUCCESS
}

extern "efiapi" fn read_key_stroke(this: *mut EfiSimpleTextInput, key: *mut KeyStroke) -> Status {
    if this.is_null() || key.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let this = unsafe { &*(this as *mut SimpleTextInput) };
    if let Some(ks) = this.read_key_stroke() {
        let k = unsafe { &mut *key };
        *k = ks;
        Status::EFI_SUCCESS
    } else {
        Status::EFI_NOT_READY
    }
}

impl SimpleTextInput {
    pub fn new(conin: fn() -> Option<u8>) -> Pin<Box<SimpleTextInput>> {
        Box::pin(SimpleTextInput {
            text_input: EfiSimpleTextInput {
                reset: reset::<EfiSimpleTextInput>,
                read_key_stroke: read_key_stroke,
                wait_for_key: Event(ptr::null_mut()),
            },
            conin: conin,
        })
    }

    fn read_key_stroke(&self) -> Option<KeyStroke> {
        let ks = match (self.conin)()? {
            // ESC
            0x1B => match (self.conin)() {
                Some(b'[') => match (self.conin)()? {
                    b'A' => KeyStroke(0x1, 0),
                    b'B' => KeyStroke(0x2, 0),
                    b'C' => KeyStroke(0x3, 0),
                    b'D' => KeyStroke(0x4, 0),
                    b'F' => KeyStroke(0x6, 0),
                    b'H' => KeyStroke(0x5, 0),

                    b'1' | b'7' => {
                        (self.conin)()?;
                        KeyStroke(0x5, 0)
                    }
                    b'4' | b'8' => {
                        (self.conin)()?;
                        KeyStroke(0x6, 0)
                    }
                    b'2' => {
                        (self.conin)()?;
                        KeyStroke(0x7, 0)
                    }
                    b'3' => {
                        (self.conin)()?;
                        KeyStroke(0x8, 0)
                    }
                    b'5' => {
                        (self.conin)()?;
                        KeyStroke(0x9, 0)
                    }
                    b'6' => {
                        (self.conin)()?;
                        KeyStroke(0xa, 0)
                    }
                    c => {
                        log::trace!("{c:x?}?");
                        return None;
                    }
                },
                Some(b'h') => KeyStroke(0x5, 0),
                Some(b'K') => KeyStroke(0x6, 0),
                Some(b'+') => KeyStroke(0x7, 0),
                Some(b'-') => KeyStroke(0x8, 0),
                Some(b'?') => KeyStroke(0x9, 0),
                Some(b'/') => KeyStroke(0xa, 0),
                Some(b'1') => KeyStroke(0xb, 0),
                Some(b'2') => KeyStroke(0xc, 0),
                Some(b'3') => KeyStroke(0xd, 0),
                Some(b'4') => KeyStroke(0xe, 0),
                Some(b'5') => KeyStroke(0xf, 0),
                Some(b'6') => KeyStroke(0x10, 0),
                Some(b'7') => KeyStroke(0x11, 0),
                Some(b'8') => KeyStroke(0x12, 0),
                Some(b'9') => KeyStroke(0x13, 0),
                Some(b'0') => KeyStroke(0x14, 0),
                None => KeyStroke(0x17, 0),
                c => {
                    log::trace!("{c:x?}?");
                    return None;
                }
            },
            // BackSpace
            0x7f => KeyStroke(0x0, 0x8),

            c => KeyStroke(0x0, c as Char16),
        };
        Some(ks)
    }
}

impl EfiProtocol for SimpleTextInput {
    fn guid(&self) -> &'static Guid {
        &EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID
    }
}

unsafe impl Send for SimpleTextInput {}

extern "efiapi" fn output_string(this: *mut EfiSimpleTextOutput, string: *const Char16) -> Status {
    if this.is_null() || string.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    let (this, string) = unsafe {
        (
            &mut *(this as *mut SimpleTextOutput),
            widestring::U16CStr::from_ptr_str(string).to_string_lossy(),
        )
    };

    (this.conout)(&string);
    for s in string.chars() {
        match s {
            '\r' => {
                this.mode.cursor_column = 0;
            }
            '\n' => {
                this.mode.cursor_row += 1;
            }
            _ => {
                this.mode.cursor_column += 1;
            }
        };
    }
    Status::EFI_SUCCESS
}

extern "efiapi" fn test_string(this: *mut EfiSimpleTextOutput, string: *const Char16) -> Status {
    if this.is_null() || string.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    log::trace!("TestString called\n");
    Status::EFI_SUCCESS
}

extern "efiapi" fn query_mode(
    this: *mut EfiSimpleTextOutput,
    mode_number: usize,
    columns: *mut usize,
    rows: *mut usize,
) -> Status {
    if this.is_null() || columns.is_null() || rows.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    match mode_number {
        0 => {
            let (columns, rows) = unsafe { (&mut *columns, &mut *rows) };
            (*columns, *rows) = (80, 25);
            Status::EFI_SUCCESS
        }
        _ => Status::EFI_UNSUPPORTED,
    }
}

extern "efiapi" fn set_mode(this: *mut EfiSimpleTextOutput, mode_number: usize) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    match mode_number {
        0 => Status::EFI_SUCCESS,
        _ => Status::EFI_UNSUPPORTED,
    }
}

extern "efiapi" fn set_attribute(this: *mut EfiSimpleTextOutput, _attribute: usize) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    Status::EFI_SUCCESS
}

extern "efiapi" fn clear_screen(this: *mut EfiSimpleTextOutput) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    log::trace!("Clear screen");
    let this = unsafe { &mut *(this as *mut SimpleTextOutput) };
    (this.conout)("\x1b[=3h\x1b[2J\x1b[H");
    this.mode.cursor_column = 0;
    this.mode.cursor_row = 0;
    Status::EFI_SUCCESS
}

extern "efiapi" fn set_cursor_position(
    this: *mut EfiSimpleTextOutput,
    column: usize,
    row: usize,
) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    if column >= 80 || row >= 25 {
        return Status::EFI_UNSUPPORTED;
    }
    log::trace!("Set cursor position to {row},{column}");
    let this = unsafe { &mut *(this as *mut SimpleTextOutput) };
    this.mode.cursor_column = column as i32;
    this.mode.cursor_row = row as i32;

    let column = column as u8 + 1;
    let row = row as u8 + 1;
    let cmd = &[
        0x1b,
        b'[',
        (b'0' + (row / 10)),
        (b'0' + (row % 10)),
        b';',
        (b'0' + (column / 10)),
        (b'0' + (column % 10)),
        b'f',
    ];
    (this.conout)(core::str::from_utf8(cmd).unwrap());
    Status::EFI_SUCCESS
}

extern "efiapi" fn enable_cursor(this: *mut EfiSimpleTextOutput, _visible: Bool) -> Status {
    if this.is_null() {
        return Status::EFI_INVALID_PARAMETER;
    }

    Status::EFI_SUCCESS
}

impl SimpleTextOutput {
    pub fn new(conout: fn(&str)) -> Pin<Box<SimpleTextOutput>> {
        let mut p = Box::new(SimpleTextOutput {
            text_output: EfiSimpleTextOutput {
                reset: reset::<EfiSimpleTextOutput>,
                output_string: output_string,
                test_string: test_string,
                query_mode: query_mode,
                set_mode: set_mode,
                set_attribute: set_attribute,
                clear_screen: clear_screen,
                set_cursor_position: set_cursor_position,
                enable_cursor: enable_cursor,
                mode: ptr::null_mut(),
            },
            mode: EfiSimpleTextOutputMode {
                max_mode: 0,
                mode: 0,
                attribute: 0,
                cursor_column: 0,
                cursor_row: 0,
                cursor_visible: 1,
            },
            conout: conout,
            pin: PhantomPinned,
        });
        p.text_output.mode = &mut p.mode;
        Pin::from(p)
    }
}

impl EfiProtocol for SimpleTextOutput {
    fn guid(&self) -> &'static Guid {
        &EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID
    }
}

unsafe impl Send for SimpleTextOutput {}
