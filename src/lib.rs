// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

//! This crate implements a stripped down EFI runtime that can be used by bootloader
//! implementations to provide the EFI context needed by OS loaders such as EFI stub Linux kernels,
//! systemd-boot UKI images or even GRUB+shim.
//!
//! The EFI runtime implements the following features/APIs:
//! - a memory map and associated page and pool allocation routines, as well as an implementation
//! of the GetMemoryMap() EFI boot service to deliver the final memory map to the OS;
//! - a EFI protocol database that supports installing and uninstalling protocols, locating handle
//! and protocol buffers and locating device paths;
//! - a EFI configuration table database
//!
//! The following EFI features are NOT supported:
//! - the UEFI driver model
//! - asynchronous events and notifications
//!
//! The runtime services related to timekeeping, the EFI variable store and reset/poweroff are left
//! to the caller to implement, as they cannot be implemented generically. The same applies to the
//! Stall() boot services.
//!
//! # Example
//!
//! ```
//! fn run_efi_image(
//!     image: impl efiloader::FileLoader + Send + 'static,
//!     mapper: impl efiloader::MemoryMapper + 'static,
//!     random: impl efiloader::Random + 'static,
//! ) {
//!     let ram = 0..0x100_0000;
//!     let memmap = efiloader::memmap::MemoryMap::new();
//!     memmap.declare_memory_region(&ram).unwrap();
//!
//!     let efi = efiloader::init(
//!         None::<&dyn efiloader::SimpleConsole>,
//!         memmap,
//!         mapper,
//!         Some(random),
//!     )
//!     .expect("Failed to init EFI runtime");
//!
//!     if let Some(mut li) = efi.load_image(&image) {
//!         let ret = li.start_image();
//!         println!("EFI app returned {ret:?}\n");
//!     }
//! }
//! ```

#![no_std]

macro_rules! align_up {
    ($value:expr, $alignment:expr) => {
        (($value - 1) | ($alignment - 1)) + 1
    };
}

use crate::{
    bootservices::*, configtable::*, loadedimage::*, memattr::*, memmap::*, memorytype::*,
    peloader::*, rng::*, runtimeservices::*, simpletext::*, systemtable::*, EfiMemoryType::*,
};

use core::cell::*;
use core::mem::*;
use core::ops::*;
use core::pin::*;
use core::ptr::*;
use core::sync::atomic::{AtomicUsize, Ordering};

extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use once_cell::unsync::OnceCell;

const UEFI_REVISION: u32 = (2 << 16) | 100; // 2.10

pub mod blockio;
pub mod bootservices;
#[cfg(target_arch = "aarch64")]
mod cmo;
mod configtable;
pub mod devicepath;
mod initrdloadfile2;
mod loadedimage;
mod memattr;
pub mod memmap;
pub mod memorytype;
mod peloader;
mod poolalloc;
mod rng;
pub mod runtimeservices;
mod simpletext;
pub mod status;
mod systemtable;
mod tableheader;

pub type Bool = u8;
pub type Char16 = u16;
type PhysicalAddress = u64;
type VirtualAddress = u64;
pub type Handle = usize;
type Tpl = usize;
#[repr(transparent)]
pub struct Event(*mut ());
type EventNotify = extern "efiapi" fn(Event, *const ());
pub type Lba = u64;

pub(crate) fn new_handle() -> usize {
    static COUNTER: AtomicUsize = AtomicUsize::new(1);
    COUNTER.fetch_add(1, Ordering::AcqRel)
}

const TPL_APPLICATION: Tpl = 4;
#[allow(dead_code)]
const TPL_CALLBACK: Tpl = 8;
#[allow(dead_code)]
const TPL_NOTIFY: Tpl = 16;
#[allow(dead_code)]
const TPL_HIGH_LEVEL: Tpl = 31;

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[macro_export]
macro_rules! guid {
    ($a:literal, $b:literal, $c: literal, $d:expr) => {
        Guid {
            data1: $a,
            data2: $b,
            data3: $c,
            data4: $d,
        }
    };
}

/// An implementation of this trait may be provided to the EFI runtime at initialization
/// time, allowing it to print diagnostic messages, and check for key presses.
pub trait SimpleConsole {
    fn write_string(&self, s: &str);
    fn read_byte(&self) -> Option<u8>;
}

/// An implementation of this trait must be provided to the EFI runtime at initialization time so
/// that the PE/COFF loader as well as the Memory Attributes Protocol implementation exposed by the
/// EFI runtime are able to manage permission attributes on memory ranges.
/// # Example
/// ```
/// #  use core::ops::Range;
/// struct MemoryMapper;
/// impl efiloader::MemoryMapper for MemoryMapper {
///     fn remap_range(&self, range: &Range<usize>, set: u64, clr: u64) -> Result<(), &str> {
///         let prot = libc::PROT_READ
///             | match clr & !set {
///                 EFI_MEMORY_RO => libc::PROT_WRITE,
///                 EFI_MEMORY_XP => libc::PROT_EXEC,
///                 0 => 0,
///                 _ => libc::PROT_WRITE | libc::PROT_EXEC,
///             };
///
///         unsafe { libc::mprotect(range.start as *mut _, range.end - range.start, prot) };
///         Ok(())
///     }
///
///     fn query_range(&self, _range: &Range<usize>) -> Option<u64> {
///         todo!();
///     }
/// }
/// ```

pub trait MemoryMapper {
    fn remap_range(&self, range: &Range<usize>, set: u64, clr: u64) -> Result<(), &str>;
    fn query_range(&self, range: &Range<usize>) -> Option<u64>;
}

/// Implementations of this trait should be provided for loading kernels, initial ramdisks and
/// potentially other assets (e.g., disk images) that are needed to load the OS.
pub trait FileLoader {
    /// Returns the size of the file
    fn get_size(&self) -> usize;

    /// Fills `loadbuffer` with as much of the file as will fit. Any remaining space will be
    /// zeroed. A reference to a [u8] slice covering the same memory region will be returned on
    /// success.
    fn load_file<'a>(&self, loadbuffer: &'a mut [MaybeUninit<u8>]) -> Result<&'a [u8], &str>;

    /// Copies `size` bytes from the file starting at `offset` into `loadbuffer`. It is up to the
    /// caller to ensure that `loadbuffer` points to a buffer with sufficient space.
    unsafe fn load_range<'a>(
        &self,
        loadbuffer: *mut (),
        offset: usize,
        size: usize,
    ) -> Result<(), &str>;
}

/// An implementation of this trait may be provided to the EFI runtime at initialization time so
/// that the PE/COFF loader and the EFI random number generator protocol have access to a source of
/// random numbers.
/// # Example
/// ```
/// # use rand::Rng;
/// struct Random {}
/// impl efiloader::Random for Random {
///     fn get_entropy(&self, bytes: &mut [u8], _use_raw: bool) -> bool {
///         let mut rng = rand::thread_rng();
///         bytes.fill_with(|| rng.gen::<u8>());
///         true
///     }
/// }
/// ```
pub trait Random {
    /// Fills `bytes` with random bytes, and returns `true` on success. If no source of randomness
    /// is available, or it returned an error, `false` will be returned. If `use_raw` is `true` and
    /// no source of raw entropy is available, `false` will be returned.
    fn get_entropy(&self, bytes: &mut [u8], use_raw: bool) -> bool;
}

const EFI_RT_PROPERTIES_TABLE_GUID: Guid = guid!(
    0xeb66918a,
    0x7eef,
    0x402a,
    [0x84, 0x2e, 0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9]
);

const EFI_RT_SUPPORTED_GET_TIME: u32 = 0x0001;
const EFI_RT_SUPPORTED_SET_TIME: u32 = 0x0002;
const EFI_RT_SUPPORTED_GET_VARIABLE: u32 = 0x0010;
const EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME: u32 = 0x0020;
const EFI_RT_SUPPORTED_RESET_SYSTEM: u32 = 0x0400;

#[repr(C)]
struct RtPropertiesTable {
    version: u16,
    length: u16,
    supported_mask: u32,
}

/// Implementations of EFI protocols must implement this trait in order to be installable into the
/// protocol database managed by the EFI runtime.
pub trait EfiProtocol {
    /// The protocol pointer. By default, this returns a pointer to the struct itself, but this
    /// assumes that the struct is `#[repr(C)]` and exposes the C function pointers directly.
    /// In cases where the `EfiProtocol` implementation wraps a C struct in a different manner,
    /// this method may be overridden to produce the C struct pointer in another way.
    fn as_proto_ptr(&self) -> *const () {
        self as *const _ as *const ()
    }

    /// A reference to the `Guid` that identifies the implementation of the EFI protocol.
    fn guid(&self) -> &Guid;
}

pub(crate) type ProtocolDb = BTreeMap<(Handle, Guid), Pin<Box<dyn EfiProtocol + Send>>>;

pub struct EfiContext {
    cfgtable: ConfigTableDb,
    pub(crate) protocol_db: RefCell<ProtocolDb>,

    pub(crate) con: Option<&'static dyn SimpleConsole>,
    pub(crate) memmap: MemoryMap,
    pub(crate) mapper: Box<dyn MemoryMapper>,
    pub(crate) rng: Option<Box<dyn Random>>,

    bs: RefCell<Box<BootServices>>,
    rt: RefCell<PoolBox<RuntimeServices>>,
    pub(crate) st: RefCell<PoolBox<SystemTable>>,
}

static EFI: EfiContextHolder = EfiContextHolder(OnceCell::new());
struct EfiContextHolder(OnceCell<EfiContext>);

// SAFETY: EFI boot services are single threaded, and the held context is only accessible via
// shared references. Interior mutability of the member data is implemented using RefCell wrappers,
// which track borrows at runtime, and will panic if the same thread ends up borrowing the same
// data multiple times in an unsupported manner.
unsafe impl Sync for EfiContextHolder {}

impl Deref for EfiContextHolder {
    type Target = EfiContext;

    fn deref(&self) -> &Self::Target {
        &self.0.get().expect("efiloader::init() has not been called yet")
    }
}

pub(crate) fn efi_system_table() -> *const SystemTable {
    &**EFI.st.borrow()
}

/// Initializes the EFI runtime, and returns a reference to a [`EfiContext`] instance that
/// encapsulates its API.
///
/// Due to the fact that EFI boot and runtime services do not take a `this` pointer, it is not
/// possible to disambiguate between different instances of this type, and so every call to
/// [`init`] will return a reference to the same instance, but only the arguments passed via the
/// first call will be taken into account.
///
/// A [`SimpleConsole`] implementation may be passed via`con`, which will be used as the EFI
/// SimpleText in/output protocol exposed via the EFI System Table.
///
/// A EFI [`MemoryMap`] describing at least a few MiB of [`EfiConventionalMemory`] must be provided so
/// that the init code can set up the memory pools needed for the system and runtime services
/// tables and the array of configuration tables.
///
/// A [`MemoryMapper`] implementation must be provided via `mapper` so that the EFI runtime can
/// manage permissions on memory ranges described in the memory map.
///
/// A [`Random`] implementation may be provided via `rng`.
pub fn init(
    con: Option<&'static (dyn SimpleConsole)>,
    memmap: MemoryMap,
    mapper: impl MemoryMapper + 'static,
    rng: Option<impl Random + 'static>,
) -> Result<&'static EfiContext, ()> {
    EFI.0.get_or_try_init(move || {
        let conhandle = new_handle();
        let inp = SimpleTextInput::new(EfiContext::read_byte);
        let out = SimpleTextOutput::new(EfiContext::write_string);

        let bs = Box::new(BootServices::new());

        let rt = memmap
            .box_new(EfiRuntimeServicesData, RuntimeServices::new())
            .or(Err(()))?;

        let st = memmap
            .box_new(
                EfiRuntimeServicesData,
                SystemTable::new(&*bs, &*rt, &inp.text_input, &out.text_output, conhandle),
            )
            .or(Err(()))?;

        let ctx = EfiContext {
            cfgtable: ConfigTableDb::new(),
            protocol_db: RefCell::new(BTreeMap::new()),
            con: con,
            memmap: memmap,
            mapper: Box::new(mapper),
            rng: rng.map(|r| Box::new(r) as _),

            bs: RefCell::new(bs),
            rt: RefCell::new(rt),
            st: RefCell::new(st),
        };

        ctx.install_pinned_protocol(conhandle, inp);
        ctx.install_pinned_protocol(conhandle, out);
        ctx.install_protocol(None, EfiMemoryAttribute::new());
        ctx.install_protocol(None, EfiRng::new());

        let rtprop = ctx
            .memmap
            .box_new(
                EfiACPIReclaimMemory,
                RtPropertiesTable {
                    version: 1,
                    length: core::mem::size_of::<RtPropertiesTable>() as _,
                    supported_mask: EFI_RT_SUPPORTED_GET_TIME
                        | EFI_RT_SUPPORTED_SET_TIME
                        | EFI_RT_SUPPORTED_GET_VARIABLE
                        | EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME
                        | EFI_RT_SUPPORTED_RESET_SYSTEM,
                },
            )
            .or(Err(()))?;

        ctx.install_configtable(&EFI_RT_PROPERTIES_TABLE_GUID, rtprop);
        Ok(ctx)
    })
}

impl EfiContext {
    pub(crate) fn install_pinned_protocol<T: EfiProtocol + Send + 'static>(
        &self,
        handle: Handle,
        protocol: Pin<Box<T>>,
    ) {
        self.protocol_db
            .borrow_mut()
            .insert((handle, *protocol.guid()), protocol);
    }

    /// Install `protocol` onto `handle`; if `handle` is `None`, a new one will be allocated.
    /// Returns the handle onto which the protocol was installed.
    pub fn install_protocol<T: EfiProtocol + Send + 'static>(
        &self,
        handle: Option<Handle>,
        protocol: T,
    ) -> Handle {
        let handle = handle.unwrap_or_else(|| new_handle());
        self.install_pinned_protocol(handle, Box::pin(protocol));
        handle
    }

    /// Uninstalls the protocol identified by `guid` from `handle`.
    pub fn uninstall_protocol<T>(&self, handle: Handle, guid: &Guid, _protocol: &T) {
        self.protocol_db.borrow_mut().remove(&(handle, *guid));
    }

    /// Installs a EFI configuration table identified by `guid`. If `table` is a raw NULL pointer,
    /// a EFI configuration table identified by `guid` will be uninstalled if one was installed.
    pub fn install_configtable<T>(&self, guid: &Guid, table: T)
    where
        T: Into<ConfigurationTablePointer>,
    {
        self.cfgtable.install(guid, table, self)
    }

    /// Installs `initrd` as the FileLoader implementation that will back the EFI LoadFile2 protocol
    /// based initial ramdisk loading method specified by Linux using a dedicated vendor media
    /// device path.
    pub fn set_initrd_loader(&self, initrd: impl FileLoader + Send + 'static) {
        initrdloadfile2::install(self, initrd);
    }

    pub(crate) fn get_entropy(&self, buf: &mut [u8], use_raw: bool) -> bool {
        self.rng
            .as_ref()
            .map(|r| r.get_entropy(buf, use_raw))
            .unwrap_or(false)
    }

    /// Load the image exposed by `loader` as a EFI PE/COFF image. Returns a `LoadedImageData`
    /// instance on success which can be used to set load options and start the image, or `None` on
    /// failure.
    pub fn load_image<'a>(&'static self, loader: &'a dyn FileLoader) -> Option<LoadedImageData> {
        let pe_ldr = PeLoader::new(loader, self)?;

        let align = EFI_PAGE_SIZE.max(pe_ldr.section_alignment()) as u64;
        let mut seed: [u8; 4] = [0; 4];
        let (placement, randomized) = if self.get_entropy(&mut seed, false) {
            (Placement::Random(u32::from_le_bytes(seed), align), true)
        } else {
            (Placement::Aligned(align), false)
        };

        let pe_image = pe_ldr.load(EfiLoaderCode, placement, &*self.mapper)?;

        Some(LoadedImageData::new(
            &self,
            &pe_image,
            EfiLoaderCode,
            EfiLoaderData,
            randomized,
        ))
    }

    /// Override the Get/SetTime EFI runtime services by local implementations.
    pub fn override_time_handler(&self, get: GetTime, set: Option<SetTime>) {
        let mut rt = self.rt.borrow_mut();
        rt.get_time = get;
        set.map(|s| rt.set_time = s);
        rt.hdr.update_crc();
    }

    /// Override the Get/SetVariable EFI runtime services by local implementations.
    pub fn override_variable_handler(
        &self,
        get: GetVariable,
        get_next: GetNextVariableName,
        set: Option<SetVariable>,
    ) {
        let mut rt = self.rt.borrow_mut();
        rt.get_variable = get;
        rt.get_next_variable_name = get_next;
        set.map(|s| rt.set_variable = s);
        rt.hdr.update_crc();
    }

    /// Override the ResetSystem EFI runtime services by a local implementation
    pub fn override_reset_handler(&self, f: ResetSystem) {
        let mut rt = self.rt.borrow_mut();
        rt.reset_system = f;
        rt.hdr.update_crc();
    }

    /// Override the Stall EFI boot service by a local implementations
    pub fn override_stall_handler(&self, f: Stall) {
        let mut bs = self.bs.borrow_mut();
        bs.stall = f;
        bs.hdr.update_crc();
    }

    fn write_string(s: &str) {
        EFI.con.map(|c| c.write_string(s));
    }

    fn read_byte() -> Option<u8> {
        EFI.con?.read_byte()
    }

    /// Allocate `size` bytes of EFI pool memory of type `pool_type`.
    pub fn allocate_pool(&self, pool_type: EfiMemoryType, size: usize) -> Result<NonNull<u8>, ()> {
        self.memmap
            .allocate_pool::<u8>(pool_type, size)
            .map_err(|e| log::debug!("Allocate pool failed {e}"))
    }

    /// Free pool memory at `buffer` that was allocated via [`allocate_pool`](Self::allocate_pool).
    /// Return an error if `buffer` is not recognized as a valid pool allocation.
    pub fn free_pool(&self, buffer: *const u8) -> Result<(), ()> {
        self.memmap.free_pool(buffer)
    }

    /// Allocate `pages` 4KiB pages of memory of type `_type`. The `placement` argument described
    /// the desired placement, which is decribed [`here`](memmap::Placement). Returns the allocated
    /// memory as a `[MaybeUninit<u8>]` slice, or `None` if the requested placement could not be
    /// honored.
    pub fn allocate_pages(
        &self,
        pages: usize,
        _type: EfiMemoryType,
        placement: Placement,
    ) -> Option<&'static mut [MaybeUninit<u8>]> {
        self.memmap.allocate_pages(pages, _type, placement)
    }

    /// Deallocate `pages` 4KiB pages of memory as address `base`. Returns an `Ok` result on
    /// success, or `Err` if the pages could not be freed.
    pub fn free_pages(&self, base: u64, pages: usize) -> Result<(), ()> {
        self.memmap.free_pages(base, pages)
    }
}
