# efiloader

`efiloader` is a `no_std` Rust library that implements a minimal UEFI environment. It provides
just enough of the UEFI boot services, runtime services, protocols and configuration tables for a
program that is not UEFI firmware to load and start EFI applications.

It is intended for boot loaders, hypervisors and other bare-metal programs that want to boot an
operating system the way UEFI firmware does, by running its EFI loader, without having to implement
UEFI themselves. EFI applications that it can run include:

- EFI stub Linux kernels and EFI zboot images, along with an initrd that is passed via the
  LoadFile2 protocol, as Linux expects;
- unified kernel images (UKIs) built with systemd-stub, including the addons, credentials and
  system extensions that systemd-stub loads from the volume that it was loaded from;
- other OS loaders, such as systemd-boot, or GRUB with shim.

The EFI application runs at the privilege level and with the MMU configuration of the program that
embeds efiloader. It calls back into efiloader via the boot services, until it calls
ExitBootServices(), at which point it owns the system.

## Features

- **Memory**: an EFI memory map that is built from the memory regions declared by the embedder,
  page and pool allocation, GetMemoryMap(), the EFI Memory Attributes Table and the EFI memory
  attribute protocol.
- **Images**: a PE/COFF loader that maps images with strict permissions (W^X), and the image
  services: LoadImage() (from memory, from a simple file system or via LoadFile2), StartImage(),
  Exit() and UnloadImage(). Images may load and start other images, as systemd-stub and EFI zboot
  images do with the kernel they carry.
- **Protocols**: the protocol database, including handle and device path lookup, OpenProtocol(),
  CloseProtocol() and ProtocolsPerHandle(). Embedders can install protocols of their own.
- **Configuration tables**, including the EFI RT properties table, and any tables the embedder
  installs, e.g., ACPI or device tree tables.
- **Console**: the simple text input and output protocols, backed by the embedder.
- **Randomness**: the EFI RNG protocol, backed by the embedder, which is also used to randomize the
  placement of images in memory.
- **Files**: the LoadFile2 protocol that Linux uses to load its initrd, read-only volumes that
  expose the contents of a cpio archive via the simple file system protocol, and a block I/O
  protocol backed by a file.
- **Robustness**: an optional hook to authenticate the image files that EFI images load, e.g., the
  addons of a UKI, and an optional limit on the time that EFI images may stall for.

Not implemented:

- the UEFI driver model;
- asynchronous events and notifications;
- runtime services that need platform support, unless the embedder provides its own
  implementations: GetTime(), SetTime(), SetVariable() and ResetSystem() return `EFI_UNSUPPORTED`,
  and GetVariable() and GetNextVariableName() behave as if there were no variables at all.
  SetVirtualAddressMap() is not supported;
- Stall() returns immediately, unless the embedder provides its own implementation.

## Requirements

- **Architecture**: aarch64 or x86_64.
- **Allocator**: efiloader uses the `alloc` crate, and so a global allocator must be provided.
- **Memory**: the embedder declares the memory that the EFI runtime and the EFI images may use.
  efiloader uses the addresses of that memory as pointers, and passes them to EFI images as
  physical addresses. To boot an OS, that memory must therefore be identity mapped, as UEFI
  requires.
- **Runtime services**: the EFI runtime services table points to functions in the embedder's
  executable, and the OS may call them after ExitBootServices(). If the OS is to use the runtime
  services, including efiloader's default implementations, the memory that holds the embedder's
  code and data must be declared as runtime regions, so that the OS keeps it mapped.
- **Memory permissions**: a `MemoryMapper` implementation must apply the memory permissions that
  the PE/COFF loader and the memory attribute protocol ask for.
- **Single threaded**: there is a single EFI runtime per program at any given time. It is created
  by the first call to `efiloader::init()`, and must only be used from one thread, as is the case
  for UEFI boot services in general. `efiloader::deinit()` tears it down again, e.g., after a failed
  attempt to boot an image, so that the next call to `efiloader::init()` creates a new one.

The console (`SimpleConsole`) and the source of randomness (`Random`) are optional, and so is a
function that receives efiloader's diagnostic messages, which can be registered using
`efiloader::logger::set_logger()`.

The `strict_nx` feature, which is enabled by default, makes the PE/COFF loader refuse images that it
cannot map with strict permissions, e.g., because their sections are not page aligned. Without it,
such images are mapped read-write-execute instead.

## Examples

### Booting an EFI stub Linux kernel

The embedder provides a console, a way to change memory permissions and a source of randomness by
implementing the corresponding traits. The `platform` module stands for the embedder's own code.

```rust
use core::ops::Range;
use efiloader::memorytype::{EFI_MEMORY_RO, EFI_MEMORY_XP};

/// The EFI console, backed by a UART
struct Uart;

impl efiloader::SimpleConsole for Uart {
    fn write_string(&self, s: &str) {
        s.bytes().for_each(platform::uart_putc);
    }

    fn read_byte(&self) -> Option<u8> {
        platform::uart_getc()
    }
}

static CONSOLE: Uart = Uart;

/// Changes the permissions of memory ranges in the identity map. `set` and `clr` are combinations
/// of EFI_MEMORY_RO and EFI_MEMORY_XP to set and to clear, respectively.
struct Mapper;

impl efiloader::MemoryMapper for Mapper {
    fn remap_range(&self, range: &Range<usize>, set: u64, clr: u64) -> Result<(), &str> {
        let read_only = set & EFI_MEMORY_RO != 0;
        let executable = clr & EFI_MEMORY_XP != 0;
        platform::set_permissions(range, read_only, executable)
    }

    /// Returns the EFI_MEMORY_RO and EFI_MEMORY_XP attributes of `range`, if they are uniform
    fn query_range(&self, range: &Range<usize>) -> Option<u64> {
        platform::get_permissions(range)
    }
}

/// A hardware random number generator
struct HwRng;

impl efiloader::Random for HwRng {
    fn get_entropy(&self, bytes: &mut [u8], _use_raw: bool) -> bool {
        platform::rng_fill(bytes)
    }
}
```

With those in place, booting a kernel takes a memory map, the kernel image, the initrd and the
command line:

```rust
use efiloader::FileLoader;
use efiloader::memmap::MemoryMap;
use efiloader::memorytype::EFI_MEMORY_WB;
use efiloader::memorytype::EfiMemoryType::{EfiRuntimeServicesCode, EfiRuntimeServicesData};
use efiloader::status::Status;

/// Boots `kernel`, an EFI stub kernel or EFI zboot image, with `initrd` and the command line
/// `cmdline`. Only returns if the kernel fails to boot.
fn boot_linux(
    kernel: &dyn FileLoader,
    initrd: impl FileLoader + Send + 'static,
    cmdline: &str,
) -> Status {
    let memmap = MemoryMap::new();
    // SAFETY: this memory is identity mapped, and not used for anything else
    unsafe { memmap.declare_memory_region(&platform::free_memory()) }.unwrap();

    // The runtime services live in this executable, which has to remain mapped for the OS
    let (text, data) = platform::executable_regions();
    memmap
        .declare_runtime_region(&text, EfiRuntimeServicesCode, EFI_MEMORY_WB, EFI_MEMORY_RO)
        .unwrap();
    memmap
        .declare_runtime_region(&data, EfiRuntimeServicesData, EFI_MEMORY_WB, EFI_MEMORY_XP)
        .unwrap();

    let console: &'static dyn efiloader::SimpleConsole = &CONSOLE;
    let efi = efiloader::init(Some(console), memmap, Mapper, Some(HwRng)).unwrap();

    // Linux loads its initrd via the LoadFile2 protocol
    efi.set_initrd_loader(initrd);

    let mut image = efi.load_image(kernel).expect("not a valid EFI image");

    // The command line is passed as the load options of the image, as a NUL terminated UTF-16
    // string
    image.set_load_options(cmdline.encode_utf16().chain([0]).collect());

    // Only returns if the kernel fails to boot: otherwise, it calls ExitBootServices() and takes
    // over the system
    image.start_image()
}
```

Configuration tables that the OS needs, e.g., the device tree or the ACPI tables, can be installed
using `EfiContext::install_configtable()` before the image is started.

### Providing files

efiloader accesses the images, initrds and archives that it is given via the `FileLoader` trait, so
that the embedder can provide them from wherever they are stored. This is how a file that is in
memory already can be exposed:

```rust
use core::mem::MaybeUninit;
use core::ptr;

/// A file that has been loaded into memory
struct MemFile(&'static [u8]);

impl efiloader::FileLoader for MemFile {
    fn get_size(&self) -> usize {
        self.0.len()
    }

    fn load_file<'a>(&self, buf: &'a mut [MaybeUninit<u8>]) -> Result<&'a [u8], &str> {
        // SAFETY: `buf` is valid for writes of its entire size, all of which load_range()
        // initializes when it succeeds
        unsafe {
            self.load_range(buf.as_mut_ptr().cast(), 0, buf.len())?;
            Ok(core::slice::from_raw_parts(buf.as_ptr().cast(), buf.len()))
        }
    }

    unsafe fn load_range<'a>(&self, buf: *mut (), offset: usize, size: usize) -> Result<(), &str> {
        let src = self.0.get(offset..).ok_or("offset out of range")?;
        let len = size.min(src.len());
        let dst = buf.cast::<u8>();
        // SAFETY: the caller guarantees that `buf` is valid for writes of `size` bytes. Space
        // beyond the end of the file is zeroed.
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
            ptr::write_bytes(dst.add(len), 0, size - len);
        }
        Ok(())
    }
}
```

A disk image can be exposed to OS loaders that access disks directly, such as GRUB, by installing
an `efiloader::blockio::EfiBlockIoProtocol` that wraps it, using `EfiContext::install_protocol()`.

### Booting a unified kernel image with its sidecar files

systemd-stub locates the addons, credentials and system extensions that accompany a UKI via the
device and file path that the UKI was loaded from. efiloader can expose a cpio archive as a
read-only volume, and present the UKI as having been loaded from a file on it. Given an archive
that is laid out like an EFI system partition, e.g.,

```text
EFI/Linux/uki.efi.extra.d/local.addon.efi
EFI/Linux/uki.efi.extra.d/local.cred
loader/addons/global.addon.efi
loader/credentials/global.cred
```

the UKI can be booted as follows:

```rust
use efiloader::status::Status;
use efiloader::{EfiContext, FileLoader, Guid, guid};

/// The vendor GUID that identifies the volume via its device path: generate your own
const VOLUME_GUID: Guid = guid!(
    0x3c1b9f5e,
    0x7d42,
    0x4a8b,
    [0x9e, 0x06, 0x51, 0xc8, 0x2f, 0xa4, 0xd7, 0x13]
);

/// Only accepts signed images: addons can change the command line and replace the device tree
struct SignedImagesOnly;

impl efiloader::ImageVerifier for SignedImagesOnly {
    fn verify(&self, image: &[u8]) -> bool {
        platform::has_valid_signature(image)
    }
}

fn boot_uki(
    efi: &'static EfiContext,
    uki: &dyn FileLoader,
    archive: impl FileLoader + Send + 'static,
) -> Status {
    let volume = efi
        .install_cpio_volume(archive, &VOLUME_GUID)
        .expect("malformed cpio archive");

    // Authenticate the addons and other images that EFI images load from the volume
    efi.set_image_verifier(SignedImagesOnly);

    // Terminate images that stall for more than 5 minutes in total, e.g., in the infinite loop
    // that systemd-stub enters after a fatal error, rather than hang forever
    efi.set_stall_limit(5 * 60 * 1_000_000);

    let mut image = efi
        .load_image_with_file_path(uki, volume, "\\EFI\\Linux\\uki.efi")
        .expect("not a valid EFI image");
    image.start_image()
}
```

### Providing platform services

Services that need platform support can be provided by the embedder, using `extern "efiapi"`
functions:

```rust
use efiloader::EfiContext;
use efiloader::runtimeservices::ResetType;
use efiloader::status::Status;

extern "efiapi" fn reset_system(
    kind: ResetType,
    _status: Status,
    _size: usize,
    _data: *const (),
) -> Status {
    match kind {
        ResetType::EfiResetShutdown => platform::power_off(),
        _ => platform::reset(),
    }
}

extern "efiapi" fn stall(micro_seconds: usize) -> Status {
    platform::delay_us(micro_seconds);
    Status::EFI_SUCCESS
}

fn install_platform_services(efi: &EfiContext) {
    efi.override_reset_handler(reset_system);
    efi.override_stall_handler(stall);
}
```

GetTime()/SetTime() and the variable services can be provided in the same way, using
`EfiContext::override_time_handler()` and `EfiContext::override_variable_handler()`.

### Running EFI applications in a process

efiloader can also run EFI applications in an ordinary user space process, e.g., to test them, or
to test efiloader itself, as its test suite does. The application must be built for the
architecture of the host, e.g., using the `x86_64-unknown-uefi` Rust target, and it cannot access
any hardware, of course. Using the `MemFile` type from above, and the `libc` crate:

```rust
use core::ops::Range;
use efiloader::memorytype::{EFI_MEMORY_RO, EFI_MEMORY_XP};
use std::io::Write;

/// Prints the output of the EFI application to stdout
struct Stdout;

impl efiloader::SimpleConsole for Stdout {
    fn write_string(&self, s: &str) {
        print!("{s}");
        std::io::stdout().flush().unwrap();
    }

    fn read_byte(&self) -> Option<u8> {
        None
    }
}

static CONSOLE: Stdout = Stdout;

/// Changes the permissions of the process's memory using mprotect()
struct Mprotect;

impl efiloader::MemoryMapper for Mprotect {
    fn remap_range(&self, range: &Range<usize>, set: u64, clr: u64) -> Result<(), &str> {
        let mut prot = libc::PROT_READ | libc::PROT_WRITE;
        if set & EFI_MEMORY_RO != 0 {
            prot &= !libc::PROT_WRITE;
        }
        if clr & EFI_MEMORY_XP != 0 {
            prot |= libc::PROT_EXEC;
        }
        // SAFETY: efiloader only remaps memory that was declared to it below
        match unsafe { libc::mprotect(range.start as *mut libc::c_void, range.len(), prot) } {
            0 => Ok(()),
            _ => Err("mprotect() failed"),
        }
    }

    fn query_range(&self, _range: &Range<usize>) -> Option<u64> {
        None
    }
}

/// Provides randomness via getrandom()
struct GetRandom;

impl efiloader::Random for GetRandom {
    fn get_entropy(&self, bytes: &mut [u8], _use_raw: bool) -> bool {
        // SAFETY: `bytes` is valid for writes of its entire size
        let n = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        n == bytes.len() as isize
    }
}

fn main() {
    const RAM_SIZE: usize = 64 << 20;

    // SAFETY: this creates a new private anonymous mapping, which is not used by anything else
    let ram = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            RAM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ram, libc::MAP_FAILED);
    let ram = ram as usize..ram as usize + RAM_SIZE;

    let memmap = efiloader::memmap::MemoryMap::new();
    // SAFETY: the mapping is used exclusively by the EFI runtime for the lifetime of the process
    unsafe { memmap.declare_memory_region(&ram) }.unwrap();

    let console: &'static dyn efiloader::SimpleConsole = &CONSOLE;
    let efi = efiloader::init(Some(console), memmap, Mprotect, Some(GetRandom)).unwrap();

    // Print efiloader's warnings and errors to stderr
    efiloader::logger::set_logger(|level, args| {
        if level <= efiloader::logger::Level::Warn {
            eprintln!("efiloader: {level:?}: {args}");
        }
    });

    let path = std::env::args().nth(1).expect("usage: run-efi <image>");
    let app = MemFile(std::fs::read(path).unwrap().leak());
    let mut image = efi.load_image(&app).expect("not a valid EFI image");
    println!("EFI application returned {:?}", image.start_image());
}
```

## Testing

`cargo test` runs the test suite, which embeds efiloader in the test process, and exercises the
boot services via EFI images that are created on the fly. It can be run for aarch64 on an x86_64
host using QEMU user mode emulation. Emulating QEMU's `max` CPU model ensures that pointer
authentication is implemented, so that it is exercised by the tests as well:

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64 -cpu max -L /usr/aarch64-linux-gnu" \
cargo test --target aarch64-unknown-linux-gnu
```

## License

efiloader is licensed under the GNU General Public License, version 2. See [LICENSE](LICENSE).
