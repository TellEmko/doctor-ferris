<div align="center">
  <img src="github-assets/doctor-ferris.png" alt="Doctor Ferris Logo" />
  <h1>Doctor Ferris</h1>
  <p><strong>Dynamic library injection framework for Rust.</strong></p>
  <a href="https://github.com/TellEmko/doctor-ferris/actions"><img src="https://img.shields.io/github/actions/workflow/status/TellEmko/doctor-ferris/ci.yml" alt="Build Status"></a>
  <a href="https://crates.io/crates/doctor-ferris"><img src="https://img.shields.io/crates/v/doctor-ferris.svg" alt="Crates.io"></a>
</div>

## Overview

Doctor Ferris is a cross-platform library and CLI for dynamic library injection. It provides an API for inserting payloads into running processes on Windows, Linux, and macOS.

### Features

*   **Cross-Platform**: Windows, Linux, and macOS support.
*   **Architecture Validation**: Prevents cross-arch injections (e.g., x86 DLL into x64 process).
*   **Extensible**: Custom methods can be added via the `InjectionMethod` trait.
*   **Techniques** (Windows): Thread hijacking, APC injection, and manual mapping.
*   **CLI**: Available as a standalone tool or library.

## Installation

Add Doctor Ferris to your `Cargo.toml`:

```toml
[dependencies]
doctor-ferris = "0.2"
```

To install the standalone CLI:
```bash
cargo install doctor-ferris --features cli
```

## Quick Start (Library)

```rust
use doctor_ferris::{Injector, InjectionConfig};

fn main() -> doctor_ferris::Result<()> {
    // 1. Initialize the injector framework with platform defaults
    let injector = Injector::new();

    // 2. Configure the injection job
    let config = InjectionConfig::builder()
        .dll_path("payload.dll")
        .target_name("target_game.exe")
        .method("manual_map") // Selects the injection technique
        .stealth(true)        // Ex. header cleanup
        .elevate(true)        // Request UAC/sudo if needed
        .build()?;

    // 3. Execute
    let result = injector.inject(&config)?;
    
    println!("Successfully injected using: {}", result.method_name);
    Ok(())
}
```

## Platform Support Matrix

### Windows (x86 / x64)
*   `loadlibrary`: Classic `CreateRemoteThread` + `LoadLibraryA`. Highly reliable.
*   `ntcreatethread`: Bypasses shallow API hooks on `CreateRemoteThread`.
*   `thread_hijack`: Suspends a thread, redirects RIP to load the DLL, and resumes. Evades thread creation monitoring.
*   `apc_injection`: Queues an APC to an alertable thread.
*   `manual_map`: Manually maps the PE sections and resolves base relocations, effectively making the module invisible in the PEB module lists.

### Linux (x64)
*   `ptrace`: Attaches to target, modifies registers to call `dlopen`, detaches.
*   `ld_preload`: *Pre-launch* injection by spawning the child with `LD_PRELOAD` set.

### macOS (x86_64)
*   `task_inject`: Uses Mach tasks to write and execute `dlopen` shellcode.
*   `dyld_insert`: *Pre-launch* injection using `DYLD_INSERT_LIBRARIES`.

## CLI Usage

```
Usage: doctor-ferris <COMMAND>

Commands:
  inject         Inject a DLL or shared object into a target process
  list-methods   List all available injection methods
  list-processes List all visible running processes
  help           Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Example: Manual map injection:
```bash
doctor-ferris inject -p 1337 -d C:\path\to\payload.dll --method manual_map --stealth --elevate
```

## Safety

Doctor Ferris validates PE/ELF/Mach-O headers against the target process architecture before attempting injection to prevent crashes. 

## Extensibility

You can implement your own injection strategies by implementing the `InjectionMethod` trait and registering it:

```rust
struct MyCustomMethod;

impl InjectionMethod for MyCustomMethod { ... }

let mut injector = Injector::new();
injector.register_method(Box::new(MyCustomMethod));
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on bug reports, feature requests, and code contributions.

## Disclaimer

**Doctor Ferris is provided for educational and research purposes only.** Do not use this software for malicious activities or against systems you do not have explicit permission to alter.

## License

MIT License. See `LICENSE` for more information.
