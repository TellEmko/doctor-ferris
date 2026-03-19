<div align="center">
  <img src="github-assets/doctor-ferris.png" alt="Doctor Ferris Logo" />
  <h1>Doctor Ferris 🦀💉</h1>
  <p><strong>High-performance, secure, and modular dynamic library injection framework for Rust.</strong></p>
  <a href="https://github.com/TellEmko/doctor-ferris/actions"><img src="https://img.shields.io/github/actions/workflow/status/TellEmko/doctor-ferris/ci.yml" alt="Build Status"></a>
  <a href="https://crates.io/crates/doctor-ferris"><img src="https://img.shields.io/crates/v/doctor-ferris.svg" alt="Crates.io"></a>
</div>

## Overview

Doctor Ferris is a production-grade, multi-platform dynamic library injector library and CLI. It is engineered with a strict focus on performance, safety, modularity, and extensibility. Whether you are building modding platforms, analyzing malware, or instrumenting game clients, Doctor Ferris provides a robust and ergonomic API to get your payload where it belongs.

### Key Features

*   **Cross-Platform Support**: Native backends for **Windows** (primary), **Linux**, and **macOS**.
*   **Architecture Validation**: Strict checks to prevent injecting x86 payloads into x64 processes (and vice versa), saving you from immediate crashes.
*   **Pluggable Architecture**: Injectors are implemented via traits (`InjectionMethod`), allowing you to register your own custom "private sauce" injection techniques perfectly integrated into the framework.
*   **Injection Modes**: Choose between `Stability` (safest methods), `Stealth` (evasive methods), and `Compatibility` to let the registry automatically pick the best tool for the job.
*   **Advanced Evasion** (Windows): Multiple techniques to bypass user-mode hooks and EDR telemetry, including `NtCreateThreadEx` bypasses, Thread Context Hijacking, APC injection, and full PE Manual Mapping.
*   **Feature-Gated CLI**: Use the library natively within your Rust application or enable the `cli` feature for a powerful standalone penetration testing tool.

## Installation

Add Doctor Ferris to your `Cargo.toml`:

```toml
[dependencies]
doctor-ferris = "0.1"
```

To enable advanced stealth methods:
```toml
doctor-ferris = { version = "0.1", features = ["stealth"] }
```

To install the standalone CLI:
```bash
cargo install doctor-ferris --features cli
```

## Quick Start (Library)

```rust
use doctor_ferris::{Injector, InjectionConfig, InjectionMode};

fn main() -> doctor_ferris::Result<()> {
    // 1. Initialize the injector framework with platform defaults
    let injector = Injector::new();

    // 2. Configure the injection job
    let config = InjectionConfig::builder()
        .dll_path("payload.dll")
        .target_name("target_game.exe")
        .mode(InjectionMode::Stealth)
        .elevate(true) // Automatically request UAC/sudo if needed
        .build()?;

    // 3. Execute! The Injector handles architecture validation,
    //    method selection, and payload delivery.
    let result = injector.inject(&config)?;
    
    println!("Successfully injected using: {}", result.method_name);
    Ok(())
}
```

## Platform Support Matrix

### Windows (x86 / x64)
*   `loadlibrary`: Classic `CreateRemoteThread` + `LoadLibraryA`. Highly reliable.
*   `ntcreatethread`: Bypasses shallow API hooks on `CreateRemoteThread`.
*   `thread_hijack`: Suspends a thread, redirects RIP to load the DLL, and resumes. Evades thread creation monitoring (Stealth).
*   `apc_injection`: Queues an APC to an alertable thread. (Stealth).
*   `manual_map`: Manually maps the PE sections and resolves base relocations, effectively making the module invisible in the PEB module lists (Requires `stealth` feature).

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

Example: Injection into a specific PID using Stealth mode.
```bash
doctor-ferris inject -p 1337 -d C:\path\to\payload.dll --mode stealth --elevate
```

## Safety & Security

Dynamic injection is inherently dangerous. Doctor Ferris mitigates this by validating PE/ELF/Mach-O headers against the target process architecture *before* the first byte of memory is modified. 

## Extensibility

Want to implement your own kernel-mode driver injector or a new exotic exploit? Simply implement the `InjectionMethod` trait and register it to the `Injector` instance!

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
