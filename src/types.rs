//! Core types shared across the injection framework.
//!
//! These types form the vocabulary used by the injector, platform backends,
//! and injection methods.

use std::fmt;
use std::path::PathBuf;

/// CPU architecture of a process or binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// 32-bit x86 (IA-32).
    X86,
    /// 64-bit x86-64 (AMD64).
    X86_64,
    /// Architecture could not be determined.
    Unknown,
}

impl Architecture {
    /// Returns `true` if two architectures are injection-compatible.
    ///
    /// A DLL can only be injected into a process of the same architecture.
    pub fn is_compatible_with(self, other: Architecture) -> bool {
        match (self, other) {
            (Architecture::X86, Architecture::X86) => true,
            (Architecture::X86_64, Architecture::X86_64) => true,
            _ => false,
        }
    }

    /// Returns the pointer width in bytes for this architecture.
    pub fn pointer_size(self) -> usize {
        match self {
            Architecture::X86 => 4,
            Architecture::X86_64 => 8,
            Architecture::Unknown => std::mem::size_of::<usize>(),
        }
    }

    /// Returns the architecture of the current compilation target.
    pub fn current() -> Self {
        if cfg!(target_arch = "x86_64") {
            Architecture::X86_64
        } else if cfg!(target_arch = "x86") {
            Architecture::X86
        } else {
            Architecture::Unknown
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Architecture::X86 => write!(f, "x86"),
            Architecture::X86_64 => write!(f, "x86_64"),
            Architecture::Unknown => write!(f, "unknown"),
        }
    }
}

/// Supported operating system platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
}

impl Platform {
    /// Returns the platform of the current compilation target.
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "macos") {
            Platform::MacOS
        } else {
            // Fallback — user will get PlatformUnsupported at injection time.
            Platform::Linux
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::Windows => write!(f, "windows"),
            Platform::Linux => write!(f, "linux"),
            Platform::MacOS => write!(f, "macOS"),
        }
    }
}

/// Unique identifier for a system process.
pub type Pid = u32;

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Operating system process ID.
    pub pid: Pid,
    /// Process executable name (e.g. `notepad.exe`).
    pub name: String,
    /// Detected CPU architecture of the process.
    pub architecture: Architecture,
}

impl fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}] ({})", self.name, self.pid, self.architecture)
    }
}

/// Describes the outcome of a successful injection operation.
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// Name of the injection method that was used.
    pub method_name: String,
    /// The target process that received the injection.
    pub target: ProcessInfo,
    /// Path of the injected library.
    pub dll_path: PathBuf,
    /// Base address of the loaded module in the target process, if available.
    pub base_address: Option<usize>,
    /// Human-readable details about the injection.
    pub details: String,
}

impl fmt::Display for InjectionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Injected '{}' into {} via [{}]",
            self.dll_path.display(),
            self.target,
            self.method_name
        )?;
        if let Some(addr) = self.base_address {
            write!(f, " at 0x{:X}", addr)?;
        }
        Ok(())
    }
}
