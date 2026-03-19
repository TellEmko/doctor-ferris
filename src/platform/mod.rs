//! Platform abstraction layer.
//!
//! This module conditionally compiles the correct backend for the host OS
//! and exposes platform-agnostic entry points consumed by [`crate::process`]
//! and [`crate::injector`].

use crate::error::Result;
use crate::types::{Architecture, Pid, ProcessInfo};

// ── Platform backends ────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

// ── Platform-agnostic dispatch ───────────────────────────────────────

/// Enumerate all visible processes on the current platform.
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
    #[cfg(target_os = "windows")]
    {
        windows::process::enumerate()
    }
    #[cfg(target_os = "linux")]
    {
        linux::process::enumerate()
    }
    #[cfg(target_os = "macos")]
    {
        macos::process::enumerate()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(crate::error::DoctorError::PlatformUnsupported(
            "unsupported operating system".into(),
        ))
    }
}

/// Detect the CPU architecture of a running process.
pub fn detect_architecture(pid: Pid) -> Result<Architecture> {
    #[cfg(target_os = "windows")]
    {
        windows::process::detect_architecture(pid)
    }
    #[cfg(target_os = "linux")]
    {
        linux::process::detect_architecture(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::process::detect_architecture(pid)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err(crate::error::DoctorError::PlatformUnsupported(
            "unsupported operating system".into(),
        ))
    }
}

/// Check whether the current process is running with elevated privileges.
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::privilege::is_elevated()
    }
    #[cfg(target_os = "linux")]
    {
        linux::privilege::is_elevated()
    }
    #[cfg(target_os = "macos")]
    {
        macos::privilege::is_elevated()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}
