//! `DYLD_INSERT_LIBRARIES`-based pre-launch injection for macOS.
//!
//! Spawns the target executable with `DYLD_INSERT_LIBRARIES` set, causing
//! `dyld` to load the specified dylib before the application starts. This is
//! the macOS equivalent of `LD_PRELOAD`.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// DYLD_INSERT_LIBRARIES pre-launch injection method.
pub struct DyldInsertMethod;

impl InjectionMethod for DyldInsertMethod {
    fn name(&self) -> &str {
        "dyld_insert"
    }

    fn description(&self) -> &str {
        "DYLD_INSERT_LIBRARIES pre-launch injection — initiates a new target process with the specified dynamic library pre-loaded."
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::MacOS]
    }

    fn supported_architectures(&self) -> &[Architecture] {
        &[Architecture::X86, Architecture::X86_64]
    }

    fn reliability(&self) -> u8 {
        90
    }

    fn compatibility(&self) -> u8 {
        85
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        let dylib_path = config.dll_path.canonicalize().map_err(|e| {
            DoctorError::InvalidPath(format!("{}: {}", config.dll_path.display(), e))
        })?;

        let dylib_str = dylib_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("The dynamic library path contains invalid UTF-8 characters".into()))?;

        log::info!(
            "[dyld_insert] Initiating target execution: '{}' with preloaded library: '{}'",
            target.name,
            dylib_str
        );

        let child = std::process::Command::new(&target.name)
            .env("DYLD_INSERT_LIBRARIES", dylib_str)
            .env("DYLD_FORCE_FLAT_NAMESPACE", "1")
            .spawn()
            .map_err(|e| {
                DoctorError::InjectionFailed(format!("The system was unable to spawn the target process '{}': {}", target.name, e))
            })?;

        let child_pid = child.id();

        log::info!(
            "[dyld_insert] Target process successfully spawned (PID: {}) with DYLD_INSERT_LIBRARIES active",
            child_pid
        );

        Ok(InjectionResult {
            method_name: self.name().to_string(),
            target: ProcessInfo {
                pid: child_pid,
                name: target.name.clone(),
                architecture: target.architecture,
            },
            dll_path: config.dll_path.clone(),
            base_address: None,
            details: format!(
                "DYLD_INSERT_LIBRARIES injection — spawned PID {} with preloaded '{}'",
                child_pid, dylib_str
            ),
        })
    }
}
