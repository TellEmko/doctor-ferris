//! `LD_PRELOAD`-based pre-launch injection for Linux.
//!
//! This method does not inject into a running process. Instead, it spawns a
//! new instance of the target executable with `LD_PRELOAD` set to the shared
//! object path, causing the dynamic linker to load it before the program starts.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// `LD_PRELOAD` environment-based injection method.
pub struct LdPreloadMethod;

impl InjectionMethod for LdPreloadMethod {
    fn name(&self) -> &str {
        "ld_preload"
    }

    fn description(&self) -> &str {
        "LD_PRELOAD pre-launch injection — spawns target with the shared object preloaded"
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux]
    }

    fn supported_architectures(&self) -> &[Architecture] {
        &[Architecture::X86, Architecture::X86_64]
    }

    fn reliability(&self) -> u8 {
        95
    }

    fn compatibility(&self) -> u8 {
        90
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        let so_path = config.dll_path.canonicalize().map_err(|e| {
            DoctorError::InvalidPath(format!("{}: {}", config.dll_path.display(), e))
        })?;

        let so_str = so_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("non-UTF-8 shared object path".into()))?;

        log::info!(
            "[ld_preload] Launching '{}' with LD_PRELOAD='{}'",
            target.name,
            so_str
        );

        let child = std::process::Command::new(&target.name)
            .env("LD_PRELOAD", so_str)
            .spawn()
            .map_err(|e| {
                DoctorError::injection_failed(format!("failed to spawn '{}': {}", target.name, e))
            })?;

        let child_pid = child.id();

        log::info!(
            "[ld_preload] Process spawned with PID {} and LD_PRELOAD active",
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
                "LD_PRELOAD injection — spawned PID {} with preloaded '{}'",
                child_pid, so_str
            ),
        })
    }
}
