//! Classic `CreateRemoteThread` + `LoadLibraryA` injection.
//!
//! The most widely known and compatible DLL injection technique. Allocates
//! memory in the target process, writes the DLL path, and spawns a remote
//! thread whose entry point is `LoadLibraryA`.
//!
//! **Pros:** Extremely compatible, works on all Windows versions.
//! **Cons:** Easily detected by any security product monitoring thread creation.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// Standard `CreateRemoteThread` + `LoadLibraryA` injection method.
pub struct LoadLibraryMethod;

impl InjectionMethod for LoadLibraryMethod {
    fn name(&self) -> &str {
        "loadlibrary"
    }

    fn description(&self) -> &str {
        "Classic CreateRemoteThread + LoadLibraryA injection"
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Windows]
    }

    fn supported_architectures(&self) -> &[Architecture] {
        &[Architecture::X86, Architecture::X86_64]
    }

    fn reliability(&self) -> u8 {
        95
    }

    fn compatibility(&self) -> u8 {
        100
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        use windows_sys::Win32::System::Threading::*;

        let dll_path_str = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("non-UTF-8 DLL path".into()))?;

        // Ensure the path is null-terminated for the C API.
        let mut dll_bytes = dll_path_str.as_bytes().to_vec();
        dll_bytes.push(0);

        log::info!(
            "[loadlibrary] Injecting '{}' into {} (PID {})",
            dll_path_str,
            target.name,
            target.pid
        );

        // Open target process.
        let process = super::super::open_process_for_injection(target.pid)?;

        // Resolve LoadLibraryA address.
        let load_library = super::super::resolve_loadlibrary_a()?;

        unsafe {
            // Allocate and write the DLL path into the target.
            let remote_path =
                super::super::remote_alloc_and_write(process.raw(), &dll_bytes)?;

            // Spawn a remote thread at LoadLibraryA with the path as the argument.
            let thread = CreateRemoteThread(
                process.raw(),
                std::ptr::null(),
                0,
                Some(std::mem::transmute(load_library)),
                remote_path,
                0,
                std::ptr::null_mut(),
            );

            if thread.is_null() {
                super::super::remote_free(process.raw(), remote_path);
                return Err(super::super::last_os_error());
            }

            let thread_handle = super::super::SafeHandle::new(thread);

            // Wait for the remote thread to complete.
            let wait_result = WaitForSingleObject(
                thread_handle.as_ref().map_or(thread, |h| h.raw()),
                config.timeout.as_millis() as u32,
            );

            // Retrieve the exit code (base address of the loaded module).
            let mut exit_code: u32 = 0;
            GetExitCodeThread(
                thread_handle.as_ref().map_or(thread, |h| h.raw()),
                &mut exit_code,
            );

            // Clean up remote memory.
            super::super::remote_free(process.raw(), remote_path);

            if wait_result == 0x00000102 {
                // WAIT_TIMEOUT
                return Err(DoctorError::Timeout(config.timeout));
            }

            let base_address = if exit_code != 0 {
                Some(exit_code as usize)
            } else {
                None
            };

            log::info!(
                "[loadlibrary] Injection complete, module base: {:?}",
                base_address
            );

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address,
                details: "CreateRemoteThread + LoadLibraryA injection successful".into(),
            })
        }
    }
}
