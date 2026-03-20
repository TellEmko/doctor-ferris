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
        "Standard injection method using CreateRemoteThread and LoadLibraryA"
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

        let dll_path_string = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("The provided DLL path contains non-UTF-8 characters".into()))?;

        // Ensure the dynamic library path is null-terminated for compatibility with the Win32 C API.
        let mut dll_path_bytes = dll_path_string.as_bytes().to_vec();
        dll_path_bytes.push(0);

        log::info!(
            "[loadlibrary] Initiating standard injection of '{}' into {} (Process ID: {})",
            dll_path_string,
            target.name,
            target.pid
        );

        // Acquire a handle to the target process with required access rights.
        let target_process = super::super::open_process_for_injection(target.pid)?;

        // Resolve the entry point for the remote thread (LoadLibraryA).
        let load_library_procedure = super::super::resolve_load_library_a()?;

        unsafe {
            // Allocate memory and write the DLL path into the target process's memory space.
            let remote_path_address = super::super::remote_alloc_and_write(target_process.raw(), &dll_path_bytes)?;

            // Spawn a remote thread within the target process, starting at the LoadLibraryA entry point.
            let remote_thread_handle_raw = CreateRemoteThread(
                target_process.raw(),
                std::ptr::null(),
                0,
                Some(std::mem::transmute(load_library_procedure)),
                remote_path_address,
                0,
                std::ptr::null_mut(),
            );

            if remote_thread_handle_raw.is_null() {
                super::super::remote_free(target_process.raw(), remote_path_address);
                return Err(super::super::last_os_error());
            }

            let remote_thread_handle = super::super::SafeHandle::new(remote_thread_handle_raw);

            // Synchronize with the remote thread and wait for its completion.
            let wait_result = WaitForSingleObject(
                remote_thread_handle.as_ref().map_or(remote_thread_handle_raw, |h| h.raw()),
                config.timeout.as_millis() as u32,
            );

            // Retrieve the exit code of the thread, which corresponds to the base address of the loaded module.
            let mut thread_exit_code: u32 = 0;
            GetExitCodeThread(
                remote_thread_handle.as_ref().map_or(remote_thread_handle_raw, |h| h.raw()),
                &mut thread_exit_code,
            );

            // Relinquish the remote memory allocated for the DLL path.
            super::super::remote_free(target_process.raw(), remote_path_address);

            // Define the timeout constant for wait synchronization.
            const WAIT_TIMEOUT: u32 = 0x00000102;
            if wait_result == WAIT_TIMEOUT {
                return Err(DoctorError::Timeout(config.timeout));
            }

            let loaded_module_base_address = if thread_exit_code != 0 {
                Some(thread_exit_code as usize)
            } else {
                None
            };

            log::info!(
                "[loadlibrary] Injection finalized successfully; module base address: {:?}",
                loaded_module_base_address
            );

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: loaded_module_base_address,
                details: "Standard library injection performed successfully via CreateRemoteThread".into(),
            })
        }
    }
}
