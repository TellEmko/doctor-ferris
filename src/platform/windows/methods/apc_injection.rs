//! APC (Asynchronous Procedure Call) injection.
//!
//! Queues an APC to every alertable thread in the target process. When the
//! thread enters an alertable wait state (e.g. `SleepEx`, `WaitForSingleObjectEx`),
//! the APC fires and executes `LoadLibraryA` with the DLL path argument.
//!
//! **Pros:** Does not create new threads. Leverages a legitimate OS mechanism.
//! More subtle than `CreateRemoteThread`.
//! **Cons:** Only works if the target has alertable threads. May inject multiple
//! times if multiple threads become alertable.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// APC-based injection method.
pub struct ApcInjectionMethod;

impl InjectionMethod for ApcInjectionMethod {
    fn name(&self) -> &str {
        "apc_injection"
    }

    fn description(&self) -> &str {
        "APC (Asynchronous Procedure Call) queue injection — executes code when target threads enter an alertable wait state"
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Windows]
    }

    fn supported_architectures(&self) -> &[Architecture] {
        &[Architecture::X86, Architecture::X86_64]
    }

    fn is_stealth(&self) -> bool {
        true
    }

    fn reliability(&self) -> u8 {
        70
    }

    fn compatibility(&self) -> u8 {
        65
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::System::Threading::*;

        let dll_path_string = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("The provided DLL path contains non-UTF-8 characters".into()))?;

        let mut dll_path_bytes = dll_path_string.as_bytes().to_vec();
        dll_path_bytes.push(0);

        log::info!(
            "[apc_injection] Initiating APC injection of '{}' into {} (Process ID: {})",
            dll_path_string,
            target.name,
            target.pid
        );

        let target_process = super::super::open_process_for_injection(target.pid)?;
        let load_library_procedure = super::super::resolve_load_library_a()?;

        unsafe {
            // Allocate memory and write the DLL path into the target process space.
            let remote_path_address = super::super::remote_alloc_and_write(target_process.raw(), &dll_path_bytes)?;

            // Enumerate all active threads and attempt to queue an APC to each.
            let active_thread_ids = enumerate_active_threads(target.pid)?;

            if active_thread_ids.is_empty() {
                super::super::remote_free(target_process.raw(), remote_path_address);
                return Err(DoctorError::injection_failed(
                    "No active threads were discovered within the target process",
                ));
            }

            let mut successfully_queued_count = 0u32;

            for thread_id in &active_thread_ids {
                let thread_handle_raw = OpenThread(THREAD_SET_CONTEXT, 0, *thread_id);
                if let Some(thread_handle) = super::super::SafeHandle::new(thread_handle_raw) {
                    let queue_status = QueueUserAPC(
                        Some(std::mem::transmute(load_library_procedure)),
                        thread_handle.raw(),
                        remote_path_address as usize,
                    );
                    if queue_status != 0 {
                        successfully_queued_count += 1;
                    }
                }
            }

            if successfully_queued_count == 0 {
                super::super::remote_free(target_process.raw(), remote_path_address);
                return Err(DoctorError::injection_failed(
                    "Failed to successfully queue an APC to any discovered thread",
                ));
            }

            log::info!(
                "[apc_injection] Successfully queued APCs to {} out of {} threads",
                successfully_queued_count,
                active_thread_ids.len()
            );

            // Note: The remote memory allocated for the DLL path is intentionally not released here.
            // The memory must remain valid until the queued APC is executed by a thread.

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: None,
                details: format!(
                    "Asynchronous Procedure Call (APC) queued to {}/{} threads; execution will occur upon the next alertable wait state",
                    successfully_queued_count,
                    active_thread_ids.len()
                ),
            })
        }
    }
}

/// Enumerates all thread identifiers associated with the specified process.
fn enumerate_active_threads(process_id: u32) -> Result<Vec<u32>> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

    unsafe {
        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        let snapshot =
            super::super::SafeHandle::new(snapshot_handle).ok_or_else(super::super::last_os_error)?;

        let mut thread_entry: THREADENTRY32 = std::mem::zeroed();
        thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut thread_ids = Vec::new();

        if Thread32First(snapshot.raw(), &mut thread_entry) != 0 {
            loop {
                if thread_entry.th32OwnerProcessID == process_id {
                    thread_ids.push(thread_entry.th32ThreadID);
                }
                if Thread32Next(snapshot.raw(), &mut thread_entry) == 0 {
                    break;
                }
            }
        }

        Ok(thread_ids)
    }
}
