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
        "APC (Asynchronous Procedure Call) queue injection — fires when target threads enter alertable wait"
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

        let dll_path_str = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("non-UTF-8 DLL path".into()))?;

        let mut dll_bytes = dll_path_str.as_bytes().to_vec();
        dll_bytes.push(0);

        log::info!(
            "[apc_injection] Injecting '{}' into {} (PID {})",
            dll_path_str,
            target.name,
            target.pid
        );

        let process = super::super::open_process_for_injection(target.pid)?;
        let load_library = super::super::resolve_loadlibrary_a()?;

        unsafe {
            // Write the DLL path into the target process.
            let remote_path = super::super::remote_alloc_and_write(process.raw(), &dll_bytes)?;

            // Enumerate threads and queue an APC to each one.
            let thread_ids = enumerate_threads(target.pid)?;

            if thread_ids.is_empty() {
                super::super::remote_free(process.raw(), remote_path);
                return Err(DoctorError::injection_failed(
                    "no threads found in target process",
                ));
            }

            let mut queued_count = 0u32;

            for tid in &thread_ids {
                let thread = OpenThread(THREAD_SET_CONTEXT, 0, *tid);
                if let Some(thread_handle) = super::super::SafeHandle::new(thread) {
                    let result = QueueUserAPC(
                        Some(std::mem::transmute(load_library)),
                        thread_handle.raw(),
                        remote_path as usize,
                    );
                    if result != 0 {
                        queued_count += 1;
                    }
                }
            }

            if queued_count == 0 {
                super::super::remote_free(process.raw(), remote_path);
                return Err(DoctorError::injection_failed(
                    "failed to queue APC to any thread",
                ));
            }

            log::info!(
                "[apc_injection] Queued APC to {}/{} threads",
                queued_count,
                thread_ids.len()
            );

            // Note: we intentionally do NOT free remote_path here because the
            // APC has not fired yet. The memory will leak (a few hundred bytes)
            // but freeing it would cause an access violation when the APC fires.

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: None,
                details: format!(
                    "APC queued to {}/{} threads; injection occurs on next alertable wait",
                    queued_count,
                    thread_ids.len()
                ),
            })
        }
    }
}

/// Enumerate all thread IDs belonging to a process.
fn enumerate_threads(pid: u32) -> Result<Vec<u32>> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        let snap =
            super::super::SafeHandle::new(snapshot).ok_or_else(super::super::last_os_error)?;

        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut ids = Vec::new();

        if Thread32First(snap.raw(), &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    ids.push(entry.th32ThreadID);
                }
                if Thread32Next(snap.raw(), &mut entry) == 0 {
                    break;
                }
            }
        }

        Ok(ids)
    }
}
