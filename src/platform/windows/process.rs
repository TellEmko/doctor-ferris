//! Windows process enumeration and architecture detection.

use crate::error::{DoctorError, Result};
use crate::types::{Architecture, Pid, ProcessInfo};

/// Enumerates all currently active processes using the `CreateToolhelp32Snapshot` API.
pub fn enumerate() -> Result<Vec<ProcessInfo>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

    unsafe {
        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let snapshot = super::SafeHandle::new(snapshot_handle).ok_or_else(super::last_os_error)?;

        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed();
        process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let mut discovered_processes = Vec::new();

        if Process32First(snapshot.raw(), &mut process_entry) != 0 {
            loop {
                let executable_name = std::ffi::CStr::from_ptr(process_entry.szExeFile.as_ptr().cast())
                    .to_string_lossy()
                    .into_owned();

                let processor_architecture =
                    detect_architecture(process_entry.th32ProcessID).unwrap_or(Architecture::Unknown);

                discovered_processes.push(ProcessInfo {
                    pid: process_entry.th32ProcessID,
                    name: executable_name,
                    architecture: processor_architecture,
                });

                if Process32Next(snapshot.raw(), &mut process_entry) == 0 {
                    break;
                }
            }
        }

        Ok(discovered_processes)
    }
}

/// Identifies the CPU architecture of the specified process by its identifier (PID).
///
/// This function utilizes the `IsWow64Process` API to determine if a process is executing
/// under the WOW64 subsystem (indicating a 32-bit process on a 64-bit OS) or natively.
pub fn detect_architecture(process_id: Pid) -> Result<Architecture> {
    use windows_sys::Win32::System::Threading::*;

    // Special cases: The System Idle Process (PID 0) and the System Process (PID 4) are kernel-level entities.
    if process_id == 0 || process_id == 4 {
        return Ok(Architecture::current());
    }

    unsafe {
        let process_handle_raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
        let process_handle = super::SafeHandle::new(process_handle_raw).ok_or_else(|| {
            DoctorError::ProcessNotFound(format!("The system was unable to open Process ID {} for an architecture query", process_id))
        })?;

        let mut is_wow64_process: i32 = 0;
        let query_status = windows_sys::Win32::System::Threading::IsWow64Process(process_handle.raw(), &mut is_wow64_process);

        if query_status == 0 {
            return Err(super::last_os_error());
        }

        if is_wow64_process != 0 {
            // A process executing under WOW64 is verified to be a 32-bit (X86) process.
            Ok(Architecture::X86)
        } else {
            // On a 64-bit operating system, a non-WOW64 process is verified as native 64-bit (X86_64).
            // On a 32-bit operating system, this also returns false, indicating native 32-bit.
            if cfg!(target_arch = "x86_64") {
                Ok(Architecture::X86_64)
            } else {
                Ok(Architecture::X86)
            }
        }
    }
}
