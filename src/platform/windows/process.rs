//! Windows process enumeration and architecture detection.

use crate::error::{DoctorError, Result};
use crate::types::{Architecture, Pid, ProcessInfo};

/// Enumerate all running processes via `CreateToolhelp32Snapshot`.
pub fn enumerate() -> Result<Vec<ProcessInfo>> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    use windows_sys::Win32::Foundation::CloseHandle;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let snap = super::SafeHandle::new(snapshot)
            .ok_or_else(super::last_os_error)?;

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let mut processes = Vec::new();

        if Process32First(snap.raw(), &mut entry) != 0 {
            loop {
                let name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr().cast())
                    .to_string_lossy()
                    .into_owned();

                let architecture =
                    detect_architecture(entry.th32ProcessID).unwrap_or(Architecture::Unknown);

                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    architecture,
                });

                if Process32Next(snap.raw(), &mut entry) == 0 {
                    break;
                }
            }
        }

        Ok(processes)
    }
}

/// Detect the CPU architecture of a process by PID.
///
/// Uses `IsWow64Process` to determine if a process is running under WOW64
/// (32-bit on 64-bit Windows) or natively.
pub fn detect_architecture(pid: Pid) -> Result<Architecture> {
    use windows_sys::Win32::System::Threading::*;

    // Special case: PID 0 (System Idle) and PID 4 (System) are kernel-level.
    if pid == 0 || pid == 4 {
        return Ok(Architecture::current());
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        let handle = super::SafeHandle::new(handle).ok_or_else(|| {
            DoctorError::ProcessNotFound(format!(
                "cannot open PID {} for architecture query",
                pid
            ))
        })?;

        let mut is_wow64: i32 = 0;
        let ok = windows_sys::Win32::System::Threading::IsWow64Process(
            handle.raw(),
            &mut is_wow64,
        );

        if ok == 0 {
            return Err(super::last_os_error());
        }

        if is_wow64 != 0 {
            // Process is running under WOW64 — it is a 32-bit process.
            Ok(Architecture::X86)
        } else {
            // On a 64-bit OS, non-WOW64 means native 64-bit.
            // On a 32-bit OS, this also returns false, so we check the system.
            if cfg!(target_arch = "x86_64") {
                Ok(Architecture::X86_64)
            } else {
                Ok(Architecture::X86)
            }
        }
    }
}
