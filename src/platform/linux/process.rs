//! Linux process enumeration and architecture detection via `/proc`.

use crate::error::{DoctorError, Result};
use crate::types::{Architecture, Pid, ProcessInfo};

use std::fs;
use std::io::Read;

/// Enumerate running processes by reading `/proc/[pid]/comm`.
pub fn enumerate() -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();

    for entry in fs::read_dir("/proc").map_err(|e| DoctorError::Unexpected(format!("Failed to read the /proc directory: {}", e)))? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let comm_path = format!("/proc/{}/comm", pid);
        let proc_name = match fs::read_to_string(&comm_path) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };

        let architecture = detect_architecture(pid).unwrap_or(Architecture::Unknown);

        processes.push(ProcessInfo {
            pid,
            name: proc_name,
            architecture,
        });
    }

    Ok(processes)
}

/// Detect the architecture of a process by reading the ELF header of
/// `/proc/<pid>/exe`.
pub fn detect_architecture(pid: Pid) -> Result<Architecture> {
    let exe_path = format!("/proc/{}/exe", pid);
    let mut file = fs::File::open(&exe_path)
        .map_err(|e| DoctorError::ProcessNotFound(format!("cannot read {}: {}", exe_path, e)))?;

    let mut header = [0u8; 5];
    file.read_exact(&mut header)
        .map_err(|e| DoctorError::Unexpected(format!("Failed to read the ELF header from the process executable: {}", e)))?;

    if &header[0..4] != b"\x7fELF" {
        return Ok(Architecture::Unknown);
    }

    Ok(match header[4] {
        1 => Architecture::X86,
        2 => Architecture::X86_64,
        _ => Architecture::Unknown,
    })
}
