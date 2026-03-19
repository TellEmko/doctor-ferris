//! Process discovery and validation utilities.
//!
//! Provides cross-platform process enumeration, architecture detection, and
//! DLL-to-process compatibility validation.

use std::path::Path;

use crate::error::{DoctorError, Result};
use crate::types::{Architecture, Pid, ProcessInfo};

/// Enumerate all processes visible to the current user.
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
    crate::platform::enumerate_processes()
}

/// Find the first process matching `name` (case-insensitive).
pub fn find_process_by_name(name: &str) -> Result<ProcessInfo> {
    let processes = enumerate_processes()?;
    processes
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| DoctorError::ProcessNotFound(name.to_string()))
}

/// Look up a process by its PID.
pub fn find_process_by_pid(pid: Pid) -> Result<ProcessInfo> {
    let processes = enumerate_processes()?;
    processes
        .into_iter()
        .find(|p| p.pid == pid)
        .ok_or_else(|| DoctorError::ProcessNotFound(format!("PID {}", pid)))
}

/// Detect the CPU architecture of a running process.
pub fn detect_architecture(pid: Pid) -> Result<Architecture> {
    crate::platform::detect_architecture(pid)
}

/// Validate that a DLL can be injected into the target process.
///
/// Checks:
/// 1. DLL file exists and is readable.
/// 2. DLL architecture matches the target process architecture.
pub fn validate_injection(dll_path: &Path, target: &ProcessInfo) -> Result<()> {
    // Verify the DLL exists.
    if !dll_path.exists() {
        return Err(DoctorError::InvalidPath(format!(
            "DLL does not exist: {}",
            dll_path.display()
        )));
    }

    if !dll_path.is_file() {
        return Err(DoctorError::InvalidPath(format!(
            "path is not a file: {}",
            dll_path.display()
        )));
    }

    // Detect DLL architecture.
    let dll_arch = detect_dll_architecture(dll_path)?;

    if dll_arch == Architecture::Unknown {
        log::warn!(
            "Could not determine architecture of '{}'; skipping arch check",
            dll_path.display()
        );
        return Ok(());
    }

    if !dll_arch.is_compatible_with(target.architecture) {
        return Err(DoctorError::ArchitectureMismatch {
            dll_arch: dll_arch.to_string(),
            process_arch: target.architecture.to_string(),
        });
    }

    Ok(())
}

/// Read the architecture from a DLL or shared-object file header.
pub fn detect_dll_architecture(path: &Path) -> Result<Architecture> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| {
        DoctorError::InvalidPath(format!("cannot open '{}': {}", path.display(), e))
    })?;

    let mut header = [0u8; 512];
    let bytes_read = file.read(&mut header).unwrap_or(0);
    if bytes_read < 4 {
        return Ok(Architecture::Unknown);
    }

    // Windows PE: MZ header → PE offset → Machine field.
    if header[0] == b'M' && header[1] == b'Z' {
        if bytes_read < 64 {
            return Ok(Architecture::Unknown);
        }
        let pe_offset =
            u32::from_le_bytes([header[60], header[61], header[62], header[63]]) as usize;
        if pe_offset + 6 > bytes_read {
            return Ok(Architecture::Unknown);
        }
        // Verify PE signature "PE\0\0".
        if &header[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Ok(Architecture::Unknown);
        }
        let machine = u16::from_le_bytes([header[pe_offset + 4], header[pe_offset + 5]]);
        return Ok(match machine {
            0x014c => Architecture::X86,    // IMAGE_FILE_MACHINE_I386
            0x8664 => Architecture::X86_64, // IMAGE_FILE_MACHINE_AMD64
            _ => Architecture::Unknown,
        });
    }

    // ELF: magic → EI_CLASS field.
    if &header[0..4] == b"\x7fELF" {
        return Ok(match header[4] {
            1 => Architecture::X86,    // ELFCLASS32
            2 => Architecture::X86_64, // ELFCLASS64
            _ => Architecture::Unknown,
        });
    }

    // Mach-O: magic number.
    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    match magic {
        0xFEED_FACE => return Ok(Architecture::X86),    // MH_MAGIC (32-bit)
        0xFEED_FACF => return Ok(Architecture::X86_64), // MH_MAGIC_64
        _ => {}
    }

    Ok(Architecture::Unknown)
}
