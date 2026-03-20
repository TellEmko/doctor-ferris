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
    let header = read_header(path)?;

    if let Some(arch) = detect_pe(&header)
        .or_else(|| detect_elf(&header))
        .or_else(|| detect_macho(&header))
    {
        return Ok(arch);
    }

    Ok(Architecture::Unknown)
}

fn read_header(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| {
        DoctorError::InvalidPath(format!("cannot open '{}': {}", path.display(), e))
    })?;

    let mut header = vec![0u8; 512];
    let bytes_read = file.read(&mut header).map_err(|e| {
        DoctorError::InvalidPath(format!("cannot read '{}': {}", path.display(), e))
    })?;

    header.truncate(bytes_read);
    Ok(header)
}

fn detect_pe(header: &[u8]) -> Option<Architecture> {
    if header.len() < 64 || &header[0..2] != b"MZ" {
        return None;
    }

    let pe_offset = u32::from_le_bytes(header[60..64].try_into().ok()?) as usize;

    if pe_offset + 6 > header.len() {
        return None;
    }
    if &header[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return None;
    }

    let machine = u16::from_le_bytes(header[pe_offset + 4..pe_offset + 6].try_into().ok()?);
    match machine {
        0x014c => Some(Architecture::X86),
        0x8664 => Some(Architecture::X86_64),
        _ => None,
    }
}

fn detect_elf(header: &[u8]) -> Option<Architecture> {
    if header.len() < 19 || &header[0..4] != b"\x7fELF" {
        return None;
    }

    // EI_CLASS alone isn't enough — also check e_machine at offset 18.
    match (header[4], header[18]) {
        (1, 3) => Some(Architecture::X86),     // ELFCLASS32 + EM_386
        (2, 62) => Some(Architecture::X86_64), // ELFCLASS64 + EM_X86_64
        _ => None,
    }
}

fn detect_macho(header: &[u8]) -> Option<Architecture> {
    if header.len() < 4 {
        return None;
    }

    // Check both endiannesses.
    let le = u32::from_le_bytes(header[0..4].try_into().ok()?);
    let be = u32::from_be_bytes(header[0..4].try_into().ok()?);

    match le {
        0xCEFA_EDFE => return Some(Architecture::X86), // MH_MAGIC 32-bit LE
        0xCFFA_EDFE => return Some(Architecture::X86_64), // MH_MAGIC_64 LE
        _ => {}
    }
    match be {
        0xFEED_FACE => return Some(Architecture::X86), // MH_MAGIC 32-bit BE
        0xFEED_FACF => return Some(Architecture::X86_64), // MH_MAGIC_64 BE
        _ => {}
    }

    None
}
