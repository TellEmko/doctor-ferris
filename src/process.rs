//! Process discovery and validation utilities.
//!
//! Provides cross-platform functionality for process enumeration, CPU architecture
//! detection, and validating compatibility between dynamic libraries and target processes.

use std::path::Path;

use crate::error::{DoctorError, Result};
use crate::types::{Architecture, Pid, ProcessInfo};

/// Enumerates all active processes visible within the current user's security context.
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
    crate::platform::enumerate_processes()
}

/// Attempts to locate a single process by its executable name (case-insensitive).
pub fn find_process_by_name(process_name: &str) -> Result<ProcessInfo> {
    let active_processes = enumerate_processes()?;
    active_processes
        .into_iter()
        .find(|proc| proc.name.eq_ignore_ascii_case(process_name))
        .ok_or_else(|| DoctorError::ProcessNotFound(format!("Executable name: '{}'", process_name)))
}

/// Attempts to locate a single process using its system-unique Process ID (PID).
pub fn find_process_by_pid(process_id: Pid) -> Result<ProcessInfo> {
    let active_processes = enumerate_processes()?;
    active_processes
        .into_iter()
        .find(|proc| proc.pid == process_id)
        .ok_or_else(|| DoctorError::ProcessNotFound(format!("Process ID: {}", process_id)))
}

/// Identifies the CPU architecture of a specified running process.
pub fn detect_architecture(process_id: Pid) -> Result<Architecture> {
    crate::platform::detect_architecture(process_id)
}

/// Validates whether a dynamic library is compatible for injection into the specified target process.
///
/// This function performs the following verifications:
/// 1. Ensures the library file exists and is accessible for reading.
/// 2. Verifies that the library's CPU architecture aligns with that of the target process.
pub fn validate_injection(library_path: &Path, target_process: &ProcessInfo) -> Result<()> {
    // Confirm the existence of the library file.
    if !library_path.exists() {
        return Err(DoctorError::InvalidPath(format!(
            "The specified dynamic library does not exist: {}",
            library_path.display()
        )));
    }

    if !library_path.is_file() {
        return Err(DoctorError::InvalidPath(format!(
            "The provided path does not refer to a valid file: {}",
            library_path.display()
        )));
    }

    // Identify the architecture of the library.
    let library_architecture = detect_dll_architecture(library_path)?;

    if library_architecture == Architecture::Unknown {
        log::warn!(
            "The architecture of library '{}' could not be identified; proceeding without validation",
            library_path.display()
        );
        return Ok(());
    }

    // Ensure architectural compatibility with the target process.
    if !library_architecture.is_compatible_with(target_process.architecture) {
        return Err(DoctorError::ArchitectureMismatch {
            dll_arch: library_architecture.to_string(),
            process_arch: target_process.architecture.to_string(),
        });
    }

    Ok(())
}

/// Reads the file header of a dynamic library or shared object to determine its CPU architecture.
pub fn detect_dll_architecture(file_path: &Path) -> Result<Architecture> {
    let header_bytes = read_file_header(file_path)?;

    // Attempt to identify the architecture via various binary format signatures.
    if let Some(identified_arch) = detect_portable_executable_architecture(&header_bytes)
        .or_else(|| detect_elf_architecture(&header_bytes))
        .or_else(|| detect_macho_architecture(&header_bytes))
    {
        return Ok(identified_arch);
    }

    Ok(Architecture::Unknown)
}

/// Reads the initial bytes of a file to extract header information for format identification.
fn read_file_header(file_path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut file_handle = std::fs::File::open(file_path).map_err(|err| {
        DoctorError::InvalidPath(format!("Unable to open file '{}': {}", file_path.display(), err))
    })?;

    let mut header_buffer = vec![0u8; 512];
    let bytes_read_count = file_handle.read(&mut header_buffer).map_err(|err| {
        DoctorError::InvalidPath(format!("Unable to read header from file '{}': {}", file_path.display(), err))
    })?;

    header_buffer.truncate(bytes_read_count);
    Ok(header_buffer)
}

/// Detects the architecture of a Windows Portable Executable (PE) from its header bytes.
fn detect_portable_executable_architecture(header_bytes: &[u8]) -> Option<Architecture> {
    if header_bytes.len() < 64 || &header_bytes[0..2] != b"MZ" {
        return None;
    }

    let pe_header_offset = u32::from_le_bytes(header_bytes[60..64].try_into().ok()?) as usize;

    if pe_header_offset + 6 > header_bytes.len() {
        return None;
    }
    if &header_bytes[pe_header_offset..pe_header_offset + 4] != b"PE\0\0" {
        return None;
    }

    let machine_identifier = u16::from_le_bytes(header_bytes[pe_header_offset + 4..pe_header_offset + 6].try_into().ok()?);
    match machine_identifier {
        0x014c => Some(Architecture::X86),
        0x8664 => Some(Architecture::X86_64),
        _ => None,
    }
}

/// Detects the architecture of a Linux Executable and Linkable Format (ELF) binary.
fn detect_elf_architecture(header_bytes: &[u8]) -> Option<Architecture> {
    if header_bytes.len() < 19 || &header_bytes[0..4] != b"\x7fELF" {
        return None;
    }

    // Identification based on the ELF class and machine field.
    match (header_bytes[4], header_bytes[18]) {
        (1, 3) => Some(Architecture::X86),     // ELFCLASS32 + EM_386
        (2, 62) => Some(Architecture::X86_64), // ELFCLASS64 + EM_X86_64
        _ => None,
    }
}

/// Detects the architecture of a macOS Mach-O binary from its header bytes.
fn detect_macho_architecture(header_bytes: &[u8]) -> Option<Architecture> {
    if header_bytes.len() < 4 {
        return None;
    }

    // Mach-O headers can be represented in either little-endian or big-endian formats.
    let magic_le = u32::from_le_bytes(header_bytes[0..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(header_bytes[0..4].try_into().ok()?);

    match magic_le {
        0xCEFA_EDFE => return Some(Architecture::X86),    // MH_MAGIC (32-bit)
        0xCFFA_EDFE => return Some(Architecture::X86_64), // MH_MAGIC_64 (64-bit)
        _ => {}
    }
    match magic_be {
        0xFEED_FACE => return Some(Architecture::X86),    // MH_MAGIC (32-bit)
        0xFEED_FACF => return Some(Architecture::X86_64), // MH_MAGIC_64 (64-bit)
        _ => {}
    }

    None
}
