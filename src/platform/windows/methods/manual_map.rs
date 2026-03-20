//! Advanced manual mapping injection procedure.
//!
//! This module implements a manual Portable Executable (PE) loader that maps a
//! dynamic library into a target process's virtual address space without
//! relying on the Windows operating system loader (e.g., `LoadLibrary`).
//!
//! The manual mapping procedure involves:
//! 1. Reading and parsing the PE file structure from disk.
//! 2. Allocating memory within the target process at the preferred base address.
//! 3. Relocating the image if the preferred base address is unavailable.
//! 4. Copying section data from the file buffer to the target process memory.
//! 5. Manually processing base relocations and resolving imports.
//! 6. Executing the `DllMain` entry point via a remote thread.
//!
//! Advantages:
//! - The injected module is not registered in the Process Environment Block (PEB) module list.
//! - It evades standard module enumeration and many automated detection tools.
//!
//! Considerations:
//! - This technique is highly complex and depends on the specific PE architecture.
//! - It may not support all advanced PE features such as Thread Local Storage (TLS) callbacks.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

use std::io::Read;

/// Manual PE mapping injection method.
pub struct ManualMapMethod;

impl InjectionMethod for ManualMapMethod {
    fn name(&self) -> &str {
        "manual_map"
    }

    fn description(&self) -> &str {
        "Manual PE image mapping — provides high evasion by bypassing the system loader"
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Windows]
    }

    fn supported_architectures(&self) -> &[Architecture] {
        &[Architecture::X86_64]
    }

    fn is_stealth(&self) -> bool {
        true
    }

    fn requires_elevation(&self) -> bool {
        true
    }

    fn reliability(&self) -> u8 {
        50
    }

    fn compatibility(&self) -> u8 {
        30
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        log::info!(
            "[manual_map] Initiating manual mapping of '{}' into {} (Process ID: {})",
            config.dll_path.display(),
            target.name,
            target.pid
        );

        // Read the entire dynamic library file into a local memory buffer.
        let mut pe_file_data = read_pe_file_from_disk(&config.dll_path)?;

        // Parse and validate the Portable Executable (PE) headers.
        let pe_headers = PortableExecutableHeaders::parse(&pe_file_data)?;

        // Resolve necessary imports locally. 
        // Note: This assumes that system-wide DLLs share the same base address across processes (ASLR consistency).
        unsafe {
            resolve_imports_locally(&pe_headers, &mut pe_file_data)?;
        }

        let target_process = super::super::open_process_for_injection(target.pid)?;

        unsafe {
            // Allocate virtual memory in the target process at the image's preferred base address if possible.
            let remote_image_base = allocate_remote_image_memory(target_process.raw(), &pe_headers)?;

            // Transfer PE sections from the local buffer to the allocated memory in the target process.
            copy_sections_to_remote_process(target_process.raw(), remote_image_base, &pe_headers, &pe_file_data)?;

            // Calculate the relocation delta if the image was not loaded at its preferred base address.
            let relocation_delta = remote_image_base as u64 - pe_headers.preferred_image_base;
            if relocation_delta != 0 {
                process_image_relocations(target_process.raw(), remote_image_base, &pe_headers, &pe_file_data, relocation_delta)?;
            }

            // Construct and deploy the remote loader shellcode and its associated parameters.
            let loader_parameters = LoaderParameters {
                image_base_address: remote_image_base as u64,
                load_library_a_address: get_procedure_address("kernel32.dll", "LoadLibraryA")? as u64,
                get_proc_address_address: get_procedure_address("kernel32.dll", "GetProcAddress")? as u64,
                entry_point_address: remote_image_base as u64 + pe_headers.entry_point_rva as u64,
                import_directory_rva: pe_headers.import_directory_rva,
                import_directory_size: pe_headers.import_directory_size,
            };

            let loader_shellcode = build_loader_shellcode_x64();

            // Write the loader parameters into the target process's memory.
            let parameters_buffer: &[u8] = std::slice::from_raw_parts(
                &loader_parameters as *const LoaderParameters as *const u8,
                std::mem::size_of::<LoaderParameters>(),
            );
            let remote_parameters_address = super::super::remote_alloc_and_write(target_process.raw(), parameters_buffer)?;

            // Write the loader shellcode into the target process's memory.
            let remote_shellcode_address =
                super::super::remote_alloc_and_write(target_process.raw(), &loader_shellcode)?;

            // Configure the shellcode memory region as executable.
            let mut previous_protection_flags = 0u32;
            windows_sys::Win32::System::Memory::VirtualProtectEx(
                target_process.raw(),
                remote_shellcode_address,
                loader_shellcode.len(),
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ,
                &mut previous_protection_flags,
            );

            // Create a remote thread to execute the loader shellcode.
            let remote_thread_handle = windows_sys::Win32::System::Threading::CreateRemoteThread(
                target_process.raw(),
                std::ptr::null(),
                0,
                Some(std::mem::transmute(remote_shellcode_address)),
                remote_parameters_address,
                0,
                std::ptr::null_mut(),
            );

            if remote_thread_handle.is_null() {
                return Err(super::super::last_os_error());
            }

            let thread_guard = super::super::SafeHandle::new(remote_thread_handle);

            // Wait for the loader thread to complete execution within the specified timeout.
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                thread_guard.as_ref().map_or(remote_thread_handle, |h| h.raw()),
                config.timeout.as_millis() as u32,
            );

            // Clean up temporary loader resources (the mapped image remains in the target process).
            super::super::remote_free(target_process.raw(), remote_parameters_address);
            super::super::remote_free(target_process.raw(), remote_shellcode_address);

            log::info!(
                "[manual_map] Manual mapping finalized; image base address in target: 0x{:X}",
                remote_image_base as usize
            );

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: Some(remote_image_base as usize),
                details: format!(
                    "Manual PE mapping performed successfully; image deployed at 0x{:X}",
                    remote_image_base as usize
                ),
            })
        }
    }
}

// ── PE parsing structures ────────────────────────────────────────────

/// Represents the essential header information extracted from a Portable Executable (PE) file.
struct PortableExecutableHeaders {
    preferred_image_base: u64,
    image_size: u32,
    entry_point_rva: u32,
    section_alignment: u32,
    file_alignment: u32,
    import_directory_rva: u32,
    import_directory_size: u32,
    relocation_directory_rva: u32,
    relocation_directory_size: u32,
    sections: Vec<SectionDescriptor>,
}

/// Contains metadata describing a single section within a PE file.
struct SectionDescriptor {
    virtual_address: u32,
    virtual_size: u32,
    raw_data_offset: u32,
    raw_data_size: u32,
    characteristics: u32,
}

impl PortableExecutableHeaders {
    /// Parses the provided binary data as a Portable Executable (PE) and extracts relevant header information.
    fn parse(data: &[u8]) -> Result<Self> {
        // Validate the DOS MZ header.
        if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
            return Err(DoctorError::validation_failed("Missing or invalid DOS MZ header signature"));
        }

        // Locate and validate the NT (PE) header.
        let pe_header_offset = read_u32_le(data, 0x3C)? as usize;
        if pe_header_offset + 4 > data.len() || &data[pe_header_offset..pe_header_offset + 4] != b"PE\0\0" {
            return Err(DoctorError::validation_failed("Missing or invalid PE header signature"));
        }

        let coff_header_start = pe_header_offset + 4;
        let machine_type = read_u16_le(data, coff_header_start)?;
        if machine_type != 0x8664 { // IMAGE_FILE_MACHINE_AMD64
            return Err(DoctorError::validation_failed("Manual mapping is currently restricted to x86_64 PE binaries"));
        }

        let section_count = read_u16_le(data, coff_header_start + 2)? as usize;
        let optional_header_size = read_u16_le(data, coff_header_start + 16)? as usize;

        let optional_header_start = coff_header_start + 20;
        let magic_number = read_u16_le(data, optional_header_start)?;
        if magic_number != 0x020B { // PE32+ (64-bit)
            return Err(DoctorError::validation_failed("The binary does not contain a valid 64-bit (PE32+) optional header"));
        }

        let entry_point_rva = read_u32_le(data, optional_header_start + 16)?;
        let preferred_image_base = read_u64_le(data, optional_header_start + 24)?;
        let section_alignment = read_u32_le(data, optional_header_start + 32)?;
        let file_alignment = read_u32_le(data, optional_header_start + 36)?;
        let image_size = read_u32_le(data, optional_header_start + 56)?;

        // Data directories start at offset 112 within the PE32+ optional header.
        let data_directory_start = optional_header_start + 112;

        // Import Directory (Index 1)
        let import_dir_rva = read_u32_le(data, data_directory_start + 8)?;
        let import_dir_size = read_u32_le(data, data_directory_start + 12)?;

        // Base Relocation Directory (Index 5)
        let reloc_dir_rva = read_u32_le(data, data_directory_start + 40)?;
        let reloc_dir_size = read_u32_le(data, data_directory_start + 44)?;

        // Parse section headers following the optional header.
        let sections_header_start = optional_header_start + optional_header_size;
        let mut sections = Vec::with_capacity(section_count);

        for i in 0..section_count {
            let offset = sections_header_start + i * 40;
            if offset + 40 > data.len() {
                break;
            }

            sections.push(SectionDescriptor {
                virtual_address: read_u32_le(data, offset + 12)?,
                virtual_size: read_u32_le(data, offset + 8)?,
                raw_data_offset: read_u32_le(data, offset + 20)?,
                raw_data_size: read_u32_le(data, offset + 16)?,
                characteristics: read_u32_le(data, offset + 36)?,
            });
        }

        Ok(PortableExecutableHeaders {
            preferred_image_base,
            image_size,
            entry_point_rva,
            section_alignment,
            file_alignment,
            import_directory_rva: import_dir_rva,
            import_directory_size: import_dir_size,
            relocation_directory_rva: reloc_dir_rva,
            relocation_directory_size: reloc_dir_size,
            sections,
        })
    }
}

// ----------------------------------------------------------------------
// Manual Mapping Helper Procedures
// ----------------------------------------------------------------------

/// Resolves necessary imports locally within the PE file data buffer.
unsafe fn resolve_imports_locally(pe_headers: &PortableExecutableHeaders, pe_file_data: &mut [u8]) -> Result<()> {
    if pe_headers.import_directory_rva == 0 || pe_headers.import_directory_size == 0 {
        return Ok(());
    }

    let import_directory_offset = convert_rva_to_file_offset(pe_headers, pe_headers.import_directory_rva)
        .ok_or_else(|| DoctorError::injection_failed("Unable to resolve the Import Directory RVA within the PE structure"))?;

    let mut descriptor_position = import_directory_offset;

    loop {
        if descriptor_position + 20 > pe_file_data.len() {
            break;
        }

        // Process each import descriptor. A return value of `Ok(false)` indicates the end of the directory.
        if !process_import_descriptor(pe_headers, pe_file_data, descriptor_position)? {
            break;
        }

        descriptor_position += 20;
    }

    Ok(())
}

/// Resolves a single function within an imported library and updates the Import Address Table (IAT).
/// Returns Ok(true) if the thunk was processed and more thunks remain, or Ok(false) if the end of the list was reached.
unsafe fn resolve_import_thunk(
    pe_headers: &PortableExecutableHeaders,
    pe_file_data: &mut [u8],
    lookup_table_offset: usize,
    iat_table_offset: usize,
    library_handle: windows_sys::Win32::Foundation::HINSTANCE,
) -> Result<bool> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;

    let thunk_value = read_u64_le(pe_file_data, lookup_table_offset)?;
    if thunk_value == 0 {
        return Ok(false);
    }

    let mut procedure_address: u64 = 0;

    if !library_handle.is_null() {
        const IMAGE_ORDINAL_FLAG64: u64 = 1 << 63;

        if (thunk_value & IMAGE_ORDINAL_FLAG64) != 0 {
            // Resolution by ordinal.
            let ordinal_value = (thunk_value & 0xFFFF) as usize;
            procedure_address = GetProcAddress(library_handle, ordinal_value as *const u8)
                .map_or(0, |proc| proc as u64);
        } else {
            // Resolution by name.
            let hint_name_rva = (thunk_value & 0x7FFFFFFF_FFFFFFFF) as u32;
            if let Some(hint_name_offset) = convert_rva_to_file_offset(pe_headers, hint_name_rva) {
                // The function name starts 2 bytes after the hint (the Hint is a WORD).
                let name_bytes = read_null_terminated_string(pe_file_data, hint_name_offset + 2)?;
                let mut name_cstr = name_bytes;
                name_cstr.push(0);

                procedure_address = GetProcAddress(library_handle, name_cstr.as_ptr())
                    .map_or(0, |proc| proc as u64);
            }
        }
    }

    // Update the IAT with the resolved address.
    pe_file_data[iat_table_offset..iat_table_offset + 8]
        .copy_from_slice(&procedure_address.to_le_bytes());

    Ok(true)
}

/// Processes a single PE import descriptor and resolves its associated functions.
unsafe fn process_import_descriptor(
    pe_headers: &PortableExecutableHeaders,
    pe_file_data: &mut [u8],
    descriptor_position: usize,
) -> Result<bool> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    // Read the primary RVA fields from the IMAGE_IMPORT_DESCRIPTOR.
    let original_first_thunk_rva = read_u32_le(pe_file_data, descriptor_position)?;
    let library_name_rva = read_u32_le(pe_file_data, descriptor_position + 12)?;
    let first_thunk_rva = read_u32_le(pe_file_data, descriptor_position + 16)?;

    if library_name_rva == 0 {
        return Ok(false); // Indicates the end of the import directory.
    }

    // Resolve the library name and load it locally to find procedure addresses.
    let library_name_offset = convert_rva_to_file_offset(pe_headers, library_name_rva)
        .ok_or_else(|| DoctorError::injection_failed("Unable to resolve library name RVA within the PE structure"))?;

    let mut library_name_bytes = read_null_terminated_string(pe_file_data, library_name_offset)?;
    library_name_bytes.push(0);

    let library_module_handle = LoadLibraryA(library_name_bytes.as_ptr());
    if library_module_handle.is_null() {
        log::warn!(
            "System failed to load dependency '{}' locally; some imports may remain unresolved",
            String::from_utf8_lossy(&library_name_bytes).trim_matches(char::from(0))
        );
    }

    let lookup_table_rva = if original_first_thunk_rva != 0 {
        original_first_thunk_rva
    } else {
        first_thunk_rva
    };

    let mut lookup_table_offset = convert_rva_to_file_offset(pe_headers, lookup_table_rva)
        .ok_or_else(|| DoctorError::injection_failed("Unable to resolve the Import Lookup Table (INT) RVA"))?;
    let mut iat_table_offset = convert_rva_to_file_offset(pe_headers, first_thunk_rva)
        .ok_or_else(|| DoctorError::injection_failed("Unable to resolve the Import Address Table (IAT) RVA"))?;

    // Iterate through the thunks until a terminal null thunk is encountered.
    loop {
        if lookup_table_offset + 8 > pe_file_data.len() || iat_table_offset + 8 > pe_file_data.len() {
            break;
        }

        if !resolve_import_thunk(pe_headers, pe_file_data, lookup_table_offset, iat_table_offset, library_module_handle)? {
            break;
        }

        lookup_table_offset += 8;
        iat_table_offset += 8;
    }

    Ok(true)
}

/// Reads the entire contents of a Portable Executable (PE) file from the specified disk path.
fn read_pe_file_from_disk(file_path: &std::path::Path) -> Result<Vec<u8>> {
    let mut file_handle = std::fs::File::open(file_path)
        .map_err(|err| DoctorError::InvalidPath(format!("Failed to open file at '{}': {}", file_path.display(), err)))?;
    let mut binary_data = Vec::new();
    file_handle.read_to_end(&mut binary_data)?;
    Ok(binary_data)
}

/// Allocates memory within a remote process for mapping a PE image.
unsafe fn allocate_remote_image_memory(
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    pe_headers: &PortableExecutableHeaders,
) -> Result<*mut std::ffi::c_void> {
    use windows_sys::Win32::System::Memory::*;

    // Attempt to allocate memory at the image's preferred base address first to avoid relocation overhead.
    let preferred_address = pe_headers.preferred_image_base as *const std::ffi::c_void;
    let allocated_address = VirtualAllocEx(
        process_handle,
        preferred_address,
        pe_headers.image_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if !allocated_address.is_null() {
        return Ok(allocated_address);
    }

    // If the preferred address is unavailable, allocate memory at any available location.
    let allocated_address = VirtualAllocEx(
        process_handle,
        std::ptr::null(),
        pe_headers.image_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if allocated_address.is_null() {
        return Err(super::super::last_os_error());
    }

    Ok(allocated_address)
}

/// Copies PE sections from the local buffer to the target process's virtual memory space.
unsafe fn copy_sections_to_remote_process(
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    base_address: *mut std::ffi::c_void,
    pe_headers: &PortableExecutableHeaders,
    pe_file_data: &[u8],
) -> Result<()> {
    // Write the Portable Executable (PE) headers to the beginning of the allocated memory.
    let header_region_size = pe_headers
        .sections
        .first()
        .map_or(0x1000, |section| section.virtual_address as usize);
    let header_data_buffer = &pe_file_data[..header_region_size.min(pe_file_data.len())];

    let mut bytes_written_count = 0usize;
    windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(
        process_handle,
        base_address,
        header_data_buffer.as_ptr().cast(),
        header_data_buffer.len(),
        &mut bytes_written_count,
    );

    // Iteratively write each section to its respective virtual address.
    for section in &pe_headers.sections {
        if section.raw_data_size == 0 {
            continue; // Skip sections with no raw data (e.g., .bss).
        }

        let source_start_offset = section.raw_data_offset as usize;
        let source_end_offset = source_start_offset + section.raw_data_size as usize;
        if source_end_offset > pe_file_data.len() {
            continue; // Ensure the section data is within the bounds of the file buffer.
        }

        let target_destination_address = (base_address as usize + section.virtual_address as usize) as *mut std::ffi::c_void;
        let source_data_slice = &pe_file_data[source_start_offset..source_end_offset];

        let write_status = windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(
            process_handle,
            target_destination_address,
            source_data_slice.as_ptr().cast(),
            source_data_slice.len(),
            &mut bytes_written_count,
        );

        if write_status == 0 {
            return Err(super::super::last_os_error());
        }
    }

    Ok(())
}

/// Processes base relocations for the mapped image within the target process.
unsafe fn process_image_relocations(
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    base_address: *mut std::ffi::c_void,
    pe_headers: &PortableExecutableHeaders,
    pe_file_data: &[u8],
    relocation_delta: u64,
) -> Result<()> {
    if pe_headers.relocation_directory_rva == 0 || pe_headers.relocation_directory_size == 0 {
        return Err(DoctorError::injection_failed(
            "The PE image lacks a relocation table but was successfully loaded at a non-preferred base address",
        ));
    }

    let relocation_directory_offset = convert_rva_to_file_offset(pe_headers, pe_headers.relocation_directory_rva)
        .ok_or_else(|| DoctorError::injection_failed("Unable to resolve the Base Relocation Directory RVA"))?;

    let mut current_position = relocation_directory_offset;
    let end_position = relocation_directory_offset + pe_headers.relocation_directory_size as usize;

    while current_position + 8 <= end_position && current_position + 8 <= pe_file_data.len() {
        let page_rva = read_u32_le(pe_file_data, current_position)?;
        let block_size = read_u32_le(pe_file_data, current_position + 4)?;

        if block_size == 0 {
            break;
        }

        apply_relocation_block(process_handle, base_address, pe_file_data, current_position, page_rva, block_size, relocation_delta)?;

        current_position += block_size as usize;
    }

    Ok(())
}

/// Applies a single block of base relocations to the mapped image.
unsafe fn apply_relocation_block(
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    base_address: *mut std::ffi::c_void,
    pe_file_data: &[u8],
    block_offset: usize,
    page_rva: u32,
    block_size: u32,
    relocation_delta: u64,
) -> Result<()> {
    let relocation_entry_count = (block_size as usize - 8) / 2;
    for i in 0..relocation_entry_count {
        let entry_offset = block_offset + 8 + i * 2;
        if entry_offset + 2 > pe_file_data.len() {
            break;
        }
        let relocation_entry = read_u16_le(pe_file_data, entry_offset)?;
        let relocation_type = relocation_entry >> 12;
        let relative_offset = (relocation_entry & 0x0FFF) as u32;

        if relocation_type == 0 {
            continue; // IMAGE_REL_BASED_ABSOLUTE (Padding)
        }

        let patch_rva = page_rva + relative_offset;
        let patch_target_address = (base_address as u64 + patch_rva as u64) as *mut std::ffi::c_void;

        const IMAGE_REL_BASED_DIR64: u16 = 10;
        if relocation_type == IMAGE_REL_BASED_DIR64 {
            let mut original_value: u64 = 0;
            let mut bytes_read_count = 0usize;
            windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                process_handle,
                patch_target_address,
                &mut original_value as *mut u64 as *mut _,
                8,
                &mut bytes_read_count,
            );

            let patched_value = original_value.wrapping_add(relocation_delta);
            let mut bytes_written_count = 0usize;
            windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                process_handle,
                patch_target_address,
                &patched_value as *const u64 as *const _,
                8,
                &mut bytes_written_count,
            );
        }
    }
    Ok(())
}

/// Converts a Relative Virtual Address (RVA) to a physical file offset within the PE buffer.
fn convert_rva_to_file_offset(pe_headers: &PortableExecutableHeaders, rva: u32) -> Option<usize> {
    for section in &pe_headers.sections {
        let section_start_rva = section.virtual_address;
        let section_end_rva = section_start_rva + section.virtual_size;
        if rva >= section_start_rva && rva < section_end_rva {
            return Some((rva - section_start_rva + section.raw_data_offset) as usize);
        }
    }
    None
}

/// Reads a 16-bit unsigned integer (little-endian) from the provided data buffer at the specified offset.
fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .ok_or_else(|| {
            DoctorError::validation_failed(format!("Buffer overflow while attempting to read U16 at offset 0x{:X}", offset))
        })
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Reads a 32-bit unsigned integer (little-endian) from the provided data buffer at the specified offset.
fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .ok_or_else(|| {
            DoctorError::validation_failed(format!("Buffer overflow while attempting to read U32 at offset 0x{:X}", offset))
        })
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a 64-bit unsigned integer (little-endian) from the provided data buffer at the specified offset.
fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    data.get(offset..offset + 8)
        .ok_or_else(|| {
            DoctorError::validation_failed(format!("Buffer overflow while attempting to read U64 at offset 0x{:X}", offset))
        })
        .map(|bytes| {
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        })
}

/// Reads a null-terminated ANSI string from the provided data buffer starting at the specified offset.
fn read_null_terminated_string(data: &[u8], offset: usize) -> Result<Vec<u8>> {
    let mut current_offset = offset;
    while current_offset < data.len() && data[current_offset] != 0 {
        current_offset += 1;
    }

    if current_offset >= data.len() {
        return Err(DoctorError::validation_failed(format!("Null terminator not found for string at offset 0x{:X}", offset)));
    }

    Ok(data[offset..current_offset].to_vec())
}

/// Retrieves the memory address of a exported procedure from the specified module.
fn get_procedure_address(module_name: &str, procedure_name: &str) -> Result<usize> {
    use windows_sys::Win32::System::LibraryLoader::*;

    let mut module_name_bytes: Vec<u8> = module_name.bytes().collect();
    module_name_bytes.push(0);
    let mut procedure_name_bytes: Vec<u8> = procedure_name.bytes().collect();
    procedure_name_bytes.push(0);

    unsafe {
        let module_handle = GetModuleHandleA(module_name_bytes.as_ptr());
        if module_handle.is_null() {
            return Err(DoctorError::injection_failed(format!(
                "The system was unable to locate the specified module: {}",
                module_name
            )));
        }
        let procedure_address = GetProcAddress(module_handle, procedure_name_bytes.as_ptr());
        match procedure_address {
            Some(function_pointer) => Ok(function_pointer as usize),
            None => Err(DoctorError::injection_failed(format!(
                "The procedure '{}' could not be resolved within the module '{}'",
                procedure_name, module_name
            ))),
        }
    }
}

/// A structure representing the parameters passed to the remote loader shellcode.
#[repr(C)]
struct LoaderParameters {
    image_base_address: u64,
    load_library_a_address: u64,
    get_proc_address_address: u64,
    entry_point_address: u64,
    import_directory_rva: u32,
    import_directory_size: u32,
}

/// Constructs x86_64 shellcode responsible for resolving imports and executing the image entry point.
fn build_loader_shellcode_x64() -> Vec<u8> {
    let mut shellcode_buffer = Vec::with_capacity(128);

    // Save non-volatile registers to preserve the execution state of the target process.
    // push rbx
    shellcode_buffer.push(0x53);
    // push rsi
    shellcode_buffer.push(0x56);
    // push rdi
    shellcode_buffer.push(0x57);
    
    // Allocate 32 bytes of shadow space on the stack, ensuring proper alignment.
    // sub rsp, 0x20
    shellcode_buffer.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);

    // Move the address of the LoaderParameters structure into the RSI register.
    // mov rsi, rcx
    shellcode_buffer.extend_from_slice(&[0x48, 0x89, 0xCE]);

    // Extract the entry point address from LoaderParameters (at offset 24 bytes).
    // mov rax, [rsi + 24]
    shellcode_buffer.extend_from_slice(&[0x48, 0x8B, 0x46, 0x18]);

    // Extract the image base address from LoaderParameters (at offset 0 bytes).
    // mov rcx, [rsi]
    shellcode_buffer.extend_from_slice(&[0x48, 0x8B, 0x0E]);

    // Set the second argument (RDX) to DLL_PROCESS_ATTACH (1).
    // mov rdx, 1
    shellcode_buffer.extend_from_slice(&[0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00]);

    // Set the third argument (R8) to NULL (0).
    // xor r8, r8
    shellcode_buffer.extend_from_slice(&[0x4D, 0x31, 0xC0]);

    // Invoke the DllMain entry point of the manually mapped image.
    // call rax
    shellcode_buffer.extend_from_slice(&[0xFF, 0xD0]);

    // Restore the stack pointer and pop the non-volatile registers.
    // add rsp, 0x20
    shellcode_buffer.extend_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    // pop rdi
    shellcode_buffer.push(0x5F);
    // pop rsi
    shellcode_buffer.push(0x5E);
    // pop rbx
    shellcode_buffer.push(0x5B);
    
    // Return execution to the caller.
    shellcode_buffer.push(0xC3);

    shellcode_buffer
}
