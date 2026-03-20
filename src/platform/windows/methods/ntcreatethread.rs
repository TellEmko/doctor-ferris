//! `NtCreateThreadEx`-based injection.
//!
//! Uses the undocumented `NtCreateThreadEx` syscall from `ntdll.dll` instead
//! of the higher-level `CreateRemoteThread`. This bypasses user-mode hooks
//! placed on `kernel32!CreateRemoteThread` by security products.
//!
//! **Pros:** Avoids common user-mode API hooks. Lower detection surface.
//! **Cons:** Relies on an undocumented API; signature may shift between Windows builds.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// Injection via `NtCreateThreadEx` from `ntdll.dll`.
pub struct NtCreateThreadMethod;

/// The function signature for the undocumented `NtCreateThreadEx` system call.
type NtCreateThreadExFunction = unsafe extern "system" fn(
    thread_handle: *mut windows_sys::Win32::Foundation::HANDLE,
    desired_access: u32,
    object_attributes: *mut std::ffi::c_void,
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    start_routine: *mut std::ffi::c_void,
    argument: *mut std::ffi::c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut std::ffi::c_void,
) -> i32;

impl InjectionMethod for NtCreateThreadMethod {
    fn name(&self) -> &str {
        "ntcreatethread"
    }

    fn description(&self) -> &str {
        "Injection using the native NtCreateThreadEx system call to bypass user-mode API monitoring"
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
        80
    }

    fn compatibility(&self) -> u8 {
        70
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        let dll_path_string = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("The provided DLL path contains non-UTF-8 characters".into()))?;

        let mut dll_path_bytes = dll_path_string.as_bytes().to_vec();
        dll_path_bytes.push(0);

        log::info!(
            "[ntcreatethread] Executing injection of '{}' into {} (Process ID: {})",
            dll_path_string,
            target.name,
            target.pid
        );

        // Retrieve the memory address of the NtCreateThreadEx system call from ntdll.dll.
        let nt_create_thread_ex_procedure = resolve_nt_create_thread_ex()?;

        // Resolve the entry point for the remote thread (LoadLibraryA).
        let load_library_entry_point = super::super::resolve_load_library_a()?;

        // Obtain a handle to the target process with sufficient privileges.
        let target_process = super::super::open_process_for_injection(target.pid)?;

        unsafe {
            // Write the DLL path string into the target process memory.
            let remote_path_address = super::super::remote_alloc_and_write(target_process.raw(), &dll_path_bytes)?;

            let mut remote_thread_handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();

            // Define full thread access rights (0x1FFFFF).
            const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

            // Invoke NtCreateThreadEx to execute LoadLibraryA within the target process context.
            let status = nt_create_thread_ex_procedure(
                &mut remote_thread_handle,
                THREAD_ALL_ACCESS,
                std::ptr::null_mut(),
                target_process.raw(),
                load_library_entry_point as *mut std::ffi::c_void,
                remote_path_address,
                0, // CreateFlags: 0 ensures the thread starts execution immediately.
                0, // ZeroBits: Default alignment.
                0, // StackSize: Use default stack size.
                0, // MaximumStackSize: Use default maximum stack size.
                std::ptr::null_mut(), // AttributeList: Not required for this procedure.
            );

            if status < 0 || remote_thread_handle.is_null() {
                super::super::remote_free(target_process.raw(), remote_path_address);
                return Err(DoctorError::injection_failed(format!(
                    "The NtCreateThreadEx system call failed with NTSTATUS: 0x{:08X}",
                    status as u32
                )));
            }

            let thread_guard = super::super::SafeHandle::new(remote_thread_handle);

            // Synchronize with the remote thread and wait for its completion.
            let wait_result = windows_sys::Win32::System::Threading::WaitForSingleObject(
                thread_guard.as_ref().map_or(remote_thread_handle, |h| h.raw()),
                config.timeout.as_millis() as u32,
            );

            // Relinquish the remote memory allocated for the DLL path.
            super::super::remote_free(target_process.raw(), remote_path_address);

            // Check for execution timeout.
            const WAIT_TIMEOUT: u32 = 0x00000102;
            if wait_result == WAIT_TIMEOUT {
                return Err(DoctorError::Timeout(config.timeout));
            }

            log::info!("[ntcreatethread] Injection procedure finalized successfully");

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: None,
                details: "Library injection performed successfully via NtCreateThreadEx".into(),
            })
        }
    }
}

/// Dynamically resolves the address of the `NtCreateThreadEx` system call from `ntdll.dll`.
fn resolve_nt_create_thread_ex() -> Result<NtCreateThreadExFunction> {
    use windows_sys::Win32::System::LibraryLoader::*;

    unsafe {
        let ntdll_handle = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll_handle.is_null() {
            return Err(DoctorError::injection_failed("The system was unable to locate ntdll.dll"));
        }

        let procedure_address = GetProcAddress(ntdll_handle, b"NtCreateThreadEx\0".as_ptr());
        match procedure_address {
            Some(function_pointer) => Ok(std::mem::transmute(function_pointer)),
            None => Err(DoctorError::injection_failed(
                "The NtCreateThreadEx procedure could not be found within ntdll.dll",
            )),
        }
    }
}
