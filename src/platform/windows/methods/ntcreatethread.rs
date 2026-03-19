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

/// `NtCreateThreadEx` function signature (undocumented).
type FnNtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: *mut windows_sys::Win32::Foundation::HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut std::ffi::c_void,
    ProcessHandle: windows_sys::Win32::Foundation::HANDLE,
    StartRoutine: *mut std::ffi::c_void,
    Argument: *mut std::ffi::c_void,
    CreateFlags: u32,
    ZeroBits: usize,
    StackSize: usize,
    MaximumStackSize: usize,
    AttributeList: *mut std::ffi::c_void,
) -> i32;

impl InjectionMethod for NtCreateThreadMethod {
    fn name(&self) -> &str {
        "ntcreatethread"
    }

    fn description(&self) -> &str {
        "NtCreateThreadEx-based injection (bypasses user-mode hooks on CreateRemoteThread)"
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
        let dll_path_str = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("non-UTF-8 DLL path".into()))?;

        let mut dll_bytes = dll_path_str.as_bytes().to_vec();
        dll_bytes.push(0);

        log::info!(
            "[ntcreatethread] Injecting '{}' into {} (PID {})",
            dll_path_str,
            target.name,
            target.pid
        );

        // Resolve NtCreateThreadEx from ntdll.dll.
        let nt_create_thread_ex = resolve_nt_create_thread_ex()?;

        // Resolve LoadLibraryA as the thread entry point.
        let load_library = super::super::resolve_loadlibrary_a()?;

        let process = super::super::open_process_for_injection(target.pid)?;

        unsafe {
            let remote_path =
                super::super::remote_alloc_and_write(process.raw(), &dll_bytes)?;

            let mut thread_handle: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();

            // THREAD_ALL_ACCESS = 0x1FFFFF
            let status = nt_create_thread_ex(
                &mut thread_handle,
                0x1FFFFF,
                std::ptr::null_mut(),
                process.raw(),
                load_library as *mut std::ffi::c_void,
                remote_path,
                0,  // No creation flags — thread starts immediately.
                0,  // ZeroBits
                0,  // StackSize (default)
                0,  // MaximumStackSize (default)
                std::ptr::null_mut(),
            );

            if status < 0 || thread_handle.is_null() {
                super::super::remote_free(process.raw(), remote_path);
                return Err(DoctorError::injection_failed(format!(
                    "NtCreateThreadEx returned NTSTATUS 0x{:08X}",
                    status as u32
                )));
            }

            let thread_guard = super::super::SafeHandle::new(thread_handle);

            // Wait for thread completion.
            let wait = windows_sys::Win32::System::Threading::WaitForSingleObject(
                thread_guard.as_ref().map_or(thread_handle, |h| h.raw()),
                config.timeout.as_millis() as u32,
            );

            super::super::remote_free(process.raw(), remote_path);

            if wait == 0x00000102 {
                return Err(DoctorError::Timeout(config.timeout));
            }

            log::info!("[ntcreatethread] Injection complete");

            Ok(InjectionResult {
                method_name: self.name().to_string(),
                target: target.clone(),
                dll_path: config.dll_path.clone(),
                base_address: None,
                details: "NtCreateThreadEx injection successful".into(),
            })
        }
    }
}

/// Dynamically resolve `NtCreateThreadEx` from `ntdll.dll`.
fn resolve_nt_create_thread_ex() -> Result<FnNtCreateThreadEx> {
    use windows_sys::Win32::System::LibraryLoader::*;

    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return Err(DoctorError::injection_failed(
                "failed to locate ntdll.dll",
            ));
        }

        let addr = GetProcAddress(ntdll, b"NtCreateThreadEx\0".as_ptr());
        match addr {
            Some(f) => Ok(std::mem::transmute(f)),
            None => Err(DoctorError::injection_failed(
                "NtCreateThreadEx not found in ntdll.dll",
            )),
        }
    }
}
