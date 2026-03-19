//! Windows platform backend.
//!
//! Provides process enumeration, architecture detection, privilege management,
//! and multiple injection method implementations for Windows targets.

pub mod methods;
pub mod privilege;
pub mod process;

use crate::method::MethodRegistry;

/// Register all built-in Windows injection methods into the given registry.
pub fn register_methods(registry: &mut MethodRegistry) {
    registry.register(Box::new(methods::loadlibrary::LoadLibraryMethod));
    registry.register(Box::new(methods::ntcreatethread::NtCreateThreadMethod));
    registry.register(Box::new(methods::thread_hijack::ThreadHijackMethod));
    registry.register(Box::new(methods::apc_injection::ApcInjectionMethod));

    registry.register(Box::new(methods::manual_map::ManualMapMethod));
}

// ── Shared helpers ───────────────────────────────────────────────────

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// RAII wrapper for a Windows `HANDLE`. Automatically closes on drop.
pub(crate) struct SafeHandle(pub HANDLE);

impl SafeHandle {
    /// Wrap a raw handle, returning `None` if it is null or invalid.
    pub fn new(h: HANDLE) -> Option<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(h))
        }
    }

    /// Access the raw handle value.
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Retrieve the last Win32 error as a [`crate::error::DoctorError::OsError`].
pub(crate) fn last_os_error() -> crate::error::DoctorError {
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    crate::error::DoctorError::os_error(code as i64, format!("Win32 error {}", code))
}

/// Allocate memory in a remote process and write `data` into it.
///
/// Returns the base address of the allocation in the target process.
pub(crate) unsafe fn remote_alloc_and_write(
    process: HANDLE,
    data: &[u8],
) -> crate::error::Result<*mut std::ffi::c_void> {
    use windows_sys::Win32::System::Memory::*;

    let addr = VirtualAllocEx(
        process,
        std::ptr::null(),
        data.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if addr.is_null() {
        return Err(last_os_error());
    }

    let mut bytes_written = 0usize;
    let ok = windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(
        process,
        addr,
        data.as_ptr().cast(),
        data.len(),
        &mut bytes_written,
    );

    if ok == 0 || bytes_written != data.len() {
        VirtualFreeEx(process, addr, 0, MEM_RELEASE);
        return Err(last_os_error());
    }

    Ok(addr)
}

/// Free previously allocated remote memory.
pub(crate) unsafe fn remote_free(
    process: HANDLE,
    addr: *mut std::ffi::c_void,
) {
    use windows_sys::Win32::System::Memory::*;
    VirtualFreeEx(process, addr, 0, MEM_RELEASE);
}

/// Resolve the address of `LoadLibraryA` within `kernel32.dll`.
pub(crate) fn resolve_loadlibrary_a() -> crate::error::Result<unsafe extern "system" fn() -> isize>
{
    use windows_sys::Win32::System::LibraryLoader::*;

    unsafe {
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if kernel32.is_null() {
            return Err(last_os_error());
        }

        let addr = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr());
        match addr {
            Some(f) => Ok(std::mem::transmute(f)),
            None => Err(last_os_error()),
        }
    }
}

/// Open a process with the required access rights for injection.
pub(crate) fn open_process_for_injection(
    pid: u32,
) -> crate::error::Result<SafeHandle> {
    use windows_sys::Win32::System::Threading::*;

    let access = PROCESS_CREATE_THREAD
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ
        | PROCESS_QUERY_INFORMATION;

    let handle = unsafe { OpenProcess(access, 0, pid) };
    SafeHandle::new(handle).ok_or_else(last_os_error)
}
