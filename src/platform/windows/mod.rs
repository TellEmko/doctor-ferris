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

// ----------------------------------------------------------------------
// Shared Helpers
// ----------------------------------------------------------------------

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

/// Retrieve the last Win32 error as a [`DoctorError::OsError`].
pub(crate) fn last_os_error() -> crate::error::DoctorError {
    let error_code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    crate::error::DoctorError::os_error(
        error_code as i64,
        format!("Win32 operational failure (code: {})", error_code),
    )
}

/// Allocates memory within a remote process and writes the specified data buffer into it.
///
/// Returns the base address of the newly allocated memory in the target process.
pub(crate) unsafe fn remote_alloc_and_write(
    process_handle: HANDLE,
    data_buffer: &[u8],
) -> crate::error::Result<*mut std::ffi::c_void> {
    use windows_sys::Win32::System::Memory::*;

    let allocation_address = VirtualAllocEx(
        process_handle,
        std::ptr::null(),
        data_buffer.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if allocation_address.is_null() {
        return Err(last_os_error());
    }

    let mut bytes_written_count = 0usize;
    let write_success = windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory(
        process_handle,
        allocation_address,
        data_buffer.as_ptr().cast(),
        data_buffer.len(),
        &mut bytes_written_count,
    );

    if write_success == 0 || bytes_written_count != data_buffer.len() {
        VirtualFreeEx(process_handle, allocation_address, 0, MEM_RELEASE);
        return Err(last_os_error());
    }

    Ok(allocation_address)
}

/// Deallocates previously reserved or committed memory within a remote process.
pub(crate) unsafe fn remote_free(process_handle: HANDLE, memory_address: *mut std::ffi::c_void) {
    use windows_sys::Win32::System::Memory::*;
    VirtualFreeEx(process_handle, memory_address, 0, MEM_RELEASE);
}

/// Resolves the memory address of the `LoadLibraryA` function within `kernel32.dll`.
pub(crate) fn resolve_load_library_a() -> crate::error::Result<unsafe extern "system" fn() -> isize> {
    use windows_sys::Win32::System::LibraryLoader::*;

    unsafe {
        let kernel32_handle = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if kernel32_handle.is_null() {
            return Err(last_os_error());
        }

        let procedure_address = GetProcAddress(kernel32_handle, b"LoadLibraryA\0".as_ptr());
        match procedure_address {
            Some(function_pointer) => Ok(std::mem::transmute(function_pointer)),
            None => Err(last_os_error()),
        }
    }
}

/// Opens a target process with the specific access rights required for library injection.
pub(crate) fn open_process_for_injection(process_id: u32) -> crate::error::Result<SafeHandle> {
    use windows_sys::Win32::System::Threading::*;

    let access_rights = PROCESS_CREATE_THREAD
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ
        | PROCESS_QUERY_INFORMATION;

    let process_handle = unsafe { OpenProcess(access_rights, 0, process_id) };
    SafeHandle::new(process_handle).ok_or_else(last_os_error)
}
