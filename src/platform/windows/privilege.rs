//! Windows privilege management.
//!
//! Provides elevation checks, debug privilege acquisition, and UAC elevation.

use crate::error::{DoctorError, Result};

/// Returns `true` if the current process is running with administrator privileges.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let _guard = super::SafeHandle::new(token);

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len: u32 = 0;

        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );

        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Enable `SeDebugPrivilege` for the current process.
///
/// This privilege is required to open handles to processes owned by other
/// users or system services. Must be called from an elevated context.
pub fn enable_debug_privilege() -> Result<()> {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        let mut token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == 0
        {
            return Err(super::last_os_error());
        }
        let _guard = super::SafeHandle::new(token);

        let mut luid: windows_sys::Win32::Foundation::LUID = std::mem::zeroed();
        if LookupPrivilegeValueA(
            std::ptr::null(),
            b"SeDebugPrivilege\0".as_ptr(),
            &mut luid,
        ) == 0
        {
            return Err(super::last_os_error());
        }

        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            token,
            0, // do not disable all
            &tp,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(super::last_os_error());
        }

        // AdjustTokenPrivileges can succeed but still set ERROR_NOT_ALL_ASSIGNED.
        let last_err = windows_sys::Win32::Foundation::GetLastError();
        if last_err != 0 {
            log::warn!(
                "AdjustTokenPrivileges partially succeeded (error {})",
                last_err
            );
        }

        log::info!("SeDebugPrivilege enabled");
        Ok(())
    }
}

/// Attempt to re-launch the current executable with elevated privileges.
///
/// This triggers a UAC prompt on Windows. If the user accepts, a new elevated
/// process is spawned. The current process should exit after calling this.
pub fn request_elevation() -> Result<()> {
    let exe_path = std::env::current_exe().map_err(|e| {
        DoctorError::PermissionDenied(format!("cannot determine executable path: {}", e))
    })?;

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Use PowerShell to trigger a UAC elevation prompt.
    let status = std::process::Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
                exe_path.display(),
                args.join("' '")
            ),
        ])
        .status()
        .map_err(|e| {
            DoctorError::PermissionDenied(format!("failed to request elevation: {}", e))
        })?;

    if !status.success() {
        return Err(DoctorError::PermissionDenied(
            "UAC elevation was denied or failed".into(),
        ));
    }

    Ok(())
}
