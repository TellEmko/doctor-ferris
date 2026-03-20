//! Windows privilege management.
//!
//! Provides elevation checks, debug privilege acquisition, and UAC elevation.

use crate::error::{DoctorError, Result};

/// Returns `true` if the current process is running with administrative privileges.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        let mut access_token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut access_token) == 0 {
            return false;
        }
        let _token_guard = super::SafeHandle::new(access_token);

        let mut elevation_info: TOKEN_ELEVATION = std::mem::zeroed();
        let mut return_length: u32 = 0;

        let success = GetTokenInformation(
            access_token,
            TokenElevation,
            &mut elevation_info as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        success != 0 && elevation_info.TokenIsElevated != 0
    }
}

/// Enables the `SeDebugPrivilege` security privilege for the current process.
///
/// This privilege is essential for opening handles to processes owned by other users
/// or system services. This operation requires the current process to be running in an elevated context.
pub fn enable_debug_privilege() -> Result<()> {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        let mut access_token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut access_token,
        ) == 0
        {
            return Err(super::last_os_error());
        }
        let _token_guard = super::SafeHandle::new(access_token);

        let mut privilege_luid: windows_sys::Win32::Foundation::LUID = std::mem::zeroed();
        if LookupPrivilegeValueA(std::ptr::null(), b"SeDebugPrivilege\0".as_ptr(), &mut privilege_luid) == 0 {
            return Err(super::last_os_error());
        }

        let mut token_privileges: TOKEN_PRIVILEGES = std::mem::zeroed();
        token_privileges.PrivilegeCount = 1;
        token_privileges.Privileges[0].Luid = privilege_luid;
        token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            access_token,
            0, // Do not disable all privileges.
            &token_privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(super::last_os_error());
        }

        // AdjustTokenPrivileges may succeed while still failing to assign all requested privileges.
        let last_error_code = windows_sys::Win32::Foundation::GetLastError();
        const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;

        if last_error_code == ERROR_NOT_ALL_ASSIGNED {
            log::warn!("The `AdjustTokenPrivileges` call completed, but not all requested privileges were successfully assigned.");
        } else if last_error_code != 0 {
            log::warn!(
                "The `AdjustTokenPrivileges` call completed with an unexpected status code: {}",
                last_error_code
            );
        }

        log::info!("The 'SeDebugPrivilege' has been successfully enabled for the current process");
        Ok(())
    }
}

/// Attempts to restart the current executable with administrative privileges.
///
/// This procedure initiates a User Account Control (UAC) elevation prompt. If the user
/// grants permission, a new instance of the process is spawned with elevated rights.
/// The calling process should terminate immediately upon successful execution of this function.
pub fn request_elevation() -> Result<()> {
    let executable_path = std::env::current_exe().map_err(|err| {
        DoctorError::PermissionDenied(format!("The system was unable to determine the executable path: {}", err))
    })?;

    let command_arguments: Vec<String> = std::env::args().skip(1).collect();

    // Utilize PowerShell to initiate the UAC elevation procedure via the 'RunAs' verb.
    let execution_status = std::process::Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
                executable_path.display(),
                command_arguments.join("' '")
            ),
        ])
        .status()
        .map_err(|err| {
            DoctorError::PermissionDenied(format!("The request for process elevation failed: {}", err))
        })?;

    if !execution_status.success() {
        return Err(DoctorError::PermissionDenied(
            "The administrative elevation request was denied by the user or failed to initialize".into(),
        ));
    }

    Ok(())
}
