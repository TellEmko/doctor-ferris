//! Dummy payload for testing doctor-ferris injection.

#[cfg(windows)]
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

#[cfg(windows)]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _hinst_dll: *mut std::ffi::c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut std::ffi::c_void,
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        write_marker();
    }
    1
}

// For Linux/macOS constructors
#[cfg(not(windows))]
#[ctor::ctor]
fn init() {
    write_marker();
}

fn write_marker() {
    use std::fs::OpenOptions;
    use std::io::Write;
    
    // Write to a well-known temporary file that the test runner can check.
    let path = std::env::temp_dir().join("doctor_ferris_injected.tmp");
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let pid = std::process::id();
        let _ = writeln!(file, "INJECTED_PID={}", pid);
    }
}
