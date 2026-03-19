//! macOS process enumeration and architecture detection.

use crate::error::{DoctorError, Result};
use crate::types::{Architecture, Pid, ProcessInfo};

/// Enumerate running processes via `sysctl` with `KERN_PROC_ALL`.
pub fn enumerate() -> Result<Vec<ProcessInfo>> {
    use libc::{
        c_int, c_void, kinfo_proc, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_ALL,
    };

    unsafe {
        let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
        let mut size: libc::size_t = 0;

        // First call to determine buffer size.
        if sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(DoctorError::Other("sysctl size query failed".into()));
        }

        let count = size / std::mem::size_of::<kinfo_proc>();
        let mut procs: Vec<kinfo_proc> = Vec::with_capacity(count);
        procs.set_len(count);

        if sysctl(
            mib.as_mut_ptr(),
            3,
            procs.as_mut_ptr() as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(DoctorError::Other("sysctl process query failed".into()));
        }

        let actual_count = size / std::mem::size_of::<kinfo_proc>();
        let mut result = Vec::with_capacity(actual_count);

        for proc in &procs[..actual_count] {
            let pid = proc.kp_proc.p_pid as u32;
            let name = std::ffi::CStr::from_ptr(proc.kp_proc.p_comm.as_ptr())
                .to_string_lossy()
                .into_owned();
            let architecture = detect_architecture(pid).unwrap_or(Architecture::Unknown);

            result.push(ProcessInfo {
                pid,
                name,
                architecture,
            });
        }

        Ok(result)
    }
}

/// Detect the architecture of a process by reading the Mach-O header from
/// the process executable path.
pub fn detect_architecture(pid: Pid) -> Result<Architecture> {
    use std::io::Read;

    // Get the executable path via `proc_pidpath`.
    let mut path_buf = [0u8; 4096];
    let path_len = unsafe {
        libc::proc_pidpath(
            pid as i32,
            path_buf.as_mut_ptr() as *mut _,
            path_buf.len() as u32,
        )
    };

    if path_len <= 0 {
        return Ok(Architecture::Unknown);
    }

    let path = std::str::from_utf8(&path_buf[..path_len as usize])
        .map_err(|_| DoctorError::Other("non-UTF-8 process path".into()))?;

    let mut file = std::fs::File::open(path).map_err(|e| {
        DoctorError::Other(format!("cannot open '{}': {}", path, e))
    })?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| {
        DoctorError::Other(format!("cannot read Mach-O header: {}", e))
    })?;

    let magic_val = u32::from_le_bytes(magic);
    Ok(match magic_val {
        0xFEED_FACE => Architecture::X86,    // MH_MAGIC (32-bit)
        0xFEED_FACF => Architecture::X86_64, // MH_MAGIC_64
        _ => Architecture::Unknown,
    })
}
