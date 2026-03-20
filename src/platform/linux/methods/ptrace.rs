//! `ptrace`-based injection for Linux.
//!
//! Attaches to the target process via `ptrace`, injects shellcode that calls
//! `dlopen` to load the shared object, then detaches. This is the Linux
//! equivalent of `CreateRemoteThread` + `LoadLibrary`.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::method::InjectionMethod;
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// Ptrace-based `dlopen` injection method.
pub struct PtraceMethod;

impl InjectionMethod for PtraceMethod {
    fn name(&self) -> &str {
        "ptrace"
    }

    fn description(&self) -> &str {
        "ptrace attach + dlopen shellcode injection"
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux]
    }

    fn supported_architectures(&self) -> &[Architecture] {
        &[Architecture::X86, Architecture::X86_64]
    }

    fn requires_elevation(&self) -> bool {
        true
    }

    fn reliability(&self) -> u8 {
        85
    }

    fn compatibility(&self) -> u8 {
        80
    }

    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult> {
        use nix::sys::ptrace;
        use nix::sys::signal::Signal;
        use nix::sys::wait::waitpid;
        use nix::unistd::Pid;

        let so_path = config
            .dll_path
            .to_str()
            .ok_or_else(|| DoctorError::InvalidPath("non-UTF-8 shared object path".into()))?;

        log::info!(
            "[ptrace] Injecting '{}' into {} (PID {})",
            so_path,
            target.name,
            target.pid
        );

        let pid = Pid::from_raw(target.pid as i32);

        // Attach to the target process.
        ptrace::attach(pid)
            .map_err(|e| DoctorError::PermissionDenied(format!("ptrace attach failed: {}", e)))?;

        // Wait for the target to stop.
        waitpid(pid, None)
            .map_err(|e| DoctorError::injection_failed(format!("waitpid failed: {}", e)))?;

        // Save original registers.
        let original_regs = ptrace::getregs(pid).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("getregs failed: {}", e))
        })?;

        // Locate `dlopen` in the target process by scanning `/proc/<pid>/maps`
        // for `libdl` or `libc` (on modern glibc, dlopen is in libc).
        let dlopen_addr = find_remote_dlopen(target.pid)?;
        let malloc_addr = find_remote_symbol(target.pid, "malloc")?;
        let free_addr = find_remote_symbol(target.pid, "free")?;

        // Allocate space for the path string in the target process.
        // We use malloc by calling it via ptrace register manipulation.
        let path_len = so_path.len() + 1; // Include null terminator.

        // Call malloc(path_len) in the target.
        let mut regs = original_regs;

        // x86_64 calling convention: rdi = first arg.
        regs.rdi = path_len as u64;
        regs.rip = malloc_addr;
        // Set up a return to a trap (int3) so we can catch the return.
        regs.rsp -= 8;

        // Write an int3 (0xCC) at the return address so execution stops.
        let trap_addr = regs.rsp;
        let original_trap_data = ptrace::read(pid, trap_addr as *mut _).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("ptrace read failed: {}", e))
        })?;

        unsafe {
            ptrace::write(pid, trap_addr as *mut _, 0xCCCCCCCCCCCCCCCC_u64 as *mut _).map_err(
                |e| {
                    let _ = ptrace::detach(pid, None);
                    DoctorError::injection_failed(format!("ptrace write failed: {}", e))
                },
            )?;
        }

        ptrace::setregs(pid, regs).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("setregs failed: {}", e))
        })?;

        ptrace::cont(pid, None).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("ptrace cont failed: {}", e))
        })?;

        // Wait for the trap (malloc returns).
        waitpid(pid, None).map_err(|e| {
            DoctorError::injection_failed(format!("waitpid after malloc failed: {}", e))
        })?;

        let post_malloc_regs = ptrace::getregs(pid).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("getregs after malloc failed: {}", e))
        })?;

        let remote_buf = post_malloc_regs.rax;
        if remote_buf == 0 {
            let _ = ptrace::setregs(pid, original_regs);
            let _ = ptrace::detach(pid, None);
            return Err(DoctorError::injection_failed("remote malloc returned NULL"));
        }

        // Write the SO path into the allocated buffer.
        let path_bytes = so_path.as_bytes();
        for (i, chunk) in path_bytes.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            let val = u64::from_le_bytes(word);
            unsafe {
                let _ = ptrace::write(pid, (remote_buf + (i * 8) as u64) as *mut _, val as *mut _);
            }
        }

        // Call dlopen(remote_buf, RTLD_NOW | RTLD_GLOBAL).
        let mut regs2 = original_regs;
        regs2.rdi = remote_buf;
        regs2.rsi = 0x102; // RTLD_NOW | RTLD_GLOBAL
        regs2.rip = dlopen_addr;
        regs2.rsp = trap_addr;

        ptrace::setregs(pid, regs2).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("setregs for dlopen failed: {}", e))
        })?;

        ptrace::cont(pid, None).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("ptrace cont for dlopen failed: {}", e))
        })?;

        waitpid(pid, None).map_err(|e| {
            DoctorError::injection_failed(format!("waitpid after dlopen failed: {}", e))
        })?;

        let post_dlopen_regs = ptrace::getregs(pid).map_err(|e| {
            let _ = ptrace::detach(pid, None);
            DoctorError::injection_failed(format!("getregs after dlopen failed: {}", e))
        })?;

        let dlopen_result = post_dlopen_regs.rax;

        // Call free(remote_buf) to clean up.
        let mut regs3 = original_regs;
        regs3.rdi = remote_buf;
        regs3.rip = free_addr;
        regs3.rsp = trap_addr;

        let _ = ptrace::setregs(pid, regs3);
        let _ = ptrace::cont(pid, None);
        let _ = waitpid(pid, None);

        // Restore the original trap data and registers.
        unsafe {
            let _ = ptrace::write(pid, trap_addr as *mut _, original_trap_data as *mut _);
        }
        let _ = ptrace::setregs(pid, original_regs);
        let _ = ptrace::detach(pid, None);

        if dlopen_result == 0 {
            return Err(DoctorError::InjectionFailed(
                "The remote call to dlopen failed (returned NULL). This typically indicates that the shared library is missing dependencies or has an incompatible format.".into(),
            ));
        }

        log::info!(
            "[ptrace] Injection procedure successfully completed; dlopen handle: 0x{:X}",
            dlopen_result
        );

        Ok(InjectionResult {
            method_name: self.name().to_string(),
            target: target.clone(),
            dll_path: config.dll_path.clone(),
            base_address: Some(dlopen_result as usize),
            details: format!(
                "ptrace-based dlopen injection was successful (library handle: 0x{:X})",
                dlopen_result
            ),
        })
    }
}

/// Find the address of `dlopen` in the target process by parsing
/// `/proc/<pid>/maps` for the C library and computing the offset.
fn find_remote_dlopen(pid: u32) -> Result<u64> {
    find_remote_symbol(pid, "__libc_dlopen_mode").or_else(|_| find_remote_symbol(pid, "dlopen"))
}

/// Find a symbol's runtime address in a remote process.
///
/// Strategy: find the base address of the library containing the symbol in
/// both the local process and the target, compute the offset, then apply it.
fn find_remote_symbol(pid: u32, symbol: &str) -> Result<u64> {
    // Find the symbol in our own process.
    let local_addr = find_local_symbol(symbol)?;

    // Find the library base in our process and in the target.
    let local_maps = parse_maps(std::process::id())?;
    let remote_maps = parse_maps(pid)?;

    // Determine which library contains the requested symbol.
    let local_lib = local_maps
        .iter()
        .find(|m| local_addr >= m.start && local_addr < m.end)
        .ok_or_else(|| {
            DoctorError::InjectionFailed(format!(
                "Unable to locate the library containing the local symbol '{}' in the current process",
                symbol
            ))
        })?;

    let remote_lib = remote_maps
        .iter()
        .find(|m| m.path == local_lib.path)
        .ok_or_else(|| {
            DoctorError::InjectionFailed(format!(
                "The target process has not loaded the required library: '{}'",
                local_lib.path
            ))
        })?;

    let offset = local_addr - local_lib.start;
    Ok(remote_lib.start + offset)
}

/// Find a symbol's address in the current process via `dlsym`.
fn find_local_symbol(name: &str) -> Result<u64> {
    use std::ffi::CString;

    let c_name = CString::new(name).map_err(|e| DoctorError::Unexpected(format!("Failed to initialize a C-compatible string for symbol '{}': {}", name, e)))?;

    unsafe {
        // RTLD_DEFAULT = 0 on Linux.
        let addr = libc::dlsym(std::ptr::null_mut(), c_name.as_ptr());
        if addr.is_null() {
            return Err(DoctorError::InjectionFailed(format!(
                "The system was unable to locate the symbol '{}' within the current process context",
                name
            )));
        }
        Ok(addr as u64)
    }
}

struct MapEntry {
    start: u64,
    end: u64,
    path: String,
}

fn parse_maps(pid: u32) -> Result<Vec<MapEntry>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(&maps_path)
        .map_err(|e| DoctorError::ProcessNotFound(format!("Unable to read the process memory map at {}: {}", maps_path, e)))?;

    let mut entries = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(6, ' ').collect();
        if parts.len() < 6 {
            continue;
        }

        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(addr_range[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_range[1], 16).unwrap_or(0);
        let path = parts[5].trim().to_string();

        if !path.is_empty() && !path.starts_with('[') {
            entries.push(MapEntry { start, end, path });
        }
    }

    Ok(entries)
}
