//! Linux privilege management.

/// Returns `true` if the current process is running as root (UID 0).
pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}
