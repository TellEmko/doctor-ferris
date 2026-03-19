//! Error types for the doctor-ferris injection framework.
//!
//! All fallible operations in this crate return [`Result<T>`] which uses
//! [`DoctorError`] as the error variant.

use std::fmt;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, DoctorError>;

/// Enumerates all error conditions the injection framework can produce.
#[derive(Debug, thiserror::Error)]
pub enum DoctorError {
    /// The target process could not be found by PID or name.
    #[error("process not found: {0}")]
    ProcessNotFound(String),

    /// The DLL architecture does not match the target process architecture.
    #[error("architecture mismatch: DLL is {dll_arch}, target process is {process_arch}")]
    ArchitectureMismatch {
        dll_arch: String,
        process_arch: String,
    },

    /// The current process lacks the required privileges for the operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// The injection procedure itself failed.
    #[error("injection failed: {0}")]
    InjectionFailed(String),

    /// The supplied DLL path is invalid or the file does not exist.
    #[error("invalid DLL path: {0}")]
    InvalidPath(String),

    /// The requested injection method is not registered in the method registry.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// The current platform does not support the requested operation.
    #[error("platform unsupported: {0}")]
    PlatformUnsupported(String),

    /// The target process or DLL failed a validation check.
    #[error("validation failed: {0}")]
    ValidationFailed(String),

    /// A timeout expired while waiting for an operation to complete.
    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// An I/O error propagated from the standard library.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A platform-specific OS error with a raw error code.
    #[error("OS error {code}: {message}")]
    OsError { code: i64, message: String },

    /// Catch-all for errors that do not fit other variants.
    #[error("{0}")]
    Other(String),
}

impl DoctorError {
    /// Construct an [`OsError`](DoctorError::OsError) from a raw code and message.
    pub fn os_error(code: i64, message: impl Into<String>) -> Self {
        Self::OsError {
            code,
            message: message.into(),
        }
    }

    /// Construct an [`InjectionFailed`](DoctorError::InjectionFailed) with a formatted message.
    pub fn injection_failed(message: impl Into<String>) -> Self {
        Self::InjectionFailed(message.into())
    }

    /// Returns `true` if the error is recoverable and the operation may be retried.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            DoctorError::Timeout(_) | DoctorError::Io(_) | DoctorError::OsError { .. }
        )
    }
}

// Display is derived by thiserror via #[error(...)] attributes.
