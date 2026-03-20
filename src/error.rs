//! Error types for the doctor-ferris injection framework.
//!
//! All fallible operations in this crate return [`Result<T>`] which uses
//! [`DoctorError`] as the error variant.


/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, DoctorError>;

/// Enumerates all error conditions the injection framework can produce.
#[derive(Debug, thiserror::Error)]
pub enum DoctorError {
    /// The specified process could not be located using the provided identifier or name.
    #[error("Process not found: {0}")]
    ProcessNotFound(String),

    /// The DLL architecture is incompatible with the target process architecture.
    #[error("Architecture mismatch: DLL is {dll_arch}, target process is {process_arch}")]
    ArchitectureMismatch {
        dll_arch: String,
        process_arch: String,
    },

    /// The current process possesses insufficient privileges to perform the requested operation.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// The procedure was unable to complete the injection into the target process.
    #[error("Injection procedure failed: {0}")]
    InjectionFailed(String),

    /// The specified library path is invalid or the file does not exist on the filesystem.
    #[error("Invalid library path: {0}")]
    InvalidPath(String),

    /// The requested injection method is not registered within the framework's internal registry.
    #[error("Injection method not found: {0}")]
    MethodNotFound(String),

    /// The current operating system or hardware platform does not support the requested operation.
    #[error("Platform unsupported: {0}")]
    PlatformUnsupported(String),

    /// The target process or library failed a prerequisite validation check.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// An operation timed out before completing successfully.
    #[error("Operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// An I/O error occurred during an interaction with the operating system.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A platform-specific OS error occurred with a native error code.
    #[error("OS error (code: {code}): {message}")]
    OsError { code: i64, message: String },

    /// An unexpected error occurred that does not fall into other categories.
    #[error("Unexpected error: {0}")]
    Unexpected(String),
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

    /// Construct a [`ValidationFailed`](DoctorError::ValidationFailed) with a formatted message.
    pub fn validation_failed(message: impl Into<String>) -> Self {
        Self::ValidationFailed(message.into())
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
