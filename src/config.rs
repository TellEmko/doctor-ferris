//! Injection configuration and builder API.
//!
//! [`InjectionConfig`] is the primary configuration type passed to the injector.
//! It supports a builder pattern for ergonomic construction.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{DoctorError, Result};


/// Target specification — either a PID or a process name.
#[derive(Debug, Clone)]
pub enum Target {
    /// Target a specific process by its PID.
    Pid(u32),
    /// Target the first process matching this name.
    Name(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Pid(pid) => write!(f, "PID {}", pid),
            Target::Name(name) => write!(f, "\"{}\"", name),
        }
    }
}

/// Complete injection configuration.
///
/// Construct via the builder pattern:
/// ```rust,no_run
/// use doctor_ferris::config::{InjectionConfig, InjectionMode};
///
/// let config = InjectionConfig::builder()
///     .dll_path("payload.dll")
///     .target_pid(1234)
///     .method("thread_hijack")
///     .stealth(true)
///     .build()
///     .expect("valid config");
/// ```
#[derive(Debug, Clone)]
pub struct InjectionConfig {
    /// Path to the DLL / shared object to inject.
    pub dll_path: PathBuf,
    /// Target process specification.
    pub target: Target,
    /// Explicit method to use. If none, a platform default is chosen.
    pub method: Option<String>,
    /// Attempt to escalate privileges if required.
    pub elevate_privileges: bool,
    /// Apply post-injection stealth techniques (e.g., zeroing headers).
    pub stealth: bool,
    /// Maximum time to wait for the injection to complete.
    pub timeout: Duration,
    /// Whether to skip architecture compatibility validation.
    /// **Danger:** enabling this can cause crashes in the target process.
    pub skip_arch_check: bool,
}

impl InjectionConfig {
    /// Returns a new configuration builder.
    pub fn builder() -> InjectionConfigBuilder {
        InjectionConfigBuilder::default()
    }
}

/// Builder for [`InjectionConfig`].
#[derive(Debug, Clone, Default)]
pub struct InjectionConfigBuilder {
    dll_path: Option<PathBuf>,
    target: Option<Target>,
    method: Option<String>,
    elevate_privileges: bool,
    stealth: bool,
    timeout: Option<Duration>,
    skip_arch_check: bool,
}

impl InjectionConfigBuilder {
    /// Set the path to the DLL or shared object to inject.
    pub fn dll_path(mut self, path: impl AsRef<Path>) -> Self {
        self.dll_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the target process by PID.
    pub fn target_pid(mut self, pid: u32) -> Self {
        self.target = Some(Target::Pid(pid));
        self
    }

    /// Set the target process by name.
    pub fn target_name(mut self, name: impl Into<String>) -> Self {
        self.target = Some(Target::Name(name.into()));
        self
    }

    /// Set a specific injection method to use.
    pub fn method(mut self, name: impl Into<String>) -> Self {
        self.method = Some(name.into());
        self
    }

    /// Enable post-injection stealth operations (like PE header cleanup).
    pub fn stealth(mut self, enable: bool) -> Self {
        self.stealth = enable;
        self
    }

    /// Enable automatic privilege escalation on permission errors.
    pub fn elevate(mut self, elevate: bool) -> Self {
        self.elevate_privileges = elevate;
        self
    }

    /// Set the timeout for the injection operation.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Skip architecture compatibility checks. **Use with extreme caution.**
    pub fn skip_arch_check(mut self, skip: bool) -> Self {
        self.skip_arch_check = skip;
        self
    }

    /// Consume the builder and produce a validated [`InjectionConfig`].
    pub fn build(self) -> Result<InjectionConfig> {
        let dll_path = self
            .dll_path
            .ok_or_else(|| DoctorError::InvalidPath("DLL path is required".into()))?;

        let target = self
            .target
            .ok_or_else(|| DoctorError::ValidationFailed("target process is required".into()))?;

        Ok(InjectionConfig {
            dll_path,
            target,
            method: self.method,
            elevate_privileges: self.elevate_privileges,
            stealth: self.stealth,
            timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
            skip_arch_check: self.skip_arch_check,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_requires_dll_path() {
        let result = InjectionConfig::builder().target_pid(1234).build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_requires_target() {
        let result = InjectionConfig::builder().dll_path("test.dll").build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_produces_valid_config() {
        let config = InjectionConfig::builder()
            .dll_path("test.dll")
            .target_pid(1234)
            .method("manual_map")
            .stealth(true)
            .elevate(true)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        assert_eq!(config.method.as_deref(), Some("manual_map"));
        assert!(config.stealth);
        assert!(config.elevate_privileges);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }
}
