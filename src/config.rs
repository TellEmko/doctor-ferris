//! Injection configuration and builder API.
//!
//! [`InjectionConfig`] is the primary configuration type passed to the injector.
//! It supports a builder pattern for ergonomic construction.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{DoctorError, Result};

/// Determines the strategy the injector uses when selecting a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InjectionMode {
    /// Prefer the most reliable, well-tested injection technique.
    /// Best for general-purpose use where detection is not a concern.
    #[default]
    Stability,

    /// Prefer techniques that minimize observable side-effects.
    /// Avoids `CreateRemoteThread` and similar easily-detected primitives.
    Stealth,

    /// Prefer techniques with the widest OS version and configuration support.
    /// Useful when targeting unknown or legacy environments.
    Compatibility,
}

impl std::fmt::Display for InjectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectionMode::Stability => write!(f, "stability"),
            InjectionMode::Stealth => write!(f, "stealth"),
            InjectionMode::Compatibility => write!(f, "compatibility"),
        }
    }
}

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
///     .mode(InjectionMode::Stealth)
///     .build()
///     .expect("valid config");
/// ```
#[derive(Debug, Clone)]
pub struct InjectionConfig {
    /// Path to the DLL / shared object to inject.
    pub dll_path: PathBuf,
    /// Target process specification.
    pub target: Target,
    /// Injection mode governing method selection.
    pub mode: InjectionMode,
    /// If set, overrides automatic method selection with the named method.
    pub method_override: Option<String>,
    /// Whether to attempt privilege escalation if injection fails due to
    /// insufficient permissions.
    pub elevate_privileges: bool,
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
    mode: InjectionMode,
    method_override: Option<String>,
    elevate_privileges: bool,
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

    /// Set the injection mode.
    pub fn mode(mut self, mode: InjectionMode) -> Self {
        self.mode = mode;
        self
    }

    /// Override automatic method selection with a specific named method.
    pub fn method(mut self, method_name: impl Into<String>) -> Self {
        self.method_override = Some(method_name.into());
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
            mode: self.mode,
            method_override: self.method_override,
            elevate_privileges: self.elevate_privileges,
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
            .mode(InjectionMode::Stealth)
            .elevate(true)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        assert_eq!(config.mode, InjectionMode::Stealth);
        assert!(config.elevate_privileges);
        assert_eq!(config.timeout, Duration::from_secs(10));
    }
}
