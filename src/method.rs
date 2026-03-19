//! Injection method trait and pluggable method registry.
//!
//! Every injection technique — built-in or user-provided — implements the
//! [`InjectionMethod`] trait. The [`MethodRegistry`] collects them and provides
//! selection logic based on platform, architecture, and injection mode.

use crate::config::{InjectionConfig, InjectionMode};
use crate::error::{DoctorError, Result};
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// Trait implemented by every injection technique.
///
/// Implementations must be `Send + Sync` to allow the registry and injector
/// to be shared across threads.
pub trait InjectionMethod: Send + Sync {
    /// Unique machine-readable name for this method (e.g. `"loadlibrary"`).
    fn name(&self) -> &str;

    /// Human-readable description of the technique.
    fn description(&self) -> &str;

    /// Platforms on which this method is available.
    fn supported_platforms(&self) -> &[Platform];

    /// CPU architectures supported by this method.
    fn supported_architectures(&self) -> &[Architecture];

    /// Whether this method requires elevated / root privileges.
    fn requires_elevation(&self) -> bool {
        false
    }

    /// Whether this method is classified as a stealth technique.
    ///
    /// Stealth methods avoid easily-detectable primitives such as
    /// `CreateRemoteThread` and are preferred when [`InjectionMode::Stealth`]
    /// is selected.
    fn is_stealth(&self) -> bool {
        false
    }

    /// Reliability score from 0 (experimental) to 100 (battle-tested).
    ///
    /// Used by the registry to rank methods for [`InjectionMode::Stability`].
    fn reliability(&self) -> u8 {
        50
    }

    /// Compatibility score from 0 (narrow support) to 100 (universal).
    ///
    /// Used by the registry to rank methods for [`InjectionMode::Compatibility`].
    fn compatibility(&self) -> u8 {
        50
    }

    /// Execute the injection.
    ///
    /// Implementations may assume that architecture and target validation
    /// have already been performed by the caller.
    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult>;
}

/// Registry of available injection methods.
///
/// The registry stores methods and provides lookup, enumeration, and
/// automatic selection based on the current platform, target architecture,
/// and injection mode.
pub struct MethodRegistry {
    methods: Vec<Box<dyn InjectionMethod>>,
}

impl MethodRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            methods: Vec::new(),
        }
    }

    /// Create a registry pre-populated with all built-in methods for the
    /// current platform.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register_platform_defaults();
        registry
    }

    /// Register a custom injection method.
    pub fn register(&mut self, method: Box<dyn InjectionMethod>) {
        log::info!("Registered injection method: {}", method.name());
        self.methods.push(method);
    }

    /// Look up a method by name.
    pub fn get(&self, name: &str) -> Option<&dyn InjectionMethod> {
        self.methods
            .iter()
            .find(|m| m.name().eq_ignore_ascii_case(name))
            .map(|m| m.as_ref())
    }

    /// List all registered method names.
    pub fn list(&self) -> Vec<&str> {
        self.methods.iter().map(|m| m.name()).collect()
    }

    /// List all registered methods with full trait access.
    pub fn methods(&self) -> &[Box<dyn InjectionMethod>] {
        &self.methods
    }

    /// Automatically select the best method for the given mode, platform, and
    /// architecture.
    ///
    /// Selection priority depends on the mode:
    /// - **Stability**: highest [`InjectionMethod::reliability`] score.
    /// - **Stealth**: only stealth methods, ranked by reliability.
    /// - **Compatibility**: highest [`InjectionMethod::compatibility`] score.
    pub fn select(
        &self,
        mode: InjectionMode,
        platform: Platform,
        arch: Architecture,
    ) -> Result<&dyn InjectionMethod> {
        let candidates: Vec<&dyn InjectionMethod> = self
            .methods
            .iter()
            .map(|m| m.as_ref())
            .filter(|m| m.supported_platforms().contains(&platform))
            .filter(|m| {
                m.supported_architectures().contains(&arch)
                    || m.supported_architectures().contains(&Architecture::Unknown)
            })
            .collect();

        if candidates.is_empty() {
            return Err(DoctorError::MethodNotFound(format!(
                "no methods available for {} / {}",
                platform, arch
            )));
        }

        let selected = match mode {
            InjectionMode::Stability => candidates
                .iter()
                .max_by_key(|m| m.reliability())
                .copied(),
            InjectionMode::Stealth => {
                let stealth: Vec<_> = candidates.iter().filter(|m| m.is_stealth()).collect();
                if stealth.is_empty() {
                    // Fall back to highest-reliability non-stealth method.
                    candidates
                        .iter()
                        .max_by_key(|m| m.reliability())
                        .copied()
                } else {
                    stealth
                        .iter()
                        .max_by_key(|m| m.reliability())
                        .copied()
                        .copied()
                }
            }
            InjectionMode::Compatibility => candidates
                .iter()
                .max_by_key(|m| m.compatibility())
                .copied(),
        };

        selected.ok_or_else(|| {
            DoctorError::MethodNotFound(format!("no suitable method for mode '{}'", mode))
        })
    }

    /// Register all built-in methods for the current compilation target.
    fn register_platform_defaults(&mut self) {
        #[cfg(target_os = "windows")]
        crate::platform::windows::register_methods(self);

        #[cfg(target_os = "linux")]
        crate::platform::linux::register_methods(self);

        #[cfg(target_os = "macos")]
        crate::platform::macos::register_methods(self);
    }
}

impl Default for MethodRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl std::fmt::Debug for MethodRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodRegistry")
            .field("methods", &self.list())
            .finish()
    }
}
