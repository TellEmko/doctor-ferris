//! Injection method trait and pluggable method registry.
//!
//! Every injection technique — whether built-in or user-provided — must implement the
//! [`InjectionMethod`] trait. The [`MethodRegistry`] serves as a centralized collection
//! of these methods and provides selection logic based on the target platform,
//! architecture, and required injection characteristics.

use crate::config::InjectionConfig;
use crate::error::{DoctorError, Result};
use crate::types::{Architecture, InjectionResult, Platform, ProcessInfo};

/// A trait that defines the interface for all library injection techniques.
///
/// Implementations must be thread-safe (`Send + Sync`) to facilitate their use
/// across concurrent execution contexts.
pub trait InjectionMethod: Send + Sync {
    /// Returns a unique, machine-readable identifier for the injection method (e.g., `"loadlibrary"`).
    fn name(&self) -> &str;

    /// Returns a formal, human-readable description of the injection technique.
    fn description(&self) -> &str;

    /// Returns the list of platforms supported by this injection method.
    fn supported_platforms(&self) -> &[Platform];

    /// Returns the CPU architectures compatible with this injection method.
    fn supported_architectures(&self) -> &[Architecture];

    /// Indicates whether the method requires administrative or elevated privileges.
    fn requires_elevation(&self) -> bool {
        false
    }

    /// Indicates whether the method is classified as an evasion-oriented technique.
    ///
    /// Evasion-oriented methods typically avoid easily-monitored system primitives
    /// such as `CreateRemoteThread`.
    fn is_stealth(&self) -> bool {
        false
    }

    /// Returns a reliability score, ranging from 0 (experimental) to 100 (production-ready).
    fn reliability(&self) -> u8 {
        50
    }

    /// Returns a compatibility score, ranging from 0 (highly specific) to 100 (universal).
    fn compatibility(&self) -> u8 {
        50
    }

    /// Executes the injection procedure.
    ///
    /// Callers are responsible for ensuring that architecture and target validation
    /// have been successfully performed prior to invocation.
    fn inject(&self, config: &InjectionConfig, target: &ProcessInfo) -> Result<InjectionResult>;
}

/// A centralized registry for managing and selecting available injection methods.
pub struct MethodRegistry {
    methods: Vec<Box<dyn InjectionMethod>>,
}

impl MethodRegistry {
    /// Initializes an empty injection method registry.
    pub fn new() -> Self {
        Self {
            methods: Vec::new(),
        }
    }

    /// Initializes a registry pre-populated with default methods for the current platform.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register_platform_defaults();
        registry
    }

    /// Registers a new injection method within the registry.
    pub fn register(&mut self, method: Box<dyn InjectionMethod>) {
        log::info!("Registered injection method: {}", method.name());
        self.methods.push(method);
    }

    /// Retrieves an injection method by its unique identifier name.
    pub fn get(&self, name: &str) -> Option<&dyn InjectionMethod> {
        self.methods
            .iter()
            .find(|method| method.name().eq_ignore_ascii_case(name))
            .map(|method| method.as_ref())
    }

    /// Returns a list of all registered injection method identifiers.
    pub fn list(&self) -> Vec<&str> {
        self.methods.iter().map(|method| method.name()).collect()
    }

    /// Returns an immutable slice of all registered injection methods.
    pub fn methods(&self) -> &[Box<dyn InjectionMethod>] {
        &self.methods
    }

    /// Automatically selects an appropriate default injection method for the specified platform and architecture.
    pub fn get_default(
        &self,
        platform: Platform,
        architecture: Architecture,
    ) -> Result<&dyn InjectionMethod> {
        let potential_candidates: Vec<&dyn InjectionMethod> = self
            .methods
            .iter()
            .map(|method| method.as_ref())
            .filter(|method| method.supported_platforms().contains(&platform))
            .filter(|method| {
                method.supported_architectures().contains(&architecture)
                    || method.supported_architectures().contains(&Architecture::Unknown)
            })
            .collect();

        if potential_candidates.is_empty() {
            return Err(DoctorError::MethodNotFound(format!(
                "No compatible injection methods were found for the {} / {} environment",
                platform, architecture
            )));
        }

        // Prioritize standard, high-compatibility methods as defaults.
        const PREFERRED_DEFAULTS: &[&str] = &["loadlibrary", "ptrace", "task_inject"];
        for preferred_name in PREFERRED_DEFAULTS {
            if let Some(selected_method) = potential_candidates.iter().find(|candidate| candidate.name() == *preferred_name) {
                return Ok(*selected_method);
            }
        }

        // Fallback to the method with the highest compatibility score.
        let selected_method = potential_candidates
            .into_iter()
            .max_by_key(|method| method.compatibility())
            .unwrap();

        Ok(selected_method)
    }

    /// Registers all built-in injection methods relevant to the current compilation target.
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
    /// Returns a default registry instance populated with platform-specific methods.
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl std::fmt::Debug for MethodRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("MethodRegistry")
            .field("methods", &self.list())
            .finish()
    }
}
