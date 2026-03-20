//! Injector — the primary user-facing API.
//!
//! [`Injector`] ties together the configuration, process discovery,
//! architecture validation, method registry, and platform dispatch into
//! a single, ergonomic entry point.
//!
//! # Example
//!
//! ```rust,no_run
//! use doctor_ferris::{Injector, InjectionConfig, InjectionMode};
//!
//! let injector = Injector::new();
//!
//! let config = InjectionConfig::builder()
//!     .dll_path("payload.dll")
//!     .target_pid(1234)
//!     .mode(InjectionMode::Stability)
//!     .build()
//!     .expect("valid config");
//!
//! let result = injector.inject(&config).expect("injection succeeded");
//! println!("{}", result);
//! ```

use crate::config::{InjectionConfig, Target};
use crate::error::{DoctorError, Result};
use crate::method::{InjectionMethod, MethodRegistry};
use crate::process;
use crate::types::{InjectionResult, Platform, ProcessInfo};

/// Primary entry point for the injection framework.
pub struct Injector {
    registry: MethodRegistry,
}

impl Injector {
    /// Create an injector with the default method registry for the current
    /// platform.
    pub fn new() -> Self {
        Self {
            registry: MethodRegistry::with_defaults(),
        }
    }

    /// Create an injector with a custom method registry.
    pub fn with_registry(registry: MethodRegistry) -> Self {
        Self { registry }
    }

    /// Register an additional injection method at runtime.
    pub fn register_method(&mut self, method: Box<dyn InjectionMethod>) {
        self.registry.register(method);
    }

    /// Execute an injection according to the given configuration.
    ///
    /// This is the primary method. It handles the full pipeline from target
    /// resolution through injection.
    pub fn inject(&self, config: &InjectionConfig) -> Result<InjectionResult> {
        log::info!("Starting injection pipeline for {}", config.target);

        let target = self.resolve_target(config)?;
        log::info!("Resolved target: {}", target);
        if !config.skip_arch_check {
            process::validate_injection(&config.dll_path, &target)?;
            log::info!("Architecture validation passed");
        } else {
            log::warn!("Architecture check skipped by configuration");
        }
        if !crate::platform::is_elevated() {
            log::warn!("Running without elevated privileges — some methods may fail");
            if config.elevate_privileges {
                log::info!("Privilege escalation requested");
                #[cfg(target_os = "windows")]
                {
                    crate::platform::windows::privilege::enable_debug_privilege().unwrap_or_else(
                        |e| {
                            log::warn!("Failed to enable debug privilege: {}", e);
                        },
                    );
                }
            }
        }

        let method = self.select_method(config, &target)?;
        log::info!(
            "Selected method: {} — {}",
            method.name(),
            method.description()
        );

        let result = method.inject(config, &target)?;
        log::info!("Injection successful: {}", result);

        if config.stealth {
            log::info!("Applying post-injection cleanup (e.g., zero headers)");
            // Advanced PE/ELF wiping logic can be hooked here.
        }

        Ok(result)
    }

    /// List all registered method names.
    pub fn list_methods(&self) -> Vec<&str> {
        self.registry.list()
    }

    /// List all registered methods with full details.
    pub fn methods(&self) -> &[Box<dyn InjectionMethod>] {
        self.registry.methods()
    }

    /// Access the underlying method registry.
    pub fn registry(&self) -> &MethodRegistry {
        &self.registry
    }

    /// Access the underlying method registry mutably.
    pub fn registry_mut(&mut self) -> &mut MethodRegistry {
        &mut self.registry
    }

    // ── Internal ─────────────────────────────────────────────────────

    fn resolve_target(&self, config: &InjectionConfig) -> Result<ProcessInfo> {
        match &config.target {
            Target::Pid(pid) => process::find_process_by_pid(*pid),
            Target::Name(name) => process::find_process_by_name(name),
        }
    }

    fn select_method<'a>(
        &'a self,
        config: &InjectionConfig,
        target: &ProcessInfo,
    ) -> Result<&'a dyn InjectionMethod> {
        if let Some(ref name) = config.method {
            // User explicitly requested a method.
            self.registry.get(name).ok_or_else(|| {
                DoctorError::MethodNotFound(format!(
                    "'{}' — available methods: {:?}",
                    name,
                    self.registry.list()
                ))
            })
        } else {
            // Automatic selection based on platform + architecture.
            self.registry
                .get_default(Platform::current(), target.architecture)
        }
    }
}

impl Default for Injector {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Injector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injector")
            .field("registry", &self.registry)
            .finish()
    }
}
