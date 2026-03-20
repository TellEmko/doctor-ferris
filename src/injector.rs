//! Injector — the primary user-facing API.
//!
//! [`Injector`] ties together the configuration, process discovery,
//! architecture validation, method registry, and platform dispatch into
//! a single, ergonomic entry point.

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

    /// Executes the injection procedure according to the provided configuration.
    ///
    /// This method orchestrates the entire injection lifecycle, including target resolution,
    /// architecture validation, privilege acquisition, and method execution.
    pub fn inject(&self, config: &InjectionConfig) -> Result<InjectionResult> {
        log::info!("Initiating the injection procedure for target: {}", config.target);

        let target = self.resolve_target(config)?;
        log::info!("Successfully resolved the target process: {}", target);

        if !config.skip_arch_check {
            process::validate_injection(&config.dll_path, &target)?;
            log::info!("Target architecture validation completed successfully");
        } else {
            log::warn!("Architecture compatibility verification was bypassed by configuration");
        }

        if !crate::platform::is_elevated() {
            log::warn!("The current process lacks administrative privileges; some injection methods may be restricted or fail.");
            if config.elevate_privileges {
                log::info!("Attempting to elevate process privileges as requested");
                #[cfg(target_os = "windows")]
                {
                    crate::platform::windows::privilege::enable_debug_privilege().unwrap_or_else(
                        |e| {
                            log::warn!("The system failed to enable debug privileges: {}", e);
                        },
                    );
                }
            }
        }

        let method = self.select_method(config, &target)?;
        log::info!(
            "Utilizing injection method: {} ({})",
            method.name(),
            method.description()
        );

        let result = method.inject(config, &target)?;
        log::info!("Injection procedure completed successfully: {}", result);

        if config.stealth {
            log::info!("Executing post-injection stealth routines (e.g., header obfuscation)");
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
