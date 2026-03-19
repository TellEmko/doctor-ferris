//! # Doctor Ferris
//!
//! High-performance, modular dynamic library injection framework for
//! Windows, Linux, and macOS.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use doctor_ferris::{Injector, InjectionConfig, InjectionMode};
//!
//! let injector = Injector::new();
//!
//! let config = InjectionConfig::builder()
//!     .dll_path("payload.dll")
//!     .target_pid(1234)
//!     .mode(InjectionMode::Stealth)
//!     .build()
//!     .expect("valid configuration");
//!
//! match injector.inject(&config) {
//!     Ok(result) => println!("Success: {}", result),
//!     Err(e) => eprintln!("Failed: {}", e),
//! }
//! ```
//!
//! ## Feature Flags
//!
//! | Feature   | Description                                    |
//! |-----------|------------------------------------------------|
//! | `cli`     | Enables the command-line interface binary       |
//! | `stealth` | Enables advanced stealth injection methods      |
//!
//! ## Architecture
//!
//! The crate is organized into:
//!
//! - **[`config`]** — Injection configuration and builder API.
//! - **[`error`]** — Error types and result alias.
//! - **[`types`]** — Shared types (Architecture, Platform, ProcessInfo, etc.).
//! - **[`method`]** — The [`InjectionMethod`] trait and pluggable [`MethodRegistry`].
//! - **[`process`]** — Process discovery and validation utilities.
//! - **[`injector`]** — The [`Injector`] facade, the primary entry point.
//! - **[`platform`]** — Platform-specific backends (Windows, Linux, macOS).

pub mod config;
pub mod error;
pub mod injector;
pub mod method;
pub mod platform;
pub mod process;
pub mod types;

#[cfg(feature = "cli")]
pub mod cli;

// ── Convenience re-exports ──────────────────────────────────────────

pub use config::{InjectionConfig, InjectionConfigBuilder, Target};
pub use error::{DoctorError, Result};
pub use injector::Injector;
pub use method::{InjectionMethod, MethodRegistry};
pub use process::{
    detect_dll_architecture, enumerate_processes, find_process_by_name, find_process_by_pid,
    validate_injection,
};
pub use types::{Architecture, InjectionResult, Platform, ProcessInfo};
