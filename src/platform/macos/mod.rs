//! macOS platform backend.
//!
//! Provides process enumeration via `sysctl`, architecture detection via
//! Mach-O headers, and injection methods using `task_for_pid` and
//! `DYLD_INSERT_LIBRARIES`.

pub mod methods;
pub mod privilege;
pub mod process;

use crate::method::MethodRegistry;

/// Register all built-in macOS injection methods.
pub fn register_methods(registry: &mut MethodRegistry) {
    registry.register(Box::new(methods::task_inject::TaskInjectMethod));
    registry.register(Box::new(methods::dyld_insert::DyldInsertMethod));
}
