//! Linux platform backend.
//!
//! Provides process enumeration via `/proc`, architecture detection via ELF
//! headers, and injection methods using `ptrace` and `LD_PRELOAD`.

pub mod methods;
pub mod privilege;
pub mod process;

use crate::method::MethodRegistry;

/// Register all built-in Linux injection methods.
pub fn register_methods(registry: &mut MethodRegistry) {
    registry.register(Box::new(methods::ptrace::PtraceMethod));
    registry.register(Box::new(methods::ld_preload::LdPreloadMethod));
}
