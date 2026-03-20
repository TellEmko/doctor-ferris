//! Command-line interface for doctor-ferris.
//!
//! Enabled via `--features cli`. Provides a minimal CLI exposing the core
//! injection functionality and introspection commands.

use clap::{Parser, Subcommand};

use crate::config::InjectionConfig;
use crate::injector::Injector;

/// Doctor Ferris — cross-platform dynamic library injection toolkit.
#[derive(Parser)]
#[command(name = "doctor-ferris", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inject a DLL or shared object into a target process.
    Inject {
        /// Path to the DLL / .so / .dylib to inject.
        #[arg(short, long)]
        dll: String,

        /// Target process ID.
        #[arg(short, long, conflicts_with = "name")]
        pid: Option<u32>,

        /// Target process name (case-insensitive).
        #[arg(short, long, conflicts_with = "pid")]
        name: Option<String>,

        /// Select a specific injection method to use.
        #[arg(short, long)]
        method: Option<String>,

        /// Apply post-injection cleanup (e.g. wiping headers in target).
        #[arg(long)]
        stealth: bool,

        /// Attempt privilege escalation if injection fails due to permissions.
        #[arg(long)]
        elevate: bool,

        /// Skip architecture compatibility checks (dangerous).
        #[arg(long)]
        skip_arch_check: bool,
    },

    /// List all available injection methods.
    ListMethods,

    /// List all visible running processes.
    ListProcesses {
        /// Optional filter string (case-insensitive substring match).
        #[arg(short, long)]
        filter: Option<String>,
    },
}

pub fn run() -> crate::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inject {
            dll,
            pid,
            name,
            method,
            stealth,
            elevate,
            skip_arch_check,
        } => handle_inject(
            dll,
            pid,
            name,
            method,
            stealth,
            elevate,
            skip_arch_check,
        ),

        Commands::ListMethods => {
            let injector = Injector::new();
            let methods = injector.methods();

            println!(
                "{:<20} {:<10} {:<12} {:<14} {}",
                "IDENTIFIER", "EVASION", "RELIABILITY", "COMPATIBILITY", "DESCRIPTION"
            );
            println!("{}", "-".repeat(100));

            for method in methods {
                println!(
                    "{:<20} {:<10} {:<12} {:<14} {}",
                    method.name(),
                    if method.is_stealth() { "Enabled" } else { "Disabled" },
                    format!("{}%", method.reliability()),
                    format!("{}%", method.compatibility()),
                    method.description(),
                );
            }
        }

        Commands::ListProcesses { filter } => {
            let processes = crate::process::enumerate_processes()?;

            println!("{:<8} {:<12} {}", "PID", "ARCH", "NAME");
            println!("{}", "-".repeat(50));

            for proc in &processes {
                if let Some(ref f) = filter {
                    if !proc.name.to_lowercase().contains(&f.to_lowercase()) {
                        continue;
                    }
                }
                println!("{:<8} {:<12} {}", proc.pid, proc.architecture, proc.name);
            }

            if filter.is_none() {
                println!("\n({} processes total)", processes.len());
            }
        }
    }

    Ok(())
}

fn handle_inject(
    dll: String,
    pid: Option<u32>,
    name: Option<String>,
    method: Option<String>,
    stealth: bool,
    elevate: bool,
    skip_arch_check: bool,
) {
    let mut builder = InjectionConfig::builder()
        .dll_path(&dll)
        .stealth(stealth)
        .elevate(elevate)
        .skip_arch_check(skip_arch_check);

    if let Some(pid) = pid {
        builder = builder.target_pid(pid);
    } else if let Some(name) = name {
        builder = builder.target_name(name);
    } else {
        eprintln!("Operation aborted: A target process must be specified using either the --pid or --name flag.");
        std::process::exit(1);
    }

    if let Some(method_name) = method {
        builder = builder.method(method_name);
    }

    let config = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration Error: {}", e);
            std::process::exit(1);
        }
    };

    let injector = Injector::new();
    match injector.inject(&config) {
        Ok(result) => {
            println!("Injection successfully completed.");
            if let Some(addr) = result.base_address {
                println!("  Base Memory Address: 0x{:X}", addr);
            }
            println!("  Selected Method:     {}", result.method_name);
            println!("  Procedure Details:   {}", result.details);
        }
        Err(e) => {
            eprintln!("Procedure Failure: {}", e);
            if e.is_retryable() {
                eprintln!("  Notice: This error may be transient; re-attempting the operation may yield a successful result.");
            }
            std::process::exit(1);
        }
    }
}
