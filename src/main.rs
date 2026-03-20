//! Doctor Ferris CLI entry point.
//!
//! This binary is only built when the `cli` feature is enabled:
//! ```sh
//! cargo build --features cli
//! ```

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    if let Err(error) = doctor_ferris::cli::run() {
        eprintln!("Application Error: {}", error);
        std::process::exit(1);
    }
}
