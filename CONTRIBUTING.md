# Contributing to Doctor Ferris

Thank you for your interest in contributing to **Doctor Ferris**! We welcome bug reports, feature requests, and pull requests.

## Ways to Contribute

1.  **Reporting Bugs:** Open an issue if you encounter crashes, architecture detection failures, or injection failures. Please include OS version, architecture, and injection mode/method used.
2.  **Suggesting Features:** Have an idea for a new injection technique, evasion strategy, or platform target? Open a feature request!
3.  **Submitting Code:** We welcome PRs for bug fixes, new injection methods, and optimizations.

## Development Workflow

1.  Fork the repository and create your branch from `main`.
2.  Setup your environment. (You'll need the Rust toolchain and platform-specific build dependencies).
3.  Write your code. Ensure it adheres to the existing style and architecture (e.g., implementing the `InjectionMethod` trait for new methods).
4.  Run tests. (Integration tests in the `/tests` directory require the test harness to be built first).
5.  Format your code with `cargo fmt` and run `cargo clippy` to catch common mistakes.
6.  Open a Pull Request describing your changes.

## Adding a New Injection Method

To add a new injection method:
1.  Create a new file in the appropriate platform module (e.g., `src/platform/windows/methods/mymethod.rs`).
2.  Implement the `InjectionMethod` trait. Provide realistic `reliability` and `compatibility` scores.
3.  Register the method in the platform's `mod.rs` (`register_methods` function).
4.  Ensure it is gated appropriately (e.g., under the `#[cfg(feature = "stealth")]` flag if it is an advanced evasion technique).

## Code of Conduct

Please review our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
