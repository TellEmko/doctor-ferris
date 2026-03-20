use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    println!("Target process initialized (PID: {})", std::process::id());
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("Termination signal received; initiating shutdown sequence...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to establish the Ctrl-C interruption handler");

    println!("Awaiting injection procedure. Press Ctrl-C to terminate the process.");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    println!("Target process has terminated successfully.");
}
