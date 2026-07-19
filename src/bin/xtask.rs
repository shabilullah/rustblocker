#[path = "xtask/api_smoke.rs"]
mod api_smoke;
#[path = "xtask/baselines.rs"]
mod baselines;
#[path = "xtask/core.rs"]
mod core;
#[path = "xtask/stress_https.rs"]
mod stress_https;

use std::env;

fn main() {
    if let Err(err) = run() {
        eprintln!("xtask: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        usage();
        return Err("missing command".to_string());
    };

    match command.as_str() {
        "mock-deploy" => core::mock_deploy(args.collect()),
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => {
            usage();
            Err(format!("unknown command: {other}"))
        }
    }
}

fn usage() {
    eprintln!("usage:");
    eprintln!(
        "  cargo run --bin xtask -- mock-deploy [--report-dir=DIR] [--compare=SUMMARY_JSON] [--skip-build] [--skip-deploy] [--timeout=SECONDS]"
    );
    eprintln!("  runs native Rust mock-deploy scaffold; reads scripts/.deployenv");
}
