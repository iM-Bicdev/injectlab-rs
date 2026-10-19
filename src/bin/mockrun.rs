//! mockrun: the scripted end-to-end run.
//!
//! Loads the sibling injectlab attack sets, grades the mock fixtures with the
//! ported graders, and prints the report as JSON (shaped like the Python
//! `python -m injectlab.run --mock --json` output).
//!
//! Usage:
//!     cargo run --bin mockrun
//!     cargo run --bin mockrun -- --attack-set PATH --control-set PATH

use injectlab_rs::runner::run_mock;

fn usage() -> ! {
    eprintln!("usage: mockrun [--attack-set PATH] [--control-set PATH]");
    std::process::exit(2);
}

fn main() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut attack_set = format!("{manifest}/../injectlab/attacks/attack-set-v1.4.json");
    let mut control_set = format!("{manifest}/../injectlab/attacks/control-set-v1.1.json");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--attack-set" => attack_set = args.next().unwrap_or_else(|| usage()),
            "--control-set" => control_set = args.next().unwrap_or_else(|| usage()),
            _ => usage(),
        }
    }

    match run_mock(&attack_set, &control_set) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report.to_json()).unwrap()
            );
        }
        Err(e) => {
            eprintln!("mockrun: {e}");
            std::process::exit(1);
        }
    }
}
