//! rundiff: diff two scored runs (`injectlab run --json` output files).
//!
//! Ports `python -m injectlab.run diff old.json new.json [--json]`.
//! Prints the markdown diff by default, JSON with `--json`.
//!
//! Usage:
//!     cargo run --bin rundiff -- old.json new.json [--json]

use injectlab_rs::compare::compare_reports;
use std::fs;

fn usage() -> ! {
    eprintln!("usage: rundiff old.json new.json [--json]");
    std::process::exit(2);
}

fn read_report(path: &str) -> serde_json::Value {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("rundiff: cannot parse {path}: {e}");
                std::process::exit(2);
            }
        },
        Err(e) => {
            eprintln!("rundiff: cannot read {path}: {e}");
            std::process::exit(2);
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let old_path = args.next().unwrap_or_else(|| usage());
    let new_path = args.next().unwrap_or_else(|| usage());
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            _ => usage(),
        }
    }

    let old = read_report(&old_path);
    let new = read_report(&new_path);
    let diff = compare_reports(&old, &new);
    if json {
        println!("{}", serde_json::to_string_pretty(&diff.to_dict()).unwrap());
    } else {
        // println!: the Python CLI does print(to_markdown()) — to_markdown()
        // already ends with "\n" and print adds another. Byte-fidelity at
        // the CLI layer means matching that, odd as it looks.
        println!("{}", diff.to_markdown());
    }
}
