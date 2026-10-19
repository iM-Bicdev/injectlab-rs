//! `lint` — the `injectlab lint` CLI in Rust: probe-set integrity check.
//!
//! Mirrors `injectlab/run.py::_lint_cmd`:
//! - `lint [--file SET.json] [--json]`
//! - `--file`: pick the fixture matching the set's shape (control fixtures
//!   when any probe expects "comply", attack fixtures otherwise).
//! - default: lint the bundled attack set with attack fixtures, then the
//!   control set with control fixtures.
//! - exit 0 when clean, 1 on warnings only, 2 on any error.

use injectlab_rs::{lint, mock};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn manifest() -> String {
    env!("CARGO_MANIFEST_DIR").to_string()
}

fn default_attack_set() -> PathBuf {
    PathBuf::from(format!("{}/../injectlab/attacks/attack-set-v1.4.json", manifest()))
}

fn default_control_set() -> PathBuf {
    PathBuf::from(format!("{}/../injectlab/attacks/control-set-v1.1.json", manifest()))
}

/// Fixture ids for one `--file` set: control fixtures when any probe row
/// expects "comply", attack fixtures otherwise (strict string compare, like
/// Python's `p.get("expected") == "comply"`).
fn fixture_ids_for_file(path: &PathBuf) -> Result<BTreeSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let raw: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
    let control_like = raw
        .get("probes")
        .and_then(|p| p.as_array())
        .map(|rows| {
            rows.iter().any(|r| {
                r.get("expected").and_then(|v| v.as_str()) == Some("comply")
            })
        })
        .unwrap_or(false);
    let ids: Vec<&str> = if control_like { mock::control_fixture_ids() } else { mock::attack_fixture_ids() };
    Ok(ids.into_iter().map(|s| s.to_string()).collect())
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut file: Option<PathBuf> = None;
    let mut json = false;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--file" => {
                i += 1;
                if i >= argv.len() {
                    eprintln!("lint: --file needs a path");
                    std::process::exit(2);
                }
                file = Some(PathBuf::from(&argv[i]));
            }
            "--json" => json = true,
            other => {
                eprintln!("lint: unknown argument '{other}'");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let mut findings: Vec<lint::Finding> = Vec::new();
    let run = |findings: &mut Vec<lint::Finding>| -> Result<(), String> {
        if let Some(ref f) = file {
            let fids = fixture_ids_for_file(f)?;
            findings.extend(lint::lint_file(f, Some(&fids))?);
        } else {
            let attack_ids: BTreeSet<String> =
                mock::attack_fixture_ids().into_iter().map(|s| s.to_string()).collect();
            let control_ids: BTreeSet<String> =
                mock::control_fixture_ids().into_iter().map(|s| s.to_string()).collect();
            findings.extend(lint::lint_file(&default_attack_set(), Some(&attack_ids))?);
            findings.extend(lint::lint_file(&default_control_set(), Some(&control_ids))?);
        }
        Ok(())
    };
    if let Err(e) = run(&mut findings) {
        eprintln!("lint: {e}");
        std::process::exit(2);
    }

    if json {
        println!("{}", lint::findings_to_json(&findings));
    } else {
        for f in &findings {
            println!("{}", f.to_line());
        }
        println!("{}", lint::summarize(&findings));
    }

    if findings.iter().any(|f| f.level == "error") {
        std::process::exit(2);
    }
    std::process::exit(if findings.is_empty() { 0 } else { 1 });
}
