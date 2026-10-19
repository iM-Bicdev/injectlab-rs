//! injectlab-rs: faithful port of `injectlab/lint.py` — the probe-set
//! integrity check.
//!
//! An exact payload is the unit of the experiment, so `lint` hunts the
//! mistakes that silently wreck a run: duplicate ids, invalid taxonomy,
//! payload whitespace, success markers the grader can never hit, markers that
//! fire when the model merely echoes the prompt, and mock-fixture drift.
//!
//! Fidelity notes (byte-faithful, judged by `scripts/lint_parity.py`):
//! - `to_line()` matches Python's f-string field widths exactly. Python pads
//!   by *character* count, so the port pads by `chars().count()`, not bytes.
//! - `to_json_entry()` hand-rolls `json.dumps(..., indent=2)`: key order is
//!   `level, probe_id, check, message` (serde_json's default Map would sort
//!   keys alphabetically and break byte equality), and strings escape exactly
//!   like Python's `ensure_ascii=True` (non-ASCII out as `\uXXXX`, astral
//!   chars as surrogate pairs).
//! - `summarize()` keeps the em-dash in the clean case verbatim.
//! - Taxonomy values that aren't strings render like Python's f-string of the
//!   raw JSON scalar (`None`, `True`, `3`); floats are out of scope for the
//!   judge and format shortest-round-trip.
//! - A truthy non-list `success_markers` (e.g. a string) iterates its items
//!   like Python does — for a string, its characters.

use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::path::Path;

const SEVERITIES: &[&str] = &["low", "medium", "high", "info"];
const EXPECTED: &[&str] = &["refuse", "ignore-injection", "comply"];
const DELIVERIES: &[&str] = &["", "single", "embedded-in-data", "fabricated-history", "escalation-ladder"];
const MECHANISMS: &[&str] = &["", "refusal-direction", "harmfulness-judge"];
const REQUIRED: &[&str] = &["id", "category", "severity", "title", "prompt", "injected_goal", "expected"];

/// One lint finding. Mirrors the Python `Finding` dataclass field for field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: String,    // "error" | "warn"
    pub probe_id: String, // probe id, or "(set)" for set-level findings
    pub check: String,    // machine-readable check name
    pub message: String,
}

impl Finding {
    pub fn new(level: &str, probe_id: &str, check: &str, message: String) -> Self {
        Finding {
            level: level.to_string(),
            probe_id: probe_id.to_string(),
            check: check.to_string(),
            message,
        }
    }

    /// `f"{level.upper():5}  {probe_id:12}  {check}: {message}"` — widths are
    /// character counts, never truncate.
    pub fn to_line(&self) -> String {
        format!(
            "{}  {}  {}: {}",
            pad_chars(&self.level.to_uppercase(), 5),
            pad_chars(&self.probe_id, 12),
            self.check,
            self.message
        )
    }

    /// One entry of the `--json` list, matching `json.dumps(..., indent=2)`
    /// byte-for-byte (key order level/probe_id/check/message, 2-space
    /// indent, `ensure_ascii` escaping).
    pub fn to_json_entry(&self) -> String {
        format!(
            "  {{\n    \"level\": {},\n    \"probe_id\": {},\n    \"check\": {},\n    \"message\": {}\n  }}",
            py_json_escape(&self.level),
            py_json_escape(&self.probe_id),
            py_json_escape(&self.check),
            py_json_escape(&self.message)
        )
    }
}

fn pad_chars(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n >= width {
        s.to_string()
    } else {
        let mut out = String::with_capacity(s.len() + (width - n));
        out.push_str(s);
        for _ in 0..(width - n) {
            out.push(' ');
        }
        out
    }
}

/// Escape a string exactly like Python's `json.dumps` with `ensure_ascii=True`:
/// `"`, `\`, control chars (named where Python names them), DEL, and every
/// non-ASCII char as `\uXXXX` (astral chars as surrogate pairs). Hex is
/// lowercase, as CPython emits it.
pub fn py_json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) > 0x7e => {
                let n = c as u32;
                if n > 0xffff {
                    let v = n - 0x10000;
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", 0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff)));
                } else {
                    out.push_str(&format!("\\u{:04x}", n));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The `--json` document: `json.dumps([f.to_dict() ...], indent=2)`.
pub fn findings_to_json(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "[]".to_string();
    }
    let entries: Vec<String> = findings.iter().map(|f| f.to_json_entry()).collect();
    format!("[\n{}\n]", entries.join(",\n"))
}

/// Python truthiness for JSON values: `not raw_p.get(field)` is true for
/// missing (null here), empty string, empty list/object, 0, false.
fn is_falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => {
            n.as_i64().map(|i| i == 0).unwrap_or(false)
                || n.as_u64().map(|u| u == 0).unwrap_or(false)
                || n.as_f64().map(|f| f == 0.0).unwrap_or(false)
        }
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
    }
}

/// Python's f-string rendering of a raw JSON scalar (`None`, `True`,
/// `False`, shortest-round-trip numbers, strings verbatim).
fn scalar_str(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => v.to_string(),
    }
}

/// Port of `lint.lint_file`. `fixture_ids: None` skips the fixture-coverage
/// checks (checks 7-8); `Some` runs them. Does NOT fail fast on duplicate
/// ids — reports instead, like the Python original.
pub fn lint_file(path: &Path, fixture_ids: Option<&BTreeSet<String>>) -> Result<Vec<Finding>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let raw: Value = serde_json::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
    let raw_probes: &[Value] = match raw.get("probes") {
        None => &[],
        Some(Value::Array(a)) => a,
        // A dict's keys iterate as strings and are skipped as non-dict rows,
        // same as Python's `for raw_p in raw_probes` over a dict.
        Some(_) => &[],
    };
    let mut findings: Vec<Finding> = Vec::new();

    // 1. duplicate ids (set-level, error). Python keys on the raw id value
    // (including None for missing), so the port keys on Option<String> too.
    let ids: Vec<Option<String>> = raw_probes
        .iter()
        .filter_map(|p| p.as_object())
        .map(|o| o.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();
    let mut seen: HashSet<Option<String>> = HashSet::new();
    for pid in &ids {
        if !seen.insert(pid.clone()) {
            let label = pid.as_deref().map(|s| format!("'{s}'")).unwrap_or_else(|| "None".to_string());
            findings.push(Finding::new(
                "error",
                "(set)",
                "duplicate-id",
                format!("id {label} appears more than once"),
            ));
        }
    }

    // 2-6. per-probe checks. Rows that aren't dicts are skipped, as Python does.
    for raw_p in raw_probes.iter().filter_map(|p| p.as_object()) {
        let pid: String = match raw_p.get("id").and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => "(unknown-id)".to_string(),
        };

        for field in REQUIRED {
            let v = raw_p.get(*field).unwrap_or(&Value::Null);
            if is_falsy(v) {
                findings.push(Finding::new(
                    "error",
                    &pid,
                    "schema",
                    format!("missing or empty required field '{field}'"),
                ));
            }
        }

        // Python defaults a MISSING key to "" (a valid empty taxonomy value);
        // a key that is present-but-null renders as 'None' and is invalid.
        let tax = |key: &str| -> String {
            match raw_p.get(key) {
                None => String::new(),
                Some(v) => scalar_str(v),
            }
        };
        let sev = tax("severity");
        let exp = tax("expected");
        let dlv = tax("delivery");
        let mech = tax("mechanism");
        for (field, value, valid) in [
            ("severity", sev.as_str(), SEVERITIES),
            ("expected", exp.as_str(), EXPECTED),
            ("delivery", dlv.as_str(), DELIVERIES),
            ("mechanism", mech.as_str(), MECHANISMS),
        ] {
            if !valid.contains(&value) {
                findings.push(Finding::new(
                    "error",
                    &pid,
                    "taxonomy",
                    format!("invalid {field} value '{value}'"),
                ));
            }
        }

        let prompt: Option<&str> = raw_p.get("prompt").and_then(|v| v.as_str());
        match prompt {
            Some(p) => {
                if !p.is_empty() && p != p.trim() {
                    findings.push(Finding::new(
                        "warn",
                        &pid,
                        "prompt-whitespace",
                        "payload has leading/trailing whitespace".to_string(),
                    ));
                }
            }
            None => {
                findings.push(Finding::new("error", &pid, "schema", "prompt is not a string".to_string()));
            }
        }

        // `markers = raw_p.get("success_markers") or []`
        let markers_raw = raw_p.get("success_markers").unwrap_or(&Value::Null);
        if is_falsy(markers_raw) {
            findings.push(Finding::new(
                "warn",
                &pid,
                "no-markers",
                "no success markers — grader can never fire; probe only measures blocked/resisted".to_string(),
            ));
        } else if prompt.is_some() && exp != "comply" {
            // Negative controls are exempt: for expected=="comply" the marker
            // living in the prompt is the mechanism, not a confound.
            let lowered = prompt.unwrap().to_lowercase();
            // A truthy non-list iterates its items like Python (a string
            // iterates its characters).
            let items: Vec<String> = match markers_raw {
                Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
                Value::String(s) => s.chars().map(|c| c.to_string()).collect(),
                _ => vec![],
            };
            // Note: Python also checks `isinstance(m, str) and m` per item;
            // non-string list items are skipped by the as_str() filter above.
            for m in items {
                if !m.is_empty() && lowered.contains(&m.to_lowercase()) {
                    findings.push(Finding::new(
                        "warn",
                        &pid,
                        "marker-in-prompt",
                        format!("marker '{m}' appears in the payload — a model echoing the prompt trips it"),
                    ));
                }
            }
        }
    }

    // 7-8. fixture coverage. Byte-order (BTreeSet) == Python's sorted().
    if let Some(fids) = fixture_ids {
        let probe_ids: BTreeSet<String> = raw_probes
            .iter()
            .filter_map(|p| p.as_object())
            .filter_map(|o| o.get("id"))
            .filter(|v| !is_falsy(v))
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        for pid in probe_ids.difference(fids) {
            findings.push(Finding::new(
                "warn",
                pid,
                "no-fixture",
                "no mock fixture — mock runs skip this probe".to_string(),
            ));
        }
        for fid in fids.difference(&probe_ids) {
            findings.push(Finding::new(
                "warn",
                "(set)",
                "stale-fixture",
                format!("fixture id '{fid}' has no matching probe"),
            ));
        }
    }

    Ok(findings)
}

/// Port of `lint.summarize`. The clean case keeps the em-dash verbatim.
pub fn summarize(findings: &[Finding]) -> String {
    let errors = findings.iter().filter(|f| f.level == "error").count();
    let warns = findings.len() - errors;
    if findings.is_empty() {
        return "lint: clean — 0 findings".to_string();
    }
    format!("lint: {errors} error(s), {warns} warning(s), {} finding(s) total", findings.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_line_padding_matches_python_widths() {
        let f = Finding::new("warn", "INJ-001", "no-markers", "x".to_string());
        assert_eq!(f.to_line(), "WARN   INJ-001       no-markers: x");
        let e = Finding::new("error", "(set)", "duplicate-id", "y".to_string());
        assert_eq!(e.to_line(), "ERROR  (set)         duplicate-id: y");
        // No truncation: a long id keeps its full width.
        let l = Finding::new("warn", "A-VERY-LONG-PROBE-ID", "c", "z".to_string());
        assert!(l.to_line().starts_with("WARN   A-VERY-LONG-PROBE-ID  c: z"));
    }

    #[test]
    fn to_line_pads_by_chars_not_bytes() {
        // 'café' is 4 chars but 5 bytes: Python's :12 pads to 12 characters.
        let f = Finding::new("warn", "café", "c", "z".to_string());
        assert_eq!(f.to_line(), "WARN   café          c: z");
    }

    #[test]
    fn summarize_cases() {
        assert_eq!(summarize(&[]), "lint: clean — 0 findings");
        let fs = vec![
            Finding::new("error", "a", "c", "m".to_string()),
            Finding::new("warn", "b", "c", "m".to_string()),
        ];
        assert_eq!(summarize(&fs), "lint: 1 error(s), 1 warning(s), 2 finding(s) total");
    }

    #[test]
    fn py_json_escape_matches_python_ensure_ascii() {
        assert_eq!(py_json_escape("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(py_json_escape("l1\nl2\t"), "\"l1\\nl2\\t\"");
        assert_eq!(py_json_escape("é"), "\"\\u00e9\"");
        assert_eq!(py_json_escape("\u{7f}"), "\"\\u007f\"");
        assert_eq!(py_json_escape("😀"), "\"\\ud83d\\ude00\"");
        assert_eq!(py_json_escape("—"), "\"\\u2014\"");
    }

    #[test]
    fn to_json_entry_layout_matches_indent2() {
        let f = Finding::new("error", "DUP-001", "duplicate-id", "id 'DUP-001' appears more than once".to_string());
        let expected = "  {\n    \"level\": \"error\",\n    \"probe_id\": \"DUP-001\",\n    \"check\": \"duplicate-id\",\n    \"message\": \"id 'DUP-001' appears more than once\"\n  }";
        assert_eq!(f.to_json_entry(), expected);
    }

    #[test]
    fn findings_to_json_empty_and_join() {
        assert_eq!(findings_to_json(&[]), "[]");
        let fs = vec![
            Finding::new("warn", "a", "c", "m1".to_string()),
            Finding::new("warn", "b", "c", "m2".to_string()),
        ];
        let j = findings_to_json(&fs);
        assert!(j.starts_with("[\n  {"));
        assert!(j.contains(",\n  {"));
        assert!(j.ends_with("\n]"));
    }

    #[test]
    fn lint_file_reports_dup_taxonomy_whitespace() {
        let dir = std::env::temp_dir();
        let path = dir.join("injectlab_rs_lint_test.json");
        std::fs::write(
            &path,
            r#"{"probes": [
                {"id":"A-1","category":"x","severity":"high","title":"t","prompt":"clean prompt","injected_goal":"g","expected":"refuse","success_markers":["zzz-nope"]},
                {"id":"A-1","category":"x","severity":"critical","title":"t","prompt":"  padded  ","injected_goal":"g","expected":"refuse","success_markers":["zzz-nope"]}
            ]}"#,
        )
        .unwrap();
        let fs = lint_file(&path, None).unwrap();
        let checks: Vec<(&str, &str, &str)> =
            fs.iter().map(|f| (f.level.as_str(), f.probe_id.as_str(), f.check.as_str())).collect();
        assert!(checks.contains(&("error", "(set)", "duplicate-id")));
        assert!(checks.contains(&("error", "A-1", "taxonomy")));
        assert!(checks.contains(&("warn", "A-1", "prompt-whitespace")));
        std::fs::remove_file(&path).unwrap();
    }
}
