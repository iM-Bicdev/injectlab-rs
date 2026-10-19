//! injectlab-rs: port of `injectlab/compare.py` — run-to-run diffing.
//!
//! Score a model, ship a defense (system-prompt tweak, guardrail), score
//! again: the diff says what actually moved, probe by probe, so the defense
//! gets judged on both sides of the ledger. Flat totals lie — a drop of 3
//! vulnerable probes is good unless it cost 5 new over-refusals.
//!
//! Input: the JSON a run emits (`injectlab run --json`), parsed as
//! `serde_json::Value`. Compare on probe id, not position — sets can gain
//! or lose probes between runs. Counts are recomputed from `results`, never
//! trusted from the report's cached aggregates.
//!
//! Fidelity notes:
//! - `_delta` formats floats the way Python's `str()` does: `0.0714`,
//!   `0.0` (never bare `0` — Rust's `{}` would print `0`, Python prints
//!   `0.0`). `py_float` carries that rule; `{:?}` on f64 already does.
//! - Pre-v1.3 reports lack `mechanism` on their results; they land in the
//!   `"?"` bucket instead of vanishing — same as the Python original.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The four verdicts, in the Python original's iteration order.
pub const VERDICTS: [&str; 4] = ["blocked", "resisted", "vulnerable", "unclear"];

fn get_str<'a>(v: &'a Value, key: &str, default: &'a str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or(default)
}

/// Python `str()` of a float: `0.0714`, `0.125`, and `0.0` — never `0`.
/// Rust's `{:?}` on f64 already follows this shape (shortest repr, decimal
/// point always present). FP rates and deltas are small enough that the
/// Python-vs-Rust scientific-notation boundary (`1e-05`) never bites.
fn py_float(x: f64) -> String {
    format!("{:?}", x)
}

/// Python: `f"{a} → {b} ({sign}{d})"` with `sign = "+" if d > 0 else ""`.
fn delta_int(a: i64, b: i64) -> String {
    let d = b - a;
    format!("{} → {} ({}{})", a, b, if d > 0 { "+" } else { "" }, d)
}

/// Python: `_delta(round(old_fp, 4), round(new_fp, 4))` — same `{sign}{d}`
/// shape, float formatting.
fn delta_float(a: f64, b: f64) -> String {
    let d = b - a;
    format!(
        "{} → {} ({}{})",
        py_float(a),
        py_float(b),
        if d > 0.0 { "+" } else { "" },
        py_float(d)
    )
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

/// A probe whose verdict changed between the two runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictFlip {
    pub probe_id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub delivery: String,
    pub old: String,
    pub new: String,
}

impl VerdictFlip {
    /// Vulnerable -> anything is a fix; anything -> vulnerable is a leak.
    pub fn improved(&self) -> bool {
        self.old == "vulnerable" && self.new != "vulnerable"
    }
    pub fn regressed(&self) -> bool {
        self.old != "vulnerable" && self.new == "vulnerable"
    }
}

fn index(report: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    if let Some(results) = report.get("results").and_then(|r| r.as_array()) {
        for r in results {
            if let Some(id) = r.get("id").and_then(|i| i.as_str()) {
                out.insert(id.to_string(), r.clone());
            }
        }
    }
    out
}

/// Recompute verdict counts from `results` — never trust the cached
/// aggregates (the design point the Python original exists to make).
fn counts(report: &Value) -> BTreeMap<String, i64> {
    let mut out: BTreeMap<String, i64> = BTreeMap::new();
    if let Some(results) = report.get("results").and_then(|r| r.as_array()) {
        for r in results {
            let v = get_str(r, "verdict", "unclear");
            *out.entry(v.to_string()).or_insert(0) += 1;
        }
    }
    out
}

fn vuln_by(report: &Value, key: &str) -> BTreeMap<String, i64> {
    let mut out: BTreeMap<String, i64> = BTreeMap::new();
    if let Some(results) = report.get("results").and_then(|r| r.as_array()) {
        for r in results {
            if get_str(r, "verdict", "unclear") == "vulnerable" {
                let k = get_str(r, key, "?");
                *out.entry(k.to_string()).or_insert(0) += 1;
            }
        }
    }
    out
}

fn fp_rate(report: &Value) -> Option<f64> {
    report
        .get("controls")
        .and_then(|c| c.get("false_positive_rate"))
        .and_then(|f| f.as_f64())
}

pub struct RunDiff {
    pub old_label: String,
    pub new_label: String,
    pub old_attack_set: String,
    pub new_attack_set: String,
    pub same_attack_set: bool,
    pub old_counts: BTreeMap<String, i64>,
    pub new_counts: BTreeMap<String, i64>,
    pub flips: Vec<VerdictFlip>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub old_fp: Option<f64>,
    pub new_fp: Option<f64>,
    // Precomputed so to_dict/to_markdown stay cheap; set by compare_reports.
    old_vuln_by: BTreeMap<String, BTreeMap<String, i64>>,
    new_vuln_by: BTreeMap<String, BTreeMap<String, i64>>,
}

impl RunDiff {
    pub fn fixed(&self) -> Vec<&VerdictFlip> {
        self.flips.iter().filter(|f| f.improved()).collect()
    }
    pub fn leaked(&self) -> Vec<&VerdictFlip> {
        self.flips.iter().filter(|f| f.regressed()).collect()
    }

    fn vuln_delta(&self, key: &str) -> BTreeMap<String, String> {
        let old = self.old_vuln_by.get(key).cloned().unwrap_or_default();
        let new = self.new_vuln_by.get(key).cloned().unwrap_or_default();
        let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        keys.into_iter()
            .map(|k| {
                (
                    k.clone(),
                    delta_int(old.get(k).copied().unwrap_or(0), new.get(k).copied().unwrap_or(0)),
                )
            })
            .collect()
    }

    pub fn vulnerable_delta_by_category(&self) -> BTreeMap<String, String> {
        self.vuln_delta("category")
    }
    pub fn vulnerable_delta_by_delivery(&self) -> BTreeMap<String, String> {
        self.vuln_delta("delivery")
    }
    pub fn vulnerable_delta_by_severity(&self) -> BTreeMap<String, String> {
        self.vuln_delta("severity")
    }
    pub fn vulnerable_delta_by_mechanism(&self) -> BTreeMap<String, String> {
        self.vuln_delta("mechanism")
    }

    pub fn to_dict(&self) -> Value {
        let counts = VERDICTS
            .iter()
            .map(|v| {
                (
                    v.to_string(),
                    Value::String(delta_int(
                        self.old_counts.get(*v).copied().unwrap_or(0),
                        self.new_counts.get(*v).copied().unwrap_or(0),
                    )),
                )
            })
            .collect::<serde_json::Map<String, Value>>();
        serde_json::json!({
            "old": self.old_label,
            "new": self.new_label,
            "same_attack_set": self.same_attack_set,
            "counts": counts,
            "vulnerable_delta_by_category": self.vulnerable_delta_by_category(),
            "vulnerable_delta_by_delivery": self.vulnerable_delta_by_delivery(),
            "vulnerable_delta_by_severity": self.vulnerable_delta_by_severity(),
            "vulnerable_delta_by_mechanism": self.vulnerable_delta_by_mechanism(),
            "flips": self.flips.iter().map(|f| serde_json::json!({
                "id": f.probe_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "delivery": f.delivery,
                "old": f.old,
                "new": f.new,
                "improved": f.improved(),
                "regressed": f.regressed(),
            })).collect::<Vec<_>>(),
            "added_probes": self.added,
            "removed_probes": self.removed,
            "false_positive_rate": { "old": self.old_fp, "new": self.new_fp },
        })
    }

    pub fn to_markdown(&self) -> String {
        let mut lines = vec![
            format!("# injectlab diff — {} → {}", self.old_label, self.new_label),
            format!("Old: {} | New: {}", self.old_attack_set, self.new_attack_set),
        ];
        if !self.same_attack_set {
            lines.push(
                "_warning: attack sets differ — flips are computed on probe id, \
                 so added/removed probes show separately_"
                    .to_string(),
            );
        }
        lines.push(String::new());
        lines.push("## Headline".to_string());
        for v in VERDICTS {
            lines.push(format!(
                "- {v}: {}",
                delta_int(
                    self.old_counts.get(v).copied().unwrap_or(0),
                    self.new_counts.get(v).copied().unwrap_or(0)
                )
            ));
        }
        lines.push(format!(
            "- probes fixed (vulnerable → not): {}",
            self.fixed().len()
        ));
        lines.push(format!(
            "- probes leaked (not → vulnerable): {}",
            self.leaked().len()
        ));
        if let (Some(a), Some(b)) = (self.old_fp, self.new_fp) {
            lines.push(format!(
                "- false-positive rate: {}",
                delta_float(round4(a), round4(b))
            ));
        }
        for (title, table) in [
            ("Vulnerable Δ by category", self.vulnerable_delta_by_category()),
            ("Vulnerable Δ by delivery", self.vulnerable_delta_by_delivery()),
            ("Vulnerable Δ by severity", self.vulnerable_delta_by_severity()),
            ("Vulnerable Δ by mechanism", self.vulnerable_delta_by_mechanism()),
        ] {
            lines.push(String::new());
            lines.push(format!("## {title}"));
            lines.push("| group | old → new (Δ) |".to_string());
            lines.push("|---|---|".to_string());
            for (k, d) in &table {
                lines.push(format!("| {k} | {d} |"));
            }
        }
        lines.push(String::new());
        lines.push("## Verdict flips".to_string());
        lines.push("| id | old → new | title |".to_string());
        lines.push("|---|---|---|".to_string());
        if self.flips.is_empty() {
            lines.push("_none — every probe graded identically in both runs_".to_string());
        }
        let mut flips = self.flips.clone();
        // Python: sorted by (regressed, probe_id) — fixes (False) sort before leaks (True).
        flips.sort_by(|a, b| {
            (a.regressed() as u8, &a.probe_id).cmp(&(b.regressed() as u8, &b.probe_id))
        });
        for f in &flips {
            let mark = if f.regressed() {
                "🔴 leak"
            } else if f.improved() {
                "🟢 fix"
            } else {
                "↔️ move"
            };
            lines.push(format!(
                "| {} | {} → {} | {mark} {} |",
                f.probe_id, f.old, f.new, f.title
            ));
        }
        if !self.added.is_empty() {
            lines.push(String::new());
            lines.push("## Added probes".to_string());
            let mut added = self.added.clone();
            added.sort();
            lines.push(added.join(", "));
        }
        if !self.removed.is_empty() {
            lines.push(String::new());
            lines.push("## Removed probes".to_string());
            let mut removed = self.removed.clone();
            removed.sort();
            lines.push(removed.join(", "));
        }
        lines.join("\n") + "\n"
    }
}

/// Diff two report dicts (the `--json` output of a run), on probe id.
pub fn compare_reports(old: &Value, new: &Value) -> RunDiff {
    let old_idx = index(old);
    let new_idx = index(new);
    let mut flips: Vec<VerdictFlip> = Vec::new();
    let ids: BTreeSet<&String> = old_idx.keys().chain(new_idx.keys()).collect();
    for pid in ids {
        if let (Some(o), Some(n)) = (old_idx.get(pid), new_idx.get(pid)) {
            let ov = get_str(o, "verdict", "unclear");
            let nv = get_str(n, "verdict", "unclear");
            if ov != nv {
                flips.push(VerdictFlip {
                    probe_id: pid.clone(),
                    title: get_str(n, "title", get_str(o, "title", "")).to_string(),
                    category: get_str(n, "category", get_str(o, "category", "")).to_string(),
                    severity: get_str(n, "severity", get_str(o, "severity", "")).to_string(),
                    delivery: get_str(n, "delivery", get_str(o, "delivery", "single")).to_string(),
                    old: ov.to_string(),
                    new: nv.to_string(),
                });
            }
        }
    }
    let mut added: Vec<String> = new_idx
        .keys()
        .filter(|k| !old_idx.contains_key(*k))
        .cloned()
        .collect();
    let mut removed: Vec<String> = old_idx
        .keys()
        .filter(|k| !new_idx.contains_key(*k))
        .cloned()
        .collect();
    added.sort();
    removed.sort();

    let old_attack_set = get_str(old, "attack_set", "?").to_string();
    let new_attack_set = get_str(new, "attack_set", "?").to_string();
    let same = old_attack_set == new_attack_set;
    RunDiff {
        old_label: format!("{} @ {}", get_str(old, "adapter", "?"), old_attack_set),
        new_label: format!("{} @ {}", get_str(new, "adapter", "?"), new_attack_set),
        old_attack_set,
        new_attack_set,
        same_attack_set: same,
        old_counts: counts(old),
        new_counts: counts(new),
        flips,
        added,
        removed,
        old_fp: fp_rate(old),
        new_fp: fp_rate(new),
        old_vuln_by: [
            ("category", vuln_by(old, "category")),
            ("delivery", vuln_by(old, "delivery")),
            ("severity", vuln_by(old, "severity")),
            ("mechanism", vuln_by(old, "mechanism")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        new_vuln_by: [
            ("category", vuln_by(new, "category")),
            ("delivery", vuln_by(new, "delivery")),
            ("severity", vuln_by(new, "severity")),
            ("mechanism", vuln_by(new, "mechanism")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(
        id: &str,
        verdict: &str,
        category: &str,
        severity: &str,
        delivery: &str,
        mechanism: &str,
    ) -> Value {
        serde_json::json!({
            "id": id,
            "title": format!("Title {id}"),
            "category": category,
            "severity": severity,
            "delivery": delivery,
            "mechanism": mechanism,
            "verdict": verdict,
            "reason": "r",
        })
    }

    fn report(adapter: &str, attack_set: &str, results: Vec<Value>, fp: Option<f64>) -> Value {
        serde_json::json!({
            "adapter": adapter,
            "attack_set": attack_set,
            "counts": {},
            "results": results,
            "controls": { "false_positive_rate": fp },
        })
    }

    fn baseline() -> Value {
        report(
            "mock",
            "set v1",
            vec![
                result("INJ-001", "blocked", "a", "high", "single", ""),
                result("INJ-002", "vulnerable", "b", "low", "single", ""),
                result("INJ-003", "vulnerable", "b", "high", "embedded-in-data", "x"),
            ],
            Some(0.125),
        )
    }

    fn defended() -> Value {
        report(
            "mock",
            "set v1",
            vec![
                result("INJ-001", "blocked", "a", "high", "single", ""),
                result("INJ-002", "blocked", "b", "low", "single", ""),
                result("INJ-003", "vulnerable", "b", "high", "embedded-in-data", "x"),
                result("INJ-004", "blocked", "c", "low", "single", ""),
            ],
            Some(0.25),
        )
    }

    #[test]
    fn flips_detected_with_direction() {
        let d = compare_reports(&baseline(), &defended());
        let by_id: BTreeMap<_, _> = d.flips.iter().map(|f| (f.probe_id.as_str(), f)).collect();
        let fix = by_id["INJ-002"];
        assert!(fix.improved() && !fix.regressed());
        assert_eq!(fix.old, "vulnerable");
        assert_eq!(fix.new, "blocked");
        assert_eq!(d.fixed().len(), 1);
        assert_eq!(d.leaked().len(), 0);
    }

    #[test]
    fn added_and_removed_probes() {
        let d = compare_reports(&baseline(), &defended());
        assert_eq!(d.added, vec!["INJ-004"]);
        assert_eq!(d.removed, Vec::<String>::new());
        let d2 = compare_reports(&defended(), &baseline());
        assert_eq!(d2.removed, vec!["INJ-004"]);
        assert_eq!(d2.added, Vec::<String>::new());
    }

    #[test]
    fn headline_deltas_and_fp_rate() {
        let d = compare_reports(&baseline(), &defended());
        let j = d.to_dict();
        assert_eq!(j["counts"]["vulnerable"], Value::String("2 → 1 (-1)".to_string()));
        assert_eq!(j["counts"]["blocked"], Value::String("1 → 3 (+2)".to_string()));
        assert_eq!(j["false_positive_rate"]["old"], Value::from(0.125));
        assert_eq!(j["false_positive_rate"]["new"], Value::from(0.25));
    }

    #[test]
    fn no_flips_on_identical_reports() {
        let d = compare_reports(&baseline(), &baseline());
        assert!(d.flips.is_empty());
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        let md = d.to_markdown();
        assert!(md.contains("_none — every probe graded identically in both runs_"));
    }

    #[test]
    fn markdown_marks_fix_before_leak() {
        // Regression flips sort after fixes, like the Python original.
        let mut old = baseline();
        let mut new = defended();
        // Make INJ-001 leak too: fix (INJ-002) must still render first.
        let arr = new.get_mut("results").unwrap().as_array_mut().unwrap();
        arr[0]["verdict"] = Value::String("vulnerable".to_string());
        let d = compare_reports(&old, &new);
        let md = d.to_markdown();
        let fix_pos = md.find("🟢 fix").unwrap();
        let leak_pos = md.find("🔴 leak").unwrap();
        assert!(fix_pos < leak_pos);
        let _ = &mut old;
    }

    #[test]
    fn markdown_renders_headline_and_tables() {
        let d = compare_reports(&baseline(), &defended());
        let md = d.to_markdown();
        assert!(md.contains("# injectlab diff — mock @ set v1 → mock @ set v1"));
        assert!(md.contains("probes fixed (vulnerable → not): 1"));
        assert!(md.contains("probes leaked (not → vulnerable): 0"));
        assert!(md.contains("- false-positive rate: 0.125 → 0.25 (+0.125)"));
        assert!(md.contains("## Vulnerable Δ by severity"));
        assert!(md.contains("| high | 1 → 1 (0) |"));
        assert!(md.contains("| low | 1 → 0 (-1) |"));
    }

    #[test]
    fn attack_set_mismatch_warns_and_labels() {
        let mut new = defended();
        new["attack_set"] = Value::String("set v2".to_string());
        let d = compare_reports(&baseline(), &new);
        assert!(!d.same_attack_set);
        assert!(d
            .to_markdown()
            .contains("_warning: attack sets differ"));
        assert_eq!(d.new_label, "mock @ set v2");
    }

    #[test]
    fn counts_recomputed_not_trusted() {
        // The report's cached aggregates are lies here; the diff must use
        // the recomputed ones from results.
        let mut old = baseline();
        old["counts"] = serde_json::json!({"vulnerable": 99});
        let d = compare_reports(&old, &defended());
        let j = d.to_dict();
        assert_eq!(j["counts"]["vulnerable"], Value::String("2 → 1 (-1)".to_string()));
    }

    #[test]
    fn missing_mechanism_lands_in_question_mark_bucket() {
        // Pre-v1.3 reports lack `mechanism`; they must not vanish.
        let mut old = baseline();
        for r in old.get_mut("results").unwrap().as_array_mut().unwrap() {
            r.as_object_mut().unwrap().remove("mechanism");
        }
        let d = compare_reports(&old, &defended());
        let t = d.vulnerable_delta_by_mechanism();
        assert!(t.contains_key("?"));
    }

    #[test]
    fn py_float_never_prints_bare_zero() {
        assert_eq!(py_float(0.0), "0.0");
        assert_eq!(py_float(0.125), "0.125");
        assert_eq!(delta_float(0.125, 0.125), "0.125 → 0.125 (0.0)");
        assert_eq!(delta_int(5, 2), "5 → 2 (-3)");
    }

    #[test]
    fn null_fp_rate_stays_null_and_skips_line() {
        let mut old = baseline();
        old["controls"] = serde_json::json!({});
        let d = compare_reports(&old, &defended());
        assert_eq!(d.old_fp, None);
        let j = d.to_dict();
        assert!(j["false_positive_rate"]["old"].is_null());
        assert!(!d.to_markdown().contains("false-positive rate:"));
    }
}
