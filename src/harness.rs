//! The runner: probes in, report out. Faithful port of `injectlab/harness.py`.
//!
//! Assumptions, kept verbatim:
//! - `run()` takes an attack set and an adapter. For the mock it calls
//!   `generate_for(probe_id)`; for anything else it calls
//!   `generate(prompt)`. (The isinstance check is a v1 wart — real adapters
//!   all speak `generate()`.)
//! - Latency is measured per probe in ms. With the mock it's ~0; with real
//!   endpoints it tells you which probes are slow, which is its own signal.
//! - The report is a plain data object with `to_markdown()` and `to_dict()`.
//!   No HTML dashboard in v1 — markdown pastes into a write-up, and the
//!   write-up is the product.
//!
//! Fidelity notes:
//! - Verdict tallies (`counts`, `by_category`, ...) preserve first-seen
//!   insertion order, exactly like the Python dicts they mirror — the JSON
//!   judge compares bytes, not sets.
//! - `to_markdown()` is built line-by-line to match the original's
//!   `"\n".join(lines) + "\n"` exactly, em dashes included.
//! - `to_dict()` emits through `pyjson` so the output is byte-identical to
//!   `json.dumps(report.to_dict(), indent=2)` — key order, 2-space indent,
//!   `ensure_ascii` escaping. `latency_ms` is the one field that can never
//!   byte-match (timing is nondeterministic); the judge normalizes it out
//!   and says so.

use std::time::Instant;

use serde_json::Value;

use crate::models::Adapter;
use crate::pyjson::{dumps, JVal};
use crate::{grade, grade_control, Probe};

/// One probe, every field the report reads. Mirrors the Python `Probe`
/// dataclass (defaults: expected "refuse", delivery "single", mechanism "").
pub struct FullProbe {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub title: String,
    pub prompt: String,
    pub success_markers: Vec<String>,
    pub expected: String,
    pub delivery: String,
    pub mechanism: String,
}

impl FullProbe {
    fn as_grading_probe(&self) -> Probe {
        Probe {
            id: self.id.clone(),
            success_markers: self.success_markers.clone(),
            expected: self.expected.clone(),
        }
    }
}

pub struct AttackSet {
    pub name: String,
    pub version: String,
    pub probes: Vec<FullProbe>,
}

/// Load one probe-set JSON. Missing keys are an error, not a guess — a probe
/// without an id, markers, or an expectation is a confounded experiment.
/// Optional fields take the documented defaults (`attacks.py`).
pub fn load_attack_set(path: &str) -> Result<AttackSet, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let doc: Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    let raw_probes = doc
        .get("probes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}: no 'probes' array"))?;

    let get = |p: &Value, key: &str| -> Result<String, String> {
        p.get(key)
            .and_then(Value::as_str)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                format!(
                    "{path}: probe missing {key}",
                    path = path,
                    key = key
                )
            })
    };
    let get_d = |p: &Value, key: &str, default: &str| -> String {
        p.get(key)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_string()
    };

    let mut probes = Vec::with_capacity(raw_probes.len());
    for p in raw_probes {
        let markers = p
            .get("success_markers")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{path}: probe without success_markers"))?;
        let mut success_markers = Vec::with_capacity(markers.len());
        for m in markers {
            success_markers.push(
                m.as_str()
                    .ok_or_else(|| format!("{path}: non-string success marker"))?
                    .to_string(),
            );
        }
        probes.push(FullProbe {
            id: get(p, "id")?,
            category: get(p, "category")?,
            severity: get(p, "severity")?,
            title: get(p, "title")?,
            prompt: get(p, "prompt")?,
            success_markers,
            expected: get_d(p, "expected", "refuse"),
            delivery: get_d(p, "delivery", "single"),
            mechanism: get_d(p, "mechanism", ""),
        });
    }
    let ids: Vec<&str> = probes.iter().map(|p| p.id.as_str()).collect();
    let mut seen = std::collections::HashSet::new();
    let mut dupes = Vec::new();
    for id in &ids {
        if !seen.insert(id) {
            dupes.push(id.to_string());
        }
    }
    if !dupes.is_empty() {
        return Err(format!("duplicate probe ids: {dupes:?}"));
    }
    Ok(AttackSet {
        name: doc
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unnamed")
            .to_string(),
        version: doc
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("0.0.0")
            .to_string(),
        probes,
    })
}

/// One scored probe.
pub struct ProbeResult {
    pub probe_id: String,
    pub category: String,
    pub severity: String,
    pub title: String,
    pub verdict: String,
    pub reason: String,
    pub latency_ms: f64,
    pub delivery: String,
    pub mechanism: String,
}

pub struct RunReport {
    pub attack_set_name: String,
    pub attack_set_version: String,
    pub adapter_name: String,
    pub results: Vec<ProbeResult>,
    pub controls: Vec<ProbeResult>,
}

/// First-seen-ordered tally — the Rust shape of the Python dict built by
/// `counts()`: keys appear in the order their verdict first occurred.
fn tally(results: &[ProbeResult]) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    for r in results {
        match out.iter_mut().find(|(v, _)| *v == r.verdict) {
            Some((_, n)) => *n += 1,
            None => out.push((r.verdict.clone(), 1)),
        }
    }
    out
}

/// First-seen-ordered tally grouped by a key function — the shape of
/// `by_category()` / `by_delivery()` / `by_mechanism()`.
fn tally_by(results: &[ProbeResult], key: fn(&ProbeResult) -> String) -> Vec<(String, Vec<(String, usize)>)> {
    let mut out: Vec<(String, Vec<(String, usize)>)> = Vec::new();
    for r in results {
        let k = key(r);
        let cell = match out.iter_mut().find(|(kk, _)| *kk == k) {
            Some((_, cell)) => cell,
            None => {
                out.push((k.clone(), Vec::new()));
                &mut out.last_mut().unwrap().1
            }
        };
        match cell.iter_mut().find(|(v, _)| *v == r.verdict) {
            Some((_, n)) => *n += 1,
            None => cell.push((r.verdict.clone(), 1)),
        }
    }
    out
}

fn get_count(tally: &[(String, usize)], verdict: &str) -> usize {
    tally
        .iter()
        .find(|(v, _)| v == verdict)
        .map(|(_, n)| *n)
        .unwrap_or(0)
}

impl RunReport {
    pub fn counts(&self) -> Vec<(String, usize)> {
        tally(&self.results)
    }

    pub fn control_counts(&self) -> Vec<(String, usize)> {
        tally(&self.controls)
    }

    /// Share of benign controls the model over-refused. None ran -> 0.0.
    pub fn false_positive_rate(&self) -> f64 {
        if self.controls.is_empty() {
            return 0.0;
        }
        get_count(&self.control_counts(), "over-refusal") as f64 / self.controls.len() as f64
    }

    pub fn by_category(&self) -> Vec<(String, Vec<(String, usize)>)> {
        tally_by(&self.results, |r| r.category.clone())
    }

    /// Verdict counts per delivery shape. The same payload lands differently
    /// depending on how it's shaped for delivery — the Grok re-probe proved
    /// it. If "embedded-in-data" leaks twice as often as "single", that's
    /// not one finding, that's the defense's weak axis.
    pub fn by_delivery(&self) -> Vec<(String, Vec<(String, usize)>)> {
        tally_by(&self.results, |r| r.delivery.clone())
    }

    /// Verdict counts per target mechanism. Probes tagged before the
    /// taxonomy existed carry mechanism "" and land in the "(untagged)"
    /// bucket honestly.
    pub fn by_mechanism(&self) -> Vec<(String, Vec<(String, usize)>)> {
        tally_by(&self.results, |r| {
            if r.mechanism.is_empty() {
                "(untagged)".to_string()
            } else {
                r.mechanism.clone()
            }
        })
    }

    pub fn vulnerable(&self) -> Vec<&ProbeResult> {
        self.results
            .iter()
            .filter(|r| r.verdict == "vulnerable")
            .collect()
    }

    /// How many probes of each severity the model failed to stop.
    /// Severities not seen in the run are omitted (not zero-filled).
    pub fn vulnerable_by_severity(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for r in self.results.iter().filter(|r| r.verdict == "vulnerable") {
            match out.iter_mut().find(|(s, _)| *s == r.severity) {
                Some((_, n)) => *n += 1,
                None => out.push((r.severity.clone(), 1)),
            }
        }
        out
    }

    fn counts_jval(counts: &[(String, usize)]) -> JVal {
        JVal::obj(
            counts
                .iter()
                .map(|(v, n)| (v.as_str(), JVal::Int(*n as i64)))
                .collect(),
        )
    }

    fn grouped_jval(groups: &[(String, Vec<(String, usize)>)]) -> JVal {
        JVal::obj(
            groups
                .iter()
                .map(|(k, cell)| (k.as_str(), Self::counts_jval(cell)))
                .collect(),
        )
    }

    /// The `to_dict()` shape, as a `JVal` for byte-exact emission.
    pub fn to_jval(&self) -> JVal {
        let results: Vec<JVal> = self
            .results
            .iter()
            .map(|r| {
                JVal::obj(vec![
                    ("id", JVal::Str(r.probe_id.clone())),
                    ("category", JVal::Str(r.category.clone())),
                    ("severity", JVal::Str(r.severity.clone())),
                    ("delivery", JVal::Str(r.delivery.clone())),
                    ("mechanism", JVal::Str(r.mechanism.clone())),
                    ("title", JVal::Str(r.title.clone())),
                    ("verdict", JVal::Str(r.verdict.clone())),
                    ("reason", JVal::Str(r.reason.clone())),
                    (
                        "latency_ms",
                        JVal::Float((r.latency_ms * 10.0).round() / 10.0),
                    ),
                ])
            })
            .collect();
        JVal::obj(vec![
            (
                "attack_set",
                JVal::Str(format!("{} v{}", self.attack_set_name, self.attack_set_version)),
            ),
            ("adapter", JVal::Str(self.adapter_name.clone())),
            ("counts", Self::counts_jval(&self.counts())),
            ("by_category", Self::grouped_jval(&self.by_category())),
            ("by_delivery", Self::grouped_jval(&self.by_delivery())),
            ("by_mechanism", Self::grouped_jval(&self.by_mechanism())),
            (
                "vulnerable_by_severity",
                Self::counts_jval(&self.vulnerable_by_severity()),
            ),
            (
                "controls",
                JVal::obj(vec![
                    ("count", JVal::Int(self.controls.len() as i64)),
                    ("verdicts", Self::counts_jval(&self.control_counts())),
                    (
                        "false_positive_rate",
                        JVal::Float(
                            (self.false_positive_rate() * 10_000.0).round() / 10_000.0,
                        ),
                    ),
                ]),
            ),
            ("results", JVal::arr(results)),
        ])
    }

    /// `json.dumps(report.to_dict(), indent=2)`, byte-exact.
    pub fn to_json(&self) -> String {
        dumps(&self.to_jval())
    }

    /// `"\n".join(lines) + "\n"`, byte-exact — em dashes included.
    pub fn to_markdown(&self) -> String {
        let mut lines: Vec<String> = vec![
            format!("# injectlab run — {}", self.adapter_name),
            format!(
                "Attack set: {} v{} ({} probes)",
                self.attack_set_name,
                self.attack_set_version,
                self.results.len()
            ),
            String::new(),
            "## Totals".to_string(),
        ];
        let counts = self.counts();
        for verdict in ["blocked", "resisted", "vulnerable", "unclear"] {
            lines.push(format!("- {verdict}: {}", get_count(&counts, verdict)));
        }
        let vbs = self.vulnerable_by_severity();
        let vbs_str = ["high", "medium", "low"]
            .iter()
            .map(|sev| format!("{sev}: {}", get_count(&vbs, sev)))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("- vulnerable by severity: {vbs_str}"));

        let table = |title: &str, header: &str, groups: &[(String, Vec<(String, usize)>)], lines: &mut Vec<String>| {
            lines.push(String::new());
            lines.push(format!("## {title}"));
            lines.push(header.to_string());
            lines.push("|---|---|---|---|---|".to_string());
            let mut keys: Vec<&String> = groups.iter().map(|(k, _)| k).collect();
            keys.sort();
            for k in keys {
                let cell = &groups.iter().find(|(kk, _)| kk == k).unwrap().1;
                lines.push(format!(
                    "| {k} | {} | {} | {} | {} |",
                    get_count(cell, "blocked"),
                    get_count(cell, "resisted"),
                    get_count(cell, "vulnerable"),
                    get_count(cell, "unclear"),
                ));
            }
        };
        table(
            "By category",
            "| category | blocked | resisted | vulnerable | unclear |",
            &self.by_category(),
            &mut lines,
        );
        table(
            "By delivery shape",
            "| delivery | blocked | resisted | vulnerable | unclear |",
            &self.by_delivery(),
            &mut lines,
        );
        table(
            "By target mechanism",
            "| mechanism | blocked | resisted | vulnerable | unclear |",
            &self.by_mechanism(),
            &mut lines,
        );

        lines.push(String::new());
        lines.push("## Vulnerable probes".to_string());
        let vuln = self.vulnerable();
        if vuln.is_empty() {
            lines.push("_none — the model held on every probe_".to_string());
        }
        for r in vuln {
            lines.push(format!(
                "- **{}** ({}) — {}: {}",
                r.probe_id, r.severity, r.title, r.reason
            ));
        }

        if !self.controls.is_empty() {
            let cc = self.control_counts();
            lines.push(String::new());
            lines.push("## Controls (negative probes)".to_string());
            lines.push(format!(
                "- clean: {} / over-refusal: {} / unclear: {} ({} controls)",
                get_count(&cc, "clean"),
                get_count(&cc, "over-refusal"),
                get_count(&cc, "unclear"),
                self.controls.len()
            ));
            // Python: f"{self.false_positive_rate():.1%}"
            let pct = format!("{:.1}", self.false_positive_rate() * 100.0);
            lines.push(format!(
                "- false-positive rate: {pct}% (over-refused / all controls)"
            ));
            for r in self.controls.iter().filter(|r| r.verdict == "over-refusal") {
                lines.push(format!("- **{}** — {}: {}", r.probe_id, r.title, r.reason));
            }
        }

        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

/// Score every probe in the set against the adapter. Returns the report.
///
/// Pass a control set (benign probes, graded with `grade_control`) to also
/// measure the false-positive rate alongside the attack results.
pub fn run(
    attack_set: &AttackSet,
    adapter: &Adapter,
    controls: Option<&AttackSet>,
) -> RunReport {
    let mut report = RunReport {
        attack_set_name: attack_set.name.clone(),
        attack_set_version: attack_set.version.clone(),
        adapter_name: adapter.name(),
        results: Vec::new(),
        controls: Vec::new(),
    };
    let score = |probe: &FullProbe, is_control: bool| -> ProbeResult {
        let start = Instant::now();
        // The v1 wart, kept: the mock answers by probe id, real adapters
        // get the raw prompt.
        let response = match adapter.generate_for_mock(&probe.id) {
            Some(r) => r,
            None => adapter.generate(&probe.prompt),
        };
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let g = if is_control {
            grade_control(&response, &probe.as_grading_probe())
        } else {
            grade(&response, &probe.as_grading_probe())
        };
        ProbeResult {
            probe_id: probe.id.clone(),
            category: probe.category.clone(),
            severity: probe.severity.clone(),
            title: probe.title.clone(),
            verdict: g.verdict,
            reason: g.reason,
            latency_ms,
            delivery: probe.delivery.clone(),
            mechanism: probe.mechanism.clone(),
        }
    };
    for probe in &attack_set.probes {
        report.results.push(score(probe, false));
    }
    if let Some(control_set) = controls {
        for probe in &control_set.probes {
            report.controls.push(score(probe, true));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MockAdapter;

    fn manifest() -> String {
        env!("CARGO_MANIFEST_DIR").to_string()
    }

    fn set_paths() -> (String, String) {
        (
            format!("{}/../injectlab/attacks/attack-set-v1.4.json", manifest()),
            format!("{}/../injectlab/attacks/control-set-v1.1.json", manifest()),
        )
    }

    fn mock_report() -> RunReport {
        let (a, c) = set_paths();
        let attack = load_attack_set(&a).unwrap();
        let controls = load_attack_set(&c).unwrap();
        run(&attack, &Adapter::Mock(MockAdapter::new()), Some(&controls))
    }

    #[test]
    fn loads_real_sets_with_full_metadata() {
        let (a, c) = set_paths();
        let attack = load_attack_set(&a).unwrap();
        assert_eq!(attack.probes.len(), 54);
        assert_eq!(attack.name, "injectlab attack set v1.4");
        assert_eq!(attack.version, "1.1.0");
        // Delivery/mechanism defaults hold for untagged probes.
        let inj001 = attack.probes.iter().find(|p| p.id == "INJ-001").unwrap();
        assert_eq!(inj001.delivery, "single");
        assert_eq!(inj001.mechanism, "");
        let inj039 = attack.probes.iter().find(|p| p.id == "INJ-039").unwrap();
        assert!(!inj039.mechanism.is_empty());
        let controls = load_attack_set(&c).unwrap();
        assert_eq!(controls.probes.len(), 14);
    }

    #[test]
    fn duplicate_ids_fail_fast() {
        let dir = std::env::temp_dir();
        let path = dir.join("dup-set.json");
        std::fs::write(
            &path,
            r#"{"name":"x","version":"1","probes":[
                {"id":"A","category":"c","severity":"high","title":"t","prompt":"p","success_markers":[],"expected":"refuse"},
                {"id":"A","category":"c","severity":"high","title":"t","prompt":"p","success_markers":[],"expected":"refuse"}
            ]}"#,
        )
        .unwrap();
        assert!(load_attack_set(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn report_shape_matches_python_surface() {
        let r = mock_report();
        assert_eq!(r.adapter_name, "mock");
        assert_eq!(r.results.len(), 54);
        assert_eq!(r.controls.len(), 14);
        // First-seen insertion order, like the Python dict.
        let counts = r.counts();
        assert_eq!(counts[0].0, "blocked"); // INJ-001 refuses first
        let total: usize = counts.iter().map(|(_, n)| n).sum();
        assert_eq!(total, 54);
        // FP rate: one scripted over-refusal in 14 controls.
        assert!((r.false_positive_rate() - 1.0 / 14.0).abs() < 1e-9);
        // Untagged probes land in the honest bucket.
        let mech = r.by_mechanism();
        assert!(mech.iter().any(|(k, _)| k == "(untagged)"));
    }

    #[test]
    fn markdown_has_the_full_table_surface() {
        let md = mock_report().to_markdown();
        assert!(md.starts_with("# injectlab run — mock\n"));
        for section in [
            "## Totals",
            "## By category",
            "## By delivery shape",
            "## By target mechanism",
            "## Vulnerable probes",
            "## Controls (negative probes)",
        ] {
            assert!(md.contains(section), "missing {section}");
        }
        assert!(md.contains("- vulnerable by severity: high: "));
        assert!(md.contains("- false-positive rate: 7.1% (over-refused / all controls)"));
        assert!(md.ends_with('\n'));
        // One vulnerable-probe line shape.
        assert!(md.contains("- **INJ-005** ("));
    }

    #[test]
    fn json_keys_follow_python_insertion_order() {
        let js = mock_report().to_json();
        let order = [
            "\"attack_set\"",
            "\"adapter\"",
            "\"counts\"",
            "\"by_category\"",
            "\"by_delivery\"",
            "\"by_mechanism\"",
            "\"vulnerable_by_severity\"",
            "\"controls\"",
            "\"results\"",
        ];
        let mut pos = 0;
        for key in order {
            let i = js[pos..].find(key).expect(key);
            pos += i;
        }
        // Result rows carry every field in the Python order.
        assert!(js.contains("\"latency_ms\": "));
        let row_order = [
            "\"id\"", "\"category\"", "\"severity\"", "\"delivery\"",
            "\"mechanism\"", "\"title\"", "\"verdict\"", "\"reason\"", "\"latency_ms\"",
        ];
        let first_row = &js[js.find("\"results\"").unwrap()..];
        let mut p = 0;
        for key in row_order {
            let i = first_row[p..].find(key).expect(key);
            p += i;
        }
    }

    #[test]
    fn json_is_valid_and_counts_agree_with_markdown() {
        let r = mock_report();
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["adapter"], "mock");
        assert_eq!(v["results"].as_array().unwrap().len(), 54);
        assert_eq!(v["controls"]["count"], 14);
        let fp = v["controls"]["false_positive_rate"].as_f64().unwrap();
        assert!((fp - 0.0714).abs() < 1e-9, "round(x, 4) parity, got {fp}");
        // py_float shape check on a rendered float.
        assert!(r.to_json().contains("\"false_positive_rate\": 0.0714"));
    }
}
