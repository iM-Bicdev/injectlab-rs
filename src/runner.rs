//! The mock runner: probe metadata comes from the sibling injectlab
//! attack-set JSONs — the single source of truth, read live, never vendored.
//! Vendored copies drift; `injectlab lint` already hunts fixture drift on the
//! Python side, and reading the same files keeps the port honest by default.
//!
//! Pipeline: load sets -> mock fixtures -> ported graders -> report shaped
//! like the Python `python -m injectlab.run --mock --json` output (minus
//! latency_ms — a scripted adapter has no meaningful latency, and inventing
//! one would be fiction).
//!
//! What the report does NOT carry (deliberately): by_category / by_delivery /
//! by_mechanism breakdowns. Those are presentation on top of graded results;
//! v0.2.0 ports the graded run first, and the script `mockrun_parity.py`
//! judges it against the Python implementation it claims to be.

use std::collections::HashMap;

use serde_json::Value;

use crate::mock::MockAdapter;
use crate::{grade, grade_control, Probe};

/// Probe metadata, trimmed to what grading reads. (Mirrors the Python
/// `Probe` fields the graders consume: id, success_markers, expected.)
pub struct ProbeMeta {
    pub id: String,
    pub success_markers: Vec<String>,
    pub expected: String,
}

impl ProbeMeta {
    fn as_probe(&self) -> Probe {
        Probe {
            id: self.id.clone(),
            success_markers: self.success_markers.clone(),
            expected: self.expected.clone(),
        }
    }
}

/// Load one attack/control set JSON by reading only the grading fields.
/// Missing keys are an error, not a guess — a probe without an expectation
/// or markers is a confounded experiment.
pub fn load_set(path: &str) -> Result<Vec<ProbeMeta>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read {path}: {e}"))?;
    let doc: Value =
        serde_json::from_str(&text).map_err(|e| format!("parse {path}: {e}"))?;
    let probes = doc
        .get("probes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}: no 'probes' array"))?;
    probes
        .iter()
        .map(|p| {
            let id = p
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{path}: probe without id"))?
                .to_string();
            let expected = p
                .get("expected")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{id}: no expected verdict"))?
                .to_string();
            let markers = p
                .get("success_markers")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{id}: no success_markers"))?;
            let mut success_markers = Vec::with_capacity(markers.len());
            for m in markers {
                success_markers.push(
                    m.as_str()
                        .ok_or_else(|| format!("{id}: non-string success marker"))?
                        .to_string(),
                );
            }
            Ok(ProbeMeta {
                id,
                success_markers,
                expected,
            })
        })
        .collect()
}

/// One graded row.
pub struct RunResult {
    pub id: String,
    pub verdict: String,
    pub reason: String,
}

/// The graded mock run: attack results + control results.
pub struct MockReport {
    pub attack: Vec<RunResult>,
    pub controls: Vec<RunResult>,
}

impl MockReport {
    fn tally(results: &[RunResult]) -> HashMap<String, usize> {
        let mut out = HashMap::new();
        for r in results {
            *out.entry(r.verdict.clone()).or_insert(0) += 1;
        }
        out
    }

    /// Verdict counts over the attack probes (mirrors Report.counts()).
    pub fn counts(&self) -> HashMap<String, usize> {
        Self::tally(&self.attack)
    }

    /// Verdict counts over the negative controls (mirrors control_counts()).
    pub fn control_counts(&self) -> HashMap<String, usize> {
        Self::tally(&self.controls)
    }

    /// Share of benign controls the mock over-refused. None ran -> 0.0
    /// (mirrors false_positive_rate()).
    pub fn false_positive_rate(&self) -> f64 {
        if self.controls.is_empty() {
            return 0.0;
        }
        self.control_counts().get("over-refusal").copied().unwrap_or(0) as f64
            / self.controls.len() as f64
    }

    /// Report as JSON, shaped like the Python `--mock --json` to_dict()
    /// (attack results + control rollup; no latency_ms — see module docs).
    pub fn to_json(&self) -> Value {
        let results: Vec<Value> = self
            .attack
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "verdict": r.verdict,
                    "reason": r.reason,
                })
            })
            .collect();
        serde_json::json!({
            "adapter": "mock",
            "counts": self.counts(),
            "results": results,
            "controls": {
                "count": self.controls.len(),
                "verdicts": self.control_counts(),
                "false_positive_rate": (self.false_positive_rate() * 10_000.0).round() / 10_000.0,
                "results": self.controls.iter().map(|r| serde_json::json!({
                    "id": r.id,
                    "verdict": r.verdict,
                    "reason": r.reason,
                })).collect::<Vec<_>>(),
            },
        })
    }
}

/// Run every probe in both sets against the scripted mock adapter.
pub fn run_mock(attack_set_path: &str, control_set_path: &str) -> Result<MockReport, String> {
    let adapter = MockAdapter::new();

    let attack: Vec<RunResult> = load_set(attack_set_path)?
        .iter()
        .map(|meta| {
            let response = adapter.generate_for(&meta.id);
            let g = grade(response, &meta.as_probe());
            RunResult {
                id: meta.id.clone(),
                verdict: g.verdict,
                reason: g.reason,
            }
        })
        .collect();

    let controls: Vec<RunResult> = load_set(control_set_path)?
        .iter()
        .map(|meta| {
            let response = adapter.generate_for(&meta.id);
            let g = grade_control(response, &meta.as_probe());
            RunResult {
                id: meta.id.clone(),
                verdict: g.verdict,
                reason: g.reason,
            }
        })
        .collect();

    Ok(MockReport { attack, controls })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> String {
        env!("CARGO_MANIFEST_DIR").to_string()
    }

    fn set_paths() -> (String, String) {
        (
            format!("{}/../injectlab/attacks/attack-set-v1.4.json", manifest()),
            format!("{}/../injectlab/attacks/control-set-v1.1.json", manifest()),
        )
    }

    #[test]
    fn loads_both_real_sets() {
        let (a, c) = set_paths();
        assert_eq!(load_set(&a).unwrap().len(), 54);
        assert_eq!(load_set(&c).unwrap().len(), 14);
    }

    #[test]
    fn missing_file_is_an_error_not_a_guess() {
        assert!(load_set("/nonexistent/set.json").is_err());
    }

    #[test]
    fn every_fixture_id_exists_in_a_set() {
        // Fixture drift is the failure mode: a fixture for a probe that no
        // longer exists silently grades nothing. Fail loud.
        let (a, c) = set_paths();
        let attack = load_set(&a).unwrap();
        let control = load_set(&c).unwrap();
        let known: std::collections::HashSet<&str> = attack
            .iter()
            .chain(control.iter())
            .map(|p| p.id.as_str())
            .collect();
        let adapter = MockAdapter::new();
        for id in ["INJ-001", "INJ-046", "CTRL-001", "CTRL-014"] {
            assert!(known.contains(id), "{id} fixture has no probe");
            assert_ne!(
                adapter.generate_for(id),
                crate::mock::UNKNOWN_FIXTURE,
                "{id} has no fixture"
            );
        }
    }

    #[test]
    fn mock_run_grades_all_sixty_eight_probes() {
        let (a, c) = set_paths();
        let report = run_mock(&a, &c).unwrap();
        assert_eq!(report.attack.len(), 54);
        assert_eq!(report.controls.len(), 14);
        // The mock is scripted to exercise every attack verdict.
        let counts = report.counts();
        for v in ["blocked", "resisted", "vulnerable", "unclear"] {
            assert!(
                counts.get(v).copied().unwrap_or(0) > 0,
                "verdict {v} not exercised"
            );
        }
        // One scripted over-refusal: FP rate 1/14.
        assert!((report.false_positive_rate() - 1.0 / 14.0).abs() < 1e-9);
    }
}
