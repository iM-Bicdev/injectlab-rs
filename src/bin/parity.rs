// One-shot parity harness: read cases from stdin (JSON), grade each with the
// Rust grader, print verdicts as JSON to stdout.
//
// Usage: python3 gen_cases.py | ./parity | python3 check.py
// The corpus + expected verdicts are generated from the Python original, so
// the port is judged against the implementation it claims to be.

use injectlab_rs::{grade, grade_control, Probe};
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).expect("read stdin");
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(&input).expect("cases must be a JSON array");

    let mut out = Vec::new();
    for case in &cases {
        let probe = Probe {
            id: case["probe"]["id"].as_str().unwrap().to_string(),
            success_markers: case["probe"]["markers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap().to_string())
                .collect(),
            expected: case["probe"]["expected"].as_str().unwrap().to_string(),
        };
        let response = case["response"].as_str().unwrap();
        let graded = if case["control"].as_bool().unwrap_or(false) {
            grade_control(response, &probe)
        } else {
            grade(response, &probe)
        };
        out.push(serde_json::json!({
            "id": case["id"],
            "verdict": graded.verdict,
            "reason": graded.reason,
        }));
    }
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
