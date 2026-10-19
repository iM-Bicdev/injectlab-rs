#!/usr/bin/env python3
"""run_parity.py — judge the Rust `run` CLI against the Python one.

Rounds (Python `python3 -m injectlab.run ...` vs `cargo run -q --bin run -- ...`):
  1. `--mock --json`:   byte-identical after normalizing latency_ms
  2. `--mock`:          byte-identical markdown
  3. `--list`:          byte-identical catalogue
  4. `smoke --mock --json`: byte-identical
  5. `smoke --mock`:    byte-identical text lines

`latency_ms` can never byte-match: it measures real wall-clock time per
probe, so the judge normalizes `"latency_ms": <float>` to 0.0 on both sides
before comparing. Everything else must be byte-equal — key order, indent,
escaping, markdown tables, the lot. A parity break is a port bug until
proven otherwise.

Exit 0 on parity, 1 on any mismatch.
"""

import json
import os
import re
import subprocess
import sys

CRATE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INJECTLAB = os.path.join(os.path.dirname(CRATE), "injectlab")
CARGO_ENV = {
    **os.environ,
    "PATH": os.path.expanduser("~/.cargo/bin") + os.pathsep + os.environ.get("PATH", ""),
}

LATENCY_RE = re.compile(r'"latency_ms": [0-9.eE+-]+')


def run_python(*argv):
    proc = subprocess.run(
        [sys.executable, "-m", "injectlab.run", *argv],
        cwd=INJECTLAB,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"python injectlab.run {' '.join(argv)} failed:\n{proc.stderr}")
        sys.exit(2)
    return proc.stdout


def run_rust(*argv):
    proc = subprocess.run(
        ["cargo", "run", "--offline", "--quiet", "--bin", "run", "--", *argv],
        cwd=CRATE,
        capture_output=True,
        text=True,
        env=CARGO_ENV,
    )
    if proc.returncode != 0:
        print(f"cargo run --bin run {' '.join(argv)} failed:\n{proc.stderr}")
        sys.exit(2)
    return proc.stdout


def check(name, py_out, rs_out, normalize_latency=False):
    if normalize_latency:
        py_out = LATENCY_RE.sub('"latency_ms": 0.0', py_out)
        rs_out = LATENCY_RE.sub('"latency_ms": 0.0', rs_out)
    if py_out == rs_out:
        print(f"  ok   {name}")
        return []
    # Find the first divergence for a useful report.
    py_lines, rs_lines = py_out.splitlines(), rs_out.splitlines()
    detail = f"{name}: outputs differ ({len(py_lines)} vs {len(rs_lines)} lines)"
    for i, (a, b) in enumerate(zip(py_lines, rs_lines)):
        if a != b:
            detail += f"\n  first divergence at line {i + 1}:\n    py: {a[:160]}\n    rs: {b[:160]}"
            break
    else:
        if len(py_lines) != len(rs_lines):
            longer = py_lines if len(py_lines) > len(rs_lines) else rs_lines
            detail += f"\n  length differs; extra line: {longer[min(len(py_lines), len(rs_lines))][:160]}"
    return [detail]


def main():
    print("run_parity: python -m injectlab.run  vs  cargo run --bin run")
    failures = []

    failures += check(
        "--mock --json (latency normalized)",
        run_python("--mock", "--json"),
        run_rust("--mock", "--json"),
        normalize_latency=True,
    )
    # The normalized JSON must also be *valid* and carry the full surface.
    doc = json.loads(LATENCY_RE.sub('"latency_ms": 0.0', run_rust("--mock", "--json")))
    for key in ("attack_set", "adapter", "counts", "by_category", "by_delivery",
                "by_mechanism", "vulnerable_by_severity", "controls", "results"):
        if key not in doc:
            failures.append(f"--mock --json: missing top-level key {key}")
    if len(doc["results"]) != 54:
        failures.append(f"--mock --json: expected 54 results, got {len(doc['results'])}")

    failures += check("--mock (markdown)", run_python("--mock"), run_rust("--mock"))
    failures += check("--list", run_python("--list"), run_rust("--list"))
    failures += check(
        "smoke --mock --json",
        run_python("smoke", "--mock", "--json"),
        run_rust("smoke", "--mock", "--json"),
    )
    failures += check(
        "smoke --mock",
        run_python("smoke", "--mock"),
        run_rust("smoke", "--mock"),
    )

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("parity holds.")


if __name__ == "__main__":
    main()
