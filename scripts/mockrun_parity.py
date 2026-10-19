#!/usr/bin/env python3
"""mockrun_parity.py — judge the Rust mock runner against the Python one.

Runs:
    python3 -m injectlab.run --mock --json      (in ../injectlab)
    cargo run --quiet --bin mockrun             (in this crate)

and diffs them: every attack probe id and every control id must carry the
same verdict AND the same reason string, and the count rollups + FP rate
must match. A parity break is a port bug until proven otherwise —
break-first means the port gets judged, not the implementation it claims.
Exit 0 on parity, 1 on any mismatch.
"""

import json
import subprocess
import sys
import os

CRATE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INJECTLAB = os.path.join(os.path.dirname(CRATE), "injectlab")


def run_python():
    # Inline driver: the CLI's --mock --json output has no per-control
    # result rows, but report.controls does — emit them so the parity check
    # is byte-identical on controls too, not just rollups.
    driver = (
        "import json\n"
        "from injectlab import harness, load_attack_set, MockAdapter\n"
        "from injectlab.run import MOCK_FIXTURE, MOCK_CONTROL_FIXTURE\n"
        "attack_set = load_attack_set('attacks/attack-set-v1.3.json')\n"
        "control_set = load_attack_set('attacks/control-set-v1.1.json')\n"
        "report = harness.run(attack_set, "
        "MockAdapter({**MOCK_FIXTURE, **MOCK_CONTROL_FIXTURE}), "
        "controls=control_set)\n"
        "d = report.to_dict()\n"
        "d['controls']['results'] = [\n"
        "    {'id': r.probe_id, 'verdict': r.verdict, 'reason': r.reason}\n"
        "    for r in report.controls\n"
        "]\n"
        "print(json.dumps(d))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", driver],
        cwd=INJECTLAB,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"python mock run failed:\n{proc.stderr}")
        sys.exit(2)
    return json.loads(proc.stdout)


def run_rust():
    proc = subprocess.run(
        ["cargo", "run", "--quiet", "--bin", "mockrun"],
        cwd=CRATE,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": os.path.expanduser("~/.cargo/bin")
             + os.pathsep + os.environ.get("PATH", "")},
    )
    if proc.returncode != 0:
        print(f"rust mockrun failed:\n{proc.stderr}")
        sys.exit(2)
    return json.loads(proc.stdout)


def main():
    py = run_python()
    rs = run_rust()
    failures = []

    py_results = {r["id"]: r for r in py["results"]}
    rs_results = {r["id"]: r for r in rs["results"]}
    if set(py_results) != set(rs_results):
        failures.append(
            f"id sets differ: py-only {set(py_results) - set(rs_results)}, "
            f"rs-only {set(rs_results) - set(py_results)}"
        )
    for pid in sorted(set(py_results) & set(rs_results)):
        a, b = py_results[pid], rs_results[pid]
        if (a["verdict"], a["reason"]) != (b["verdict"], b["reason"]):
            failures.append(
                f"{pid}: py=({a['verdict']}, {a['reason']!r}) "
                f"rs=({b['verdict']}, {b['reason']!r})"
            )

    py_ctrl = {r["id"]: r for r in py["controls"].get("results", [])}
    rs_ctrl = {r["id"]: r for r in rs["controls"]["results"]}
    if set(py_ctrl) != set(rs_ctrl):
        failures.append("control id sets differ")
    for pid in sorted(set(py_ctrl) & set(rs_ctrl)):
        a, b = py_ctrl[pid], rs_ctrl[pid]
        if (a["verdict"], a["reason"]) != (b["verdict"], b["reason"]):
            failures.append(f"{pid}: py=({a['verdict']}) rs=({b['verdict']})")

    if py["counts"] != rs["counts"]:
        failures.append(f"attack counts differ: py={py['counts']} rs={rs['counts']}")
    if py["controls"]["verdicts"] != rs["controls"]["verdicts"]:
        failures.append(
            f"control verdicts differ: py={py['controls']['verdicts']} "
            f"rs={rs['controls']['verdicts']}"
        )
    if abs(py["controls"]["false_positive_rate"]
           - rs["controls"]["false_positive_rate"]) > 1e-9:
        failures.append(
            f"FP rate differs: py={py['controls']['false_positive_rate']} "
            f"rs={rs['controls']['false_positive_rate']}"
        )

    if failures:
        print(f"MOCK PARITY FAILED — {len(failures)} mismatches:")
        for f in failures:
            print(f"  {f}")
        return 1
    n = len(py_results)
    print(
        f"MOCK PARITY OK — {n} attack probes + {len(rs_ctrl)} controls, "
        f"verdicts and reasons byte-identical, counts + FP rate match."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
