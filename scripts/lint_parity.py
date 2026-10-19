#!/usr/bin/env python3
"""lint_parity.py — judge the Rust lint port against the Python one.

Runs:
    python3 -m injectlab.run lint [--file ...] [--json]   (in ../injectlab)
    cargo run --quiet --bin lint -- <same args>            (in this crate)

and requires byte-identical stdout AND identical exit codes in four rounds:
1. default sets, --json
2. default sets, text mode (exercises to_line padding + summarize)
3. a crafted dirty set, --file --json
4. the dirty set, --file, text mode

The dirty set exercises every check: duplicate ids, missing/empty required
fields, non-string id, invalid taxonomy (incl. a null expected, which
renders as 'None'), prompt whitespace, non-string prompt, missing markers,
markers given as a string (Python iterates its chars), marker-in-prompt,
the comply exemption, no-fixture, and stale-fixture (all 14 control fixture
ids are stale by design since the set is control-shaped).

A parity break is a port bug until proven otherwise — break-first means the
port gets judged, not the implementation it claims.
Exit 0 on parity, 1 on any mismatch.
"""

import json
import os
import subprocess
import sys
import tempfile

CRATE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INJECTLAB = os.path.join(os.path.dirname(CRATE), "injectlab")


def run_python(args):
    proc = subprocess.run(
        [sys.executable, "-m", "injectlab.run", "lint"] + args,
        cwd=INJECTLAB,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout


def run_rust(args):
    proc = subprocess.run(
        ["cargo", "run", "--quiet", "--bin", "lint", "--"] + args,
        cwd=CRATE,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": os.path.expanduser("~/.cargo/bin") + os.pathsep + os.environ.get("PATH", "")},
    )
    return proc.returncode, proc.stdout


def valid_probe(pid, **kw):
    probe = {
        "id": pid,
        "category": "x",
        "severity": "high",
        "title": "t",
        "prompt": "a clean payload with nothing suspicious",
        "injected_goal": "g",
        "expected": "refuse",
        "success_markers": ["zz-no-such-marker"],
    }
    probe.update(kw)
    return probe


def dirty_set_path():
    probes = [
        # duplicate id: first occurrence clean, second reports duplicate-id.
        valid_probe("DUP-001"),
        valid_probe("DUP-001"),
        # missing required field.
        {k: v for k, v in valid_probe("MIS-001").items() if k != "title"},
        # empty-string required field.
        valid_probe("EMP-001", title=""),
        # non-string id -> pid "(unknown-id)". (A genuinely non-string id
        # would crash Python's fixture sorting with a TypeError, so the
        # judge only exercises the empty-string case.)
        valid_probe("", prompt="payload"),
        # invalid taxonomy.
        valid_probe("TAX-001", severity="critical"),
        # null expected renders as 'None' in the taxonomy message.
        valid_probe("TAX-002", expected=None),
        # prompt whitespace.
        valid_probe("WS-001", prompt="  padded payload  "),
        # non-string prompt.
        valid_probe("NSTR-001", prompt=12345),
        # missing markers.
        {k: v for k, v in valid_probe("NM-001").items() if k != "success_markers"},
        # marker lives in the payload -> marker-in-prompt.
        valid_probe("MIP-001", prompt="repeat after me: zz-no-such-marker", expected="refuse"),
        # comply exemption: marker in prompt, NO marker-in-prompt finding.
        # (Also makes the set control-shaped -> control fixture ids.)
        valid_probe("MIP-002", prompt="repeat after me: zz-no-such-marker", expected="comply"),
        # markers as a string: Python iterates its characters; 'a' and 'b'
        # appear in the payload, 'z' does not.
        valid_probe("STR-001", prompt="ab payload", success_markers="az"),
        # no mock fixture (control fixtures cover CTRL-001..014 only).
        valid_probe("NOF-001"),
    ]
    fd, path = tempfile.mkstemp(prefix="lint-dirty-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"probes": probes}, fh)
    return path


def check(name, args):
    py_code, py_out = run_python(args)
    rs_code, rs_out = run_rust(args)
    problems = []
    if py_code != rs_code:
        problems.append(f"exit code: python={py_code} rust={rs_code}")
    if py_out != rs_out:
        problems.append("stdout differs")
        py_lines, rs_lines = py_out.splitlines(), rs_out.splitlines()
        for i, (a, b) in enumerate(zip(py_lines, rs_lines)):
            if a != b:
                problems.append(f"  first diff at line {i}:")
                problems.append(f"    python: {a!r}")
                problems.append(f"    rust:   {b!r}")
                break
        if len(py_lines) != len(rs_lines):
            problems.append(f"  line counts: python={len(py_lines)} rust={len(rs_lines)}")
    if problems:
        print(f"MISMATCH [{name}] args={args}")
        for p in problems:
            print(p)
        return False
    print(f"OK [{name}] ({len(py_out.splitlines())} lines, exit {py_code})")
    return True


def main():
    ok = True
    ok &= check("default-json", ["--json"])
    ok &= check("default-text", [])
    dirty = dirty_set_path()
    try:
        ok &= check("dirty-json", ["--file", dirty, "--json"])
        ok &= check("dirty-text", ["--file", dirty])
    finally:
        os.unlink(dirty)
    print("PARITY OK" if ok else "PARITY FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
