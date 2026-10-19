#!/usr/bin/env python3
"""Parity judge: injectlab-rs `rundiff` vs Python `injectlab diff`.

Builds two report JSONs (real `--mock --json` output from the Python
harness, one mutated for flips/added/removed/different set labels), then
requires byte-identical markdown AND parsed-equal JSON from both
implementations. Any divergence is a bug in the port — the Python is the
reference.

Usage: python3 scripts/diff_parity.py   (cwd: injectlab-rs/)
Exit 0 on parity, 1 on divergence.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PY_HARNESS = _HERE.parent.parent / "injectlab"


def sh(cmd, cwd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"command failed: {' '.join(cmd)}\n{r.stderr}", file=sys.stderr)
        sys.exit(2)
    return r.stdout


def main():
    # 1. Baseline: the real Python mock-run JSON (full result metadata).
    old = json.loads(sh(
        [sys.executable, "-m", "injectlab.run", "--mock", "--json"],
        cwd=_PY_HARNESS,
    ))

    # 2. Mutated copy: fixes, leaks, added, removed, different set label,
    #    and one old-side result with no `mechanism` (the "?" bucket path).
    new = json.loads(json.dumps(old))
    vulns = [r for r in new["results"] if r["verdict"] == "vulnerable"]
    blocks = [r for r in new["results"] if r["verdict"] == "blocked"]
    vulns[0]["verdict"] = "blocked"      # fix
    vulns[0]["reason"] = "refusal opener detected"
    blocks[0]["verdict"] = "vulnerable"  # leak
    blocks[0]["reason"] = "success marker fired: ['api key']"
    dropped = new["results"].pop()["id"]  # removed probe
    new["results"].append({
        "id": "INJ-999", "title": "New probe", "category": "test",
        "severity": "low", "delivery": "single", "mechanism": "",
        "verdict": "blocked", "reason": "refusal opener detected",
    })
    new["attack_set"] = old["attack_set"] + " (v2)"  # set-label mismatch path
    old["results"][2].pop("mechanism")                # pre-v1.3 shape

    tmp = Path(tempfile.mkdtemp(prefix="diffparity"))
    old_p, new_p = tmp / "old.json", tmp / "new.json"
    old_p.write_text(json.dumps(old))
    new_p.write_text(json.dumps(new))

    def py(*args):
        return sh([sys.executable, "-m", "injectlab.run", "diff",
                   str(old_p), str(new_p), *args], cwd=_PY_HARNESS)

    def rs(*args):
        return sh(["cargo", "run", "--offline", "-q", "--bin", "rundiff",
                   "--", str(old_p), str(new_p), *args], cwd=_HERE.parent)

    failures = 0

    py_md, rs_md = py(), rs()
    if py_md != rs_md:
        failures += 1
        print("MARKDOWN DIVERGENCE")
        py_lines, rs_lines = py_md.splitlines(), rs_md.splitlines()
        for i, (a, b) in enumerate(zip(py_lines, rs_lines)):
            if a != b:
                print(f"  line {i+1}: py={a!r}")
                print(f"  line {i+1}: rs={b!r}")
                break
        if len(py_lines) != len(rs_lines):
            print(f"  line counts: py={len(py_lines)} rs={len(rs_lines)}")
    else:
        print(f"markdown: identical ({len(py_md)} bytes)")

    py_j, rs_j = json.loads(py("--json")), json.loads(rs("--json"))
    if py_j != rs_j:
        failures += 1
        print("JSON DIVERGENCE")
        for k in py_j:
            if py_j[k] != rs_j.get(k):
                print(f"  key {k!r}: py={json.dumps(py_j[k])[:200]}")
                print(f"  key {k!r}: rs={json.dumps(rs_j.get(k))[:200]}")
                break
    else:
        print("json: parsed-equal")

    meta = (f"fixtures: fix={vulns[0]['id']} leak={blocks[0]['id']} "
            f"removed={dropped} added=INJ-999 set-mismatch=1 missing-mechanism=1")
    print(meta)
    if failures:
        print("PARITY FAILED", file=sys.stderr)
        sys.exit(1)
    print("PARITY OK — rundiff is judged, not the implementation it claims")


if __name__ == "__main__":
    main()
