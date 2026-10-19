#!/usr/bin/env python3
"""all_parity.py — the one command that re-verifies the whole port.

Runs `cargo test` for the crate, then every parity judge against the Python
reference implementation:

    parity_check.py    graders (v0.1.0)
    mockrun_parity.py   scripted mock runner (v0.2.0)
    diff_parity.py     run differ (v0.3.0)
    lint_parity.py     probe-set lint (v0.4.0)
    run_parity.py      real runner: harness + adapters + smoke (v0.5.0)

Pass a subset of judge names (without .py) to run only those, e.g.
`all_parity.py lint_parity run_parity`. Unknown names fail loud — a typo must not silently
skip the thing you meant to verify.

Exit 0 iff every selected check passes; exit 1 otherwise. Exit 2 on usage
errors (bad judge name), so CI can tell "misconfigured" from "broken".

Must run from the crate root (the judges assume sibling ../injectlab).
"""

import os
import subprocess
import sys
import time

JUDGES = [
    "parity_check.py",
    "mockrun_parity.py",
    "diff_parity.py",
    "lint_parity.py",
    "run_parity.py",
]

# The individual judges fix PATH for cargo themselves (except diff_parity,
# which was repaired). The aggregator fixes it once for its own `cargo test`
# step; children inherit it.
os.environ["PATH"] = (
    os.path.expanduser("~/.cargo/bin") + os.pathsep + os.environ.get("PATH", "")
)


def run_step(name, cmd):
    """Run one check; print its banner; return (name, passed, seconds)."""
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=1200, cwd="."
        )
        passed = proc.returncode == 0
        tail = ""
        if not passed:
            out = (proc.stdout or "") + (proc.stderr or "")
            tail = "\n".join(out.splitlines()[-25:])
        return (name, passed, time.monotonic() - start, tail)
    except subprocess.TimeoutExpired:
        return (name, False, time.monotonic() - start, "TIMED OUT after 1200s")
    except OSError as e:
        return (name, False, 0.0, f"could not start: {e}")


def main(argv):
    selected = JUDGES
    if argv:
        wanted = [j for j in JUDGES if j[:-3] in argv]
        unknown = [a for a in argv if a + ".py" not in JUDGES]
        if unknown:
            print(f"all_parity: unknown judge(s): {', '.join(unknown)}")
            print(f"known: {', '.join(j[:-3] for j in JUDGES)}")
            return 2
        selected = wanted

    print("=== all_parity: full-port verification ===")
    results = []

    # 1. Rust unit tests — the crate's own contract with itself.
    print("\n--- cargo test ---")
    results.append(run_step("cargo test", ["cargo", "test", "--quiet"]))

    # 2. Parity judges — the port's contract with the Python original.
    for judge in selected:
        print(f"\n--- {judge} ---")
        results.append(run_step(judge, [sys.executable, f"scripts/{judge}"]))

    # 3. Summary. No hedging: every row is pass or fail, nothing "mostly".
    print("\n=== summary ===")
    worst = 0
    for name, passed, seconds, tail in results:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name} ({seconds:.1f}s)")
        if not passed:
            worst = 1
            if tail:
                print("  ---- tail of failing output ----")
                print("  " + tail.replace("\n", "\n  "))
                print("  ---- end tail ----")

    total = sum(s for _, _, s, _ in results)
    if worst == 0:
        print(f"\nALL GREEN: {len(results)} checks, {total:.1f}s total.")
    else:
        failed = [n for n, p, _, _ in results if not p]
        print(f"\nBROKEN: {', '.join(failed)}")
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
