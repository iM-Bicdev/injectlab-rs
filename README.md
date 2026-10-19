# injectlab-rs

The Rust rewrite of injectlab's hottest loop — the heuristic grader — built in
public. Growth queue item #5: learn Rust by porting the part that matters.

## Why the grader?

The grader runs once per probe per model. It's the loop a scored run lives in:
harness → adapter → grader → report. It's also small enough to port *exactly*,
bugs and all, which is the whole point of the exercise — a port that changes
semantics isn't a port, it's a rewrite wearing a costume.

## Fidelity notes (grader.rs docs)

The Python grader (`injectlab/graders.py`) has known confound paths the port
keeps deliberately:

- A response that echoes the payload without a standard refusal opener grades
  **vulnerable** — the refusal check runs first and only matches openers. The
  v1.4 `injectlab lint` flags marker-in-prompt probes so scored runs watch this.
- `unclear` is a first-class citizen: heuristics flag, humans judge. False
  confidence is worse than an honest "unclear".

## The Rust-specific lesson (day one)

Python's `text[:300]` slices Unicode *code points* — it can't panic. Rust's
`&text[..300]` slices *bytes* — it panics on multi-byte chars at the boundary.
So the head-window helper walks `chars().take(300)`, not bytes. The port is
faithful to the Python semantics (300 characters, not 300 bytes), and there's
a test proving a 300-emoji wall doesn't panic.

```sh
cargo test   # break-first: tests were written before the implementation
```

## v0.3.0 — the run differ

`src/compare.rs` ports `injectlab/compare.py` (`injectlab diff`): diff two
scored runs, judged on both sides of the ledger — verdict flips probe by
probe (fixed 🟢 / leaked 🔴), vulnerable deltas by category/delivery/
severity/mechanism, and the false-positive delta. Counts are recomputed from
`results`, never trusted from the report's cached aggregates (a unit test
feeds the differ lying aggregates to prove it).

The port is judged by `scripts/diff_parity.py`: real Python `--mock --json`
output, one copy mutated (a fix, a leak, an added probe, a removed probe,
a changed attack-set label, one pre-v1.3 result with no `mechanism`), then
both implementations' `--json` and markdown outputs compared — markdown
must be byte-identical, JSON parsed-equal. It caught exactly one
divergence, and it was at the CLI layer, not the logic: Python's
`print(to_markdown())` emits a double trailing newline because
`to_markdown()` already ends with one — the Rust `rundiff` binary matches
it on purpose. Byte-fidelity means matching the reference, oddities
included.

The honest confound to record: this judge diffs two implementations of
`compare` against each other, both fed the same Python-produced inputs.
That judges the port, not the comparison logic — and the logic is the
Python author's, which is me. Self-port, self-judge; the receipts are the
byte equality.

```sh
cargo run --bin rundiff -- old.json new.json [--json]
python3 scripts/diff_parity.py   # markdown identical (1529 bytes), JSON parsed-equal
```

[Changelog note: this file documents injectlab-rs; the growth log lives in
the parent PORTFOLIO.md.]

## v0.2.0 — the mock runner

The grader alone grades nothing without a run around it. v0.2.0 ports the
scripted end-to-end run: `src/mock.rs` (the MockAdapter, 46 attack + 14
control fixtures, verbatim), `src/runner.rs` (loads probe metadata from the
sibling `injectlab/attacks/*.json` — the single source of truth, never
vendored copies — grades via the ported graders, emits a JSON report shaped
like `python -m injectlab.run --mock --json`), and `src/bin/mockrun`.

The port is judged by `scripts/mockrun_parity.py`: it runs the Python mock
run and the Rust `mockrun`, then diffs per-probe verdict **and reason**,
count rollups, control verdicts, and the FP rate. Full mock parity:
46 attack probes + 14 controls, byte-identical.

The parity harness earned its keep on day one: it caught a real port bug the
20-case v0.1.0 corpus missed — the vulnerable reason string is Python's
`str(list)`, and Python's list-repr picks *double* quotes when a marker
carries an apostrophe (`"here's a key"`, INJ-008). My naive single-quote
wrapper produced 59/60. `py_str_repr`/`py_list_repr` now port Python's repr
rules whole (quote selection, escapes, control chars), with regression
tests. Break-first means the port gets judged, not the implementation it
claims.
