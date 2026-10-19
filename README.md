# injectlab-rs

The Rust rewrite of injectlab's hottest loop — the heuristic grader — built in
public. Growth queue item #5: learn Rust by porting the part that matters.

## Why the grader?

The grader runs once per probe per model. It's the loop a scored run lives in:
harness → adapter → grader → report. It's also small enough to port *exactly*,
bugs and all, which is the whole point of the exercise — a port that changes
semantics isn't a port, it's a rewrite wearing a costume.

## v0.5.0 — the real runner

`src/harness.rs` ports `injectlab/harness.py` (the `run()` orchestration +
`RunReport` with byte-exact `to_markdown()`/`to_dict()`), `src/models.rs`
ports `injectlab/models.py` (mock + OpenRouter + HuggingFace adapters),
`src/smoke.rs` ports `injectlab/smoke.py`, and `src/bin/run.rs` is the CLI
(`run [--mock] [--list] [--json]`, `run --openrouter MODEL`, `run --hf MODEL`,
`run smoke ...`). The judge, `scripts/run_parity.py`, requires byte-identical
output in five rounds: `--mock --json`, `--mock` markdown, `--list`,
`smoke --mock --json`, `smoke --mock` text.

Fidelity work this round:
- HTTP without dependencies: the Python original is stdlib-only (`urllib`);
  Rust's stdlib has no HTTP client, so the real adapters shell out to `curl`
  — zero new crates, same philosophy. The `-w "\n%{http_code}"` trailer is
  the status channel: the smoke classifier needs the code to tell auth-failed
  (401) from rate-limited (429), and `Http401`/`Curl28` keep that identity in
  the no-raise error string.
- `src/pyjson.rs`: a minimal insertion-ordered value type + `ensure_ascii`
  escaper emitting `json.dumps(obj, indent=2)` byte-for-byte — key order,
  2-space indent, `é` → `\u00e9`. Tally dicts preserve first-seen order like
  the Python originals; the judge compares bytes, not sets.
- `latency_ms` is the one field that can never byte-match (real wall-clock
  per probe); the judge normalizes it out and says so.
- Kept warts: the mock's `generate()` panics like the Python
  `NotImplementedError`, and `run()` dispatches on the adapter variant the
  way the original dispatches on `isinstance`.

```sh
python3 scripts/run_parity.py   # 5/5 rounds byte-identical
cargo test                      # 66/66 green
```

Scored runs still wait on the one API key — but the moment it exists, both
harnesses (Python and Rust) can spend it.

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

## v0.4.0 — the lint port

`src/lint.rs` ports `injectlab/lint.py` (`injectlab lint`), with `src/bin/lint`
as the CLI (`lint [--file SET.json] [--json]`, exit 0/1/2). The judge,
`scripts/lint_parity.py`, requires byte-identical stdout AND identical exit
codes in four rounds: default sets `--json`, default sets text mode, and a
crafted dirty set (duplicate ids, missing/empty fields, invalid taxonomy
including a null `expected`, payload whitespace, non-string prompt, missing
markers, string-valued markers, marker-in-prompt, the comply exemption,
no-fixture, stale-fixture) in both modes.

Fidelity work this round:
- `to_line()` pads by *character* count (Python's f-string widths are code
  points) — a `café` id pads 8 spaces to width 12, not 7.
- `--json` is hand-rolled `json.dumps(..., indent=2)`: key order
  `level/probe_id/check/message` (serde_json's default Map would sort keys),
  strings escaped exactly like Python's `ensure_ascii=True` — `é` → `\u00e9`,
  emoji → surrogate pairs, DEL → `\u007f`.
- A missing taxonomy key defaults to `""` (valid), a present-but-null key
  renders as `None` (invalid) — Python's `.get(key, "")` vs f-string of None.
- The judge found a real Python edge, not a port bug: a non-string probe id
  crashes the *Python* fixture sort with a TypeError, so the dirty set
  exercises the empty-string id instead.

```sh
python3 scripts/lint_parity.py   # 4/4 rounds byte-identical
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
