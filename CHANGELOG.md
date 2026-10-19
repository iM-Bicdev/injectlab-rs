# injectlab-rs — CHANGELOG

The Rust port of [injectlab](../injectlab) (`../injectlab`), judged by the
parity harnesses in `scripts/`, not by vibes. A parity break is a port bug
until proven otherwise.

## v0.7.0 — the gray-case port
- Default set bumped to injectlab **v1.4**: 8 new gray-case probes (INJ-047..054),
  new category `gray-case`, new `channel-trust` mechanism (models reasoning from
  channel-trust priors instead of the instruction's authority chain — the failure
  field note 001 caught a frontier model making in the wild).
- Mock fixtures ported fixture-for-fixture (4 scripted vulnerable / 4 resisted);
  `ATTACK_FIXTURES` count assertion 46 → 54.
- `src/lint.rs`: `MECHANISMS` allowlist gains `channel-trust` (mirrors the
  `lint.py` taxonomy fix) — the parity judge caught the drift before it shipped.
- Judges updated to the v1.4 set: `mockrun_parity.py` pins `attack-set-v1.4.json`;
  `run_parity.py` result-count assertion 46 → 54.
- Rust unit-test count assertions updated 46 → 54 (runner, harness, mock);
  `mock_run_grades_all_sixty_probes` renamed to `mock_run_grades_all_sixty_eight_probes`.
- 66/66 tests green; `all_parity.py`: 6/6 PASS — the port still agrees with
  Python byte-for-byte on the bigger set.

## v0.6.0 — one verification command
- New: `scripts/all_parity.py` — `cargo test` + all five judges in one command,
  subset-selectable (`all_parity.py lint run`), exit 2 on unknown judge names
  so a typo can't silently skip verification. The CI entry point.
- New: this CHANGELOG.

## v0.5.0 — the real runner
- `src/harness.rs`: port of `injectlab/harness.py` — `run()` orchestration +
  `RunReport` with byte-exact `to_markdown()`/`to_dict()`.
- `src/models.rs`: port of `injectlab/models.py` — mock + OpenRouter +
  HuggingFace adapters. HTTP via `curl` subprocess (Rust's stdlib has no HTTP
  client) — zero new crates, same stdlib-only philosophy. No-raise transport
  contract kept.
- `src/smoke.rs`: port of `injectlab/smoke.py` — canary + classifier.
- `src/bin/run.rs`: CLI parity with `injectlab run` / `injectlab smoke`.
- `src/pyjson.rs`: shared insertion-ordered `JVal` emitting
  `json.dumps(obj, indent=2)` byte-for-byte.
- Judge `scripts/run_parity.py`: 5/5 rounds byte-identical
  (`latency_ms` normalized — real wall-clock, can never byte-match).
- 66/66 tests green. Older judges re-run clean.

## v0.4.0 — the lint port
- `src/lint.rs`: port of `injectlab/lint.py` — all checks in check order,
  `to_line()` pads by character count (Python f-string widths are code
  points), hand-rolled `json.dumps(indent=2)` with `ensure_ascii` escaping,
  missing taxonomy key → `""` vs present-null → `None`.
- `src/bin/lint`: CLI parity (`--file/--json`, exit 0/1/2).
- Judge `scripts/lint_parity.py`: 4/4 rounds byte-identical stdout + exit codes.
- 42/42 tests green.

## v0.3.0 — the run differ
- `src/compare.rs`: port of `injectlab/compare.py` — verdict flips, counts
  recomputed from results (never trusted from cached aggregates), deltas by
  category/delivery/severity/mechanism, FP-rate delta, markdown byte-faithful.
- `src/bin/rundiff`: `rundiff old.json new.json [--json]`.
- Judge `scripts/diff_parity.py`: markdown identical (1529 bytes), JSON
  parsed-equal.
- 35/35 tests green.

## v0.2.0 — the mock runner
- `src/mock.rs`: MockAdapter, fixture-for-fixture (46 attack + 14 control
  scripted fixtures); `generate()` panics loud like `NotImplementedError`.
- `src/runner.rs`: probe metadata read live from the sibling
  `injectlab/attacks/*.json` — single source of truth, no vendored copies.
- `src/bin/mockrun`: the scripted end-to-end run binary.
- Judge `scripts/mockrun_parity.py`: 60/60 byte-identical (verdicts + reasons
  + rollups + FP rate). Caught a real port bug: Python's `str(list)` picks
  double quotes when a marker carries an apostrophe — fixed by porting
  Python's repr rules whole (`py_str_repr`/`py_list_repr`).
- 24/24 tests green.

## v0.1.0 — the grader
- Port of `injectlab/graders.py`: `is_refusal` / `followed_injection` /
  `grade` / `grade_control` — known confounds kept, not fixed.
- Lesson documented in code: Python's `text[:300]` slices code points,
  Rust's `&text[..300]` slices bytes — the head window walks
  `chars().take(300)`; a 300-emoji-wall test proves it.
- Judge `scripts/parity_check.py`: 20/20 cases byte-identical.
- 13/13 tests green.
