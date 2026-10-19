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
