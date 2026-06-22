---
description: Run the aion-trust quality gates (the definition of done) and report.
allowed-tools: Bash(scripts/gate.sh), Bash(./scripts/gate.sh), Bash(bash scripts/gate.sh)
---

Run the full quality-gate suite and report the result.

1. Execute `bash scripts/gate.sh`.
2. Summarize each gate (passed / failed / skipped) in a short table.
3. If any gate FAILED, list the specific failures with the file:line or output that caused
   them, and propose the minimal fix for each. Do not call the work done until the gate is green.
4. If gates were skipped because no Rust workspace exists yet, say so plainly — the doc and
   secret gates still apply.

The bar (see `CLAUDE.md`): fmt clean · clippy `-D warnings` clean · tests green · `cargo deny`
clean · `cargo mutants` **0 survivors** on changed files · no PII in ledger/registry/status ·
no secrets in the tree.
