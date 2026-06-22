---
description: Convene the aion-trust dream team to review the current diff (or a path you name).
argument-hint: "[path or 'staged' or 'HEAD~1' — defaults to the working diff]"
---

Convene the expert panel on **$ARGUMENTS** (default: the current working diff —
`git diff` plus untracked files; if a path or git ref is given, scope to that).

Steps:

1. Gather the changes. Determine what was touched: cryptography, the trust model
   (registry/epochs/accreditation/revocation), data flow & persistence, core types/APIs,
   tests, or general Rust.
2. **Spawn the relevant reviewers in parallel** (Task tool), one per touched dimension. Send
   each only its lens; do not have one agent do everything:
   - **rivest** — if signing/hashing/multisig/nonce/disclosure changed.
   - **lamport** — if the registry/epochs/accreditation/revocation/verify-flow changed.
   - **saltzer** — if ledger/registry/status, data flow, disclosure, or logging changed
     (always run when persistence is involved — the NO-PII invariant).
   - **liskov** — if core types, schemas, or public APIs changed.
   - **hoare** — always, before declaring done: tests, no-panic, mutation gate.
   - **graydon** — on any Rust change: idiom, errors, clippy, deps.
   When unsure, convene more rather than fewer. For a docs-only change, convene **saltzer**
   (privacy framing) and **liskov** (model coherence).
3. Collect each verdict (SOUND / PII-SAFE / DONE / SHIP-SHAPE, etc.) and findings.
4. **Synthesize** into one report: a headline verdict, then findings grouped by severity
   (blocker / should-fix / nit), each with file:line and the fix. Note any disagreement
   between reviewers explicitly.
5. End with the gate status: remind to run `/gate`; a change is done only when the panel's
   blockers are cleared AND `/gate` is green.

Be adversarial, not agreeable — the panel's job is to find what's wrong before an attacker or
an auditor does.
