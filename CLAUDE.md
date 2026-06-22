# aion-trust — working contract

aion-trust is the verifiable-résumé / human-capital trust layer — a reference implementation
of **aion-context**. It must be exemplary: people will read this code to learn how to build
on aion-context. Hold the bar accordingly. Read `README.md` and `docs/` before changing
anything substantive.

## Load-bearing invariants (never violate)

1. **NO PII ON THE LEDGER.** aion-context holds only keys, accreditation, schemas, and opaque
   claim *status*. Personal data lives ONLY in the subject's wallet and in disclosed
   presentations. If PII can reach the shared/immutable layer, the change is wrong.
   (`docs/ARCHITECTURE.md#the-privacy-model`)
2. **The subject owns the artifact.** Claims live in the wallet; disclosure is the subject's,
   audience-bound and expiring. No central store of subjects.
3. **Verification is offline and trustless.** A verifier checks a presentation against
   aion-context with no middleman — presentation binding, claim authenticity, issuer
   accreditation, and revocation/validity. All four, every time.
4. **Never hand-roll cryptography.** Signing, hashing, multisig, epochs come from aion-context.
5. **Authentic ≠ authoritative.** A valid signature from a non-accredited issuer is
   *self-asserted*, not trusted. Keep the two layers distinct.

## Code standard (Tiger Style)

- Libraries return typed errors; **no `unwrap`/`expect`/`panic!` in library code** (tests and
  binary entry points excepted).
- Functions ≤ **60 lines** (clippy `too-many-lines`). `cargo fmt` clean; `cargo clippy
  -D warnings` clean. No `#[allow]` without a one-line reason.
- Newtypes over primitives (`ClaimId`, `SubjectId`, `Epoch`). Illegal states unrepresentable.
- Dependencies earn their place; prefer std + aion-context; keep `cargo deny` green.

## The dream team — convene them, don't guess

Six expert reviewers live in `.claude/agents/`. Invoke the relevant ones (via the Task tool,
in parallel) when their area is touched, and **always before declaring a unit of work done**.
`/review` convenes the panel on the current diff.

| Agent | Owns | Convene when… |
|-------|------|---------------|
| **rivest** | cryptography & protocol security | signing, hashing, multisig, nonce/replay, disclosure |
| **lamport** | distributed correctness & trust model | registry, epochs, accreditation, revocation, verify flow |
| **saltzer** | security & privacy (NO-PII invariant) | ledger/registry/status, data flow, disclosure, logging |
| **liskov** | data abstraction & API design | core types, schemas, public APIs, module seams |
| **hoare** | correctness & testing rigor | before "done" — tests, no-panic, mutation gate |
| **graydon** | Rust craftsmanship / Tiger Style | any Rust change — idiom, errors, clippy, deps |

## Quality gates — the definition of done

A change is **done** only when `/gate` (and CI) is green. Run `scripts/gate.sh`:

1. `cargo fmt --check` — formatted.
2. `cargo clippy --all-targets --all-features -- -D warnings` — zero warnings.
3. `cargo test --all` — green.
4. `cargo deny check` — dependencies/licenses clean (if installed).
5. `cargo mutants` — **0 survivors** on changed source files (if installed). A surviving
   mutant is an untested line; it is not done.
6. `scripts/gates/pii-ledger-scan.sh` — no PII fields in ledger/registry/status code.
7. `scripts/gates/secret-scan.sh` — no secrets/keys in the tree.

A `PreToolUse` hook hard-blocks writing secrets; a `PostToolUse` hook auto-formats Rust.
Gates 6–7 also run before code exists, guarding the docs and config.

## Workflow

- Match the surrounding code; read before you write.
- For non-trivial work: implement → convene the relevant agents → fix findings → `/gate` →
  only then call it done.
- Commit/push only when asked. Branch off `main` first. Never commit secrets or runtime data
  (`aion-trust-data/`).
