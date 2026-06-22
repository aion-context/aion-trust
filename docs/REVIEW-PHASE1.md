# Phase 1 — dream-team review & dispositions

The Phase 1 kernel was reviewed by the expert panel (`.claude/agents/`). This records their
verdicts, what was **fixed in Phase 1**, and what is **tracked for later** — so nothing is
silently dropped.

## Verdicts

- **lamport (correctness): SOUND** for what Phase 1 enforces. Confirmed under adversarial
  interleaving: a claim issued to Alice cannot be accepted in Bob's presentation; no
  expiry/validity boundary slips (closed intervals); the accept decision is a pure function
  of the artifact + inputs.
- **rivest (crypto): mostly sound.** Confirmed: domain separation (claim vs presentation),
  verify-before-trust ordering, no `claim_id` circularity, private keys never serialized,
  `SigningWriter` length-prefixing prevents collisions.
- **saltzer (privacy): PII-SAFE.** PII is isolated to `Claim.body`/`VerifiedClaim`; error and
  detail strings carry only DIDs/claim_ids; verification is default-deny.
- **liskov (types): the `VerifiedClaim` typestate is exemplary.** Body unreachable without a
  passed signature check.

## Fixed in Phase 1 (this review)

| Finding | Reviewer | Fix |
|---------|----------|-----|
| `body_hash` was an **unsalted** hash of low-entropy PII → guess-and-confirm re-identification | saltzer F1 | Added a random per-claim `salt`; `body_hash` is now a salted, **canonical** (domain-separated, length-prefixed) commitment via `SigningWriter` — a *hiding* commitment, reproducible across serializers (also closes rivest H1's non-canonical-JSON concern) |
| **DID truncated to 16 bytes** (64-bit collision) | rivest M1 | Widened to 24 bytes (~96-bit collision resistance) |
| **Empty-claims presentation was accepted** (misreadable as "proved something") | lamport G2 | Added a `discloses at least one claim` check |
| **Weak/short nonce** silently defeats replay protection | rivest H2, liskov | Verifier requires `nonce ≥ 16 bytes`; CLI emits a 24-byte nonce |
| `accepted` could be misread as **authoritative** when Phase 1 only proves **authentic + recognized** | lamport, saltzer | Documented `VerificationReport` semantics explicitly; the check is named `issuer recognized` (not "accredited") |

All fixes are covered by tests (the mutation gate stays at **0 survivors**).

## Tracked for Phase 2 (type hardening)

- **`VerifiedPresentation` typestate** (liskov #2, highest-leverage): `verify_presentation`
  should return `Accepted(VerifiedPresentation) | Rejected(report)` so `accepted: bool` cannot
  be ignored — mirroring `VerifiedClaim`. Carry `Vec<VerifiedClaim>`, not `Vec<Claim>`.
- **`ClaimBody` enum** (liskov #3): fuse claim type + body + schema into one sum type so a
  `ClaimType::Education` claim cannot carry an `EmploymentBody`, and the verifier needs no
  per-type `match`. Do this as the first step of adding claim type #2 (it gets harder later).
- **Role-typed ids** (liskov #5): `SubjectId`/`IssuerId` newtypes over `Did` so subject/issuer
  cannot be transposed. Newtype `body_hash`/signatures (always fixed-width hex) too.
- **Per-field commitments** (saltzer F3): re-shape the salted body commitment into per-field
  (Merkleized) form so Phase 4 selective disclosure can open one field without the rest.

## Tracked for Phase 3 (federation & status) — deferred by design

- **Accreditation** (issuer *authority*, K-of-N) — Phase 1 checks only that an issuer is
  *recognized* (in the verifier's directory), not *accredited*. lamport & saltzer both note a
  green Phase-1 result is "authentic", never "authoritative".
- **Revocation / validity status** — no revocation check yet; a revoked claim would verify.
- **`LedgerRecord` type** (saltzer F2, do before any ledger writer): introduce the non-PII
  `{claim_id, status, epoch}` as the *only* ledger-facing type, so full-`Claim` serialization
  to the immutable layer cannot typecheck. The salt fix (above) is the other half — it makes
  the on-ledger `claim_id` a hiding commitment, so right-to-erasure genuinely survives.

## Notes on the holder-binding model (not a bug)

rivest raised that the presentation is *self-authenticating* (the verifying key comes from the
artifact). This is the **correct** verifiable-credential holder-binding model: the claims are
issuer-signed to a specific subject DID, and the presentation proves control of that DID's key.
lamport independently confirmed no claim can be re-targeted across subjects. A use case that
needs a pre-known subject identity can pin the subject DID at the verifier — a Phase 2 option.
