# Roadmap

Phased like the aion-edu reference implementation: a thin cryptographic spine first, then
claim breadth, then the surfaces that make it tangible. Each phase is independently
demonstrable.

## Phase 0 — Architecture  ✅ (this repository)

The founding design: vision, actors, the privacy model, the data model, the workflows, the
trust model. Establishes the load-bearing decisions (no PII on the ledger; subject-owned
artifacts; offline, middleman-free verification) before any code.

## Phase 1 — The kernel

The spine on aion-context. One claim type end to end.

- `aion-trust-core`, `aion-trust-claims`: identity, the `Claim` object, issuer signing and
  offline verification via aion-context.
- A single category (`employment`) proven end to end: issue → store → present → verify.
- CLI: `issue`, `present`, `verify`.
- **Demo:** an employment claim issued, presented, and verified offline — with a tampered
  body and a wrong subject both correctly rejected.

## Phase 2 — Claims, wallet & reuse  ✅

Breadth and the money workflow.

- The full claim set: `education` (incl. aion-edu import), `certification`,
  `background_check`, `identity`, `reference`, `skill`.
- `aion-trust-wallet`: the subject's Trust Profile, claim store, and Presentation builder.
- The **run-once / reuse-many** background-check workflow, demonstrated across two employers.
- Key succession + a first recovery policy.

## Phase 3 — Accreditation & federation  ✅

Authority, not just authenticity.

- `aion-trust-registry`: issuer registration, accreditation records, **K-of-N** for
  high-assurance categories, epoch-scoped revocation.
- Verifier reports the two-layer result (authentic / accredited) and lets a verifier choose
  which accreditors it honors.
- **Demo:** a background-check provider accredited 2-of-2; an un-accredited "employer" claim
  correctly shown as self-asserted; an accreditation lapse flipping a prior green to amber.

## Phase 4 — Selective disclosure  ✅

Privacy as a feature.

- Field-level disclosure (Merkleized claim bodies) so a Presentation can reveal
  `{institution, credential}` without the rest, signature still intact — with the field set
  fixed by the signed category so a maliciously omitted field is detectable.
- Audience/nonce/expiry binding hardened; a single-use nonce store proves anti-replay
  (recorded only on accept; cross-audience, post-expiry, and reuse all rejected).
- Path-finding for predicate proofs ("degree ≥ bachelor's", "check < 12 months old").
  **Caveat:** these are *data minimization, not zero-knowledge* — the coarse, issuer-attested
  attribute is revealed (aion-context has no range primitive; invariant #4 forbids hand-rolling
  one). The types are shaped so a real ZK proof can drop in without a wire change.

## Phase 5 — The surfaces  ✅

Make it real, the way aion-edu's web app did.

- `aion-trust-web` (axum): an **issuer console**, a **candidate wallet**, and an **employer
  verifier**, served as one local app (`aion-trust serve`).
- A live walkthrough: issue a claim → candidate presents it → employer verifies instantly
  (green) → the issuer revokes → the same claim now fails (red), streamed over SSE.
- **Local single-operator demo** — loopback-bound, in-memory, no persistence; the wallet would
  move to the subject's device in production. See [`WEB-SURFACES.md`](WEB-SURFACES.md).

## Phase 6 — Interop & cost model

Connect outward and quantify the pitch.

- `docs/INTEROP.md` + export/import for **W3C Verifiable Credentials / DIDs**, so artifacts
  travel beyond this implementation.
- `docs/COST-MODEL.md`: a parameterized model (checks per hire, fee per check, HR hours,
  bad-hire rate) turning the savings thesis into numbers.
- `docs/COMPLIANCE.md`: mapping to FCRA, EEOC, GDPR/CCPA, NIST 800-63.

---

### Beyond hiring

Once the kernel and disclosure model are solid, the same machinery extends to licensure,
tenancy, KYC/finance, and right-to-work — the **portable, person-owned identity layer** the
vision points at. Those are new claim categories and accreditor sets, not new architecture.
