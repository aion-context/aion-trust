# Dependency-aware trust — issuer-committed reliance

aion-trust revokes **point-wise**: an issuer flips one `claim_id` to `revoked`, and that one
claim fails everywhere ([`TRUST-MODEL.md`](TRUST-MODEL.md#revocation--validity)). But a claim's
trustworthiness often *rests on other facts*:

- a `background_check` "clear" was performed against a verified `identity`;
- a `reference` rests on the referee's own `identity`;
- an aion-edu–*assessed* `skill` rests on the assessor's accreditation;
- a renewed `certification` rests on its predecessor.

When a load-bearing fact is later revoked, nothing connects it to the claims that relied on it —
the threat-model row *"issuer compromised / mistaken → revocation"* has no computable reach into
the claims that stood on the thing that fell. This document adds that reach **without a new
shared-ledger structure** and without weakening any of the five invariants.

> **Design note.** A first draft recorded reliance as a signed `claim_id → claim_id` edge *on the
> aion-context ledger*. The Phase-7 review panel (lamport, saltzer, rivest) rejected it: a
> traversable graph on the shared, immutable ledger breaks **complete mediation** (one held
> `claim_id` becomes a lever into the subject's *undisclosed* claims), leaks claim *type*,
> destroys **erasure**, and leaves same-issuer authority cryptographically unenforced (reliance
> injection). The design below is the correction. It reuses the Phase-4 Merkleized-body machinery
> instead of inventing a ledger object.

## Reliance is an issuer commitment, not a ledger edge

At issue time, **B's issuer commits to B's reliance set inside B's signed claim**, exactly the way
it already commits to the body:

```json
// added to the Claim (see DATA-MODEL.md) — signed by the issuer, PII-free.
// BOTH fields are MANDATORY and signed; count=0 with reliance_root=EMPTY_ROOT is the
// *signed* "no reliance declared" state — never "absent" (an absent field is a strip vector).
"reliance_root":  "blake3:…",   // Merkle root over the per-index tagged reliance leaves
"reliance_count": 1,            // number of reliance leaves; signed, pins the set shape
```

Each reliance leaf commits one dependency at a fixed index, **domain-tagged and index-bound** so
it cannot be swapped, reordered, duplicated, or confused with a body-field leaf:

```
leaf_i = H("aion-trust/reliance-leaf/v1" ‖ i ‖ salt_i ‖ from_claim_id ‖ kind_commit_i)
salt_i = KDF(master_salt, "reliance", i)                       // per-index, from the claim master salt
kind_commit_i = H("aion-trust/reliance-kind/v1" ‖ kind_salt_i ‖ kind)   // separately-salted sub-commitment
```

`from_claim_id` is disclosed whenever the leaf is proven (the fifth check needs it to read the
target's status). **`kind` is a separate sub-commitment**, so a bare revocation check reveals only
*which* claim was relied upon, not *why* — the subject opens `kind` only when it wants the
provenance story (§ what it delivers). The leaves live **only in the subject's wallet**.
`reliance_root`/`reliance_count` are folded into the bytes the issuer already signs, under the
claim's versioned domain tag and canonical encoding —
`Ed25519.sign(H("aion-trust/claim/v1" ‖ CANON{…,body_root,field_count,reliance_root,reliance_count,…}))`
— so reliance inherits the claim signature's domain separation; no new signed structure, no new
primitive (invariant #4). Whether a claim carries reliance is pinned by its signed `schema_id`
version, so a legacy (pre-Phase-7) claim is unambiguously `count=0` and cannot be spoofed either
way. A verifier accepts the disclosed set only if it presents **exactly** leaves `0..count-1`,
each with a valid audit path to the signed `reliance_root`.

**The shared ledger is unchanged.** It still holds only issuer/accreditor keys, accreditation, and
point-wise `{claim_id, status, epoch}`. No reliance topology, no `kind`, no graph reaches the
immutable layer (invariant #1). Erasing a claim from the wallet leaves nothing behind but its
non-PII status record — erasure survives (`ARCHITECTURE.md`).

## Disclosure — the subject reveals reliance, and cannot hide it

Reliance travels the way a field does. In a Presentation, the subject discloses B's reliance
targets as leaves proven against the issuer-signed `reliance_root` by an audit path — and
`reliance_count` **fixes the set**, so a maliciously *omitted* target is detectable exactly as a
withheld body field is ([`TRUST-MODEL.md`](TRUST-MODEL.md#selective-disclosure)). The subject
chooses *which claims to present*; it cannot silently drop a reliance the issuer committed.

- **Same-issuer authority is inherent.** Reliance is signed by **B's own issuer** as part of B's
  claim. There is no free-floating edge for a third party to forge onto B, and no self-declared
  `issuer_id` to select a verification key from — the *reliance-injection* attack is structurally
  impossible.
- **No strip attack.** `reliance_count` is under the issuer signature; a subject that discloses B
  must disclose B's full committed reliance set or fail verification, just like a field set.
- **Completeness is bounded by issuer honesty — and only there.** The commitment stops the
  *subject* omitting a *declared* dependency. Nothing forces an *issuer* to declare a dependency
  of its own claim; a dishonest issuer under-declaring is a governance/accreditation problem,
  surfaced by traceability — consistent with the standing non-goal that *aion-trust does not
  adjudicate the truth an issuer attests.* Transitive revocation is therefore **"every declared
  reliance," best-effort against a malicious issuer — not a guarantee.**

## The fifth verification check

Invariant #3 requires four checks, every time: presentation binding → authenticity →
accreditation → revocation/validity. Reliance adds a fifth, order-preserving step, evaluated over a single epoch `e_v` = **the
verifier's own current ledger epoch at verification time**, pinned once for the whole verdict —
**including the check-4 revocation read**. No epoch encoded in or implied by the subject's
presentation may select `e_v`: a subject-pinned epoch would let a subject bind while an upstream is
still `issued`, wait for it to be revoked, and present against the stale epoch → a false green. The
whole verdict stays a pure function of one verifier-chosen epoch — no live per-node reads, no
cross-epoch cache:

> For claim B (already past checks 1–4), verify each disclosed reliance target against B's signed
> `reliance_root`/`reliance_count`. For each target claim A:
> 1. **Revocation (always).** Read A's `{status}` from the ledger *as-of `e_v`*. If A is
>    `revoked` → **fail-closed** (strict policy) or **amber** (flag policy).
> 2. **Validity & accreditation (only if A is itself disclosed).** A's `valid_until` and A's
>    issuer's accreditation live in A's claim/registry, **not** on A's status record. So expiry
>    and upstream-accreditation are checked **only when the subject discloses A as a full claim**;
>    for a status-only target, the transitive check covers **revocation, not expiry/accreditation**
>    (honest floor — the ledger cannot supply what it does not hold).
> 3. **Recurse only through disclosed claims**, carrying a visited-set, to the depth the subject
>    disclosed.

**Boundary rule (fail-closed, never silent-green).** Any target whose status is unresolvable, or
any *undisclosed-deeper* reliance the verifier cannot examine, is **at least amber** for a flag
verifier and **red** for a strict verifier — it is never accepted as clean. Depth is bounded by
disclosure, not by a silent cap; there is no "beyond D → green" path.

A predicate still runs **last**, only over a claim that passed every check including reliance, so a
revoked basis can never be laundered through a reliant claim.

## What it delivers (and what it deliberately gives up)

- **Transitive revocation at verify time** — a `background_check` presented against an `identity`
  that has since been `revoked` fails (or ambers) offline, no separate revocation of the check.
- **Reliance provenance to the verifier** — the disclosed reliance *is* the "why is this
  trustworthy" chain, to the depth the subject chose to reveal, bound to that one audience.
- **Integrity** — `reliance_root` is under the issuer's claim signature (tamper-evident); the
  ledger's status integrity remains `aion_verify`-able.
- **Given up on purpose: the global forward "blast-radius" query.** A public `aion_impact(A,
  forward)` over a shared reliance graph is *exactly* the complete-mediation and correlation
  violation the panel rejected. So the global cascade is removed. In its place: an **issuer** keeps
  its own private reliance index and computes *its own* blast radius to re-issue affected claims,
  and every dependent claim is caught **at its next verification** by the fifth check. This is the
  real adaptation cost — a pattern that is pure upside on an audit ledger (no adversarial subject,
  no privacy constraint) must shed its global graph when the *subject owns the data*.

## Honest floors

- **Revocation-complete, not validity/accreditation-complete** for status-only upstream (above).
- **Completeness bounded by issuer honesty** (above) — governance, not crypto.
- **Linkability.** Reliance is disclosed only to the chosen verifier, inside an audience-bound,
  expiring Presentation — the same posture as any disclosed field. Because nothing reaches the
  shared ledger, this design adds **no** public dependency graph and **no** new cross-verifier
  correlator beyond the `claim_id`/`body_root` linkability the project already documents
  ([`TRUST-MODEL.md`](TRUST-MODEL.md#selective-disclosure)). (This corrects the first draft, whose
  ledger edge *did* add a strictly larger, public correlator.) One honest extension: presenting B
  exposes the stable `claim_id`s of B's *disclosed* reliance targets — upstream claims not
  themselves presented — so two verifiers each shown a presentation citing the same upstream
  `claim_id` can correlate on it. Same class of correlator as a shared `claim_id`, now reaching the
  disclosed reliance set.
- **`claim_id` must be a hiding commitment — a hard Phase-7 prerequisite.** Since a reliance leaf
  discloses an upstream `claim_id`, a low-entropy upstream body (an `identity` is only a few bits)
  must not be confirmable by hashing. `claim_id` must derive from the per-claim `master_salt`, not
  from a bare digest of the body; **confirm the actual `claim_id` derivation is salted before any
  reliance leaf is ever disclosed** (this gates the feature, it is not an optional nicety).
- **Strict-green pulls toward over-disclosure.** To earn a *strict*-policy green, the subject must
  disclose its entire *declared* reliance closure down to `count=0` leaves (else undisclosed-deeper
  → amber). That is safe (it fails to amber, never to a false green) but is in tension with the
  "coercion to over-disclose" threat ([`TRUST-MODEL.md`](TRUST-MODEL.md#threat-model-initial)):
  dependency-completeness and data-minimization pull opposite ways. A verifier should set its
  amber-vs-strict bar deliberately, per claim category.

## Worked example

1. `identity` claim **A** (IAL2) issued to the subject.
2. Accredited provider issues `background_check` **B** = "clear", committing `reliance_root` over
   `{ from_claim_id: A, kind: identity_basis }`, `reliance_count: 1`, under B's issuer signature.
3. Subject presents **B** to an employer and discloses B's one reliance target, **A**, proven
   against `reliance_root`.
4. Months later, **A is revoked** — the identity was synthetic.
5. The employer's fifth check reads **A's status = `revoked`** (as-of the pinned epoch) and
   **fails B closed** (or ambers it) — the check was only ever as good as the identity beneath it.
6. If the subject later erases A from the wallet, **nothing about A or the reliance persists on
   the ledger** — only A's non-PII `revoked` status record, as before.

## Invariant check

1. **No PII on the ledger** — reliance lives in the claim commitment + the subject's presentation;
   the ledger still holds only keys/accreditation/status. ✓
2. **Subject owns the artifact** — reliance is disclosed by the subject, audience-bound, expiring;
   default closed. ✓
3. **Offline & trustless** — the fifth check reads only signed claims (in the presentation) and
   public status (from the ledger), as-of one pinned epoch; same-issuer authority is re-derived
   from B's own issuer signature. ✓
4. **No hand-rolled crypto** — reuses Merkle bodies, Ed25519 claim signatures, epochs. ✓
5. **Authentic ≠ authoritative** — reliance authenticity (issuer signed it) stays distinct from
   whether the upstream issuer is accredited. ✓

## Design history & review

**Round 1** rejected a first draft that recorded reliance as a signed edge on the shared ledger —
saltzer (BLOCKER: complete-mediation amplification, erasure, `kind` type-leak), rivest (BLOCKER:
same-issuer authority unenforced / reliance-injection, no domain separation), lamport (BLOCKER:
fifth check read off-ledger data; bounded depth failed open). The issuer-committed design here
addresses those by construction.

**Round 2** re-reviewed this design: **saltzer PII-SAFE**, **lamport SOUND for design phase** (all
nine prior findings resolved), **rivest "sound after five drafting fixes."** Those fixes are now
folded in: `e_v` = the verifier's current epoch (not subject-pinned); `reliance_root`/
`reliance_count` mandatory & signed with a `count=0`/`EMPTY_ROOT` sentinel and `schema_id`-pinned
presence; domain-tagged, per-index, index-bound reliance leaves with `kind` as a separate salted
sub-commitment; the reliance commitment carried in the DisclosedClaim and in every signed-set
enumeration (`DATA-MODEL.md`, `ARCHITECTURE.md`); and salted/hiding `claim_id` promoted to a hard
prerequisite. A third confirming pass and `/gate` are advised before any implementation lands.

**Executable proof.** [`proofs/phase7_reliance_proof.py`](proofs/phase7_reliance_proof.py) turns
each panel finding into a runnable hypothesis — omission-detection, transitive fail-closed,
injection/strip rejection, verifier-controlled `e_v`, no ledger topology, leaf index-binding,
hiding `claim_id`, `kind` minimization — and all **11/11 pass**. It models the mechanism with
domain-separated BLAKE2b + a Merkle commitment and an HMAC stand-in for the issuer signature, so it
proves the design *logic*, not the shipped crypto. These hypotheses are the spec to port to Rust
tests (real Ed25519/BLAKE3, under the `cargo mutants` gate) when Phase 7 is implemented.

## Status

**Phase 7 — IMPLEMENTED (strict-policy subset).** The commitment + disclosure + fifth check are
built and gated: `reliance_root`/`reliance_count` in the signed `Claim`
([`aion-trust-claims`]); the reliance-leaf disclosure in `DisclosedClaim`; the fifth check in
`verify_presentation` (fail-closed, at the verifier's `now`); the `kind` hiding sub-commitment; and
VC interop carrying the commitment. Re-reviewed by the panel on the **code**: saltzer PII-SAFE,
lamport SOUND, rivest SOUND — the executable-proof hypotheses are now Rust tests under the
`cargo mutants` 0-survivor gate.

**Scoped follow-ups (Phase 3, when revocation is fully wired against aion-context):**

- **Tri-state upstream status (rivest R1).** `TrustAnchor::is_revoked` returns `bool`, so an
  *unresolvable* upstream status resolves to "not revoked" (fail-open). Today this is inert —
  revocation is a Phase-3 stub. When it is wired, the anchor needs an `Unresolvable` state and the
  fifth check must treat it as fail-closed/amber, per the boundary rule above.
- **Amber / undisclosed-deeper (lamport, rivest R2).** Only the strict fail-closed policy is
  implemented (binary `accepted`). The *amber* verdict — and the "undisclosed-deeper reliance ⇒
  at-least-amber" signal for a status-only target — is not yet surfaced; a status-only target has
  its revocation checked but not its own deeper reliance (the documented revocation-only floor).
- **`kind` opening.** No path yet opens `kind_commit` for the provenance story; `kind` is currently
  always withheld (more private than the N1 floor — fine, but the reverse "why-trustworthy" story
  is unimplemented).
- The forward issuer-side blast-radius index (`aion-trust-registry`, issuer-private) is unbuilt.
