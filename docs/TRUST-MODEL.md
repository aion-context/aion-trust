# Trust model

aion-trust's guarantee is only as good as the answer to one question: *why should a verifier
believe an issuer?* This document defines how issuer trust is established, how disclosure
stays in the subject's hands, how trust is withdrawn, and what the system defends against.

## Two layers of trust

A claim carries two independent assurances; verification reports both.

1. **Authenticity** — *the signature is valid and binds this issuer to this subject and
   body.* Always checkable, for any signed claim. A correct signature from an unknown issuer
   is **self-asserted**: authentic, but not authoritative.
2. **Authority (accreditation)** — *this issuer is recognized to attest this category of
   claim.* Established by Accreditors and resolved against aion-context. An employer trusts a
   `background_check` only if the provider is accredited for it.

A green verification means *authentic AND from an accredited authority*. Splitting the two
lets verifiers set their own bar (e.g. accept self-asserted skills, require accredited
identity and background checks).

## Accreditation (issuer federation)

Accreditation reuses aion-context's federation primitives — the same machinery that lets
universities recognize each other in aion-edu.

- An **Accreditor** signs an accreditation record: *issuer X may attest category Y*.
- **High-assurance categories use K-of-N multisig.** A `background_check` or `identity`
  provider should require, say, **2-of-2** independent accreditors before it is trusted — so
  no single accreditor can unilaterally bless a screening provider.
- Accreditations are **epoch-scoped**. They have a `from_epoch` and can be revoked by
  advancing the registry epoch — the same mechanism aion-edu uses to scope and revoke
  faculty delegation.
- Accreditation is **transitive and inspectable**: a verifier can trace *who* vouched for an
  issuer and under what policy, and can choose which accreditors it honors.

> Real-world anchor: in the US, background screening is governed by the **FCRA**; identity
> proofing maps to **NIST 800-63 IAL** levels. Accreditation is where those regimes attach —
> an accreditor asserts (and stakes its key on) an issuer's compliance.

## Selective disclosure

The subject controls what each verifier sees. Two granularities ship today, with an honest
floor on a third.

- **Claim-level.** Include or exclude whole claims. A Presentation reveals only the chosen
  claims, to one audience, for a bounded time.
- **Field-level (Merkleized bodies).** A claim body is committed not as one hash but as a
  **Merkle root over its salted field leaves** (`body_root`), which the issuer signs. A subject
  can then disclose a *subset* of fields — each proven against the signed root by an audit path
  — while the withheld fields contribute only sibling hashes and stay hidden. Two properties
  make this safe:
  - **Hiding.** Every field has its own salt, derived from one per-claim master salt; disclosing
    one field's salt reveals nothing about the withheld fields.
  - **No invisible omission.** The full field *set* is a function of the (signed) category, and
    the leaf count is signed (`field_count`). A verifier therefore knows exactly which fields a
    claim has and rejects a maliciously *omitted* field (e.g. a withheld `rehire_eligible:
    false`). Disclosure hides field *values*; it can never silently shrink the field set.
- **Predicate proofs — data minimization, not zero knowledge.** A predicate ("degree ≥
  bachelor's", "check performed within 12 months") is answered by disclosing the **minimal,
  issuer-attested coarse attribute** that settles it — a `degree_rank`, a date — and the verifier
  evaluates the comparison over that Merkle-proven, signed value. **It hides every other field of
  the claim, but it does not hide the disclosed attribute itself.** This is genuine
  minimization, not a zero-knowledge proof: there is no range proof, and equal attributes are
  **linkable** across presentations. `aion-context` exposes no ZK/range primitive and we never
  hand-roll cryptography (invariant #4); when such a primitive arrives, the same predicate
  plumbing can carry a real proof without a wire change.

Two rules keep predicates sound: a predicate is evaluated **only over a claim that already
passed every check** (authenticity, accreditation, revocation, validity), so it can only
*narrow* acceptance and can never launder a revoked or self-asserted claim; and the ordinal
scale is **issuer-attested and schema-pinned** — the verifier never infers a rank from free
text, and a scale-version mismatch fails closed.

> **Linkability (not a goal of this layer).** A claim's `claim_id` and `body_root` are stable
> across presentations, so two colluding verifiers can confirm they hold presentations of the
> *same* claim regardless of which fields each saw — and disclosing the same coarse attribute
> twice is itself a correlator. Unlinkability would require per-presentation re-randomization or
> a zero-knowledge proof, neither of which aion-context yet provides. This layer minimizes *what*
> is disclosed, not *whether disclosures can be linked*.

Every Presentation is **audience-bound, nonce-bound, and expiring**, so a bundle disclosed to
one employer cannot be replayed against another. A verifier additionally enforces **single use**
against its own nonce store, recording a nonce only when a presentation is accepted (a failed
presentation never burns its nonce). Single-use is atomic per single-process store; a
multi-replica verifier without a shared store has no cross-replica replay protection, and
replay/expiry safety assumes an honest, monotonic clock at the verifier.

## Revocation & validity

Two independent ways a claim stops being trustworthy, both enforced at verify time with no
need to contact the issuer:

- **Revocation** — the issuer flips the claim's status to `revoked` (an epoch-scoped registry
  record keyed by the opaque `claim_id`). A revoked employment claim — say, one issued in
  error — fails verification immediately and everywhere.
- **Validity window** — `valid_until` on checks and certifications. An expired background
  check or lapsed certification fails the validity step without any revocation event.

## Threat model (initial)

| Threat | Defense |
|--------|---------|
| **Fabricated résumé** | claims are issuer-signed; an unsigned/forged claim fails authenticity |
| **Self-issued "employer" claim** | the fake employer is not an accredited issuer → self-asserted, not authoritative |
| **Stolen presentation replayed** | presentations are audience-bound, nonce-bound, and expiring |
| **Issuer compromised / mistaken** | revocation + epoch rotation; high-assurance categories need K-of-N so one bad accreditor isn't enough |
| **PII leak from the ledger** | impossible by construction — the ledger holds no PII, only keys/status/schemas |
| **Coercion to over-disclose** | field-level disclosure + predicate (coarse-attribute) proofs reduce what *can* be demanded |
| **Subject key loss** | signed key-succession records + a recovery policy (Phase 2) |
| **Tampered claim body** | the signed `body_root` (Merkle) is recomputed from the disclosed fields; any edit breaks the audit path |
| **Maliciously omitted field** | the field set is fixed by the signed category and `field_count`; a withheld field is detectable, and a verifier can require specific fields |
| **Predicate laundering** (predicate over a revoked/unaccredited/expired claim) | a predicate is evaluated only over a claim that passed all four checks; it can only narrow acceptance |
| **Replayed presentation** (same audience) | single-use nonce store, recorded only on accept; bound nonce/audience/expiry stop cross-audience and post-expiry replay |
| **Sybil issuers** | authority requires accreditation, not mere registration; accreditors stake their keys |

## Non-goals (for now)

- aion-trust does not adjudicate the *truth* an issuer attests — it proves *who said it,
  about whom, and whether they're still standing behind it*. Garbage in by an accredited
  issuer is a governance/accreditation problem, surfaced by traceability, not a cryptographic
  one.
- It does not replace regulatory regimes (FCRA, EEOC, GDPR/CCPA, NIST 800-63); it gives them
  a cleaner substrate to attach to. A future `docs/COMPLIANCE.md` maps the obligations.
