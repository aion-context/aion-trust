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

The subject controls what each verifier sees. Granularity grows in stages:

- **Phase 1 — claim-level.** Include or exclude whole claims. A Presentation already reveals
  only the chosen claims, to one audience, for a bounded time.
- **Phase 2 — field-level.** Disclose specific fields of a claim (`institution`, `credential`,
  `conferred`) while withholding the rest, with the issuer's signature still verifiable over
  the disclosed subset (Merkleized claim bodies / selective-disclosure signatures).
- **Phase 3 — predicate proofs.** Prove a *property* without the value: "degree is a
  bachelor's or higher", "age ≥ 18", "check performed within 12 months" — zero-knowledge-style
  proofs that minimize disclosure to exactly the question asked.

Every Presentation is **audience-bound and nonce-bound**, so a bundle disclosed to one
employer cannot be replayed against another.

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
| **Coercion to over-disclose** | minimized presentations + predicate proofs reduce what *can* be demanded |
| **Subject key loss** | signed key-succession records + a recovery policy (Phase 2) |
| **Tampered claim body** | `body_hash` is signed; any edit breaks the issuer signature |
| **Sybil issuers** | authority requires accreditation, not mere registration; accreditors stake their keys |

## Non-goals (for now)

- aion-trust does not adjudicate the *truth* an issuer attests — it proves *who said it,
  about whom, and whether they're still standing behind it*. Garbage in by an accredited
  issuer is a governance/accreditation problem, surfaced by traceability, not a cryptographic
  one.
- It does not replace regulatory regimes (FCRA, EEOC, GDPR/CCPA, NIST 800-63); it gives them
  a cleaner substrate to attach to. A future `docs/COMPLIANCE.md` maps the obligations.
