# Compliance mapping

How aion-trust's architecture attaches to the major regimes governing hiring, personal data, and
identity assurance. aion-trust is a **substrate**, not a compliance program: it makes the right
properties *cheap and provable* (data minimization, no central PII store, attested-at-source
authority, revocation), but the surrounding *process* obligations remain the deploying
organization's. Each row is marked **Satisfied** (the protocol provides it), **Partial** (provides
the substrate; process required), or **Out of scope** (a process/legal obligation the protocol
does not address).

## FCRA (Fair Credit Reporting Act — US background screening)

| Requirement | aion-trust mechanism | Status |
|---|---|---|
| Checks performed by a compliant screening provider | `background_check` claims are issued by an **accredited** issuer (K-of-N), carry `fcra_compliant`, `jurisdiction`, `scope` (`bodies.rs::BackgroundCheckBody`); an unaccredited issuer is *self-asserted*, not authoritative | Partial |
| Recency / re-screening | `valid_until` validity window + epoch-scoped revocation fail an aged or withdrawn check at verify time | Satisfied |
| Permissible purpose; candidate consent | disclosure is the **subject's** act — audience-bound, single-use, expiring (`Presentation`) | Partial |
| Adverse-action notice & dispute workflow | a **process** the employer runs; not a protocol concern | Out of scope |

## EEOC (Equal Employment Opportunity)

| Requirement | aion-trust mechanism | Status |
|---|---|---|
| Minimize collection of protected-class proxies | **field-level selective disclosure** + **predicate proofs** (e.g. "degree ≥ bachelor" via the coarse issuer-attested `degree_rank`, not the full transcript) reveal only what the role needs (`disclosure.rs`, `predicate.rs`) | Partial |
| Consistent, documented criteria | the verifier's per-check `VerificationReport` is explicit and reproducible; the *decision policy* over it is the employer's | Partial |
| Disparate-impact auditing of hiring decisions | a governance task over the employer's decisions; the protocol does not make hiring decisions | Out of scope |

## GDPR / CCPA (personal-data protection)

| Requirement | aion-trust mechanism | Status |
|---|---|---|
| Data minimization | selective disclosure + predicates disclose the minimum; the ledger/registry hold **no PII** (`crates/aion-trust-registry/src/lib.rs` — keys, accreditation, opaque `claim_id`/status only) | Satisfied |
| Storage limitation / no central honeypot | **no central store of subjects**: claims live in the subject's wallet; there is no queryable PII silo to breach or subpoena | Satisfied |
| Right to erasure on an immutable substrate | the subject deletes the claim from their wallet; the shared layer only ever held a non-PII status record, so there is nothing PII to expunge ([`ARCHITECTURE.md`](ARCHITECTURE.md#the-privacy-model)) | Satisfied |
| Purpose limitation / consent | a presentation is built by the subject for one audience and purpose, expiring | Satisfied |
| Controller obligations over a *received* disclosure | once a verifier receives a presentation, the copy it holds is its own controller responsibility | Out of scope |

## NIST 800-63 (Digital Identity / Identity Assurance Levels)

| Requirement | aion-trust mechanism | Status |
|---|---|---|
| Convey identity assurance | `identity` claims carry `assurance` (e.g. IAL2) and `method` (`bodies.rs::IdentityBody`), attested by an accredited identity provider | Partial |
| Bind & verifiably transport the assurance | the claim is issuer-signed, subject-bound, selectively disclosable, and revocable — verifiable offline | Satisfied |
| Perform the IAL-2/3 proofing event | the **accredited identity issuer's** role (document + liveness, etc.); aion-trust transports the attestation, it does not perform proofing | Out of scope |
| Authenticator/AAL (session authentication) | a separate layer from credential issuance/verification | Out of scope |

## The throughline

The protocol's load-bearing privacy invariants — **no PII on the ledger** and **the subject owns
the artifact** ([`VISION.md`](VISION.md#design-commitments)) — are exactly what make GDPR/CCPA
data-minimization and erasure *structural rather than aspirational*. The accreditation layer is
where FCRA/NIST authority attaches. What aion-trust deliberately does **not** do is adjudicate the
truth an issuer attests or make the hiring decision — those stay with accountable humans and
processes, surfaced (not replaced) by verifiable provenance.
