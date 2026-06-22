# Architecture

## Actors

| Actor | Role |
|-------|------|
| **Subject** | the person the claims are about; holds a cryptographic identity and a wallet of claims; controls all disclosure |
| **Issuer** | a party with authority to attest a fact: employer, university, certification body, accredited background-check / identity provider, government |
| **Verifier** | a party evaluating the subject: a hiring employer, a landlord, a financial institution |
| **Accreditor** | a party that vouches for *issuers* — establishing that a background-check provider is FCRA-compliant, that a university is recognized, that an identity provider meets a KYC bar |

A single organization can wear several hats (an employer is a Verifier when hiring and an
Issuer when an employee leaves).

## Layering

```
┌──────────────────────────────────────────────────────────────────┐
│  Surfaces:  Issuer console · Candidate wallet · Employer verifier  │  (web / cli)
├──────────────────────────────────────────────────────────────────┤
│  aion-trust domain:                                                │
│    Identity · Claims · Trust Profile · Presentation · Disclosure   │
│    Accreditation/federation of issuers · Revocation                │
├──────────────────────────────────────────────────────────────────┤
│  aion-context  (the provenance kernel)                             │
│    Ed25519 attestations · BLAKE3 hash-chains · key registry        │
│    K-of-N multisig · registry epochs · offline verification        │
└──────────────────────────────────────────────────────────────────┘
```

aion-trust is a *domain* on aion-context, exactly as aion-edu is. Everything that needs
trust — signing a claim, registering an issuer, accrediting a provider, revoking a credential,
verifying offline — is an aion-context operation. aion-trust contributes the human-capital
*semantics*: what a claim means, how a résumé is assembled, what an employer checks.

## The core objects

- **Identity** — a subject's Ed25519 keypair and a stable subject identifier (a DID-style
  id derived from the public key). The private key never leaves the wallet.
- **Claim** — a single signed attestation: `{ subject, issuer, type, body, validity }`,
  signed by the issuer over the subject's id and a content hash. Typed (employment,
  education, certification, background-check, identity, reference, skill). Revocable.
- **Trust Profile** — the subject's owned collection of claims (the full "career graph").
  Lives in the wallet; never transmitted whole.
- **Presentation** — a *signed, minimized bundle* the subject builds for a specific verifier
  and purpose: a chosen subset of claims, bound to a verifier id and a nonce/expiry, signed
  by the subject. This is "the résumé you submit."
- **Accreditation** — an issuer-trust record: an Accreditor vouches for an Issuer for a
  claim category, scoped by registry epoch (so it can be time-boxed and revoked). Reuses
  aion-context's K-of-N multisig for high-assurance categories (e.g. two accreditors must
  agree before a background-check provider is trusted).
- **Revocation** — a status record keyed by an opaque claim id; flips a claim to revoked
  without revealing anything about its content.

## The privacy model

> This is the load-bearing decision. Get it wrong and you have built a surveillance ledger.

**aion-context never holds personal data.** The immutable, shared layer holds only:

- **issuer & accreditor public keys** (the registry),
- **accreditation records** (issuer X is trusted for category Y, this epoch),
- **claim *status*** — issued / revoked — keyed by an **opaque claim id** (a hash), carrying
  no PII,
- **schema identifiers** (what shape a claim type takes).

The **claim itself — with the PII (names, dates, results) — lives only in the subject's
wallet**, as a signed document. It is disclosed selectively, peer-to-peer, to a chosen
verifier. The ledger proves *integrity and standing*; it never stores *content*.

This yields three properties that a database-backed "verification service" cannot offer:

1. **Right to erasure survives.** The subject can delete a claim from their wallet; the
   ledger only ever held a non-PII status record. There is no PII to expunge from an
   immutable log.
2. **Disclosure is the subject's.** Nothing is shared until the subject builds a
   Presentation and hands it over. There is no central store an attacker or insider can mine.
3. **Verification is still offline and trustless.** The verifier checks the issuer's
   signature (registry-resolved), the issuer's accreditation, and the claim's revocation
   status — all against aion-context — without the issuer's involvement and without trusting
   aion-trust the company.

### What gets signed

```
Claim          = issuer signs over { subject_id, type, schema_id, body_hash, validity, claim_id }
                 (body, containing PII, travels with the claim — never to the ledger)
Ledger record  = { claim_id, status: issued|revoked, epoch }          ← no PII
Presentation   = subject signs over { verifier_id, nonce, expiry, [claim refs + disclosed bodies] }
```

Selective disclosure starts coarse (include/exclude whole claims) and has a clear path to
fine-grained, privacy-preserving proofs (disclose "degree = B.S." or "age ≥ 18" without the
surrounding fields) — see [`docs/TRUST-MODEL.md`](TRUST-MODEL.md#selective-disclosure).

## Verification flow

When a verifier receives a Presentation, it checks, entirely offline against aion-context:

1. **Presentation binding** — signed by the subject, addressed to *this* verifier, unexpired,
   nonce unused (anti-replay).
2. **For each claim** — issuer signature valid; `subject_id` matches; `body` matches the
   signed `body_hash`.
3. **Issuer standing** — the issuer is accredited for this claim's category in the current
   epoch.
4. **Revocation** — the `claim_id`'s status is `issued`, not `revoked`.

All four are aion-context operations (`verify_file`, registry resolution, epoch checks). A
green result is a cryptographic fact, not a vendor's assurance.

## Proposed crate layout (Rust, on aion-context)

Mirrors the aion-edu reference implementation; subject to refinement in Phase 1.

| Crate | Responsibility |
|-------|----------------|
| `aion-trust-core` | shared types, ids, errors |
| `aion-trust-claims` | claim types, schemas, signing & verification via aion-context |
| `aion-trust-registry` | issuer registration, accreditation, K-of-N, epochs (the federation layer) |
| `aion-trust-wallet` | the subject's identity, Trust Profile, and Presentation builder |
| `aion-trust-verify` | the verifier: offline checking of a Presentation |
| `aion-trust-web` | issuer console · candidate wallet · employer verifier (axum) |
| `aion-trust-cli` | `issue`, `accredit`, `present`, `verify`, `revoke` |

## Interoperability

The model is deliberately aligned with **W3C Verifiable Credentials** and **Decentralized
Identifiers (DIDs)**: subject ids are DID-shaped, claims map to Verifiable Credentials, and a
Presentation maps to a Verifiable Presentation. aion-context is the trust anchor and status
mechanism. This keeps a clean path to exporting/importing standard VCs so aion-trust
artifacts interoperate beyond this implementation. (Detailed mapping: future
`docs/INTEROP.md`.)
