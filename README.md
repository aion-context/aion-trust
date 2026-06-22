# aion-trust

**The verifiable résumé — and the trust layer beneath it.
A reference implementation of [aion-context](https://github.com/aion-context/aion-context).**

A résumé today is an *unverified claim*: a PDF anyone can fabricate, that an employer then
has to verify by hand — calling past employers, re-running background checks, chasing
transcripts, waiting on references. It is slow, expensive, repeated for every application,
and routinely defrauded.

aion-trust replaces that with a **portable, self-verifying trust artifact**. Every line of
a résumé becomes a cryptographically signed attestation from the party that can actually
vouch for it — an employer, a university, a certification body, an accredited
background-check provider — sealed on aion-context and verifiable by **anyone, offline, in
seconds**. The candidate owns the artifact, discloses only what a given employer needs, and
reuses it across every application.

> **Do the work once. Prove it forever.**

This is also the seed of something larger. A résumé is just the first surface: the same
machinery — signed claims about a person, owned by that person, verifiable without a
middleman — is a general **identity-and-trust layer**. aion-trust starts with hiring
because that is where the pain and the savings are most obvious.

## The thesis, in one workflow

```
Issuer  ──signs──▶  Claim  ──held by──▶  Subject's wallet
                                              │
                                       selective disclosure
                                              ▼
Verifier (employer)  ◀──presents──  Presentation (a signed bundle of claims)
        │
        └─ verifies every claim offline against aion-context: issuer signature,
           issuer accreditation, and revocation status — no phone calls, no portals.
```

A **background check** becomes a reusable signed claim: run once by an accredited provider,
presented to many employers — instead of paid for again on every application. A degree
becomes a claim issued by the university (or imported straight from
[aion-edu](https://github.com/aion-context/aion-edu)). An employment record becomes a claim
signed by the former employer. The "new résumé" is the verifiable bundle of these.

## Why it saves money

- **Background checks, run once:** an accredited check becomes a reusable, tamper-proof
  claim — the candidate stops paying (and waiting) for a fresh check per application.
- **Verification at zero marginal cost:** employment and education verification drop from
  hours of HR labor and third-party fees to an instant offline cryptographic check.
- **Fraud goes to zero:** you cannot present a degree, title, or clean check you were never
  issued. Bad hires from résumé misrepresentation — among the most expensive hiring errors —
  are designed out.
- **Time-to-hire compresses:** onboarding verification that took weeks resolves in seconds.

See [`docs/VISION.md`](docs/VISION.md) for the full case and where the savings land.

## Status

**Phase 0 — Architecture.** This repository currently holds the founding design. The
documents below define the model before any code is written.

## Architecture documents

| Doc | What it covers |
|-----|----------------|
| [`docs/VISION.md`](docs/VISION.md) | The problem, the world aion-trust enables, the cost case, the identity future |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Actors, layering on aion-context, the privacy model, proposed crate layout |
| [`docs/DATA-MODEL.md`](docs/DATA-MODEL.md) | Claim types, the Trust Profile, the Presentation artifact, schemas |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | End-to-end flows: issue, assemble, present, verify, reuse, revoke |
| [`docs/TRUST-MODEL.md`](docs/TRUST-MODEL.md) | Issuer accreditation, selective disclosure, revocation, threat model |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phases from kernel to web demo to interop |
| [`docs/GLOSSARY.md`](docs/GLOSSARY.md) | Terms of art |

## Family

aion-trust is part of a family of reference implementations that show **aion-context** wired
into real domains:

- **[aion-context](https://github.com/aion-context/aion-context)** — the signed,
  hash-chained provenance kernel everything is built on.
- **[aion-edu](https://github.com/aion-context/aion-edu)** — verifiable education
  credentials. (Its sealed diplomas import directly into aion-trust as education claims.)
- **aion-trust** — verifiable human-capital identity: résumés, employment, background checks.
