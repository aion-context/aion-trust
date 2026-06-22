# Data model

> Shapes are illustrative JSON for the architecture phase — not a frozen wire format.
> `body` fields carry PII and live only in the subject's wallet and in disclosed
> presentations; they are **never** written to aion-context. The ledger sees only the
> hashes and status records noted below.

## Identity

```json
{
  "subject_id": "did:aion:7Hx…",        // derived from the subject's Ed25519 public key
  "public_key": "ed25519:…",
  "created_at": "2026-06-21T00:00:00Z"
}
```

The private key stays in the wallet. `subject_id` is the stable anchor every claim binds to.

## Claim (the building block)

Every fact is a claim: an issuer's signed attestation about a subject.

```json
{
  "claim_id": "blake3:…",               // opaque; the only thing the ledger keys on
  "type": "employment",                 // employment | education | certification |
                                        // background_check | identity | reference | skill
  "schema_id": "aion-trust/employment/v1",
  "subject_id": "did:aion:7Hx…",
  "issuer_id":  "did:aion:Acme…",
  "validity": { "from": "2021-03-01", "until": null },   // until=null → open / current
  "body": { … type-specific, PII-bearing … },
  "master_salt": "blake3:…",            // 32-byte per-claim secret; per-field salts derive from it
  "body_root": "blake3:…",              // Merkle root over the body's salted field leaves
  "field_count": 6,                     // number of field leaves; signed, pins the tree shape
  "issuer_signature": "ed25519:…"       // issuer signs {subject_id,type,schema_id,body_root,field_count,validity,claim_id}
}
```

The body commitment is a **Merkle tree over the body's top-level fields** (JCS key order, each
a salted leaf), not a single hash — that is what lets a subject disclose a subset of fields and
still prove them against the issuer-signed `body_root`. The full claim (with `body` and
`master_salt`) lives only in the wallet; what travels to a verifier is a `DisclosedClaim` (below)
carrying no body.

### Claim types

**`employment`**
```json
{ "employer": "Acme Corp", "title": "Senior Engineer", "employment_type": "full_time",
  "start": "2021-03-01", "end": "2024-08-15", "rehire_eligible": true }
```

**`education`** — importable directly from an [aion-edu](https://github.com/aion-context/aion-edu) sealed diploma.
```json
{ "institution": "State University", "credential": "B.S. Computer Science",
  "conferred": "2020-05-20", "aion_edu_ref": "blake3:…", "degree_rank": 3 }
```
`degree_rank` is an **issuer-attested ordinal** (0 none · 1 secondary · 2 associate · 3 bachelor
· 4 master · 5 doctorate) on the scale pinned by `schema_id`. It lets a subject answer "degree ≥
bachelor's" by disclosing only this coarse rank — a data-minimizing predicate, not a
zero-knowledge proof (see [`TRUST-MODEL.md`](TRUST-MODEL.md#selective-disclosure)).

**`certification`**
```json
{ "authority": "Amazon Web Services", "name": "Solutions Architect – Professional",
  "issued": "2024-02-01", "expires": "2027-02-01", "credential_no": "…" }
```

**`background_check`** — the reusable, money-saving claim.
```json
{ "provider": "Acme Screening (accredited)", "scope": ["criminal","identity","sanctions"],
  "result": "clear", "performed": "2026-05-10", "valid_until": "2027-05-10",
  "jurisdiction": "US", "fcra_compliant": true }
```

**`identity`** — KYC / right-to-work.
```json
{ "method": "document+liveness", "verified": "2026-04-01", "assurance": "IAL2" }
```

**`reference`** — a named reference's attestation (the referee is itself an issuer).
```json
{ "relationship": "former manager", "statement_hash": "blake3:…", "given": "2026-06-01" }
```

**`skill`** — self-asserted, optionally *endorsed* (an endorsement is another claim whose
subject is this claim) or *assessed* (issued by an assessor like aion-edu).

## Trust Profile

The subject's complete, owned collection — held in the wallet, never transmitted whole.

```json
{
  "subject_id": "did:aion:7Hx…",
  "claims": [ "blake3:…", "blake3:…", … ],     // references into the wallet's claim store
  "updated_at": "2026-06-21T…"
}
```

## Presentation (the new résumé)

A signed, minimized bundle built for one verifier and purpose. **This is what gets
submitted.**

```json
{
  "presentation_id": "blake3:…",
  "subject_id": "did:aion:7Hx…",
  "audience": "did:aion:HiringCo…",     // bound to ONE verifier — not reusable elsewhere
  "purpose": "application:senior-engineer",
  "nonce": "…",                         // anti-replay, supplied by the verifier
  "issued_at": "2026-06-21T…",
  "expires_at": "2026-06-28T…",
  "claims": [                           // a list of DisclosedClaim — NO body, only proven fields
    {
      "claim_id": "blake3:…", "subject_id": "did:aion:7Hx…", "issuer_id": "did:aion:Uni…",
      "category": "education", "schema_id": "aion-trust/education/v1",
      "validity": { "from": "2020-05-20", "until": null },
      "body_root": "blake3:…", "field_count": 5, "issuer_signature": "ed25519:…",
      "fields": [                       // only the disclosed fields, each with a Merkle proof
        { "key": "institution", "index": 4, "salt": "…", "value": "State University",
          "audit_path": ["blake3:…","blake3:…"] },
        { "key": "credential",  "index": 2, "salt": "…", "value": "B.S. Computer Science",
          "audit_path": ["blake3:…","blake3:…"] }
      ]
    }
  ],
  "subject_signature": "ed25519:…"      // subject signs {audience,purpose,nonce,issued_at,expires_at,[claim_id…]}
}
```

The verifier checks, in order: presentation binding (subject key, audience, expiry, nonce
freshness + length, subject signature); then per claim — subject match, issuer recognized,
issuer signature over the reconstructed `{…,body_root,field_count,…}`, and **each disclosed
field's leaf recomputing the signed `body_root` via its audit path** (with the field's key
matching the schema field at its index, and `field_count` matching the schema's field set so an
omitted field is visible); then issuer accreditation and revocation. Optional **predicates** are
evaluated last, only over claims that passed every check. See
[`ARCHITECTURE.md`](ARCHITECTURE.md#verification-flow).

## Ledger records (the only things on aion-context)

No PII. Ever.

```json
// issuer / accreditor registry entry
{ "issuer_id": "did:aion:Acme…", "public_key": "ed25519:…", "registered_epoch": 12 }

// accreditation — Accreditor vouches for Issuer for a category (K-of-N for high assurance)
{ "issuer_id": "did:aion:AcmeScreening…", "category": "background_check",
  "accreditor_ids": ["did:aion:Reg1…","did:aion:Reg2…"], "policy": "2-of-2",
  "from_epoch": 12, "until_epoch": null }

// claim status — keyed by opaque claim_id, carries nothing about the person
{ "claim_id": "blake3:…", "status": "issued", "epoch": 12 }
{ "claim_id": "blake3:…", "status": "revoked", "epoch": 19 }
```
