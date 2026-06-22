# Workflows

The end-to-end flows that turn an unverified résumé into a verifiable artifact. Each
references the objects in [`DATA-MODEL.md`](DATA-MODEL.md) and the privacy rules in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

## 0 · Onboard an issuer (one-time)

An employer, university, certification body, or screening provider registers a key with
aion-context and is **accredited** for the categories it may attest.

```
issuer        → register public key in the aion-context registry
accreditor(s) → sign an accreditation: "issuer X may attest category Y" (K-of-N for
                high-assurance categories like background_check / identity)
```

Until an issuer is accredited for a category, claims it makes in that category verify as
*self-asserted* (valid signature, untrusted authority) rather than *accredited*.

## 1 · Issue a claim

The party with authority attests a fact and hands the signed claim to the subject.

```
subject     → shares subject_id with the issuer (+ consent)
issuer      → builds the claim body, computes body_hash, signs the claim
issuer      → records claim status = issued on aion-context (opaque claim_id only)
subject     → stores the claim in their wallet
```

Nothing about the person reaches the ledger — only `{claim_id, status: issued}`.

## 2 · Run a background check **once**, reuse it many times

The flow that captures most of the savings.

```
employer A  → requests a check (with subject consent)
provider    → performs the check, issues a background_check claim to the SUBJECT
              (not to employer A's silo), records status = issued
subject     → now holds a reusable, signed check in their wallet
… later …
employer B  → subject presents the SAME check; B verifies it offline and accepts it
              (within the check's validity window) — no new check purchased
```

A check becomes an **asset the candidate carries**, not a cost each employer re-pays.

## 3 · Import an education claim from aion-edu

aion-trust consumes the output of its sibling implementation.

```
subject     → exports a sealed diploma from aion-edu
wallet      → wraps it as an education claim (aion_edu_ref = the diploma's content hash)
verifier    → checks the aion-edu seal AND the aion-trust claim — one artifact, two proofs
```

## 4 · Assemble and present (the "new résumé")

The candidate builds a minimized, single-use bundle for one employer.

```
verifier    → posts a request: audience (its id), purpose, nonce, what categories it needs
subject     → selects the relevant claims from the Trust Profile
subject     → chooses disclosure granularity per claim (full / specific fields)
subject     → signs a Presentation bound to {audience, nonce, expiry}
subject     → submits the Presentation (this replaces sending a PDF résumé)
```

The candidate discloses *only* what the role needs, to *only* that employer, for a *bounded*
time.

## 5 · Verify (instant, offline)

The employer evaluates the Presentation with no callbacks and no portals.

```
for the presentation:  subject signature ✓ · audience = me ✓ · unexpired ✓ · nonce fresh ✓
for each claim:        issuer signature ✓ · subject matches ✓ · body ↔ body_hash ✓
for each issuer:       accredited for this category, this epoch ✓
for each claim:        status = issued (not revoked) ✓
⇒ ACCEPTED — every line of the résumé is a cryptographic fact.
```

A failure is specific and explainable ("the screening provider's accreditation lapsed",
"this certification was revoked"), not a vague "could not verify."

## 6 · Revoke / expire

Trust is living. Issuers can withdraw a claim; checks and certifications age out.

```
issuer      → records status = revoked for claim_id (aion-context registry epoch)
expiry      → validity.until / valid_until passes
⇒ any future verification of a presentation containing that claim fails the revocation
  or validity step — automatically, with no need to re-contact anyone.
```

## 7 · Rotate keys / recover

The subject's identity must outlive a lost device.

```
subject     → rotates to a new key; links old→new with a signed succession record
              (anchored via aion-context so verifiers can follow the chain)
recovery    → social or custodial recovery policy (design detail for Phase 2) restores
              wallet access without exposing claims to a third party
```

---

### The before/after, in one line

> **Before:** every employer re-verifies the same facts, by hand, for a fee, slowly, and
> still gets defrauded.
> **After:** each fact is verified once at its source, and proven instantly by anyone,
> forever — until the issuer says otherwise.
