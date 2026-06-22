# Vision

## The problem: a résumé is an unverified claim

Hiring runs on a document that no one trusts. A résumé is a self-asserted list of jobs,
degrees, and skills — and because anyone can write anything, every employer independently
pays to *re-verify* it:

- **Employment verification** — HR or a third party contacts each prior employer to confirm
  titles and dates. Days of latency; per-check fees; frequently unanswered.
- **Education verification** — registrars and clearinghouses are queried for each degree.
- **Background checks** — criminal, identity, sanctions, and credential checks are run by a
  screening provider, **per application**, even if the same candidate was cleared last month
  by a different employer.
- **References** — phone tag with people who, legally cautious, say almost nothing.

The result is slow, redundant, and gameable. Studies consistently find a large share of
résumés contain material misrepresentations; a meaningful fraction of bad hires trace back
to claims that were never true. The cost is paid three times over: by employers (labor,
fees, bad hires), by candidates (repeated check fees, weeks of delay), and by honest
applicants (whose real credentials are indistinguishable from fabricated ones).

## The shift: from *claim* to *artifact*

aion-trust changes the unit of hiring from a **claim** (something asserted) to an
**artifact** (something proven). Each fact about a person is attested *at the source* by the
party with authority over it, signed once, and from then on **verifiable by anyone without
contacting that source again**:

| Fact | Who attests it | What it becomes |
|------|----------------|-----------------|
| "Senior Engineer at Acme, 2021–2024" | Acme (former employer) | a signed employment claim |
| "B.S. Computer Science" | the university (or aion-edu) | a signed education claim |
| "Background check: clear, run 2026-05" | an accredited screening provider | a reusable signed check claim |
| "AWS Solutions Architect, valid to 2027" | the certification body | a signed certification claim |
| "Identity verified (KYC)" | an accredited identity provider | a signed identity claim |

The candidate holds these in a **wallet**, assembles the subset an employer needs into a
**Presentation**, and submits *that* as the new résumé. The employer verifies every claim
offline against aion-context — issuer signature, issuer accreditation, and live revocation
status — and is done. No portals, no callbacks, no waiting.

## Where the money is

The savings compound because verification work that is done **once** is reused **many** times.

- **Background checks become an asset, not a recurring cost.** A check run once by an
  accredited provider is a reusable claim. A candidate applying to ten roles presents the
  same verified check ten times instead of paying for ten checks. Multiply across a labor
  market and the redundant-screening spend is enormous.
- **Verification labor approaches zero.** Confirming employment and education shifts from
  hours of HR time and per-lookup fees to a sub-second cryptographic check.
- **Fraud is designed out.** You cannot present a degree, title, license, or clean check you
  were never issued. The most expensive class of hiring error — the confidently fabricated
  résumé — is structurally eliminated.
- **Time-to-hire collapses.** Verification that gated onboarding for days or weeks resolves
  in seconds, pulling forward start dates and revenue.
- **Candidates win too.** No repeated check fees, no weeks of waiting, and an honest
  applicant's real history is finally *legible* — provably distinct from a fabrication.

> These are directional; a future `docs/COST-MODEL.md` will turn them into a parameterized
> model (checks per hire, fee per check, HR hours per verification, bad-hire rate).

## The larger arc: identity, not just hiring

A résumé is the first surface, not the last. The same machinery — **signed claims about a
person, owned by that person, verifiable without a middleman** — is a general identity-and-
trust layer. The same artifact that proves an employment history can prove:

- professional licensure and continuing-education compliance,
- tenancy and rental history,
- KYC / accredited-investor status for finance,
- volunteer, security-clearance, or right-to-work attestations.

aion-trust starts with hiring because the pain is acute and the savings are concrete. But
the destination is **portable, person-owned, verifiable identity** — credentials that follow
the person, disclosed on their terms, trusted without a gatekeeper.

## Design commitments

Three commitments separate aion-trust from a database or a centralized "verification
service," and they hold for every document that follows:

1. **The person owns their artifact.** Claims live in the subject's wallet, not a vendor's
   silo. The subject decides what is disclosed, to whom, for how long.
2. **No PII on the ledger.** aion-context holds *keys, accreditation, schemas, and
   revocation status* — never personal data. Privacy and the right to erasure survive
   because the sensitive content never sits in an immutable shared record.
   (See [`docs/ARCHITECTURE.md`](ARCHITECTURE.md#the-privacy-model).)
3. **Verification needs no middleman.** Anyone can verify a presentation offline against
   aion-context. There is no service to call, no fee to pay, and no party who can quietly
   change the record.
