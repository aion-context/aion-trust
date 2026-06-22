# Glossary

- **Subject** — the person a claim is about; owns their identity and wallet and controls all
  disclosure.
- **Issuer** — a party with authority to attest a fact (employer, university, certification
  body, accredited background-check or identity provider, government).
- **Verifier** — a party evaluating the subject (hiring employer, landlord, financial
  institution).
- **Accreditor** — a party that vouches for *issuers*, establishing that an issuer may attest
  a given category (e.g. that a screening provider is FCRA-compliant).
- **Claim** — a single signed attestation about a subject: `{subject, issuer, type, body,
  validity}`, signed by the issuer. Typed and revocable.
- **Trust Profile** — the subject's complete, wallet-held collection of claims; never
  transmitted whole.
- **Presentation** — a signed, minimized bundle of selected claims built for one verifier and
  purpose. The artifact that replaces the résumé.
- **Accreditation** — a signed record that an issuer may attest a category; epoch-scoped, and
  K-of-N for high-assurance categories.
- **Authenticity** — the claim's signature is valid and binds issuer↔subject↔body. True even
  for unknown issuers (then it is *self-asserted*).
- **Authority** — the issuer is accredited to attest this category. Authenticity + authority
  = a trusted claim.
- **Self-asserted** — authentic but from a non-accredited issuer; valid signature, untrusted
  authority.
- **Revocation** — an issuer flipping a claim's status to `revoked` via an epoch-scoped,
  PII-free ledger record keyed by the opaque `claim_id`.
- **Validity window** — `valid_until` on time-bounded claims (checks, certifications); expiry
  fails verification without a revocation event.
- **Selective disclosure** — the subject revealing only chosen claims (claim-level), fields
  (field-level), or properties (predicate proofs).
- **body_root** — the Merkle root over a claim body's salted field leaves; the issuer signs it,
  so a subject can disclose a subset of fields and still prove them. Replaces the earlier
  single `body_hash`.
- **master_salt** — a 32-byte per-claim secret in the wallet from which every field's leaf salt
  derives; makes `body_root` a hiding commitment without storing one salt per field.
- **field leaf** — one body field committed as `hash(domain ‖ index ‖ key ‖ salt ‖ value)`; the
  unit of field-level disclosure.
- **audit path** — the sibling hashes from a disclosed leaf up to `body_root`, letting a verifier
  recompute the root and confirm the field belongs to the signed body.
- **field_count** — the signed number of field leaves in a claim's tree; fixes the field set so a
  maliciously omitted field is detectable.
- **DisclosedClaim** — the on-the-wire, body-less form of a claim: signed scalars + `body_root`
  plus only the revealed fields and their Merkle proofs. Verifies into a `VerifiedDisclosure`.
- **predicate proof (minimal-disclosure)** — answering "degree ≥ bachelor's" by disclosing a
  minimal, issuer-attested coarse attribute (e.g. `degree_rank`) and evaluating it; **not**
  zero-knowledge — the attribute is revealed and is linkable across presentations.
- **nonce store** — the verifier's single-use memory of accepted `(audience, nonce)` pairs;
  recorded only on accept, enforcing anti-replay against the same audience.
- **claim_id** — an opaque BLAKE3 hash; the only handle the ledger keys claim status on,
  carrying no PII.
- **Epoch** — an aion-context registry version boundary used to scope and revoke registrations
  and accreditations.
- **K-of-N** — a multisig accreditation policy requiring N independent accreditors to agree
  before an issuer is trusted for a category.
- **aion-context** — the signed, hash-chained provenance kernel aion-trust is built on.
- **aion-edu** — the sibling reference implementation for education credentials; its sealed
  diplomas import into aion-trust as education claims.
