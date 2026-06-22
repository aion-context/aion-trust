# Interoperability — W3C VC/VP & did:key

aion-trust artifacts map onto the **W3C Verifiable Credentials data model** and **did:key**, so a
disclosure or presentation can travel to tooling beyond this implementation. The mapping is
implemented in the `aion-trust-interop` crate (`export_disclosed_vc` / `import_disclosed_vc`,
`export_presentation_vp` / `import_presentation_vp`).

> ## ⚠ NATIVE PROOF — data-model interop, not W3C Data Integrity
>
> The `proof` object is **not** a Data-Integrity / JSON-LD-canonicalized proof. The holder cannot
> re-sign as the issuer (and re-signing would sever the issuer→accreditation chain that makes a
> claim *authoritative*), so we deliberately do **not** forge one. The exported `proof` carries
> aion-trust's own Ed25519 signature over the project's domain-separated `signing_bytes`, plus the
> Merkle disclosure. A generic W3C tool can **parse** these artifacts; cryptographic
> **verification** requires an aion-trust-aware verifier (this crate's `import_*` path).
> `proof.type` is `"AionTrustNativeProof2026"` — deliberately *not* a registered cryptosuite — so a
> conformant Data-Integrity verifier **fails closed** rather than mistaking it for one it knows.

## What is exportable

Only a **`DisclosedClaim`** or a **`Presentation`** — never a full `Claim`. A full claim carries
the wallet-only `master_salt`; exporting it would let a recipient brute-force *withheld*
low-entropy fields against `body_root` and defeat selective disclosure. (Full-claim wallet backup
uses plain serde JSON, not a VC.)

## did:key

`did:aion:<hex>` is a one-way hash of the public key — it does not carry the key. So the key a
verifier needs rides in `proof.verificationMethod` as a **did:key**: `did:key:z` +
base58btc(`0xed01` ‖ 32-byte Ed25519 key), where `0xed01` is the `ed25519-pub` multicodec varint
and `z` is the base58btc multibase tag. Known-answer (RFC 8032 test-1 key):
`d75a9801…511a` → `did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw`.

### The binding check (the trust hinge)

On import the public key is recovered from the did:key and must **derive the `did:aion` the
document claims** (`Did::from_key(pubkey) == issuer_id`). This is enforced by feeding the recovered
key into aion-trust's native `verify` (which rejects `IssuerKeyMismatch`), plus an explicit
pre-check. Without it, a VC could claim issuer *X* while being signed by an attacker's key —
key-substitution / accreditation laundering. Import is **verify-then-read**: the native artifact is
rebuilt from the *proof* (the human-readable `credentialSubject` is non-authoritative decoration),
re-verified, and only then trusted.

## Field mapping

**DisclosedClaim → VC**

| aion-trust | VC |
|---|---|
| `claim_id` | `id` (`urn:aion-trust:claim:<hex>`) |
| `issuer_id` (did:aion) | `issuer` |
| `subject_id` (did:aion) | `credentialSubject.id` |
| `category` | `type[1]` (`<Category>Credential`) + `proof.category` (authoritative) |
| `schema_id` | `credentialSchema.id` + `proof.schemaId` |
| `validity.from` / `.until` | `validFrom` / `validUntil` (RFC 3339; `validUntil` omitted if open) |
| disclosed `{key:value}` | `credentialSubject.<key>` (decoration) |
| `body_root`, `field_count`, `issuer_signature` | `proof.bodyRoot`, `proof.fieldCount`, `proof.aionSignature` |
| `RevealedField[]` (key/index/salt/value/audit_path) | `proof.disclosures[]` (authoritative) |
| issuer public key | `proof.verificationMethod` (did:key) |

**Presentation → VP**

| aion-trust | VP |
|---|---|
| `presentation_id` | `id` (`urn:aion-trust:presentation:<hex>`) |
| `subject_id` | `holder` |
| `subject_key` | `proof.verificationMethod` (did:key — self-contained holder binding) |
| `audience` | `proof.domain` |
| `nonce` | `proof.challenge` |
| `purpose`, `issued_at`, `expires_at` | `proof.purpose`, `proof.issuedAt`, `proof.expiresAt` |
| `claims[]` | `verifiableCredential[]` (each a disclosed VC) |
| `subject_signature` | `proof.aionSignature` |

## Caveats

- **Not Data Integrity / not JSON-LD-canonicalized.** The signature secures the aion-trust
  artifact, not the JSON-LD bytes. Verify only via an aion-trust verifier.
- **Disclosure-only export.** Never export a full `Claim` (would leak `master_salt`).
- **Verification requires the registry for VP issuers.** Importing a VP verifies each embedded
  credential against its own did:key; whole-presentation acceptance (accreditation, revocation,
  audience, single-use nonce, expiry) is still `verify_presentation` against the verifier's anchor.

## Relationship to SD-JWT / BBS+

aion-trust's selective disclosure is a **salted-Merkle** scheme: the issuer signs one Ed25519
signature over a Merkle root of salted field leaves, and a holder reveals a subset with per-field
audit paths. It is *functionally analogous* to other selective-disclosure credentials but is not
those formats on the wire:

| | aion-trust | SD-JWT(-VC) | BBS+ |
|---|---|---|---|
| Issuer signature | 1× Ed25519 over a Merkle root | 1× JWS over salted-hash digests | 1× BBS+ over N messages |
| Disclosure unit | field + Merkle audit path | field + salt (hash preimage) | message + ZK reveal |
| Predicate proofs | coarse, issuer-attested ordinals (not ZK) | none native | ZK range/predicate |
| Unlinkability | no (stable `claim_id`/`body_root`) | no (per-presentation salts help) | yes (per-presentation rerandomization) |
| Verifier deps | aion-trust verifier | JWS + hash | pairing crypto |

This crate is a **data-model bridge** — it does not turn aion-trust into SD-JWT or BBS+. A future
move to BBS+ (true unlinkability) or a real ZK range proof would slot in behind the existing
`ProvenField` (`#[non_exhaustive]`) and disclosure plumbing without changing the wire envelope.
