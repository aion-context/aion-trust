//! aion-trust-interop — map aion-trust disclosures and presentations to the W3C Verifiable
//! Credentials / Verifiable Presentations **data model** and `did:key`, for portability and
//! tooling, and import them back.
//!
//! ## ⚠ NATIVE PROOF, NOT W3C DATA INTEGRITY
//!
//! The `proof` object is **not** a Data-Integrity / JSON-LD-canonicalized proof and is **not**
//! interoperable with a generic VC verifier's cryptography. It carries aion-trust's own Ed25519
//! signature over the project's domain-separated `signing_bytes`, plus the Merkle disclosure.
//! A generic W3C tool can **parse** these artifacts; cryptographic **verification** requires an
//! aion-trust-aware verifier (this crate's `import_*` path). The holder cannot re-sign as the
//! issuer — and re-signing would sever the issuer→accreditation chain — so we deliberately do
//! **not** forge a Data-Integrity proof. `proof.type` is `"AionTrustNativeProof2026"` precisely
//! so a conformant Data-Integrity verifier fails closed on the unknown suite rather than
//! mistaking it for `Ed25519Signature2020` / `DataIntegrityProof`.
//!
//! ## What is safe to export
//!
//! Only a [`DisclosedClaim`](aion_trust_claims::DisclosedClaim) or a
//! [`Presentation`](aion_trust_claims::Presentation) — never a full `Claim`, which carries the
//! wallet-only `master_salt` whose disclosure would defeat the hiding of withheld fields.
//!
//! ## The trust hinge
//!
//! Import is **verify-then-read**: it reconstructs the native artifact from the *proof* (not the
//! human-readable `credentialSubject`), runs aion-trust's own `verify`, and trusts only the
//! result. The issuer/holder key travels in `verificationMethod` as a `did:key`; import requires
//! that key to derive the `did:aion` the document claims (`Did::from_key` equality), so a
//! substituted key is rejected before any value is trusted.

#![forbid(unsafe_code)]

pub mod didkey;
pub mod error;
pub(crate) mod jsonget;
pub mod rfc3339;
pub mod vc;
pub mod vp;

pub use didkey::{decode_did_key, encode_did_key};
pub use error::{InteropError, Result};
pub use vc::{export_disclosed_vc, import_disclosed_vc};
pub use vp::{export_presentation_vp, import_presentation_vp};

/// The JSON-LD `@context` for exported artifacts: the W3C VC v2 context plus this project's.
pub(crate) const CONTEXT_V1: [&str; 2] = [
    "https://www.w3.org/ns/credentials/v2",
    "https://aion.dev/trust/interop/v1",
];

/// The vendor-namespaced proof type — deliberately NOT a registered Data-Integrity suite, so a
/// conformant W3C verifier fails closed rather than mistaking the native proof for one it knows.
pub(crate) const PROOF_TYPE: &str = "AionTrustNativeProof2026";

/// Base for the (informational) `credentialSchema.id` URL.
pub(crate) const SCHEMA_BASE: &str = "https://aion.dev/trust/schema/";
