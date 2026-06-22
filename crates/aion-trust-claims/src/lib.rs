//! aion-trust-claims — the verifiable building blocks of a résumé.
//!
//! A [`Claim`] is an issuer-signed attestation about a subject, of any [`ClaimBody`] category
//! (employment, education, certification, background-check, identity, reference, skill). It
//! carries its PII-bearing body privately: you cannot read the body until you have *verified*
//! the claim, at which point you hold a [`VerifiedClaim`]. A [`Presentation`] is a
//! subject-signed, audience-bound bundle of claims — the artifact that replaces the résumé —
//! checked offline by [`verify_presentation`].

pub mod bodies;
pub mod claim;
pub mod presentation;

pub use bodies::{
    BackgroundCheckBody, CertificationBody, ClaimBody, EducationBody, EmploymentBody, IdentityBody,
    ReferenceBody, SkillBody,
};
pub use claim::{Claim, ClaimReject, Validity, VerifiedClaim};
pub use presentation::{
    build_presentation, verify_presentation, Check, IssuerDirectory, Presentation,
    VerificationReport,
};
