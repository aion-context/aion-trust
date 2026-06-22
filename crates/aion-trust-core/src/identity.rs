//! A cryptographic identity: an Ed25519 keypair plus its derived `Did`. The private
//! key is held by `aion-context`'s `SigningKey` (zeroized on drop) and never leaves it.

use aion_context::crypto::{SigningKey, VerifyingKey};

use crate::encoding::{decode_array, to_hex};
use crate::error::Result;
use crate::id::Did;

pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(),
        }
    }

    /// Restore an identity from its 32-byte secret, hex-encoded.
    pub fn from_secret_hex(hex: &str) -> Result<Self> {
        let bytes = decode_array::<32>(hex)?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes)?,
        })
    }

    /// The 32-byte secret, hex-encoded. Treat as a secret: never log or commit it.
    pub fn secret_hex(&self) -> String {
        to_hex(self.signing_key.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// This identity's public did.
    pub fn did(&self) -> Did {
        Did::from_key(&self.verifying_key())
    }

    /// Sign a message, producing a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message)
    }
}

/// Decode a verifying key from its 32-byte hex encoding.
pub fn verifying_key_from_hex(hex: &str) -> Result<VerifyingKey> {
    let bytes = decode_array::<32>(hex)?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}
