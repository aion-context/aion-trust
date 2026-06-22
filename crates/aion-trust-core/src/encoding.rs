//! Hex codec and the domain-separated signing-byte writer.
//!
//! Signatures must cover *unambiguous* bytes. `SigningWriter` length-prefixes every
//! field and is seeded with a domain tag, so no two distinct messages can ever encode
//! to the same byte string (no concatenation collisions, no cross-context replay).

use crate::error::{Result, TrustError};

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(TrustError::Decode("hex length must be even".into()));
    }
    let nib = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(TrustError::Decode("invalid hex character".into())),
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

/// Decode a hex string into a fixed-size array, erroring on the wrong length.
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = from_hex(s)?;
    v.try_into()
        .map_err(|_| TrustError::Decode(format!("expected {N} bytes")))
}

/// Builds unambiguous, domain-separated bytes for signing.
pub struct SigningWriter {
    buf: Vec<u8>,
}

impl SigningWriter {
    /// Start a message in `domain` (e.g. `b"aion-trust/claim/v1"`).
    pub fn new(domain: &[u8]) -> Self {
        let mut w = Self { buf: Vec::new() };
        w.field(domain);
        w
    }

    /// Append a length-prefixed field (4-byte big-endian length, then the bytes).
    pub fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Append a signed 64-bit integer as a fixed 8-byte field.
    pub fn int(&mut self, v: i64) -> &mut Self {
        self.field(&v.to_be_bytes())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}
