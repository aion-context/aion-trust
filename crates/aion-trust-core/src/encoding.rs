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
        // `hi * 16 + lo` rather than `(hi << 4) | lo`: arithmetically identical, but every
        // operator mutation of it is observably wrong (no equivalent-mutant blind spot).
        out.push(nib(pair[0])? * 16 + nib(pair[1])?);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_known_vectors_and_round_trip() {
        assert_eq!(to_hex(&[0x00, 0xff, 0xab, 0x10]), "00ffab10");
        assert_eq!(to_hex(&[]), "");
        assert_eq!(from_hex("00ffab10").unwrap(), vec![0x00, 0xff, 0xab, 0x10]);
        // distinct nibbles in distinct positions pin the `hi * 16 + lo` assembly
        assert_eq!(from_hex("12").unwrap(), vec![0x12]);
        assert_eq!(from_hex("21").unwrap(), vec![0x21]);
        // upper- and lower-case both decode (pins the A..=F arm and its arithmetic)
        assert_eq!(from_hex("FF").unwrap(), vec![0xff]);
        assert_eq!(from_hex("aF").unwrap(), vec![0xaf]);
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert!(from_hex("abc").is_err()); // odd length
        assert!(from_hex("zz").is_err()); // invalid characters
        assert!(from_hex("0g").is_err());
    }

    #[test]
    fn decode_array_checks_length() {
        assert_eq!(decode_array::<2>("00ff").unwrap(), [0x00, 0xff]);
        assert!(decode_array::<2>("00").is_err()); // too short
        assert!(decode_array::<2>("00ffab").is_err()); // too long
    }

    #[test]
    fn signing_writer_exact_encoding() {
        let mut w = SigningWriter::new(b"dom");
        w.field(b"x");
        // domain "dom" (len 3) then field "x" (len 1), each length-prefixed big-endian
        assert_eq!(
            w.into_bytes(),
            vec![0, 0, 0, 3, b'd', b'o', b'm', 0, 0, 0, 1, b'x']
        );
    }

    #[test]
    fn signing_writer_is_content_dependent_and_unambiguous() {
        let bytes = |f: &[u8]| {
            let mut w = SigningWriter::new(b"dom");
            w.field(f);
            w.into_bytes()
        };
        assert_ne!(bytes(b"x"), bytes(b"y"));
        assert!(!bytes(b"x").is_empty());
        // length-prefixing prevents concatenation collisions: ("ab","c") != ("a","bc")
        let join = |a: &[u8], b: &[u8]| {
            let mut w = SigningWriter::new(b"d");
            w.field(a).field(b);
            w.into_bytes()
        };
        assert_ne!(join(b"ab", b"c"), join(b"a", b"bc"));
    }

    #[test]
    fn signing_writer_int_is_eight_byte_big_endian() {
        let mut w = SigningWriter::new(b"d");
        w.int(1);
        assert_eq!(
            w.into_bytes(),
            vec![0, 0, 0, 1, b'd', 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        let pos = {
            let mut w = SigningWriter::new(b"d");
            w.int(1);
            w.into_bytes()
        };
        let neg = {
            let mut w = SigningWriter::new(b"d");
            w.int(-1);
            w.into_bytes()
        };
        assert_ne!(pos, neg);
    }
}
