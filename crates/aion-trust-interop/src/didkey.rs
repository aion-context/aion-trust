//! `did:key` for Ed25519 — pure, dependency-free, mutation-tested.
//!
//! A `did:key` for an Ed25519 public key is `did:key:z` + base58btc( `0xed 0x01` ‖ 32-byte key ),
//! where `0xed01` is the multicodec varint for `ed25519-pub` and `z` is the multibase tag for
//! base58btc. This is the canonical form W3C tooling expects, and — unlike `did:aion` (a one-way
//! hash) — it carries the public key, so an importer can recover the key and re-verify.

use aion_context::crypto::VerifyingKey;

use crate::error::{InteropError, Result};

/// Multicodec varint for `ed25519-pub`.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Bitcoin/IPFS base58 alphabet (no `0 O I l`).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode an Ed25519 verifying key as a `did:key`.
pub fn encode_did_key(vk: &VerifyingKey) -> String {
    let mut payload = Vec::with_capacity(34);
    payload.extend_from_slice(&ED25519_MULTICODEC);
    payload.extend_from_slice(&vk.to_bytes());
    format!("did:key:z{}", base58btc_encode(&payload))
}

/// The verificationMethod form of a key's did:key: `did:key:zXXX#zXXX`.
pub(crate) fn verification_method(vk: &VerifyingKey) -> String {
    let did = encode_did_key(vk);
    let frag = did.strip_prefix("did:key:").unwrap_or(&did);
    format!("{did}#{frag}")
}

/// Decode a `did:key` (with optional `#fragment`) back to an Ed25519 verifying key. Strict: the
/// multibase tag must be `z`, the multicodec must be ed25519-pub, the key must be 32 bytes and a
/// valid curve point. Any deviation fails closed.
pub fn decode_did_key(s: &str) -> Result<VerifyingKey> {
    let base = s.split('#').next().unwrap_or(s);
    let mb = base
        .strip_prefix("did:key:z")
        .ok_or_else(|| InteropError::DidKey("expected 'did:key:z' prefix".into()))?;
    let bytes = base58btc_decode(mb)?;
    if bytes.len() != 34 || bytes[0..2] != ED25519_MULTICODEC {
        return Err(InteropError::DidKey("not an ed25519-pub did:key".into()));
    }
    let key: [u8; 32] = bytes[2..34]
        .try_into()
        .map_err(|_| InteropError::DidKey("bad key length".into()))?;
    VerifyingKey::from_bytes(&key).map_err(|e| InteropError::DidKey(e.to_string()))
}

/// Base58btc encode: big-endian base conversion, leading zero bytes become leading `1`s.
fn base58btc_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) * 256;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Base58btc decode: inverse of [`base58btc_encode`]; leading `1`s become leading zero bytes.
fn base58btc_decode(s: &str) -> Result<Vec<u8>> {
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| InteropError::DidKey("invalid base58 character".into()))?
            as u32;
        let mut carry = val;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_trust_core::encoding::{from_hex, to_hex};

    /// The RFC 8032 Ed25519 test-1 public key, and its did:key (base58 anchored to the
    /// multibase spec vectors in `base58_unit_vectors`, so this pairing is verified, not assumed).
    const KAT_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const KAT_DID: &str = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

    fn vk(hex: &str) -> VerifyingKey {
        let bytes: [u8; 32] = from_hex(hex).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn known_answer_vector() {
        assert_eq!(encode_did_key(&vk(KAT_HEX)), KAT_DID);
        assert_eq!(
            to_hex(&decode_did_key(KAT_DID).unwrap().to_bytes()),
            KAT_HEX
        );
    }

    #[test]
    fn round_trip_and_fragment_strip() {
        let key = vk(KAT_HEX);
        let did = encode_did_key(&key);
        assert_eq!(decode_did_key(&did).unwrap().to_bytes(), key.to_bytes());
        // a #fragment (verificationMethod form) is stripped
        let with_frag = format!("{did}#{}", &did["did:key:".len()..]);
        assert_eq!(
            decode_did_key(&with_frag).unwrap().to_bytes(),
            key.to_bytes()
        );
    }

    #[test]
    fn base58_unit_vectors() {
        // authoritative multibase-spec base58btc vectors (anchors the implementation externally)
        assert_eq!(base58btc_encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
        assert_eq!(base58btc_encode(b"yes mani !"), "7paNL19xttacUY");
        assert_eq!(
            base58btc_decode("2NEpo7TZRRrLZSi2U").unwrap(),
            b"Hello World!"
        );
        // leading-zero handling
        assert_eq!(base58btc_encode(&[]), "");
        assert_eq!(base58btc_encode(&[0]), "1"); // leading zero → '1'
        assert_eq!(base58btc_encode(&[0, 0, 1]), "112"); // two leading zeros, then 1
        assert_eq!(base58btc_decode("1").unwrap(), vec![0]);
        assert_eq!(base58btc_decode("112").unwrap(), vec![0, 0, 1]);
        assert_eq!(base58btc_decode("").unwrap(), Vec::<u8>::new());
        // round-trip arbitrary bytes
        let data = b"\x00\x01hello-base58\xff\xfe";
        assert_eq!(base58btc_decode(&base58btc_encode(data)).unwrap(), data);
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode_did_key("did:key:Q123").is_err()); // wrong multibase tag (not z)
        assert!(decode_did_key("did:aion:abc").is_err()); // wrong method
        assert!(decode_did_key("did:key:z0OIl").is_err()); // invalid base58 chars
                                                           // a secp256k1 multicodec (0xe7,0x01) prefix must be rejected
        let mut payload = vec![0xe7, 0x01];
        payload.extend_from_slice(&[7u8; 33]);
        let did = format!("did:key:z{}", base58btc_encode(&payload));
        assert!(decode_did_key(&did).is_err());
        // wrong codec, CORRECT length (34), over a VALID Ed25519 key — so only the codec check
        // can reject it. Pins that length and codec are OR'd, not AND'd: with `&&`, the valid key
        // would slip through `from_bytes` and be wrongly accepted.
        let mut wrong_codec = vec![0xe7, 0x01];
        wrong_codec.extend_from_slice(&from_hex(KAT_HEX).unwrap());
        let did = format!("did:key:z{}", base58btc_encode(&wrong_codec));
        assert!(decode_did_key(&did).is_err());
    }
}
