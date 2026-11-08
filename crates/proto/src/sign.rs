//! Canonical digests and Ed25519 signatures for wire records.
//!
//! Signed bytes are `domain + "\n" + hex(sha256(JCS(body)))`. JCS is RFC 8785
//! canonical JSON, so two processes that serialize the same value produce the
//! same digest regardless of key order or whitespace.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{Digest, KeyId, Signed};

/// Why signing, verification or key loading failed.
#[derive(Debug)]
pub enum SignError {
    /// The body could not be canonicalized as JSON.
    Canonicalize(serde_json::Error),
    /// The record's domain is not the one the caller expected.
    WrongDomain { expected: String, actual: String },
    /// `signer` does not match the verifying key's id.
    WrongSigner { expected: KeyId, actual: KeyId },
    /// A hex field has the wrong length or alphabet.
    BadHex {
        field: &'static str,
        source: hex::FromHexError,
    },
    /// The public key bytes are not a valid Ed25519 point.
    BadPublicKey(ed25519_dalek::SignatureError),
    /// The signature does not verify.
    BadSignature(ed25519_dalek::SignatureError),
    /// The operating system could not supply randomness for a new key.
    Randomness(getrandom::Error),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonicalize(e) => write!(f, "cannot canonicalize record: {e}"),
            Self::WrongDomain { expected, actual } => {
                write!(f, "signature domain is {actual}, expected {expected}")
            }
            Self::WrongSigner { expected, actual } => {
                write!(f, "record names signer {actual}, but the key is {expected}")
            }
            Self::BadHex { field, source } => write!(f, "{field} is not valid hex: {source}"),
            Self::BadPublicKey(e) => write!(f, "invalid Ed25519 public key: {e}"),
            Self::BadSignature(e) => write!(f, "signature does not verify: {e}"),
            Self::Randomness(e) => write!(f, "operating-system randomness unavailable: {e}"),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonicalize(e) => Some(e),
            Self::BadHex { source, .. } => Some(source),
            Self::BadPublicKey(e) | Self::BadSignature(e) => Some(e),
            Self::Randomness(e) => Some(e),
            Self::WrongDomain { .. } | Self::WrongSigner { .. } => None,
        }
    }
}

/// `sha256:<hex>` of arbitrary bytes.
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> Digest {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// `sha256:<hex>` of the RFC 8785 canonical JSON of `value`.
///
/// # Errors
/// Fails if `value` cannot be serialized as JSON.
pub fn digest_of<T: Serialize>(value: &T) -> Result<Digest, SignError> {
    serde_jcs::to_vec(value)
        .map(|bytes| hash_bytes(&bytes))
        .map_err(SignError::Canonicalize)
}

/// Key id: `sha256:<hex>` of the raw 32-byte public key.
#[must_use]
pub fn key_id(key: &VerifyingKey) -> KeyId {
    hash_bytes(key.as_bytes())
}

/// Generate a fresh signing key from operating-system randomness.
///
/// # Errors
/// Fails if the OS cannot supply randomness.
pub fn generate_key() -> Result<SigningKey, SignError> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(SignError::Randomness)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Parse a 32-byte Ed25519 secret seed from lowercase hex.
///
/// # Errors
/// Fails if `seed_hex` is not 64 hex digits.
pub fn signing_key_from_hex(seed_hex: &str) -> Result<SigningKey, SignError> {
    Ok(SigningKey::from_bytes(&fixed_hex(seed_hex, "secret seed")?))
}

/// Parse a 32-byte Ed25519 public key from lowercase hex.
///
/// # Errors
/// Fails if `public_hex` is not 64 hex digits or is not a valid curve point.
pub fn verifying_key_from_hex(public_hex: &str) -> Result<VerifyingKey, SignError> {
    VerifyingKey::from_bytes(&fixed_hex(public_hex, "public key")?).map_err(SignError::BadPublicKey)
}

/// The exact bytes a signature covers: `domain + "\n" + hex(sha256(JCS(body)))`.
///
/// # Errors
/// Fails if `body` cannot be canonicalized.
fn signed_bytes<T: Serialize>(domain: &str, body: &T) -> Result<Vec<u8>, SignError> {
    let digest = digest_of(body)?;
    let hex_digest = digest.strip_prefix("sha256:").unwrap_or(&digest);
    Ok(format!("{domain}\n{hex_digest}").into_bytes())
}

/// Sign `body` under `domain`.
///
/// # Errors
/// Fails if `body` cannot be canonicalized.
pub fn sign<T: Serialize>(key: &SigningKey, domain: &str, body: T) -> Result<Signed<T>, SignError> {
    let signature = key.sign(&signed_bytes(domain, &body)?);
    Ok(Signed {
        domain: domain.to_owned(),
        body,
        signer: key_id(&key.verifying_key()),
        sig: hex::encode(signature.to_bytes()),
    })
}

/// Verify that `signed` was made by `key` under `expected_domain`.
///
/// # Errors
/// Fails on a domain or signer mismatch, malformed hex, or an invalid signature.
pub fn verify<T: Serialize>(
    signed: &Signed<T>,
    key: &VerifyingKey,
    expected_domain: &str,
) -> Result<(), SignError> {
    if signed.domain != expected_domain {
        return Err(SignError::WrongDomain {
            expected: expected_domain.to_owned(),
            actual: signed.domain.clone(),
        });
    }
    let expected_signer = key_id(key);
    if signed.signer != expected_signer {
        return Err(SignError::WrongSigner {
            expected: expected_signer,
            actual: signed.signer.clone(),
        });
    }
    let signature = Signature::from_bytes(&fixed_hex(&signed.sig, "signature")?);
    key.verify_strict(&signed_bytes(&signed.domain, &signed.body)?, &signature)
        .map_err(SignError::BadSignature)
}

/// Decode exactly `N` bytes of hex.
///
/// # Errors
/// Fails if `value` is not `2 * N` hex digits.
fn fixed_hex<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], SignError> {
    let mut out = [0_u8; N];
    hex::decode_to_slice(value, &mut out).map_err(|source| SignError::BadHex { field, source })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Audience, BusBody, BusMessage, Principal, domain};

    fn message(text: &str) -> BusMessage {
        BusMessage {
            id: "m1".into(),
            at: "2026-11-08T01:00:00Z".into(),
            from: Principal::System,
            to: Audience::All,
            body: BusBody::Chat { text: text.into() },
        }
    }

    #[test]
    fn tampered_body_or_wrong_domain_fails_verification() {
        let key = signing_key_from_hex(&"11".repeat(32)).expect("fixed 32-byte test seed");
        let signed = sign(&key, domain::BUS, message("hello")).expect("chat message serializes");
        verify(&signed, &key.verifying_key(), domain::BUS).expect("untampered record verifies");

        let mut tampered = signed.clone();
        tampered.body = message("hel1o");
        assert!(matches!(
            verify(&tampered, &key.verifying_key(), domain::BUS),
            Err(SignError::BadSignature(_))
        ));
        assert!(matches!(
            verify(&signed, &key.verifying_key(), domain::RECEIPT),
            Err(SignError::WrongDomain { .. })
        ));
    }

    #[test]
    fn digest_ignores_key_order() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":[2,3]}"#).expect("literal JSON");
        let b: serde_json::Value =
            serde_json::from_str(r#"{ "a":[2,3], "b":1 }"#).expect("literal JSON");
        assert_eq!(
            digest_of(&a).expect("serializes"),
            digest_of(&b).expect("serializes")
        );
    }
}
