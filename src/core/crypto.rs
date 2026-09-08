//! Audited crypto helpers.
//!
//! All HMAC construction and all constant-time comparison live here so the
//! security guarantees are implemented once (`spec.md` §4). Providers must not
//! call `hmac`/`sha2`/`sha1`/`subtle` directly; they call these helpers.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

#[cfg(feature = "sendgrid")]
use p256::ecdsa::signature::hazmat::PrehashVerifier;
#[cfg(feature = "sendgrid")]
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
#[cfg(feature = "sendgrid")]
use p256::pkcs8::DecodePublicKey;
#[cfg(feature = "sendgrid")]
use sha2::Digest;

#[cfg(feature = "paypal")]
use crate::core::error::VerifyError;
#[cfg(feature = "paypal")]
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
// Aliased: `p256` and the crate's own `sha2`/`ed25519_dalek` already import
// `DecodePublicKey`, `Sha256`, and `Verifier`, which collide here. `rsa`
// re-exports `sha2` 0.10 (its own digest major), not this crate's `sha2` 0.11,
// so the RSA helpers must use the rsa-flavoured hasher.
#[cfg(feature = "paypal")]
use rsa::RsaPublicKey;
#[cfg(feature = "paypal")]
use rsa::pkcs8::DecodePublicKey as RsaDecodePublicKey;
#[cfg(feature = "paypal")]
use rsa::sha2::Sha256 as RsaSha256;
#[cfg(feature = "paypal")]
use rsa::signature::Verifier as RsaSignatureVerifier;
#[cfg(feature = "paypal")]
use rsa::traits::PublicKeyParts as RsaPublicKeyParts;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;
type HmacSha512 = Hmac<Sha512>;

/// Ed25519 public-key length in bytes (compressed Edwards point).
const ED25519_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes (`R` || `S`).
const ED25519_SIG_LEN: usize = 64;

/// Verifies `provided_signature` against HMAC-SHA256(`key`, `signed_string`)
/// using a constant-time comparison.
///
/// Fails closed: if key construction fails (cannot happen for HMAC, which
/// accepts arbitrary-length keys, but the API returns `Result`) this returns
/// `false`. Signature length mismatches also simply compare unequal in
/// constant time — length is public information, so branching on it leaks
/// nothing secret.
#[must_use]
pub(crate) fn verify_hmac_sha256(
    key: &[u8],
    signed_string: &[u8],
    provided_signature: &[u8],
) -> bool {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(signed_string);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided_signature).into()
}

/// Verifies `provided_signature` against HMAC-SHA1(`key`, `signed_string`)
/// using a constant-time comparison.
///
/// Same guarantees as [`verify_hmac_sha256`]. Used by Twilio's scheme, which
/// mandates HMAC-SHA1 (`spec.md` §3); Twilio's own docs note HMAC is not
/// affected by SHA-1's collision attacks given a secret key.
#[must_use]
pub(crate) fn verify_hmac_sha1(
    key: &[u8],
    signed_string: &[u8],
    provided_signature: &[u8],
) -> bool {
    let mut mac = match HmacSha1::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(signed_string);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided_signature).into()
}

/// Verifies `provided_signature` against HMAC-SHA512(`key`, `signed_string`)
/// using a constant-time comparison.
///
/// Same guarantees as [`verify_hmac_sha256`]. Used by [`crate::CustomScheme`]
/// (`spec.md` §2.2), whose `HashAlg::Sha512` option covers long-tail senders
/// standardizing on SHA-512 HMACs.
#[must_use]
pub(crate) fn verify_hmac_sha512(
    key: &[u8],
    signed_string: &[u8],
    provided_signature: &[u8],
) -> bool {
    let mut mac = match HmacSha512::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(signed_string);
    let expected = mac.finalize().into_bytes();
    expected.as_slice().ct_eq(provided_signature).into()
}

/// Verifies an Ed25519 `signature` over `message` against a 32-byte
/// compressed Edwards public key.
///
/// Used for asymmetric schemes (Discord) where the [`Secret`](crate::Secret)
/// holds a *public* key. Fails closed: malformed keys/signatures (wrong
/// length, undecodable point, non-canonical `S`) verify as `false` rather
/// than erroring; callers that need to distinguish operator misconfiguration
/// (bad configured key) from forged input decode/length-check their inputs
/// before calling this.
///
/// Curve arithmetic inside `ed25519-dalek` is constant-time with respect to
/// secret-dependent data; signature bytes and messages are public inputs by
/// construction of the scheme.
#[must_use]
pub(crate) fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key_bytes = match <[u8; ED25519_KEY_LEN]>::try_from(public_key) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(key) => key,
        // A public key that fails point decompression is malformed
        // configuration; treat it like any other unusable key.
        Err(_) => return false,
    };
    if signature.len() != ED25519_SIG_LEN {
        // Length is public information; branching on it leaks nothing secret.
        return false;
    }
    match Signature::from_slice(signature) {
        Ok(sig) => verifying_key.verify(message, &sig).is_ok(),
        Err(_) => false,
    }
}

#[cfg(feature = "sendgrid")]
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcdsaP256Check {
    /// The signature is valid for `message` under the given public key.
    Verified,
    /// The public key bytes are not a parseable ECDSA P-256
    /// `SubjectPublicKeyInfo` (operator configuration issue).
    BadKey,
    /// The signature bytes are not parseable ECDSA DER (wire-encoding issue).
    BadSignature,
    /// The key and signature parse, but the signature does not match.
    Mismatch,
}

/// Verifies an ECDSA P-256 signature over the **pre-hashed** digest of
/// `message` against an SPKI `SubjectPublicKeyInfo` public key (SendGrid).
///
/// The signed-string construction is provider-specific (SendGrid signs the
/// SHA-256 digest of `{timestamp}{raw_body}`); this helper takes the already
/// assembled `message` and hashes it with SHA-256 internally — the digest
/// then being what ECDSA operatively verifies, exactly matching the wire
/// scheme (`spec.md` §3).
///
/// Returns a tri-state so providers can classify configuration errors
/// (`BadKey` → `InvalidSecret`) and wire-encoding errors (`BadSignature` →
/// `BadEncoding`) distinctly from a forgery (`Mismatch` →
/// `SignatureMismatch`). Like [`verify_ed25519`], parsing fails closed to a
/// check result rather than panicking on attacker-controlled or
/// operator-controlled input.
#[cfg(feature = "sendgrid")]
pub(crate) fn check_ecdsa_p256(
    verifying_key_spki: &[u8],
    message: &[u8],
    signature_der: &[u8],
) -> EcdsaP256Check {
    let verifying_key = match EcdsaVerifyingKey::from_public_key_der(verifying_key_spki) {
        Ok(key) => key,
        Err(_) => return EcdsaP256Check::BadKey,
    };
    let signature = match EcdsaSignature::from_der(signature_der) {
        Ok(sig) => sig,
        Err(_) => return EcdsaP256Check::BadSignature,
    };

    let mut hasher = Sha256::new();
    hasher.update(message);
    let digest = hasher.finalize();

    if verifying_key.verify_prehash(&digest, &signature).is_err() {
        return EcdsaP256Check::Mismatch;
    }
    EcdsaP256Check::Verified
}

/// dudect-style statistical timing assertion on the comparison step
/// (`spec.md` §5.7).
///
/// Interleaves two classes of *unequal* inputs — one differing from the
/// expected digest at its first byte, the other at its last byte — and times
/// the exact `subtle::ConstantTimeEq` slice comparison the HMAC helpers use
/// (a 32-byte expected digest against attacker-controlled bytes, precisely
/// the real-world leakage surface). A constant-time comparison must show no
/// statistically significant difference between the classes (Welch's
/// t-statistic near 0); a naive byte comparison that early-exits on the first
/// differing byte leaks a large, reliably detectable signal, because the
/// first-byte-diff class compares one byte while the last-byte-diff class
/// scans all 32.
///
/// The t-threshold of 10 is dudect's conventional leak bound and sits ~10x
/// above the observed noise floor for `subtle` (|t| ~ 1); a naive comparison
/// produces |t| in the hundreds, so the margin is deliberate.
///
/// `#[ignore]`d on purpose (`spec.md` §5.7): timing tests are inherently noisy
/// on shared runners, so CI runs this in release mode as an informational,
/// non-blocking job rather than gating the build on it. Run it locally with:
///
/// ```text
/// cargo test --release --all-features -- constant_time_comparison --ignored
/// ```
#[cfg(all(test, feature = "std"))]
#[test]
#[ignore]
fn constant_time_comparison() {
    use std::hint::black_box;
    use std::time::Instant;
    use subtle::ConstantTimeEq;

    // 32 bytes = HMAC-SHA256's digest size, the most common scheme.
    const EXPECTED: [u8; 32] = [0xAB; 32];
    // Interleaving the two classes back-to-back cancels drift and cache
    // effects: the only systematic difference left is input-dependence in the
    // comparison itself.
    const TRIALS: usize = 100_000;
    const LEAK_T_STAT: f64 = 10.0;

    let diff_first = {
        let mut v = EXPECTED;
        v[0] ^= 0x01;
        v
    };
    let diff_last = {
        let mut v = EXPECTED;
        v[31] ^= 0x01;
        v
    };

    let mut class_first = vec![0u128; TRIALS];
    let mut class_last = vec![0u128; TRIALS];
    for i in 0..TRIALS {
        // The crate's exact comparison step (e.g. `verify_hmac_sha256`):
        // `expected.as_slice().ct_eq(provided).into()`. The result goes to
        // `black_box` so the optimizer cannot drop the computation.
        let t0 = Instant::now();
        let first = black_box(bool::from(EXPECTED.as_slice().ct_eq(&diff_first)));
        let t0 = t0.elapsed().as_nanos();

        let t1 = Instant::now();
        let last = black_box(bool::from(EXPECTED.as_slice().ct_eq(&diff_last)));
        let t1 = t1.elapsed().as_nanos();

        class_first[i] = t0;
        class_last[i] = t1;
        // Keep the results live; identical for both classes (both are
        // mismatches), so this cannot skew the classes against each other.
        black_box((first, last));
    }

    let mean_of = |samples: &[u128]| 0.0f64 + samples.iter().sum::<u128>() as f64 / TRIALS as f64;
    let variance_of = |samples: &[u128], mean: f64| {
        samples
            .iter()
            .map(|t| {
                let delta = *t as f64 - mean;
                delta * delta
            })
            .sum::<f64>()
            / (TRIALS - 1) as f64
    };

    let mean_first = mean_of(&class_first);
    let mean_last = mean_of(&class_last);
    let variance_first = variance_of(&class_first, mean_first);
    let variance_last = variance_of(&class_last, mean_last);

    // Welch's t-statistic for the difference of two means.
    let t_stat = (mean_first - mean_last)
        / (variance_first / TRIALS as f64 + variance_last / TRIALS as f64).sqrt();

    assert!(
        t_stat.abs() <= LEAK_T_STAT,
        "signature comparison shows input-dependent timing (|t| = {t_stat:.1}); \
         a naive/early-exit comparison (or miscompiled constant-time code) has \
         replaced `subtle::ConstantTimeEq` (spec.md §4.1)",
    );
}

/// CRC-32 (IEEE 802.3 / zlib polynomial) of the raw body bytes, matching the
/// checksum PayPal's signed-string construction incorporates (`spec.md` §3).
///
/// Only the raw bytes are hashed — never a re-serialized/re-encoded version
/// (`spec.md` §4): the caller passes `raw_body` through untouched.
#[cfg(feature = "paypal")]
#[must_use]
pub(crate) fn crc32_body(raw_body: &[u8]) -> u32 {
    crc32fast::hash(raw_body)
}

/// Extracts the RSA public key embedded in a DER- or PEM-encoded X.509
/// certificate.
///
/// Only the embedded public key is read; no chain validation, hostname
/// checking, or network fetch is performed (`spec.md` §7 — trust decisions on
/// the certificate are the caller's). Fails closed with
/// [`VerifyError::InvalidSecret`] when the input is not a parseable
/// certificate or does not carry an RSA public key.
#[cfg(feature = "paypal")]
pub(crate) fn extract_rsa_pubkey_from_x509(cert_bytes: &[u8]) -> Result<RsaPublicKey, VerifyError> {
    let invalid = || VerifyError::InvalidSecret {
        reason: "certificate is not a valid X.509 certificate",
    };

    // The certificate (and its DER-contained SPKI raw bytes) is a borrowed
    // view into the input; copy the SPKI out before any owned parser result
    // goes out of scope.
    let subject_spki: alloc::vec::Vec<u8> = if let Ok(x509) =
        x509_parser::parse_x509_certificate(cert_bytes)
    {
        // DER-encoded certificate. Fail closed on trailing garbage so a
        // concatenated/mislabelled buffer is not silently accepted.
        if !x509.0.is_empty() {
            return Err(invalid());
        }
        x509.1.public_key().raw.to_vec()
    } else if let Ok(pem) = x509_parser::pem::parse_x509_pem(cert_bytes) {
        // PEM-encoded certificate; only an exact `CERTIFICATE` block is valid
        // material for this scheme, and trailing whitespace is all that may
        // follow it in the file.
        if pem.1.label != "CERTIFICATE" {
            return Err(invalid());
        }
        if !pem.0.iter().all(u8::is_ascii_whitespace) {
            return Err(invalid());
        }
        let x509 = x509_parser::parse_x509_certificate(&pem.1.contents).map_err(|_| invalid())?;
        if !x509.0.is_empty() {
            return Err(invalid());
        }
        x509.1.public_key().raw.to_vec()
    } else {
        return Err(invalid());
    };

    // Parse the SPKI into an RSA key; a certificate that is not RSA (or not a
    // valid key) is operator misconfiguration, not an attack signal.
    RsaPublicKey::from_public_key_der(&subject_spki).map_err(|_| VerifyError::InvalidSecret {
        reason: "certificate does not contain an RSA public key",
    })
}

/// Outcome of an RSASSA-PKCS1-v1_5 SHA-256 signature check, so providers can
/// classify configuration errors and wire-encoding errors distinctly from a
/// forgery (mirroring [`EcdsaP256Check`]).
#[cfg(feature = "paypal")]
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsaSha256Check {
    /// The signature is valid for `message` under the given public key.
    Verified,
    /// The signature bytes are not a valid RSASSA-PKCS1-v1_5 signature of the
    /// right length for the key.
    BadSignature,
    /// The signature parses but does not match `message`.
    Mismatch,
}

/// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature (PayPal's
/// `SHA256withRSA`, `spec.md` §3) over `message` against the given RSA public
/// key.
///
/// Generates the full PKCS#1 v1.5 DigestInfo prefix internally from the
/// SHA-256 OID — nothing provider-specific about the padding is left to the
/// caller. Parsing fails closed to a check result rather than panicking on
/// attacker- or operator-controlled input.
#[cfg(feature = "paypal")]
pub(crate) fn check_rsa_pkcs1v15_sha256(
    public_key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> RsaSha256Check {
    // RSASSA-PKCS1-v1_5 signatures are exactly `k` bytes for a modulus of `k`
    // bytes. `rsa`'s opaque signature type happily wraps any byte slice, so the
    // length gate is checked here to classify out-of-range wire input as a
    // decoding problem rather than a plain mismatch (mirrors ECDSA's strict
    // DER parse).
    if signature.len() != RsaPublicKeyParts::size(public_key) {
        return RsaSha256Check::BadSignature;
    }
    let verifying_key = RsaVerifyingKey::<RsaSha256>::new(public_key.clone());
    let signature = match RsaSignature::try_from(signature) {
        Ok(sig) => sig,
        Err(_) => return RsaSha256Check::BadSignature,
    };
    if RsaSignatureVerifier::verify(&verifying_key, message, &signature).is_err() {
        return RsaSha256Check::Mismatch;
    }
    RsaSha256Check::Verified
}

#[cfg(test)]
mod tests {
    use super::{verify_ed25519, verify_hmac_sha1, verify_hmac_sha256, verify_hmac_sha512};

    /// Decodes a hardcoded vector; keeps the crate-wide
    /// `clippy::unwrap_used`/`expect_used` denials intact in tests too.
    fn decode(vector: &str) -> Vec<u8> {
        match hex::decode(vector) {
            Ok(bytes) => bytes,
            Err(_) => panic!("hardcoded test vectors must be valid hex"),
        }
    }

    #[test]
    fn matches_known_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let sig = decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert!(verify_hmac_sha256(key, data, &sig));
    }

    #[test]
    fn hmac_sha1_matches_rfc2202_vector() {
        // RFC 2202 test case 2: key "Jefe", data "what do ya want for nothing?"
        let sig = decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        assert!(verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig
        ));
    }

    #[test]
    fn rejects_tampered_and_wrong_length() {
        let sig = decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        let mut flipped = sig.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_hmac_sha256(
            b"Jefe",
            b"what do ya want for nothing?",
            &flipped
        ));
        assert!(!verify_hmac_sha256(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig[..31]
        ));
        assert!(!verify_hmac_sha256(
            b"wrong key",
            b"what do ya want for nothing?",
            &sig
        ));
    }

    #[test]
    fn hmac_sha1_rejects_tampered_and_wrong_length() {
        let sig = decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        let mut flipped = sig.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &flipped
        ));
        assert!(!verify_hmac_sha1(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig[..19]
        ));
    }

    #[test]
    fn hmac_sha512_matches_rfc4231_vector() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
        let sig = decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        );
        assert!(verify_hmac_sha512(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig
        ));
    }

    #[test]
    fn hmac_sha512_rejects_tampered_and_wrong_length() {
        let sig = decode(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        );
        let mut flipped = sig.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_hmac_sha512(
            b"Jefe",
            b"what do ya want for nothing?",
            &flipped
        ));
        assert!(!verify_hmac_sha512(
            b"Jefe",
            b"what do ya want for nothing?",
            &sig[..63]
        ));
    }

    /// Deterministically derives an Ed25519 keypair from `seed` and signs
    /// `message`; used to build local test vectors without pulling in a RNG.
    fn sign_with_seed(seed: [u8; 32], message: &[u8]) -> ([u8; 32], Vec<u8>) {
        use ed25519_dalek::Signer;

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(message);
        (*verifying_key.as_bytes(), sig.to_bytes().to_vec())
    }

    #[test]
    fn ed25519_verifies_genuine_signature() {
        let (public_key, signature) = sign_with_seed([7u8; 32], b"hello");
        assert!(verify_ed25519(&public_key, b"hello", &signature));
    }

    #[test]
    fn ed25519_rejects_tampered_malformed_and_wrong_key() {
        let (public_key, signature) = sign_with_seed([7u8; 32], b"hello");

        // Tampered message.
        assert!(!verify_ed25519(&public_key, b"hellO", &signature));

        // Tampered signature byte.
        let mut flipped = signature.clone();
        flipped[0] ^= 0x01;
        assert!(!verify_ed25519(&public_key, b"hello", &flipped));

        // Wrong length signature (63/65 bytes).
        assert!(!verify_ed25519(&public_key, b"hello", &signature[..63]));
        let mut padded = signature.clone();
        padded.push(0);
        assert!(!verify_ed25519(&public_key, b"hello", &padded));

        // Wrong-length public key.
        assert!(!verify_ed25519(&public_key[..31], b"hello", &signature));

        // Non-canonical / non-decodable public key (all-ones is not a valid
        // compressed point encoding).
        let bad_point = [0xffu8; 32];
        assert!(!verify_ed25519(&bad_point, b"hello", &signature));

        // Different key entirely.
        let (other_key, _) = sign_with_seed([8u8; 32], b"hello");
        assert!(!verify_ed25519(&other_key, b"hello", &signature));

        // Empty inputs fail closed instead of panicking.
        assert!(!verify_ed25519(b"", b"hello", &signature));
        assert!(!verify_ed25519(&public_key, b"", &[]));
    }

    #[cfg(feature = "paypal")]
    mod paypal {
        use super::super::{check_rsa_pkcs1v15_sha256, crc32_body, extract_rsa_pubkey_from_x509};
        use crate::core::crypto::RsaSha256Check;
        use crate::core::error::VerifyError;
        use crate::core::secret::Secret;
        use crate::test_helpers::clocked_at;
        use crate::verify;
        use base64::Engine;
        use std::time::Duration;

        // Fixture provenance: the body, transmission ID/time, and webhook ID
        // are PayPal's own published example (developer.paypal.com "Verify
        // webhook signature" / "Integrate webhooks" REST docs). The X.509
        // certificate, the CRC-32 (Python `zlib.crc32`, independent of this
        // crate) and the RSA signature are locally generated for this test
        // over exactly the documented `transmission_id|transmission_time|
        // webhook_id|crc32` construction; the private key is not committed.
        const TRANSMISSION_ID: &str = "db49fb10-1343-11ef-ac58-e32457403f67";
        const TRANSMISSION_TIME: &str = "2024-05-16T05:19:23Z";
        const WEBHOOK_ID: &str = "0NH55953DH663215D";
        const CRC32_DECIMAL: u32 = 1_529_064_350;
        const SIGNATURE_B64: &str = "aGYe/s6lwrASh2zyTRIAz8Edo705ezMKekirejT08ev3VXdWAkq4JWADiNPUGelx5qrEKxC7mPIHmAwQ5hOT6unhY9n33M/DbXTKGsuITPdXRA7qYVmc2wsIp68BpzB6pC6+5vt/YLQvflsrwrutGa0KyZc5FinuYNN8pTNomv4uiygasWqfnDyKViKQPNZecowag6tY/9pj7+bgBu/joBpYUq0+cQxfGqNnlvywBJ7HCOf4edeTIvM/c1CvvAHGtNTU54kLjWGue640twn6iXPL8tnaABZ8Fr9m0z87v8oY0vBobERV0Yu8thUToKhvQEFF26Rckqy07VVddg1CmA==";
        const CERT_PEM: &[u8] = include_bytes!("../../tests/data/paypal_test_cert.pem");
        const OTHER_CERT_PEM: &[u8] = include_bytes!("../../tests/data/paypal_other_cert.pem");
        const BODY: &[u8] = include_bytes!("../../tests/data/paypal_docs_body.json");

        fn signature_bytes() -> Vec<u8> {
            match base64::engine::general_purpose::STANDARD.decode(SIGNATURE_B64) {
                Ok(bytes) => bytes,
                Err(_) => panic!("test-vector base64 must decode"),
            }
        }

        /// The exact signed string the frozen signature covers.
        fn signed_message() -> Vec<u8> {
            format!("{TRANSMISSION_ID}|{TRANSMISSION_TIME}|{WEBHOOK_ID}|{CRC32_DECIMAL}")
                .into_bytes()
        }

        fn rsa_key() -> rsa::RsaPublicKey {
            match extract_rsa_pubkey_from_x509(CERT_PEM) {
                Ok(key) => key,
                Err(_) => panic!("the committed test certificate must parse"),
            }
        }

        #[test]
        fn crc32_body_matches_independently_computed_vector() {
            // 1,529,064,350 was computed with Python's `zlib.crc32` (the same
            // IEEE CRC-32/ISO-HDLC the official PayPal sample code uses) over
            // the committed body bytes, independently of this crate.
            assert_eq!(crc32_body(BODY), CRC32_DECIMAL);
        }

        #[test]
        fn crc32_body_is_over_raw_bytes_and_is_deterministic() {
            // Same input, same output; and it is the raw bytes that are
            // checksummed, so re-serializing would change the result.
            assert_eq!(crc32_body(b"{}"), crc32_body(b"{}"));
            assert_ne!(crc32_body(b"{}"), crc32_body(b"{ }"));
            assert_ne!(crc32_body(BODY), crc32_body(b""));
        }

        #[test]
        fn extract_pubkey_accepts_pem_and_der() {
            let from_pem = match extract_rsa_pubkey_from_x509(CERT_PEM) {
                Ok(key) => key,
                Err(_) => panic!("PEM certificate must parse"),
            };

            let pem = match x509_parser::pem::parse_x509_pem(CERT_PEM) {
                Ok((_, pem)) => pem,
                Err(_) => panic!("PEM must parse"),
            };
            let from_der = match extract_rsa_pubkey_from_x509(&pem.contents) {
                Ok(key) => key,
                Err(_) => panic!("DER certificate must parse"),
            };
            assert_eq!(from_pem, from_der);
        }

        #[test]
        fn extract_pubkey_fails_closed_on_garbage() {
            assert_eq!(
                extract_rsa_pubkey_from_x509(b"definitely not a certificate"),
                Err(VerifyError::InvalidSecret {
                    reason: "certificate is not a valid X.509 certificate"
                })
            );
            assert_eq!(
                extract_rsa_pubkey_from_x509(b""),
                Err(VerifyError::InvalidSecret {
                    reason: "certificate is not a valid X.509 certificate"
                })
            );
            // A valid DER certificate with trailing garbage must fail closed
            // too (concatenated/mislabelled buffers are not accepted).
            let pem = match x509_parser::pem::parse_x509_pem(CERT_PEM) {
                Ok((_, pem)) => pem,
                Err(_) => panic!("PEM must parse"),
            };
            let mut der_with_garbage = pem.contents;
            der_with_garbage.push(0xde);
            assert!(matches!(
                extract_rsa_pubkey_from_x509(&der_with_garbage),
                Err(VerifyError::InvalidSecret { .. })
            ));
        }

        #[test]
        fn check_rsa_verifies_the_frozen_vector() {
            let key = rsa_key();
            let msg = signed_message();
            let sig = signature_bytes();
            assert_eq!(
                check_rsa_pkcs1v15_sha256(&key, &msg, &sig),
                RsaSha256Check::Verified
            );
        }

        #[test]
        fn check_rsa_classifies_wrong_length_signature() {
            let key = rsa_key();
            let msg = signed_message();
            let sig = signature_bytes();
            assert_eq!(
                check_rsa_pkcs1v15_sha256(&key, &msg, &sig[..sig.len() - 1]),
                RsaSha256Check::BadSignature
            );
            assert_eq!(
                check_rsa_pkcs1v15_sha256(&key, &msg, &[]),
                RsaSha256Check::BadSignature
            );
        }

        #[test]
        fn check_rsa_rejects_tampered_message_and_wrong_key() {
            let key = rsa_key();
            let other_key = match extract_rsa_pubkey_from_x509(OTHER_CERT_PEM) {
                Ok(key) => key,
                Err(_) => panic!("the committed other certificate must parse"),
            };
            let msg = signed_message();
            let sig = signature_bytes();

            // Flipped signature byte.
            let mut flipped = sig.clone();
            flipped[0] ^= 0x01;
            assert_eq!(
                check_rsa_pkcs1v15_sha256(&key, &msg, &flipped),
                RsaSha256Check::Mismatch
            );

            // Tampered message (a different signed string).
            let mut tampered = msg.clone();
            tampered[0] = if tampered[0] == b'd' { b'D' } else { b'd' };
            assert_eq!(
                check_rsa_pkcs1v15_sha256(&key, &tampered, &sig),
                RsaSha256Check::Mismatch
            );

            // Valid signature under a different key.
            assert_eq!(
                check_rsa_pkcs1v15_sha256(&other_key, &msg, &sig),
                RsaSha256Check::Mismatch
            );
        }

        #[test]
        fn full_pipeline_verifies_the_official_construction() {
            // The end-to-end proof: the frozen signature — produced over the
            // documented PayPal construction — verifies through `verify()`.
            let options = clocked_at(1_715_836_763, Some(Duration::from_secs(300)))
                .with_webhook_id(WEBHOOK_ID)
                .with_verifying_material(
                    crate::core::options::VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()),
                );
            let headers = [
                ("PayPal-Transmission-Id", TRANSMISSION_ID),
                ("PayPal-Transmission-Time", TRANSMISSION_TIME),
                ("PayPal-Transmission-Sig", SIGNATURE_B64),
                ("PayPal-Cert-Url", "https://example.invalid/cert"),
                ("PayPal-Auth-Algo", "SHA256withRSA"),
            ];
            assert_eq!(
                verify(
                    crate::Provider::PayPal,
                    &headers,
                    BODY,
                    &Secret::new("unused"),
                    options,
                ),
                Ok(())
            );
        }
    }
}
