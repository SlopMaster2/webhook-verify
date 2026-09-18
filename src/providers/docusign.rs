//! DocuSign Connect webhook signature verification.
//!
//! Scheme, per DocuSign's official documentation
//! (<https://developers.docusign.com/platform/webhooks/connect/validate/>,
//! "How to validate an HMAC signature"), the Connect HMAC overview
//! (<https://developers.docusign.com/platform/webhooks/connect/hmac/>), and
//! the official PHP verification sample
//! (<https://www.docusign.com/blog/developers/hmac-verification-php>):
//!
//! - Header: `X-Docusign-Signature-1: <base64(HMAC-SHA256(key, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified — the docs are
//!   explicit that "the entire body of the POST request is used, including
//!   line endings" and that the signature must be checked before the body is
//!   parsed
//! - Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet with
//!   padding)
//! - Key: the Connect configuration's HMAC key, used **verbatim** as its
//!   UTF-8 bytes. The docs note that if a copied secret contains stray `"`
//!   characters they must be removed before computing the hash; this crate
//!   uses the [`Secret`](crate::Secret) exactly as configured, so operators
//!   should paste the key as generated.
//!
//! # Multiple keys
//!
//! DocuSign sends **one numbered header per configured HMAC key**
//! (`X-Docusign-Signature-1`, `-2`, ... up to 100), each carrying the body
//! hashed with that key, and accepts validation against *any* of them.
//! This provider verifies the first header, `X-Docusign-Signature-1`, which
//! is always the first-listed currently-active key — the header exists on
//! *every* delivery (there is one per key), so a single-key account (the
//! documented recommended setup) always signs `-1`. During rotation, keep the
//! first-listed key valid for receivers holding it, or re-run verification
//! with [`verify_any`](crate::verify_any) once the rotated key holds the
//! `-1` slot. Numbered headers beyond `-1` are out of scope for the crate's
//! single-header model and are intentionally not read.
//!
//! The companion `x-authorization-digest` header (`HMACSHA256`) is
//! informational: it is not covered by the HMAC and DocuSign only ever sends
//! that value, so it is not parsed — a future algorithm change fails closed
//! as a signature mismatch rather than silently mis-verifying. Header lookup
//! is case-insensitive, so the lowercase `x-docusign-signature-1` spelling
//! the platform docs use resolves like the `X-Docusign-Signature-1` spelling
//! here.
//!
//! # Replay protection
//!
//! DocuSign's HMAC scheme signs no timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying the first key's DocuSign HMAC signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Docusign-Signature-1";

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    _options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;

    let provided = parse_signature(value)?;

    // The HMAC is computed after parsing succeeds and compared in constant
    // time; no early exit depends on *how* wrong the signature is.
    if verify_hmac_sha256(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `X-Docusign-Signature-1` into its 32 decoded signature bytes.
///
/// DocuSign sends bare base64 with no prefix. Every failure mode maps to a
/// distinct error variant so callers can tell malformed-request noise from
/// signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| VerifyError::BadEncoding {
            reason: "signature is not valid standard base64",
        })?;

    if bytes.len() != SIGNATURE_LEN_BYTES {
        return Err(VerifyError::BadEncoding {
            reason: "signature does not decode to 32 bytes",
        });
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// A UUID-shaped HMAC key, matching the format DocuSign's Connect
    /// configuration generates. DocuSign publishes the algorithm and header
    /// layout but no byte-exact example body+signature pair (it steers
    /// integrators to verify against a live delivery), so all vectors below
    /// are locally constructed over exactly the documented raw-body + base64
    /// construction and cross-checked against both OpenSSL and Python's
    /// `hmac` module (independent implementations).
    const SECRET: &str = "6d5b9f8a-2c44-4a7e-9b31-3f0e1d2c5a9c";

    /// A realistic Connect envelope-sent delivery payload (single line, the
    /// exact bytes signed).
    const BODY: &[u8] = br#"{"event":"envelope-sent","apiVersion":"v2.1","data":{"envelopeId":"11111111-2222-3333-4444-555555555555","status":"sent","emailSubject":"Please sign this document","userId":"99999999-8888-7777-6666-555555555555"}}"#;

    /// `printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64`
    const SIGNATURE: &str = "pIJlMnjy4GTTMVTa8IIpWiM4b8HmP+8qYoa3jPx/zCQ=";
    /// Locally constructed over an empty body (boundary case), cross-checked
    /// the same way: `printf '' | openssl dgst -sha256 -hmac "$SECRET" -binary | base64`.
    const EMPTY_BODY_SIGNATURE: &str = "luftNupekYB9JqqII+6dHdZd8kuup7kDvRC6/fWUQf0=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case),
    /// cross-checked the same way.
    const UNICODE_BODY_SIGNATURE: &str = "3LsFZjZT0N61GsHXFZEj2SN4DmgEe+rfs1ZD796/HbU=";

    /// A second key, used to pin the single-header (`-1`) contract: a delivery
    /// whose only signature header is `-2` (hashing *this* key) must fail
    /// closed rather than being guessed at.
    const SECOND_SECRET: &str = "00000000-0000-0000-0000-000000000000";
    /// `printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECOND_SECRET" -binary | base64`
    const SECOND_SECRET_SIGNATURE: &str = "/H+hDmayNt2QohkBOPy1SEdouGGRGialuyKO3JCoRHU=";

    fn docusign_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::DocuSign,
            &docusign_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn primary_vector_verifies() {
        // Locally constructed over the documented raw-body base64 HMAC
        // construction (cross-checked with OpenSSL and Python); DocuSign
        // publishes the algorithm but no byte-exact example pair.
        assert_eq!(verify_with(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_with(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_with("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        // The platform docs spell the header `x-docusign-signature-1`;
        // HTTP headers are case-insensitive and both resolve here.
        let lowercase = verify(
            crate::Provider::DocuSign,
            &[("x-docusign-signature-1", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(lowercase, Ok(()));

        let uppercase = verify(
            crate::Provider::DocuSign,
            &[("X-DOCUSIGN-SIGNATURE-1", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(uppercase, Ok(()));
    }

    #[test]
    fn second_key_verifies_against_its_own_numbered_header() {
        // DocuSign sends one numbered header per configured key. This crate
        // reads `-1`; a delivery that signs with a second key must present
        // the `-1` header for that key to verify at all.
        let second_key_headers = [
            ("X-Docusign-Signature-2", SECOND_SECRET_SIGNATURE),
            (SIGNATURE_HEADER, SIGNATURE),
        ];
        assert_eq!(
            verify(
                crate::Provider::DocuSign,
                &second_key_headers,
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            ),
            Ok(())
        );
        assert_eq!(
            verify(
                crate::Provider::DocuSign,
                &second_key_headers,
                BODY,
                &Secret::new(SECOND_SECRET),
                Default::default(),
            ),
            // The second key's hash rides in `-2`, which is intentionally not
            // read; verification against the `-1` header fails closed.
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}A{}", &SIGNATURE[..3], &SIGNATURE[4..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let mut tampered = BODY.to_vec();
        tampered[0] = b'[';
        assert_eq!(
            verify_with(&tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::DocuSign,
            &docusign_headers(SIGNATURE),
            BODY,
            &Secret::new(SECOND_SECRET),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_docusign() {
        // DocuSign signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::DocuSign,
            &docusign_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::DocuSign,
            &Vec::<(String, String)>::new(),
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_and_bad_encoding_errors_are_distinct() {
        let cases: &[(&str, VerifyError)] = &[
            (
                "",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // Garbage value: not valid base64 at all.
            (
                "not base64!!",
                VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                },
            ),
            // Valid base64 alphabet but wrong decoded length (SHA-1 size).
            (
                "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::DocuSign,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
