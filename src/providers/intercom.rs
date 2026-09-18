//! Intercom webhook signature verification.
//!
//! Scheme, per Intercom's official "Webhook Topics" reference
//! (<https://developers.intercom.com/docs/references/2.5/webhooks/webhook-models>):
//!
//! > Each webhook notification is signed by Intercom via an `X-Hub-Signature`
//! > header ... computed by creating a signature using the body of the JSON
//! > request and your app's `client_secret` value ... The signature is the
//! > hexadecimal (40-byte) representation of a SHA-1 signature computed using
//! > the HMAC algorithm as defined in RFC2104. The `X-Hub-Signature` header
//! > value starts with the string `sha1=` followed by the signature.
//!
//! - Header: `X-Hub-Signature: sha1=<hex(HMAC-SHA1(secret, raw_body))>` — 40
//!   hex characters (20 bytes), a `sha1=`-prefixed digest over the raw request
//!   body.
//! - Signed string: the raw request body bytes, unmodified. Intercom signs the
//!   body
//!   exactly as delivered, so re-serializing or reformatting the payload (JSON
//!   key order, whitespace, escapes) changes the signature.
//! - Algorithm: HMAC-SHA1, hex-encoded (lowercase hex from Intercom; decoding
//!   here is case-insensitive). Intercom is, like Twilio, a scheme that still
//!   legitimately mandates SHA-1 — the docs' reference construction is
//!   `HMAC(secret, body)` keyed with a shared secret, which HMAC's keyed use
//!   makes immune to SHA-1's collision attacks (same rationale as Twilio,
//!   `spec.md` §3).
//! - Key: the app's `client_secret` (Developer Hub → Basic Info) as its UTF-8
//!   bytes verbatim.
//!
//! The `sha1=` prefix is matched case-sensitively, exactly like GitHub's and
//! Bitbucket's `sha256=` (`spec.md` §3): the docs emit only the literal
//! lowercase form, and an unknown scheme fails closed as `MalformedHeader`
//! rather than silently mis-verifying.
//!
//! # Replay protection
//!
//! Intercom does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider (`spec.md` §3).
//! Intercom signs every webhook delivery (no unsigned "test mode"), so a
//! request without the header is never a legitimate delivery and `verify()`
//! reports `MissingHeader`.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha1;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Intercom's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Hub-Signature";

/// Required prefix of the header value.
const SIGNATURE_PREFIX: &str = "sha1=";

/// HMAC-SHA1 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 20;

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
    if verify_hmac_sha1(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `X-Hub-Signature` into its 20 decoded signature bytes.
///
/// Every failure mode maps to a distinct error variant so callers can tell
/// malformed-request noise from signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    // `get(..len)` instead of slicing: a multibyte character straddling the
    // prefix boundary must yield an error, never a panic (attacker-controlled).
    let hex_part = match value.get(..SIGNATURE_PREFIX.len()) {
        Some(prefix) if prefix == SIGNATURE_PREFIX => &value[SIGNATURE_PREFIX.len()..],
        _ => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "missing `sha1=` prefix",
            });
        }
    };

    if hex_part.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "empty signature after `sha1=` prefix",
        });
    }

    let bytes = hex::decode(hex_part).map_err(|_| VerifyError::BadEncoding {
        reason: "signature is not valid hexadecimal",
    })?;

    if bytes.len() != SIGNATURE_LEN_BYTES {
        return Err(VerifyError::BadEncoding {
            reason: "signature does not decode to 20 bytes",
        });
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::secret::Secret;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// Intercom publishes the header format and an example header value
    /// (`sha1=21ff2e149e0fdcac6f947740f6177f6434bda921`) on the "Webhook
    /// Topics" reference page, but no byte-exact signed body (the page shows
    /// the header next to an example POST with no body, and the `client_secret`
    /// is account-specific), so vectors are locally constructed over exactly
    /// the documented construction (`base64`-free: `sha1=` + lowercase hex of
    /// `HMAC-SHA1(client_secret, raw_body)`) and cross-checked with
    /// `openssl dgst -sha1 -hmac` and Python's `hmac` module. Replace them if
    /// Intercom ever publishes fixed vectors.
    const OFFICIAL_SECRET: &str = "intercom-client-secret-for-testing";

    /// Body mirrors the shape of Intercom's documented `notification_event`
    /// delivery (the example on the same docs page) — a real delivery is a
    /// JSON object but its exact bytes are what get signed, so the vector body
    /// is the exact byte string that was hashed.
    const PRIMARY_BODY: &[u8] =
        b"{\"type\":\"notification_event\",\"app_id\":\"abc123\",\"data\":{\"type\":\"notification_event_data\",\"item\":{\"type\":\"ticket\",\"id\":\"5\"}}}";

    /// Locally constructed with:
    /// `printf '{"type":"notification_event",...}' | openssl dgst -sha1 -hmac "intercom-client-secret-for-testing"`
    const PRIMARY_SIGNATURE: &str = "cbf9bf16f89d9cf089ee3500c5ba94595b3aedcd";

    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha1 -hmac "intercom-client-secret-for-testing"`
    const EMPTY_BODY_SIGNATURE: &str = "791cab26adf4ef564b06818281a43afef3880572";

    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha1 -hmac "intercom-client-secret-for-testing"`
    const UNICODE_BODY_SIGNATURE: &str = "d72606999d26b9d813065af8727267d2e8aecc07";

    fn intercom_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("sha1={signature}"))]
    }

    fn verify_primary(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Intercom,
            &intercom_headers(signature),
            body,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        )
    }

    #[test]
    fn vector_over_documented_construction_verifies() {
        // The primary vector: HMAC-SHA1 over the exact received JSON bytes,
        // keyed with the client_secret verbatim, `sha1=`-prefixed hex.
        assert_eq!(verify_primary(PRIMARY_BODY, PRIMARY_SIGNATURE), Ok(()));
    }

    #[test]
    fn locally_constructed_boundary_bodies_verify() {
        assert_eq!(verify_primary(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_primary("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Intercom,
            &[(
                "x-hub-signature",
                format!("sha1={PRIMARY_SIGNATURE}").as_str(),
            )],
            PRIMARY_BODY,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = PRIMARY_SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_primary(PRIMARY_BODY, &upper), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let sig = format!(
            "{}{}{}",
            &PRIMARY_SIGNATURE[..10],
            if PRIMARY_SIGNATURE[10..11] == *"0" {
                "1"
            } else {
                "0"
            },
            &PRIMARY_SIGNATURE[11..]
        );
        assert_ne!(sig, PRIMARY_SIGNATURE);
        assert_eq!(
            verify_primary(PRIMARY_BODY, &sig),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Same construction but a single byte of the body differs — the JSON
        // must not be re-serialized before hashing, so any byte change
        // invalidates the signature.
        let tampered = b"{\"type\":\"notification_events\",\"app_id\":\"abc123\"}";
        assert_ne!(tampered, PRIMARY_BODY);
        assert_eq!(
            verify_primary(tampered, PRIMARY_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Intercom,
            &intercom_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new("a different client_secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_intercom() {
        // Intercom signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. This pins the documented
        // "max_age ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Intercom,
            &intercom_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new(OFFICIAL_SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Intercom,
            &Vec::<(String, String)>::new(),
            PRIMARY_BODY,
            &Secret::new(OFFICIAL_SECRET),
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
    fn malformed_header_shapes_error_distinctly() {
        let cases: &[(&str, VerifyError)] = &[
            (
                "",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                "sha1=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `sha1=` prefix",
                },
            ),
            (
                "deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
            (
                "sha256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
            (
                "SHA1=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
            (
                "Sha1=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Intercom,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: &[&str] = &[
            // Not hex at all.
            "sha1=zzzz",
            // Valid hex but odd number of digits.
            "sha1=abc",
            // Valid hex but not 20 bytes (SHA-256 length).
            "sha1=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
            // Valid hex but wrong length (40 bytes).
            "sha1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::Intercom,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}