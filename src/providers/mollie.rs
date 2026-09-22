//! Mollie (next-gen) webhook signature verification.
//!
//! Scheme, per Mollie's official "Next-gen webhooks" documentation
//! (<https://docs.mollie.com/reference/webhooks-new>):
//!
//! - Header: `X-Mollie-Signature: sha256=<hex(HMAC-SHA256(secret, raw_body))>`
//! - Signed string: the unaltered raw request body bytes
//! - Algorithm: HMAC-SHA256, hex-encoded
//! - Key: the signing secret configured at webhook setup, used verbatim as
//!   its UTF-8 bytes (never decoded)
//!
//! The construction matches Mollie's official reference
//! implementations (`hash_hmac('sha256', $payload, $secret)` in
//! `mollie-api-php`'s `SignatureValidator`,
//! <https://github.com/mollie/mollie-api-php/blob/main/src/Webhooks/SignatureValidator.php>,
//! which strips the prefix with a `strpos(..., 'sha256=') === 0` check and
//! compares with `hash_equals`, and the equivalent `SignatureValidator`
//! helpers in the official Python and Go SDKs). Mollie's SDKs tolerate a
//! bare hex value without the prefix; this crate requires the documented
//! `sha256=` prefix exactly like GitHub (the signer always emits it).
//!
//! # Replay protection
//!
//! Mollie signs the body only — no timestamp — so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).
//!
//! # Key rotation
//!
//! During the documented 24-hour rotation window Mollie attaches **two**
//! `X-Mollie-Signature` headers per event (one per secret). `verify()` reads
//! the first header value, so callers rotating secrets must keep the previous
//! secret until the window closes and verify against each — at least one of
//! those `verify()` calls will pass (`spec.md` §3).
//!
//! # Scope
//!
//! Only Mollie's next-gen signed webhooks are covered. Classic payment
//! webhooks (the `webhookUrl` deliveries that POST a single
//! `id=<resource_id>` form field) are unsigned and send no signature header.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Mollie's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Mollie-Signature";

/// Required prefix of the header value.
const SIGNATURE_PREFIX: &str = "sha256=";

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

/// Parses `X-Mollie-Signature` into its 32 decoded signature bytes.
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
                reason: "missing `sha256=` prefix",
            });
        }
    };

    if hex_part.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "empty signature after `sha256=` prefix",
        });
    }

    let bytes = hex::decode(hex_part).map_err(|_| VerifyError::BadEncoding {
        reason: "signature is not valid hexadecimal",
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
    use crate::core::secret::Secret;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    // Test-vector provenance (spec.md §3): Mollie's docs publish the header
    // shape (`sha256=4a4c6f3e...`) but no byte-exact secret/body/signature
    // triple, so the vectors below are locally constructed over the documented
    // construction and cross-checked with both `openssl dgst -sha256 -hmac`
    // and Python's `hashlib`/`hmac`. The primary body mirrors the
    // `payment-link.paid` simple-payload example event from Mollie's
    // next-gen webhooks docs. Replace the vectors if Mollie ever publishes
    // fixed ones.
    const TEST_SECRET: &str = "test-signing-secret";
    const PRIMARY_BODY: &[u8] = b"{\"resource\":\"event\",\"id\":\"event_GvJ8WHrp5isUdRub9CJyH\",\"type\":\"payment-link.paid\",\"entityId\":\"pl_qng5gbbv8NAZ5gpM5ZYgx\",\"createdAt\":\"2024-12-16T15:59:04.0Z\",\"_links\":{\"self\":{\"href\":\"https://api.mollie.com/v2/events/event_GvJ8WHrp5isUdRub9CJyH\",\"type\":\"application/hal+json\"},\"documentation\":{\"href\":\"https://docs.mollie.com/guides/webhooks\",\"type\":\"text/html\"}}}";
    const PRIMARY_SIGNATURE: &str =
        "726eb72833c59fe944cf728b37d95e900329c598cd77addfd1afeceb195e6a54";
    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha256 -hmac "test-signing-secret"`
    const EMPTY_BODY_SIGNATURE: &str =
        "e6002cfc6ef5b3af2909dacc72e87fecd37768d9031a517806765b06ec0ce4fe";
    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha256 -hmac "test-signing-secret"`
    const UNICODE_BODY_SIGNATURE: &str =
        "f5b3b6e67d67a56748d4ac80714c5ef7b66b79e28ffcf92c3a66d175d851b87f";

    fn mollie_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("sha256={signature}"))]
    }

    fn verify_official(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Mollie,
            &mollie_headers(signature),
            body,
            &Secret::new(TEST_SECRET),
            Default::default(),
        )
    }

    #[test]
    fn docs_example_event_with_constructed_signature_verifies() {
        assert_eq!(verify_official(PRIMARY_BODY, PRIMARY_SIGNATURE), Ok(()));
    }

    #[test]
    fn locally_constructed_boundary_bodies_verify() {
        assert_eq!(verify_official(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_official("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Mollie,
            &[(
                "x-mollie-signature",
                "sha256=726eb72833c59fe944cf728b37d95e900329c598cd77addfd1afeceb195e6a54",
            )],
            PRIMARY_BODY,
            &Secret::new(TEST_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = PRIMARY_SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_official(PRIMARY_BODY, &upper), Ok(()));
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
            verify_official(PRIMARY_BODY, &sig),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let tampered = b"{\"resource\":\"event\",\"id\":\"event_tampered\"}";
        assert_eq!(
            verify_official(tampered, PRIMARY_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Mollie,
            &mollie_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new("a different signing secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_mollie() {
        // Mollie signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. This pins the documented
        // "max_age ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Mollie,
            &mollie_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new(TEST_SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Mollie,
            &Vec::<(String, String)>::new(),
            PRIMARY_BODY,
            &Secret::new(TEST_SECRET),
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
                "sha256=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `sha256=` prefix",
                },
            ),
            (
                "deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "sha1=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "SHA256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "Sha256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Mollie,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: &[&str] = &[
            // Not hex at all.
            "sha256=zzzz",
            // Valid hex but odd number of digits.
            "sha256=abc",
            // Valid hex but not 32 bytes (SHA-1 length).
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::Mollie,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
