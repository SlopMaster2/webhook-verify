//! WooCommerce webhook signature verification.
//!
//! Scheme, per WooCommerce's official documentation
//! (<https://developer.woocommerce.com/docs/apis/rest-api/v3/webhooks> — the
//! delivery-header reference lists `X-WC-Webhook-Signature` as "a base64
//! encoded HMAC-SHA256 hash of the payload") and the `WC_Webhook` reference
//! implementation
//! (<https://woocommerce.github.io/code-reference/classes/WC-Webhook.html>:
//! "Generate a base64-encoded HMAC-SHA256 signature of the payload body so the
//! recipient can verify the authenticity of the webhook. Note that the
//! signature is calculated after the body has already been encoded"):
//!
//! - Header: `X-WC-Webhook-Signature: <base64(HMAC-SHA256(secret, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified
//! - Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet with
//!   padding) — not hex, the same base64 bug class as Shopify and Xero
//!   (`spec.md` §3)
//! - Key: the webhook's `secret` (configured on the WooCommerce webhook) as
//!   its UTF-8 bytes, used verbatim — WooCommerce never base64/hex-decodes it
//!
//! # Replay protection
//!
//! WooCommerce does not sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the injected
//! clock have **no effect** for this provider; that is documented behavior,
//! not an oversight (`spec.md` §3). WooCommerce's own guidance is to dedupe on
//! the payload's `id`, which is outside this crate's scope (payload parsing is
//! a non-goal, §1).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying WooCommerce's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-WC-Webhook-Signature";

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

/// Parses `X-WC-Webhook-Signature` into its 32 decoded signature bytes.
///
/// The value carries no `algo=` prefix — it is bare base64. Every failure mode
/// maps to a distinct error variant so callers can tell malformed-request noise
/// from signature-mismatch signals (`spec.md` §2.1).
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

    const SECRET: &str = "woocommerce_test_secret";
    /// A webhook-shaped order payload (WooCommerce delivers JSON with the
    /// resource under an `id` field; the body is opaque to this crate).
    const BODY: &[u8] = br#"{"id":12345,"status":"processing","total":"19.99"}"#;
    /// Locally constructed:
    /// `printf '{"id":12345,"status":"processing","total":"19.99"}' | openssl dgst -sha256 -hmac "woocommerce_test_secret" -binary | base64`
    ///
    /// WooCommerce's docs and `WC_Webhook::generate_signature` reference
    /// describe the scheme but publish no byte-exact secret/body/signature
    /// triple, so vectors here are locally constructed against the documented
    /// recipe (`spec.md` §3, WooCommerce row).
    const SIGNATURE: &str = "SpTlDXndFNEBUo78JKFJzn0qlYB/8i064vyc5QaK4j8=";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "qO0MyI9UM3Vsq/2HgthPAdHTOabuxPocm5B5xlDrxMY=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "fog6dwt7NsD52pt2rgU1Knw1c+M7T4orn6FKZEP3J2w=";

    fn woocommerce_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::WooCommerce,
            &woocommerce_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn constructed_vector_verifies() {
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
        let result = verify(
            crate::Provider::WooCommerce,
            &[("x-wc-webhook-signature", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}B{}", &SIGNATURE[..3], &SIGNATURE[4..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        assert_eq!(
            verify_with(
                br#"{"id":12345,"status":"completed","total":"19.99"}"#,
                SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::WooCommerce,
            &woocommerce_headers(SIGNATURE),
            BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_woocommerce() {
        // WooCommerce signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::WooCommerce,
            &woocommerce_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::WooCommerce,
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
                crate::Provider::WooCommerce,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        let value = "SpTlDXndFNEBUo78JKFJzn0qlYB/8i064vyc5QaK4j8";
        let result = verify(
            crate::Provider::WooCommerce,
            &[(SIGNATURE_HEADER, value)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        match result {
            Err(VerifyError::BadEncoding { .. }) => {}
            other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
        }
    }
}
