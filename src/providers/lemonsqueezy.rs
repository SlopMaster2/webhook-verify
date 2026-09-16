//! Lemon Squeezy webhook signature verification.
//!
//! Scheme, per Lemon Squeezy's official documentation
//! (<https://docs.lemonsqueezy.com/help/webhooks/signing-requests> and
//! <https://docs.lemonsqueezy.com/help/webhooks/webhook-requests>):
//!
//! - Header: `X-Signature: <hex_hmac>` — a bare lower/uppercase hex digest,
//!   no prefix like `sha256=` (unlike GitHub/Notion).
//! - Signed string: the raw request body bytes, unmodified. Lemon Squeezy's
//!   own docs stress that the exact received bytes matter — their delivery
//!   JSON escapes `/` as `\/` in opaquely-checked fields, and any framework
//!   that parses and re-serializes the payload before hashing changes the
//!   bytes and fails verification (this crate hashes `raw_body` exactly as
//!   received by construction, `spec.md` §4.2).
//! - Algorithm: HMAC-SHA256, hex-encoded. Key: the webhook's signing secret
//!   as its UTF-8 bytes, matching the docs' reference implementations
//!   (`crypto.createHmac('sha256', secret).update(rawBody).digest('hex')`).
//!
//! # Replay protection
//!
//! Lemon Squeezy does **not** sign a timestamp (the delivery carries
//! `Content-Type`, `X-Event-Name`, and `X-Signature` headers only), so replay
//! protection cannot be provided at the signature layer.
//! [`VerifyOptions::max_age`] and the injected clock have **no effect** for
//! this provider; that is documented behavior, not an oversight (`spec.md` §3).
//!
//! # Test-vector provenance
//!
//! Lemon Squeezy's docs describe the construction and ship reference code but
//! publish no byte-exact example signature, so the implementation is validated
//! against locally constructed, deterministic vectors over exactly the
//! documented construction (HMAC-SHA256 over the raw body, hex-encoded),
//! each cross-checked against two independent implementations (`openssl
//! dgst` and Python's `hmac` module). Replace them if Lemon Squeezy ever
//! publishes fixed vectors.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Lemon Squeezy's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Signature";

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

/// Parses `X-Signature` into its 32 decoded signature bytes.
///
/// Lemon Squeezy sends bare hex with no prefix. Every failure mode maps to a
/// distinct error variant so callers can tell malformed-request noise from
/// signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let bytes = hex::decode(value).map_err(|_| VerifyError::BadEncoding {
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

    const SECRET: &str = "lemonsqueezy_test_secret";
    const BODY: &[u8] = b"{\"meta\":{\"event_name\":\"order_created\",\"custom_data\":{\"user_id\":\"1\"}},\"data\":{\"id\":\"1\",\"type\":\"orders\",\"attributes\":{\"store_id\":1,\"order_number\":1234,\"subtotal\":1100,\"total\":1100,\"status\":\"paid\"}}}";
    /// Locally constructed:
    /// `printf '<BODY>' | openssl dgst -sha256 -hmac "lemonsqueezy_test_secret" | awk '{print $NF}'`
    /// Cross-checked against Python's `hmac.new(secret, body, hashlib.sha256)`.
    const SIGNATURE: &str = "edeccf8b03afe11114be9fab7259703348bbe36d8964510cdbaff609c5771a1e";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "8e80ad534d2acbbf620d1cbf00c9acb98b0342d334bc4c38811da50d675b5085";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "9f5607b2f899ecb6b14c6efa89d4fda139a1a8b66b7640c60a84dfbb7a004a82";

    fn lemonsqueezy_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::LemonSqueezy,
            &lemonsqueezy_headers(signature),
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
            crate::Provider::LemonSqueezy,
            &[("x-signature", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_with(BODY, &upper), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the hex alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}0{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Differs from BODY in the `status` field; same rule as `spec.md`
        // §5.3 — re-serialized/edited bytes must fail even with a valid
        // signature for the original body.
        let tampered = b"{\"meta\":{\"event_name\":\"order_created\",\"custom_data\":{\"user_id\":\"1\"}},\"data\":{\"id\":\"1\",\"type\":\"orders\",\"attributes\":{\"store_id\":1,\"order_number\":1234,\"subtotal\":1100,\"total\":1100,\"status\":\"rejected\"}}}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::LemonSqueezy,
            &lemonsqueezy_headers(SIGNATURE),
            BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_lemonsqueezy() {
        // Lemon Squeezy signs no timestamp: even a zero-second tolerance must
        // not reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::LemonSqueezy,
            &lemonsqueezy_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::LemonSqueezy,
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
            // Garbage value: not valid hexadecimal at all.
            (
                "not hex!!",
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
            // Valid hex but wrong decoded length (SHA-1 size = 20 bytes = 40 hex chars).
            (
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::LemonSqueezy,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Odd-length hex (63 chars) fails hex decoding — covers the
        // `hex::decode` error path specifically, distinct from the wrong-length
        // decoded-bytes path above.
        let value = "5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8b";
        let result = verify(
            crate::Provider::LemonSqueezy,
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
