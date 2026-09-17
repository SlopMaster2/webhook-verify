//! LaunchDarkly webhook signature verification.
//!
//! Scheme, per LaunchDarkly's official documentation
//! (<https://launchdarkly.com/docs/home/infrastructure/webhooks> and the
//! webhooks API reference at <https://launchdarkly.com/docs/api/webhooks>):
//!
//! - Header: `X-LD-Signature: <hex_hmac>` — a bare lowercase hex digest, no
//!   `sha256=` prefix and no timestamp; same shape as Dropbox, Razorpay, and
//!   Lemon Squeezy.
//! - Signed string: raw request body bytes, unmodified. LaunchDarkly's docs
//!   state the header "will contain an HMAC SHA256 hex digest of the webhook
//!   payload", keyed by the webhook secret configured on the integration —
//!   re-serializing the JSON payload would change the bytes and fail
//!   verification.
//! - Algorithm: HMAC-SHA256, hex-encoded. Key: the webhook secret as its
//!   UTF-8 bytes, matching the documented construction
//!   (`crypto.createHmac("sha256", secret).update(body).digest("hex")`).
//!
//! # Replay protection
//!
//! LaunchDarkly does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer (the docs themselves recommend using the
//! payload's own "date" field to reorder out-of-order deliveries). [`VerifyOptions::max_age`]
//! and the injected clock have **no effect** for this provider; that is
//! documented behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying LaunchDarkly's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-LD-Signature";

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

/// Parses `X-LD-Signature` into its 32 decoded signature bytes.
///
/// LaunchDarkly sends bare hex with no prefix. Every failure mode maps to a
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

    const SECRET: &str = "ld_test_secret";
    const BODY: &[u8] = b"{\"_id\":\"58eea4c62ae7436600e1b755\",\"kind\":\"flag\",\"title\":\"Updated flag variation\",\"date\":1491945894}";
    /// Locally constructed:
    /// `printf '{"_id":"58eea4c62ae7436600e1b755","kind":"flag","title":"Updated flag variation","date":1491945894}' | openssl dgst -sha256 -hmac "ld_test_secret" | awk '{print $NF}'`
    const SIGNATURE: &str = "a5c678b7915e4397aa9993885fafee775d56fc630d0e2c84e495ce3c7a283e25";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "aed335f11c95f736b2f21d9092093ed7c86ad9deb39045f4db2ec30da213e9a0";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "4de35ee4bf4d1934988ccc774858b79e2b74489af5bde3a607f698c33547de7c";

    fn launchdarkly_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::LaunchDarkly,
            &launchdarkly_headers(signature),
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
            crate::Provider::LaunchDarkly,
            &[("x-ld-signature", SIGNATURE)],
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
        let tampered =
            b"{\"_id\":\"58eea4c62ae7436600e1b755\",\"kind\":\"flag\",\"title\":\"Updated flag variation\",\"date\":1491945895}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::LaunchDarkly,
            &launchdarkly_headers(SIGNATURE),
            BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_launchdarkly() {
        // LaunchDarkly signs no timestamp: even a zero-second tolerance must
        // not reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::LaunchDarkly,
            &launchdarkly_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::LaunchDarkly,
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
                crate::Provider::LaunchDarkly,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        let value = "5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8b";
        let result = verify(
            crate::Provider::LaunchDarkly,
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
