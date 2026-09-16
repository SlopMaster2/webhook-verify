//! Sentry webhook signature verification.
//!
//! Scheme, per Sentry's official Integration Platform webhook documentation
//! (<https://docs.sentry.io/integrations/integration-platform/webhooks>,
//! "Verifying the Signature"):
//!
//! - Header: `Sentry-Hook-Signature: <hex_hmac>`
//! - Signed string: the raw request body bytes, unmodified — the docs'
//!   reference snippet signs the exact request payload (`request.body`,
//!   `JSON.stringify`ed only to hand the parser an object)
//! - Algorithm: HMAC-SHA256 keyed with the webhook's *Client Secret* as its
//!   UTF-8 bytes, **hex**-encoded (the docs' `crypto.createHmac("sha256",
//!   secret) ... digest("hex")`), no `sha256=` prefix, no timestamp
//!
//! The signing key is the "Client Secret" shown on the Sentry
//! `sentry.io/settings/<org>/apps/<app>/` page for the integration, not an
//! organization auth token.
//!
//! # Replay protection
//!
//! Sentry webhooks do **not** sign a timestamp, so replay protection cannot be
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

/// The header carrying Sentry's signature.
pub(crate) const SIGNATURE_HEADER: &str = "Sentry-Hook-Signature";

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

/// Parses `Sentry-Hook-Signature` into its 32 decoded signature bytes.
///
/// Sentry sends bare hex with no prefix. Every failure mode maps to a
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

    const SECRET: &str = "sentry-local-test-secret";
    /// A realistic Integration Platform webhook payload (an `installation.created`
    /// event): the raw JSON body Sentry's HMAC is computed over.
    const BODY: &[u8] =
        br#"{"action":"created","installation":{"uuid":"2f30d648-1f8e-4bce-8a2e-64e26e2c5f0f"}}"#;
    /// Locally constructed over `BODY` with `SECRET` (HMAC-SHA256, hex):
    /// `printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET"`,
    /// cross-checked against Python's `hashlib.hmac`. Sentry's docs describe
    /// the construction and ship reference code but publish no byte-exact
    /// example signature, so the primary vector is locally constructed over
    /// exactly the documented recipe (see module and spec docs on
    /// provenance).
    const SIGNATURE: &str = "e51fc0e3a08e58a9b33eca67da7ab4e66b0628403d02d95bec5e48b0e2768189";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "31d3051e52836aae655a933a152d0324d4d6e520469b3665ad4c8ccde9729e15";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "79fe8f3aa2a7d3b0f963d7658eaab5333a21668beb61fa9719da3e5a9f2cdc19";

    fn sentry_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Sentry,
            &sentry_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn documented_recipe_vector_verifies() {
        // The primary vector reproduces the docs' construction
        // (`createHmac("sha256", secret)` over the payload, hex digest)
        // byte-for-byte via two independent implementations.
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
            crate::Provider::Sentry,
            &[("sentry-hook-signature", SIGNATURE)],
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
        // Signature was computed over the unmodified payload bytes; any change
        // to the raw body must break verification.
        let tampered = br#"{"action":"created","installation":{"uuid":"2f30d648-1f8e-4bce-8a2e-64e26e2c5f0e"}}"#;
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        // Only the webhook's Client Secret verifies; an auth token or a
        // different secret is a mismatch.
        let result = verify(
            crate::Provider::Sentry,
            &sentry_headers(SIGNATURE),
            BODY,
            &Secret::new("a different client secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_sentry() {
        // Sentry signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Sentry,
            &sentry_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Sentry,
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
            // A `sha256=`-prefixed GitHub-style value is not Sentry's bare-hex
            // shape and must fail closed.
            (
                "sha256=e51fc0e3a08e58a9b33eca67da7ab4e66b0628403d02d95bec5e48b0e2768189",
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Sentry,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Odd-length hex — `hex::decode` errors as not-valid-hex, but pin the
        // BadEncoding class (not a panic) rather than the exact reason string.
        let value = "abc";
        let result = verify(
            crate::Provider::Sentry,
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
