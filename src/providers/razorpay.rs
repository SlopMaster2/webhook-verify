//! Razorpay webhook signature verification.
//!
//! Scheme, per Razorpay's official "Validate and Test Webhooks" documentation
//! (<https://razorpay.com/docs/webhooks/validate-test/>):
//!
//! - Header: `X-Razorpay-Signature: <hex_hmac>`
//! - Signed string: the raw request body bytes, unmodified — Razorpay's own
//!   docs are explicit that the body must not be parsed or re-cast before
//!   hashing
//! - Algorithm: HMAC-SHA256 keyed with the webhook secret's UTF-8 bytes,
//!   **hex**-encoded, no `sha256=` prefix, no timestamp
//!
//! The signing key is the webhook secret configured in the dashboard — not the
//! API `key_id`/`key_secret` pair, per the docs and the FAQ.
//!
//! # Replay protection
//!
//! Razorpay does **not** sign a timestamp, so replay protection cannot be
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

/// The header carrying Razorpay's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Razorpay-Signature";

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

/// Parses `X-Razorpay-Signature` into its 32 decoded signature bytes.
///
/// Razorpay sends bare hex with no prefix. Every failure mode maps to a
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

    const SECRET: &str = "123456";
    /// The worked example body posted by a Razorpay maintainer in the official
    /// SDK issue tracker
    /// (<https://github.com/razorpay/razorpay-node/issues/29>).
    const BODY: &[u8] = b"{a:1, b:2}";
    /// The maintainer-posted signature for `SECRET` + `BODY`
    /// (<https://github.com/razorpay/razorpay-node/issues/29>).
    const SIGNATURE: &str = "ee0a3edebeb4be41bafa3bc0a39069d7845a5c37760b863405049de80b5fe92d";
    /// The maintainer-posted second example: same secret, body `{c:1, d:2}`
    /// (<https://github.com/razorpay/razorpay-node/issues/29>).
    const SECOND_BODY_SIGNATURE: &str =
        "58fd9fac909b57d776606e9313e83a26a9e67a3488b9ca7259134e09f4badfb1";
    /// Locally constructed over an empty body (boundary case):
    /// `printf '' | openssl dgst -sha256 -hmac "123456" | awk '{print $NF}'`.
    const EMPTY_BODY_SIGNATURE: &str =
        "b946ccc987465afcda7e45b1715219711a13518d1f1663b8c53b848cb0143441";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "d2e8ea2b3b0656b6fac10c3de1cbef5f680b857312de1d95da24c95173d4fb49";

    fn razorpay_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Razorpay,
            &razorpay_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn official_vector_verifies() {
        // Razorpay's maintainer-published examples (razorpay-node issue #29).
        assert_eq!(verify_with(BODY, SIGNATURE), Ok(()));
        assert_eq!(verify_with(b"{c:1, d:2}", SECOND_BODY_SIGNATURE), Ok(()));
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
            crate::Provider::Razorpay,
            &[("x-razorpay-signature", SIGNATURE)],
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
        let tampered = b"{a:1, b:3}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        // The API key secret is a common mistake; only the dashboard webhook
        // secret verifies.
        let result = verify(
            crate::Provider::Razorpay,
            &razorpay_headers(SIGNATURE),
            BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_razorpay() {
        // Razorpay signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Razorpay,
            &razorpay_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Razorpay,
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
            // A `sha256=`-prefixed GitHub-style value is not Razorpay's bare-hex
            // shape and must fail closed.
            (
                "sha256=ee0a3edebeb4be41bafa3bc0a39069d7845a5c37760b863405049de80b5fe92d",
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Razorpay,
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
            crate::Provider::Razorpay,
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
