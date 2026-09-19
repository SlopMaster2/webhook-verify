//! Nylas webhook signature verification.
//!
//! Scheme, per Nylas's official documentation ("Using webhooks with Nylas",
//! <https://developer.nylas.com/docs/v3/notifications/> — "Secure a webhook"
//! and "Respond to webhook notifications" — and the signed-delivery recipe at
//! <https://developer.nylas.com/docs/cookbook/use-cases/build/verify-webhook-signatures/>):
//!
//! - Header: `x-nylas-signature: <hex_hmac>` — a bare lowercase hex digest, no
//!   prefix and no timestamp. Nylas's docs state the header arrives as either
//!   `x-nylas-signature` or `X-Nylas-Signature` depending on the integration;
//!   header lookup here is case-insensitive, so either spelling works. Same
//!   shape as LaunchDarkly, Dropbox, Razorpay, and Lemon Squeezy.
//! - Signed string: raw request body bytes, unmodified. The docs stress the
//!   signature is for "the exact content of the request body", so any
//!   reformatting or re-serialization before verification breaks the HMAC —
//!   the crate hashes `raw_body` verbatim (`spec.md` §4).
//! - Algorithm: HMAC-SHA256, hex-encoded. Key: the endpoint's `webhook_secret`,
//!   generated after the endpoint passes the initial `challenge` handshake, as
//!   its UTF-8 bytes — matching the documented construction
//!   (`crypto.createHmac("sha256", secret).update(rawBody).digest("hex")`).
//!
//! Nylas optionally delivers compressed webhook notifications
//! (`compressed_delivery: true`): the payload is gzip-compressed and the HMAC
//! is computed **over the compressed bytes**. Because this crate always hashes
//! `raw_body` as received, the caller passes the compressed wire bytes straight
//! through and verification works unchanged; decompressing before verification
//! would break it (the docs call this the single most common integration bug).
//!
//! # Replay protection
//!
//! Nylas does **not** sign a timestamp, so replay protection cannot be provided
//! at the signature layer. [`VerifyOptions::max_age`] and the injected clock
//! have **no effect** for this provider; that is documented behavior, not an
//! oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Nylas's signature.
pub(crate) const SIGNATURE_HEADER: &str = "x-nylas-signature";

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
    // time (Nylas's reference recipe uses `crypto.timingSafeEqual`); no early
    // exit depends on *how* wrong the signature is.
    if verify_hmac_sha256(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `x-nylas-signature` into its 32 decoded signature bytes.
///
/// Nylas sends bare hex with no prefix. Every failure mode maps to a distinct
/// error variant so callers can tell malformed-request noise from
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

    const SECRET: &str = "nylas_test_secret";
    /// The vector body mirrors the shape of Nylas's documented
    /// `message.created` notification (`spec.md` §3, Nylas row): the Nylas
    /// always-includes ID fields (`id`, `grant_id`, `application_id`) and the
    /// `data.object` envelope.
    const BODY: &[u8] = b"{\"id\":\"84e68b5a-3e2c-4bd6-a9b1-5c6e5e8b0cf1\",\"account_id\":\"ce38bd1ab7a003ff9f06c1f949e09a38\",\"date\":1735689600,\"type\":\"message.created\",\"data\":{\"object\":{\"id\":\"a5f31b8a-2c4d-4e6f-8a9b-0c1d2e3f4a5b\",\"grant_id\":\"ef91c7a4-3b2d-4e5f-8a9b-cdef01234567\",\"thread_id\":\"9e8d7c6b-5a4f-4e3d-8c2b-1a09f8e7d6c5\"}}}";
    /// Locally constructed:
    /// `printf '{"id":...}' | openssl dgst -sha256 -hmac "nylas_test_secret"`
    /// Cross-checked against Python's
    /// `hmac.new(secret, body, hashlib.sha256).hexdigest()`; both constructions
    /// follow the recipe at
    /// <https://developer.nylas.com/docs/cookbook/use-cases/build/verify-webhook-signatures/>,
    /// which publishes no static test vector (the secret is endpoint-specific).
    /// Replace if Nylas ever publishes fixed vectors.
    const SIGNATURE: &str = "866ca213df6569c66ee957d0854f698b510788470f68d455023ed420644447dc";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "4aacc1f5b30e94264cf082cd16d505700dec96f463a9e10fd43e7e61ad9cf09a";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "47f28986282fec16aa136f9af14d28851836dade879b2a1a206202835e1b0b4f";

    fn nylas_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Nylas,
            &nylas_headers(signature),
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
        // The docs document both the `x-nylas-signature` and `X-Nylas-Signature`
        // spellings (the capitalization depends on the sending SDK); header
        // lookup is case-insensitive, so both must work.
        let result = verify(
            crate::Provider::Nylas,
            &[("X-Nylas-Signature", SIGNATURE)],
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
        // Same shape with a forged thread id — the signed string is the raw
        // body, so any byte change breaks the HMAC.
        let tampered =
            b"{\"id\":\"84e68b5a-3e2c-4bd6-a9b1-5c6e5e8b0cf1\",\"account_id\":\"ce38bd1ab7a003ff9f06c1f949e09a38\",\"date\":1735689600,\"type\":\"message.created\",\"data\":{\"object\":{\"id\":\"a5f31b8a-2c4d-4e6f-8a9b-0c1d2e3f4a5b\",\"grant_id\":\"ef91c7a4-3b2d-4e5f-8a9b-cdef01234567\",\"thread_id\":\"00000000-0000-0000-0000-000000000000\"}}}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Nylas,
            &nylas_headers(SIGNATURE),
            BODY,
            &Secret::new("a different webhook secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_nylas() {
        // Nylas signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Nylas,
            &nylas_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Nylas,
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
                crate::Provider::Nylas,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Guard the odd-length path as well: an odd number of hex digits can
        // never be a 32-byte digest, so it must fail decoding, not verify.
        let value = &SIGNATURE[..63];
        let result = verify(
            crate::Provider::Nylas,
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
