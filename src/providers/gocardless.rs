//! GoCardless webhook signature verification.
//!
//! Scheme, per GoCardless's official documentation
//! (<https://docs.gocardless.com/docs/api-reference/webhooks> — the
//! "Signature verification" section: "GoCardless signs every webhook using an
//! HMAC SHA256 hex digest of the raw request body, keyed with your webhook
//! endpoint secret", with the reference construction
//! `OpenSSL::HMAC.hexdigest(digest, secret, request_body)`):
//!
//! - Header: `Webhook-Signature: <hex(HMAC-SHA256(secret, raw_body))>` — a
//!   bare lowercase hex digest, no `sha256=` prefix and no timestamp
//!   (same shape as Razorpay and Lemon Squeezy, hex rather than base64)
//! - Signed string: the raw request body bytes, unmodified. GoCardless's docs
//!   are explicit that the *raw* body must be hashed ("do not parse the JSON
//!   and re-serialise it, as this may change the byte sequence and break the
//!   digest"), so the crate hashes `raw_body` verbatim (`spec.md` §4)
//! - Algorithm: HMAC-SHA256, hex-encoded (lowercase). Key: the webhook
//!   endpoint's secret from the Dashboard, as its UTF-8 bytes, used verbatim —
//!   never decoded. (The secret looks base64url-shaped; decoding it produces a
//!   non-matching digest, so this crate treats it as an opaque byte string,
//!   matching GoCardless's official SDKs.)
//!
//! # Replay protection
//!
//! GoCardless does not sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3). GoCardless delivers each event
//! at least once, so callers should dedupe on the payload's own `event.id`
//! values, which is outside this crate's scope (payload parsing is a
//! non-goal, §1).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying GoCardless's signature.
pub(crate) const SIGNATURE_HEADER: &str = "Webhook-Signature";

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

/// Parses `Webhook-Signature` into its 32 decoded signature bytes.
///
/// The value carries no `sha256=` prefix — it is bare lowercase hex (64
/// characters, exactly the length of the SHA-256 digest). Every failure mode
/// maps to a distinct error variant so callers can tell malformed-request
/// noise from signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let bytes = hex::decode(value).map_err(|_| VerifyError::BadEncoding {
        reason: "signature is not valid hex",
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

    const SECRET: &str = "gocardless_sandbox_webhook_secret";
    /// The vector body mirrors the shape of GoCardless's published example
    /// webhook event (`spec.md` §3, GoCardless row): the always-included
    /// `events` array with `id`, `created_at`, `action`, `resource_type`,
    /// `links`, and `details` fields mirroring the docs' `mandates.cancelled`
    /// example.
    const BODY: &[u8] = br#"{"events":[{"id":"EV123","created_at":"2014-08-04T12:00:00.000Z","action":"cancelled","resource_type":"mandates","links":{"mandate":"MD123","organisation":"OR123"},"details":{"origin":"bank","cause":"bank_account_disabled","description":"Your customer closed their bank account.","scheme":"bacs","reason_code":"ADDACS-B"}}]}"#;
    /// Locally constructed:
    /// `printf '{...}' | openssl dgst -sha256 -hmac "gocardless_sandbox_webhook_secret"`
    ///
    /// GoCardless's docs describe the construction and publish an example
    /// webhook but no byte-exact secret/body/signature triple — the endpoint
    /// secret is shown only at endpoint creation — so vectors here are locally
    /// constructed against the documented recipe and cross-checked with
    /// Python's `hashlib`/`hmac` and `openssl` (`spec.md` §3, GoCardless
    /// row). Replace if GoCardless ever publishes fixed vectors.
    const SIGNATURE: &str = "5bed8b3d569bf2753eca1b10cc25bbdc04cf10b8bb487f489fd5dec9b608e8f6";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "ec39fae967b564df152935126a6da36c9245a1d25e243ccb9a162133f062e7d4";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "4b5e1dec1d71af1b49030743db917952d9f91da93c09dcde3f21b53114792982";
    /// Locally constructed over `"\r\n"` (whitespace boundary case: the raw
    /// bytes signed on the wire must be hashed verbatim, including line
    /// endings).
    const CRLF_BODY_SIGNATURE: &str =
        "d1793bbd19d2dd5375c1d038213071ead474ec5d369a352848fd2508b48dcf71";

    fn gocardless_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::GoCardless,
            &gocardless_headers(signature),
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
        assert_eq!(verify_with(b"\r\n", CRLF_BODY_SIGNATURE), Ok(()));
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::GoCardless,
            &[("webhook-signature", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one hex digit so this exercises a wrong-but-well-formed
        // signature, not a decoding failure.
        let flipped = format!("{}f{}", &SIGNATURE[..3], &SIGNATURE[4..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Same shape with a forged event id — the signed string is the raw
        // body, so any byte change breaks the HMAC.
        let tampered =
            br#"{"events":[{"id":"EVforged","created_at":"2014-08-04T12:00:00.000Z","action":"cancelled","resource_type":"mandates","links":{"mandate":"MD123","organisation":"OR123"},"details":{"origin":"bank","cause":"bank_account_disabled","description":"Your customer closed their bank account.","scheme":"bacs","reason_code":"ADDACS-B"}}]}"#;
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::GoCardless,
            &gocardless_headers(SIGNATURE),
            BODY,
            &Secret::new("a different webhook endpoint secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_gocardless() {
        // GoCardless signs no timestamp: even a zero-second tolerance must
        // not reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::GoCardless,
            &gocardless_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::GoCardless,
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
            // Garbage value: not valid hex at all.
            (
                "not hex!!",
                VerifyError::BadEncoding {
                    reason: "signature is not valid hex",
                },
            ),
            // Valid hex but wrong decoded length (SHA-1 size: 20 bytes).
            (
                "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::GoCardless,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Odd-length hex: 63 characters can never be a 32-byte digest, so it
        // must fail decoding, not verify.
        let value = &SIGNATURE[..SIGNATURE.len() - 1];
        let result = verify(
            crate::Provider::GoCardless,
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
