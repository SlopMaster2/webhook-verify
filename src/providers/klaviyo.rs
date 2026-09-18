//! Klaviyo webhook signature verification.
//!
//! Scheme, per Klaviyo's official "Working with system webhooks" documentation
//! (<https://developers.klaviyo.com/en/docs/working_with_system_webhooks>
//! "HMAC signature verification"):
//!
//! - Headers: `Klaviyo-Signature`, `Klaviyo-Timestamp` (IMF-fixdate / RFC 1123,
//!   e.g. `Thu, 04 Jan 2024 18:05:25 GMT`), and `Klaviyo-Webhook-Id`. Only the
//!   first two participate in the HMAC; the webhook id is **not** part of the
//!   signed material.
//! - Signed string: `"{raw_body}{timestamp}"` — the raw request body bytes
//!   unmodified, then the `Klaviyo-Timestamp` value **exactly as it appears in
//!   its header** (concatenated with the body, no separators). Klaviyo's docs'
//!   reference code hashes the body first and then feeds the timestamp in:
//!   `computed_signature = hmac.new(hmac_secret, request.body, hashlib.sha256);
//!   computed_signature.update(timestamp.encode())`. The numeric grammar of the
//!   timestamp must never be re-serialized into the signed bytes — the verbatim
//!   header substring is what was signed.
//! - Algorithm: HMAC-SHA256 keyed by the webhook's signing secret as a plain
//!   UTF-8 string, **hex**-encoded, carried bare in the header (no `sha256=`
//!   prefix).
//!
//! `Klaviyo-Webhook-Id` is intentionally not verified by this crate. Klaviyo
//! directs integrators to check that it matches the body's
//! `meta.klaviyo_webhook_id`; binding it requires deserializing the body, which
//! this crate never does (`spec.md` §1 — payload parsing is a non-goal).
//! Callers should perform that pair check after a successful
//! [`verify`](crate::verify) using the [`WEBHOOK_ID_HEADER`](crate::klaviyo::WEBHOOK_ID_HEADER)
//! constant (the body side is up to the caller's own JSON parsing).
//!
//! # Replay protection
//!
//! Klaviyo signs a timestamp, enabling symmetric replay protection. The signed
//! timestamp (parsed from its IMF-fixdate spelling) is compared symmetrically
//! (`|now - t|`) against [`VerifyOptions::max_age`] (default 300s) using `now`
//! from the injected clock. Klaviyo's docs do not prescribe a freshness window;
//! applying the shared window here is strictly stronger than their sample code
//! and cannot reject a legitimate delivery the provider considers valid (the
//! timestamp is HMAC-covered, so an attacker cannot freshen it).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_imf_fixdate};
use crate::core::secret::Secret;

/// The header carrying Klaviyo's HMAC-SHA256 signature.
pub const SIGNATURE_HEADER: &str = "Klaviyo-Signature";

/// The header carrying the signed IMF-fixdate (RFC 1123) webhook timestamp.
pub const TIMESTAMP_HEADER: &str = "Klaviyo-Timestamp";

/// The header carrying the webhook's id. Not part of the HMAC; Klaviyo directs
/// integrators to check it against the body's `meta.klaviyo_webhook_id`.
pub const WEBHOOK_ID_HEADER: &str = "Klaviyo-Webhook-Id";

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let signature_value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;
    let timestamp_raw = headers
        .get(TIMESTAMP_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: TIMESTAMP_HEADER,
        })?;

    let provided_signature = parse_signature(signature_value)?;
    let timestamp = parse_imf_fixdate(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed string is `{raw_body}{timestamp_as_sent}`; the timestamp substring
    // is reused verbatim so whatever was actually signed is what gets verified
    // (Klaviyo's docs: an HMAC over the body, updated with the timestamp).
    let mut signed_string = Vec::with_capacity(raw_body.len() + timestamp_raw.len());
    signed_string.extend_from_slice(raw_body);
    signed_string.extend_from_slice(timestamp_raw.as_bytes());

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided_signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(timestamp, options)
}

/// Parses `Klaviyo-Signature` into its 32 decoded signature bytes.
///
/// The value carries no prefix — it is bare lowercase hex. Every failure mode
/// maps to a distinct error variant so callers can tell malformed-request noise
/// from signature-mismatch signals (`spec.md` §2.1).
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
    use super::{SIGNATURE_HEADER, TIMESTAMP_HEADER, WEBHOOK_ID_HEADER};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// A signing secret chosen for the locally constructed vectors below.
    /// Klaviyo publishes no static test secret, so the vectors are constructed
    /// over exactly the documented construction with a constant key rather
    /// than over a published byte-exact example (see `spec.md` §3, Klaviyo
    /// row).
    const SECRET: &str = "klaviyo-test-secret";
    /// The documented example webhook timestamp from Klaviyo's docs
    /// (<https://developers.klaviyo.com/en/docs/working_with_system_webhooks>),
    /// matching unix seconds `1704391525`.
    const TIMESTAMP: &str = "Thu, 04 Jan 2024 18:05:25 GMT";
    /// A `event:klaviyo.sent_sms` delivery shaped like the docs' example
    /// request (the webhook id is the docs' own example header value).
    const BODY: &[u8] = b"{\"data\":[{\"external_id\":\"4L3cwQae2TX\",\"topic\":\"event:klaviyo.sent_sms\"}],\"meta\":{\"klaviyo_webhook_id\":\"a8b890458b4bbfaa26d961471b83c101d6de23bd826e7e5173a15310985ec3cb\"}}";
    /// Locally constructed over the concatenation `BODY + TIMESTAMP` —
    /// Klaviyo's documented `hmac(secret, request.body)` updated with the
    /// timestamp — because Klaviyo publishes no byte-exact example signature:
    /// `cat body.ts | openssl dgst -sha256 -hmac "klaviyo-test-secret"`,
    /// cross-checked with Python's `hmac` module.
    const SIGNATURE: &str = "5aa0e720d80b3a04ca04baf3c65cdfe31da57504af69fee8da29c35d45f0596b";
    /// Locally constructed over `TIMESTAMP` alone (empty body boundary).
    const EMPTY_BODY_SIGNATURE: &str =
        "20207af32de1a92c348f827f1eace8aefdcc554c6fc41e1e5625d4480a1cf059";
    /// Locally constructed over `"héllo, 🦀 world!" + TIMESTAMP` (unicode
    /// body boundary).
    const UNICODE_BODY_SIGNATURE: &str =
        "976d9ec1a7b4a0edb37167e0e72bc58a9cb29933aa08f1f54679d49c1ee2ad82";

    /// The documented example delivery from Klaviyo's docs — the real
    /// `Klaviyo-Signature`, `Klaviyo-Timestamp`, and `Klaviyo-Webhook-Id`
    /// header values. Klaviyo publishes no body or signing key for it, so it
    /// can only be replayed as a well-formed-but-mismatching input (the
    /// signature is over a body/secret pair this crate does not know).
    const DOCS_EXAMPLE_SIGNATURE: &str =
        "e6c00e313eaea50ca3b89a7de5a782a2014f96fb8315c065898c669d831912d1";
    const DOCS_EXAMPLE_WEBHOOK_ID: &str =
        "a8b890458b4bbfaa26d961471b83c101d6de23bd826e7e5173a15310985ec3cb";

    fn klaviyo_headers(signature: &str, timestamp: &str) -> Vec<(String, String)> {
        vec![
            (SIGNATURE_HEADER.to_string(), signature.to_string()),
            (TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
        ]
    }

    #[test]
    fn webhook_id_header_constant_matches_the_spec_spelling() {
        assert_eq!(super::WEBHOOK_ID_HEADER, "Klaviyo-Webhook-Id");
    }

    fn verify_with(
        body: &[u8],
        signature: &str,
        timestamp: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Klaviyo,
            &klaviyo_headers(signature, timestamp),
            body,
            &Secret::new(SECRET),
            options,
        )
    }

    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            signature,
            TIMESTAMP,
            clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn constructed_vector_verifies() {
        // Klaviyo's docs' example timestamp header value, over a locally
        // constructed body/signature for the constant SECRET.
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_fresh(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_fresh("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn docs_example_header_is_well_formed_but_non_matching() {
        // Klaviyo's published example delivery: the real signature/timestamp
        // header values must parse cleanly (well-formed IMF-fixdate, valid
        // hex) and reach the HMAC comparison, rejecting as a plain mismatch —
        // proving the documented example shape is understood even though the
        // body and secret behind Klaviyo's example signature are unpublished.
        let headers = vec![
            (
                SIGNATURE_HEADER.to_string(),
                DOCS_EXAMPLE_SIGNATURE.to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP.to_string()),
            (
                WEBHOOK_ID_HEADER.to_string(),
                DOCS_EXAMPLE_WEBHOOK_ID.to_string(),
            ),
        ];
        let result = verify(
            crate::Provider::Klaviyo,
            &headers,
            BODY,
            &Secret::new(SECRET),
            clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
        );
        // The documented example signature was computed over an unpublished
        // body/secret, so it cannot equal this crate's locally computed
        // signature for the same timestamp.
        assert_ne!(DOCS_EXAMPLE_SIGNATURE, SIGNATURE);
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify(
            crate::Provider::Klaviyo,
            &[
                ("klaviyo-signature", SIGNATURE.to_string().as_str()),
                ("klaviyo-timestamp", TIMESTAMP.to_string().as_str()),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_fresh(BODY, &upper), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the hex alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}0{}", &SIGNATURE[..5], &SIGNATURE[6..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_fresh(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let tampered = b"{\"data\":[{\"external_id\":\"4L3cwQae2TX\",\"topic\":\"event:klaviyo.sent_sms_ALTERED\"}],\"meta\":{\"klaviyo_webhook_id\":\"a8b890458b4bbfaa26d961471b83c101d6de23bd826e7e5173a15310985ec3cb\"}}";
        assert_eq!(
            verify_fresh(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_spelling_fails_signature_check() {
        // The timestamp is signed verbatim: a different (still well-formed)
        // IMF-fixdate value changes the signed string even though it may
        // denote a nearby instant.
        let result = verify_with(
            BODY,
            SIGNATURE,
            "Thu, 04 Jan 2024 18:05:26 GMT",
            clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Klaviyo,
            &klaviyo_headers(SIGNATURE, TIMESTAMP),
            BODY,
            &Secret::new("a different secret"),
            clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let options = clocked_at(1_704_391_525 + 301, Some(Duration::from_secs(300)));
        let result = verify_with(BODY, SIGNATURE, TIMESTAMP, options);
        assert_eq!(
            result,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_future_timestamp_out_of_tolerance() {
        let options = clocked_at(1_704_391_525 - 301, Some(Duration::from_secs(300)));
        let result = verify_with(BODY, SIGNATURE, TIMESTAMP, options);
        assert_eq!(
            result,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_within_tolerance_verifies_at_window_edges() {
        for now in [1_704_391_525 - 300, 1_704_391_525 + 300] {
            let result = verify_with(
                BODY,
                SIGNATURE,
                TIMESTAMP,
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let result = verify_with(
            BODY,
            SIGNATURE,
            TIMESTAMP,
            clocked_at(1_704_391_525 + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify(
            crate::Provider::Klaviyo,
            &[(TIMESTAMP_HEADER, TIMESTAMP.to_string().as_str())],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::Klaviyo,
            &[(SIGNATURE_HEADER, SIGNATURE.to_string().as_str())],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );

        let all_missing = verify(
            crate::Provider::Klaviyo,
            &Vec::<(String, String)>::new(),
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            all_missing,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_signature_header_errors_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // Garbage value: not valid hexadecimal.
            (
                "not hex!!".to_string(),
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
            // Valid hex but wrong decoded length (SHA-1 size = 20 bytes).
            (
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
            // A `sha256=`-prefixed GitHub-style value is not Klaviyo's bare-hex
            // shape and must fail closed.
            (
                format!("sha256={SIGNATURE}"),
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                &value,
                TIMESTAMP,
                clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Odd-length hex — `hex::decode` errors as not-valid-hex, but pin the
        // BadEncoding class (not a panic) rather than the exact reason string.
        let value = "abc";
        let result = verify_with(
            BODY,
            value,
            TIMESTAMP,
            clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
        );
        match result {
            Err(VerifyError::BadEncoding { .. }) => {}
            other => panic!("expected BadEncoding for {value}, got {other:?}"),
        }
    }

    #[test]
    fn malformed_timestamp_header_errors_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
                },
            ),
            // A perfect RFC 3339 instant is not Klaviyo's IMF-fixdate shape.
            (
                "2024-01-04T18:05:25Z".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
                },
            ),
            (
                "Thu, 04 Jan 2024 18:05:25 UTC".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
                },
            ),
            // Day name must match the date: 2024-01-04 was a Thursday.
            (
                "Wed, 04 Jan 2024 18:05:25 GMT".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
                },
            ),
            // IMF-fixdate has no `:60` leap-second value.
            (
                "Thu, 04 Jan 2024 23:59:60 GMT".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
                },
            ),
            (
                "tampered".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                SIGNATURE,
                &value,
                clocked_at(1_704_391_525, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
