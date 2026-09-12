//! Cloudflare Stream webhook signature verification.
//!
//! Scheme, per Cloudflare's official Stream webhook documentation
//! (<https://developers.cloudflare.com/stream/manage-video-library/using-webhooks/>)
//! and the reference verification code in Cloudflare's docs
//! (<https://github.com/cloudflare/cloudflare-docs/blob/production/src/content/docs/stream/examples/test-webhooks-locally.mdx>):
//!
//! - Header: `Webhook-Signature: time=<unix_ts>,sig1=<hex_hmac>` — a
//!   comma-separated `key=value` list; `time` is the integer unix-seconds
//!   value set by the server, `sig1` is the signature of the request body.
//! - Signed string: `"{time}.{raw_body}"` — the `time` value exactly as it
//!   appears in the header, a literal dot, then the raw request body bytes,
//!   unmodified ("Every byte in the request body must remain unaltered for
//!   successful signature verification", per the docs).
//! - Algorithm: HMAC-SHA256 keyed by the webhook signing secret's UTF-8
//!   bytes, hex-encoded (the docs' signature format is lowercase hex).
//! - The signing secret is the plain string returned by the Stream API
//!   (`"secret": "85011ed3a913c6ad5f9cf6c5573cc0a7"` in the docs' example
//!   response) — used as raw UTF-8 bytes, never base64/hex-decoded.
//!
//! # Replay protection
//!
//! Cloudflare's docs require receivers to "discard requests with timestamps
//! that are too old for your application", so this provider applies the
//! crate's shared symmetric window: `|now - time|` against
//! [`VerifyOptions::max_age`] (default 300s) using the injected clock. The
//! symmetric check also rejects future-dated timestamps, which no legitimate
//! delivery produces; the docs candidly don't define a numeric window, so the
//! crate's default tolerance applies (as with Slack and Zoom).
//!
//! Note: the `time` value rides *inside* the single `Webhook-Signature`
//! header, not in a separate HTTP header, so there is one signature-relevant
//! header listed for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::options::VerifyOptions;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying the combined `time` and `sig1` fields.
pub(crate) const SIGNATURE_HEADER: &str = "Webhook-Signature";

/// The `time` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const TIME_FIELD: &str = "time";

/// The `sig1` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const SIG_FIELD: &str = "sig1";

/// Field separator inside [`SIGNATURE_HEADER`].
const FIELD_SEPARATOR: char = ',';

/// HMAC-SHA256 output length in bytes (what a 64-hex-char `sig1` decodes to).
const SIGNATURE_LEN_BYTES: usize = 32;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;

    let (time_raw, signature_value) = parse_header(value)?;
    let timestamp = parse_timestamp(SIGNATURE_HEADER, &time_raw)?;
    let provided = parse_signature(&signature_value)?;

    // Signed string is `{time_as_sent}.{raw_body}`; the time substring is
    // reused verbatim so whatever was actually signed is what gets verified.
    let mut signed_string = Vec::with_capacity(time_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(time_raw.as_bytes());
    signed_string.push(b'.');
    signed_string.extend_from_slice(raw_body);

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided) {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(timestamp, options)
}

/// Splits `Webhook-Signature` into its `time` and `sig1` values, verbatim.
///
/// The docs define the format as a comma-separated `key=value` list and the
/// reference code looks up `time` and `sig1`; unknown fields are ignored
/// (forward compatible). Absent fields fail closed as `missing ...`. A present
/// field with an empty value also fails closed, but downstream and with a
/// distinct error (`header is empty` for `time=`, `signature value is empty`
/// for `sig1=`) — not the same as an absent field. A duplicate `time` or
/// `sig1` field is rejected as ambiguous (`spec.md` §4.4) rather than
/// first-wins like the reference code — this crate fails closed on ambiguity.
fn parse_header(value: &str) -> Result<(String, String), VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut time: Option<&str> = None;
    let mut sig1: Option<&str> = None;

    for element in value.split(FIELD_SEPARATOR) {
        let Some((key, val)) = element.split_once('=') else {
            continue;
        };
        if key == TIME_FIELD {
            if time.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                });
            }
            time = Some(val);
        } else if key == SIG_FIELD {
            if sig1.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
                });
            }
            sig1 = Some(val);
        }
    }

    let time = time.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "missing `time` field",
    })?;
    let sig1 = sig1.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "missing `sig1` field",
    })?;

    Ok((time.to_string(), sig1.to_string()))
}

/// Decodes the hex `sig1` value into its 32 raw signature bytes.
///
/// Cloudflare emits lowercase hex; `hex::decode` accepts both cases, which is
/// fine since the comparison against the expected HMAC is constant-time.
/// Every failure mode maps to a distinct error variant (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "signature value is empty",
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
    use super::{SIG_FIELD, SIGNATURE_HEADER, TIME_FIELD};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// Signing secret from the docs' example Stream API response
    /// ("secret" field of `GET /stream/webhook`,
    /// <https://developers.cloudflare.com/stream/manage-video-library/using-webhooks/>).
    /// A published, public test constant.
    const SECRET: &str = "85011ed3a913c6ad5f9cf6c5573cc0a7";

    /// Timestamp from the docs' example `Webhook-Signature` header
    /// (`time=1230811200`, the "current UNIX time when the server sent the
    /// request").
    const TIME: u64 = 1_230_811_200;

    /// Payload shaped after the docs' example notification body
    /// (<https://developers.cloudflare.com/stream/manage-video-library/using-webhooks/>,
    /// "Notifications" section) — Cloudflare publishes the header format but
    /// no byte-exact signed body, so this vector is locally constructed over
    /// the documented recipe.
    const BODY: &[u8] = br#"{"uid":"6b9e68b07dfee8cc2d116e4c51d6a957","readyToStream":true,"status":{"state":"ready","pctComplete":"100","errorReasonCode":""}}"#;

    /// Locally constructed over `{TIME}.{BODY}` with `SECRET` (HMAC-SHA256,
    /// hex-encoded) — `printf '%s' "{TIME}.{BODY}" | openssl dgst -sha256
    /// -hmac "{SECRET}"`, cross-checked against the docs' reference
    /// implementations in Go/Node/Ruby.
    const SIGNATURE: &str = "e517b28af95a5c15bf630db474c902b8abf9308995aa6dbe8034a044de63ecd6";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "b7add7718ec459a0d6efb26624b389810ac1cd3aed3017c3694081b9876fd4b6";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "aca2bf96114b4facc2a0002e82e401047e87b2304e21c654df64f5c9dcee6bdc";
    /// The docs' full example header value
    /// (`Webhook-Signature: time=1230811200,sig1=60493ec9…`), used verbatim to
    /// prove a *well-formed but different* signature parses and then fails as
    /// a mismatch rather than as a malformed header.
    const DOCS_EXAMPLE_HEADER: &str =
        "time=1230811200,sig1=60493ec9388b44585a29543bcf0de62e377d4da393246a8b1c901d0e3e672404";

    fn verify_with(
        body: &[u8],
        header_value: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Cloudflare,
            &[(SIGNATURE_HEADER, header_value)],
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, single matching sig1.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("{TIME_FIELD}={TIME},{SIG_FIELD}={signature}"),
            &Secret::new(SECRET),
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(TIME, Some(Duration::from_secs(300))),
        )
    }

    /// The docs' documented-recipe vector verifies.
    #[test]
    fn documented_recipe_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn docs_example_header_is_well_formed_but_mismatches() {
        // The exact `Webhook-Signature` example from the docs, replayed
        // against our (different) body: it must parse as a perfectly valid
        // header and come back as a plain signature mismatch — not a
        // MalformedHeader. This pins the header-shape parsing to an official
        // published value.
        let result = verify_with(
            BODY,
            DOCS_EXAMPLE_HEADER,
            &Secret::new(SECRET),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
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
    fn header_name_is_case_insensitive() {
        let result = verify(
            crate::Provider::Cloudflare,
            &[(
                "webhook-signature",
                format!("time={TIME},sig1={SIGNATURE}").as_str(),
            )],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_hex_character_fails() {
        // Flip one hex character *within* the alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}f{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_fresh(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Same signature, body mutated after signing: the signer glued the
        // raw body bytes into the signed string, so any change breaks it.
        assert_eq!(
            verify_fresh(
                br#"{"uid":"6b9e68b07dfee8cc2d116e4c51d6a957","readyToStream":true,"status":{"state":"ready","pctComplete":"100","errorReasonCode":"ERR_FAKE"}}"#,
                SIGNATURE,
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_time_fails_signature_check() {
        // `time` is part of the signed string, so a replayed-but-remembered
        // timestamp with a valid-looking signature must not verify.
        let result = verify_with(
            BODY,
            &format!("time={},sig1={SIGNATURE}", TIME - 1),
            &Secret::new(SECRET),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify_with(
            BODY,
            &format!("time={TIME},sig1={SIGNATURE}"),
            &Secret::new("0".repeat(32)),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing — beyond the crate's
        // default tolerance (Cloudflare's docs require discarding deliveries
        // whose timestamp is too old).
        let result = verify_with(
            BODY,
            &format!("time={TIME},sig1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME + 301, Some(Duration::from_secs(300))),
        );
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
        // Symmetric window: |now - ts| > max_age in either direction is
        // rejected, matching the crate's shared replay semantics for every
        // timestamped provider.
        let result = verify_with(
            BODY,
            &format!("time={TIME},sig1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME - 301, Some(Duration::from_secs(300))),
        );
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
        // Exactly max_age old/new is still inside the closed window.
        for now in [TIME - 300, TIME + 300] {
            let result = verify_with(
                BODY,
                &format!("time={TIME},sig1={SIGNATURE}"),
                &Secret::new(SECRET),
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        // `max_age: None` explicitly disables the recency check.
        let result = verify_with(
            BODY,
            &format!("time={TIME},sig1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Cloudflare,
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
    fn malformed_signature_header_errors_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // No `time` field.
            (
                format!("{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `time` field",
                },
            ),
            // No `sig1` field.
            (
                format!("time={TIME}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sig1` field",
                },
            ),
            // `sig1` present but empty.
            (
                format!("time={TIME},{SIG_FIELD}="),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "signature value is empty",
                },
            ),
            // `time` present but empty.
            (
                format!("time=,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // Time is not a pure unix-seconds integer.
            (
                format!("time=not-a-number,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            // Negative time cannot be represented as u64 unix seconds.
            (
                format!("time=-{TIME},{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            // All digits, but past u64 range.
            (
                format!("time=99999999999999999999999,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp overflows unix seconds",
                },
            ),
            // Ambiguous duplicate `time` field: reject, never first-wins.
            (
                format!("time={TIME},time={},{SIG_FIELD}={SIGNATURE}", TIME + 60),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                },
            ),
            // Ambiguous duplicate `sig1` field: reject, never first-wins.
            (
                format!("time={TIME},{SIG_FIELD}={SIGNATURE},{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            // Not hex at all.
            format!("time={TIME},sig1=zzzz"),
            // Valid hex but odd-length.
            format!("time={TIME},sig1=abc"),
            // Valid hex but not 32 bytes (SHA-1 length).
            format!("time={TIME},sig1=40f2d4d8a1a0f6a9c9b1f4e2d3c4b5a67890abcd"),
        ];
        for value in cases {
            let result = verify_with(
                BODY,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_fields_are_ignored_but_required_ones_are_enforced() {
        // Forward compatibility: extra fields around a well-formed time/sig1
        // pair don't break verification (the docs define `time`/`sig1` and
        // the reference code ignores everything else).
        let result = verify_with(
            BODY,
            &format!("version=1,time={TIME},extra=ignored,sig1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }
}
