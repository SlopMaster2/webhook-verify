//! Coinbase (CDP) webhook signature verification.
//!
//! Scheme, per Coinbase's official CDP developer documentation
//! (<https://docs.cdp.coinbase.com/webhooks/verify-signatures> "Verify
//! Signatures") and the reference verification code published there:
//!
//! - Header: `X-Hook0-Signature: t=<unix_ts>,v0=<hex_hmac>,h=<header names>,v1=<hex_hmac>`
//!   — a comma-separated `key=value` list. `t` is the integer unix-seconds
//!   value set by the server; `v0` is HMAC-SHA256 over `{t}.{raw_body}` and
//!   "protects the body and timestamp only". The `h` and `v1` fields bind the
//!   listed HTTP headers into the signature; the docs' own recommendation is
//!   "unless you want to bind the headers, which is unnecessary for most use
//!   cases, use `v0`", so this provider verifies the `v0` path and tolerates
//!   the presence of the `h`/`v1` fields (and any future fields) without
//!   interpreting them.
//! - Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears
//!   in the header, a literal dot, then the raw request body bytes, unmodified.
//!   The docs warn that parsing the JSON payload before verification breaks
//!   the signature, because it is computed over the raw bytes.
//! - Algorithm: HMAC-SHA256 keyed by the webhook subscription secret's UTF-8
//!   bytes, hex-encoded (the docs' `crypto.createHmac('sha256', secret)`
//!   digest is lowercase hex).
//! - The secret is the plain string returned in the subscription-response
//!   `secret` field — used as raw UTF-8 bytes, never base64/hex-decoded.
//!
//! # Replay protection
//!
//! The docs recommend rejecting webhooks whose timestamp is older than a
//! `maxAgeMinutes` window (their example defaults to 5 minutes), so this
//! provider applies the crate's shared symmetric window: `|now - t|` against
//! [`VerifyOptions::max_age`] (default 300s) using the injected clock. The
//! symmetric check also rejects future-dated timestamps, which no legitimate
//! delivery produces; the docs' reference code only rejects one direction,
//! but the crate's default tolerance applies as with Slack, Zoom, and
//! Cloudflare.
//!
//! Note: the `t` value rides *inside* the single `X-Hook0-Signature` header,
//! not in a separate HTTP header, so there is one signature-relevant header
//! listed for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::options::VerifyOptions;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying the combined `t` and `v0` fields.
pub(crate) const SIGNATURE_HEADER: &str = "X-Hook0-Signature";

/// The `t` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const TIME_FIELD: &str = "t";

/// The `v0` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const SIG_FIELD: &str = "v0";

/// Field separator inside [`SIGNATURE_HEADER`].
const FIELD_SEPARATOR: char = ',';

/// HMAC-SHA256 output length in bytes (what a 64-hex-char `v0` decodes to).
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

    // Signed string is `{t}.{raw_body}`; the time substring is reused verbatim
    // so whatever was actually signed is what gets verified.
    let mut signed_string = Vec::with_capacity(time_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(time_raw.as_bytes());
    signed_string.push(b'.');
    signed_string.extend_from_slice(raw_body);

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided) {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(timestamp, options)
}

/// Splits `X-Hook0-Signature` into its `t` and `v0` values, verbatim.
///
/// The docs define the format as a comma-separated `key=value` list. The `h`
/// and `v1` fields (and any unknown future fields) are ignored — they bind
/// additional HTTP headers into the signature, which this provider does not
/// verify (the docs recommend the `v0` path for most use cases). Absent fields
/// fail closed as `missing ...`. A present field with an empty value also
/// fails closed, but downstream and with a distinct error (`header is empty`
/// for `t=`, `signature value is empty` for `v0=`) — not the same as an absent
/// field. When a field appears more than once, the first occurrence wins
/// (matching the crate's first-match header semantics).
fn parse_header(value: &str) -> Result<(String, String), VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut time: Option<&str> = None;
    let mut sig: Option<&str> = None;

    for element in value.split(FIELD_SEPARATOR) {
        let Some((key, val)) = element.split_once('=') else {
            continue;
        };
        if key == TIME_FIELD && time.is_none() {
            time = Some(val);
        } else if key == SIG_FIELD && sig.is_none() {
            sig = Some(val);
        }
    }

    let time = time.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "missing `t` field",
    })?;
    let sig = sig.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "missing `v0` field",
    })?;

    Ok((time.to_string(), sig.to_string()))
}

/// Decodes the hex `v0` value into its 32 raw signature bytes.
///
/// Coinbase emits lowercase hex; `hex::decode` accepts both cases, which is
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
    use crate::verify;
    use std::time::Duration;

    /// A subscription secret shaped like the one the Coinbase docs describe
    /// ("the response includes a secret that serves as your signing key"),
    /// used as a plain UTF-8 string.
    const SECRET: &str = "86b4711c0d4e248f0e3de0ef4c6078fa";

    /// Timestamp from the docs' example `X-Hook0-Signature` header
    /// (`t=1728394718`, the "Unix timestamp (seconds) when the webhook was
    /// sent").
    const TIME: u64 = 1_728_394_718;

    /// The docs' example webhook payload
    /// (<https://docs.cdp.coinbase.com/webhooks/verify-signatures>,
    /// "webhook-payload.json"), copied verbatim — Coinbase publishes the
    /// header format and example payload but no byte-exact signed `v0` value,
    /// so this vector is locally constructed over the documented
    /// `{t}.{body}` recipe with the example payload and timestamp.
    const BODY: &[u8] = br#"{"id":"evt_1a2b3c4d5e6f","type":"onchain.activity.detected","createdAt":"2025-10-08T13:58:38.681893Z","data":{"subscriptionId":"sub_abc123","networkId":"base-mainnet","blockNumber":12345678,"blockHash":"0xabc123...","transactionHash":"0xdef456...","logIndex":42,"contractAddress":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","eventName":"Transfer","from":"0xf20d2e37514195ebedb0bc735ba6090ce103d38c","to":"0x1234567890123456789012345678901234567890","value":"1000000"}}"#;

    /// Locally constructed over `{TIME}.{BODY}` with `SECRET` (HMAC-SHA256,
    /// hex-encoded) — `printf '%s' "{TIME}.{BODY}" | openssl dgst -sha256
    /// -hmac "{SECRET}"`, cross-checked against the docs' reference Node
    /// implementation (`crypto.createHmac('sha256', secret)`).
    const SIGNATURE: &str = "ce754a5c0e4951fdf76eb69bff339294f5dc97d118d2a3ba24d7d7eacca025ba";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "854837a3452e3655ae610adf81bece6099571a25928bff28f12272fbf983e888";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "40ad71b6ddbea57c972b8a8157380dfb43bcfc7863aefab631be335fc91018da";
    /// The docs' full example header value
    /// (`X-Hook0-Signature: t=1728394718,v0=9f8e7d6c5b4a...,h=content-type
    /// x-event-id x-event-type,v1=a1b2c3d4e5f6...`), with the published-but-
    /// truncated `v0` prefix elongated to a valid 64-hex-char signature —
    /// used verbatim in shape to prove the `h=`/`v1=` fields and an official
    /// example parse as a well-formed header and then fail as a plain
    /// signature mismatch rather than a malformed header.
    const DOCS_EXAMPLE_HEADER: &str = "t=1728394718,v0=9f8e7d6c5b4a000000000000000000000000000000000000000000000000aaaa,h=content-type x-event-id x-event-type,v1=a1b2c3d4e5f60000000000000000000000000000000000000000000000bbbb";

    fn verify_with(
        body: &[u8],
        header_value: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Coinbase,
            &[(SIGNATURE_HEADER, header_value)],
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, single matching v0.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("{TIME_FIELD}={TIME},{SIG_FIELD}={signature}"),
            &Secret::new(SECRET),
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(TIME, Some(Duration::from_secs(300))),
        )
    }

    /// The documented-recipe vector verifies.
    #[test]
    fn documented_recipe_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn docs_example_header_is_well_formed_but_mismatches() {
        // The `X-Hook0-Signature` example from the docs (with the `h=` and
        // `v1=` fields and the published-but-truncated `v0`/`v1` values
        // elongated to valid hex): it must parse as a perfectly valid header
        // and come back as a plain signature mismatch — not a
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
            crate::Provider::Coinbase,
            &[(
                "x-hook0-signature",
                format!("t={TIME},v0={SIGNATURE}").as_str(),
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
                br#"{"id":"evt_1a2b3c4d5e6f","type":"onchain.activity.detected","createdAt":"2025-10-08T13:58:38.681893Z","data":{"subscriptionId":"sub_abc123","networkId":"base-mainnet","blockNumber":12345678,"blockHash":"0xabc123...","transactionHash":"0xdef456...","logIndex":42,"contractAddress":"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","eventName":"Transfer","from":"0xf20d2e37514195ebedb0bc735ba6090ce103d38c","to":"0x1234567890123456789012345678901234567890","value":"9999999"}}"#,
                SIGNATURE,
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_time_fails_signature_check() {
        // `t` is part of the signed string, so a replayed-but-remembered
        // timestamp with a valid-looking signature must not verify.
        let result = verify_with(
            BODY,
            &format!("t={},v0={SIGNATURE}", TIME - 1),
            &Secret::new(SECRET),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify_with(
            BODY,
            &format!("t={TIME},v0={SIGNATURE}"),
            &Secret::new("0".repeat(32).as_str()),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing — beyond the crate's
        // default tolerance (the docs reject webhooks older than the max-age
        // window, default 5 minutes).
        let result = verify_with(
            BODY,
            &format!("t={TIME},v0={SIGNATURE}"),
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
            &format!("t={TIME},v0={SIGNATURE}"),
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
                &format!("t={TIME},v0={SIGNATURE}"),
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
            &format!("t={TIME},v0={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Coinbase,
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
            // No `t` field.
            (
                format!("{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `t` field",
                },
            ),
            // No `v0` field.
            (
                format!("{TIME_FIELD}={TIME}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `v0` field",
                },
            ),
            // `v0` present but empty.
            (
                format!("{TIME_FIELD}={TIME},{SIG_FIELD}="),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "signature value is empty",
                },
            ),
            // `t` present but empty.
            (
                format!("{TIME_FIELD}=,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // Time is not a pure unix-seconds integer.
            (
                format!("{TIME_FIELD}=not-a-number,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            // Negative time cannot be represented as u64 unix seconds.
            (
                format!("{TIME_FIELD}=-{TIME},{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            // All digits, but past u64 range.
            (
                format!("{TIME_FIELD}=99999999999999999999999,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp overflows unix seconds",
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
            format!("t={TIME},v0=zzzz"),
            // Valid hex but odd-length.
            format!("t={TIME},v0=abc"),
            // Valid hex but not 32 bytes (SHA-1 length).
            format!("t={TIME},v0=40f2d4d8a1a0f6a9c9b1f4e2d3c4b5a67890abcd"),
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
        // Forward compatibility: the docs' `h`/`v1` fields (and any other
        // future fields) around a well-formed t/v0 pair must not break
        // verification — the `v0` path is what the docs recommend.
        let result = verify_with(
            BODY,
            &format!(
                "version=1,t={TIME},h=content-type x-event-id x-event-type,v1=deadbeef,v0={SIGNATURE}"
            ),
            &Secret::new(SECRET),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }
}
