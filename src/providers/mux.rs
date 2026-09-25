//! Mux webhook signature verification.
//!
//! Scheme, per Mux's official documentation
//! (<https://www.mux.com/docs/core/verify-webhook-signatures> "Verify webhook
//! signatures") and Mux's official SDKs — the Elixir verifier
//! (<https://github.com/muxinc/mux-elixir/blob/master/lib/mux/webhooks.ex>)
//! and the Node verifier
//! (<https://github.com/muxinc/mux-node-sdk/blob/main/src/resources/webhooks/webhooks.ts>):
//!
//! - Header: `Mux-Signature: t=<unix_ts>,v1=<hex_hmac>[,v1=<hex_hmac>...]`
//!   — a comma-separated `key=value` list. `t` is the integer unix-seconds
//!   value set by the server; `v1` is the HMAC-SHA256 signature over
//!   `{t}.{raw_body}` and is the only signature scheme the docs define
//!   ("Currently, the only valid signature scheme is `v1`").
//! - Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears
//!   in the header, a literal dot, then the raw request body bytes, unmodified
//!   (the docs warn to pass "the raw un-parsed request body, not the parsed
//!   JSON").
//! - Algorithm: HMAC-SHA256 keyed by the webhook signing secret as a plain
//!   UTF-8 string, hex-encoded. The signing secret is the per-webhook
//!   `signing_secret` from the Webhooks API (distinct from the Mux API token).
//! - Multiple `v1=` values are accepted during signing-secret rotation
//!   (matching the official SDKs, which accept a match on *any* `v1`
//!   element); unknown schemes and fields are discarded for forward
//!   compatibility.
//!
//! # Replay protection
//!
//! Mux's SDKs apply a 300-second tolerance (`@default_tolerance 300` in the
//! Elixir verifier; `tolerance = 300` in the Node verifier), so this provider
//! uses the crate's shared symmetric window: `|now - t|` against
//! [`VerifyOptions::max_age`] (default 300s) using the injected clock. The
//! symmetric check also rejects future-dated timestamps, which no legitimate
//! delivery produces; the SDKs only reject the old half, but the crate's
//! default tolerance applies as with Slack, Zoom, Cloudflare, and Coinbase.
//!
//! Note: the `t` value rides *inside* the single `Mux-Signature` header, not
//! in a separate HTTP header, so there is one signature-relevant header listed
//! for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256_any;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying Mux's combined `t` and `v1` fields.
pub(crate) const SIGNATURE_HEADER: &str = "Mux-Signature";

/// The `t` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const TIME_FIELD: &str = "t";

/// The only signature scheme Mux defines, per its docs and SDKs.
const SCHEME: &str = "v1";

/// HMAC-SHA256 output length in bytes.
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

    let parsed = parse_header(value)?;

    // Signed string is `{t}.{raw_body}`; the raw timestamp substring is reused
    // verbatim so whatever was actually signed is what gets verified.
    let mut signed_string = Vec::with_capacity(parsed.timestamp_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(parsed.timestamp_raw.as_bytes());
    signed_string.push(b'.');
    signed_string.extend_from_slice(raw_body);

    let matched = verify_hmac_sha256_any(
        secret.as_bytes(),
        &signed_string,
        parsed
            .signatures
            .iter()
            .map(|signature| signature.as_slice()),
    );

    if !matched {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(parsed.timestamp, options)
}

/// A successfully parsed `Mux-Signature` header value.
struct ParsedHeader<'a> {
    /// Decoded unix timestamp in seconds.
    timestamp: u64,
    /// The raw timestamp substring as sent (used verbatim in the signed
    /// string).
    timestamp_raw: &'a str,
    /// Every `v1=` signature decoded to its 32 bytes.
    signatures: Vec<Vec<u8>>,
}

/// Parses the header per Mux's documented algorithm: split on `,`, split each
/// element on the first `=`, keep `t` and all `v1` values, discard every other
/// element (including unknown/non-`v1` schemes).
///
/// Duplicate `t=` elements are rejected as ambiguous (`spec.md` §4.4) rather
/// than last-wins like Mux's SDK parsers — this crate fails closed on
/// ambiguity.
fn parse_header(value: &str) -> Result<ParsedHeader<'_>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut timestamp_raw: Option<&str> = None;
    let mut signatures = Vec::new();

    for element in value.split(',') {
        // Elements without an `=` (or empty ones from stray commas) carry no
        // recognizable prefix and are discarded, as are unknown schemes.
        let Some((key, val)) = element.split_once('=') else {
            continue;
        };
        // Keys are compared after trimming surrounding whitespace: the
        // comma-space spelling (`t=..., v1=...`) that proxy header-folding and
        // hand-copied values produce must not silently drop a recognized key.
        // Values are never trimmed — the timestamp is reused verbatim in the
        // signed string, so the raw bytes must stay byte-for-byte intact.
        let key = key.trim();

        if key == TIME_FIELD {
            if timestamp_raw.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                });
            }
            timestamp_raw = Some(val);
        } else if key == SCHEME {
            if val.is_empty() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1=` prefix",
                });
            }
            let bytes = hex::decode(val).map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid hexadecimal",
            })?;
            if bytes.len() != SIGNATURE_LEN_BYTES {
                return Err(VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                });
            }
            signatures.push(bytes);
        }
        // All other keys (unknown schemes, future fields) are discarded.
    }

    let timestamp_raw = match timestamp_raw {
        Some(raw) if !raw.is_empty() => raw,
        Some(_) => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "empty timestamp after `t=` prefix",
            });
        }
        None => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "missing `t=` timestamp",
            });
        }
    };

    // `t` is "integer unix seconds" (`spec.md` §3); route it through the
    // shared timestamp parser so sign-prefixed (`t=+1591664030`),
    // whitespace-padded, and overflowing values fail closed exactly like every
    // other timestamped provider (Slack, Zoom, Discord, SendGrid, Standard
    // Webhooks, Coinbase, `Custom`). Mux's own SDKs use a lenient
    // `parseInt`-style parse; the strict shared parser is intentionally
    // stricter and cannot reject a legitimate delivery.
    let timestamp = parse_timestamp(SIGNATURE_HEADER, timestamp_raw)?;

    if signatures.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "no `v1=` signature present",
        });
    }

    Ok(ParsedHeader {
        timestamp,
        timestamp_raw,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::{SCHEME, SIGNATURE_HEADER, TIME_FIELD};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// The secret used by Mux's own published test vector.
    const SECRET: &str = "SuperSecret123";

    /// The body from Mux's published test vector
    /// (<https://hexdocs.pm/mux/Mux.Webhooks.TestUtils.html>):
    /// `generate_signature("payload", "SuperSecret123")`.
    const BODY: &[u8] = b"payload";

    /// The timestamp from that same published vector.
    const TIME: u64 = 1_591_664_030;

    /// Mux's own byte-exact published test vector:
    /// `Mux.Webhooks.TestUtils.generate_signature("payload", "SuperSecret123")`
    /// returns `t=1591664030,v1=e43496b6aae982c4c2fd6f8e92935f1d90216f1f64d56024e72390acfb988272`
    /// and the official Elixir verifier accepts it. Locally confirmed with
    /// `python3 -c 'import hmac,hashlib;
    /// print(hmac.new(b"SuperSecret123", b"1591664030.payload", hashlib.sha256).hexdigest())'`
    /// and against the official Node verifier's `${details.timestamp}.${body}`
    /// construction.
    const SIGNATURE: &str = "e43496b6aae982c4c2fd6f8e92935f1d90216f1f64d56024e72390acfb988272";

    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "ad26232d1cef549c69cc1381dcb997958ee6f9c8d14906a133cc898c6ab7dc0f";

    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "eeaa20f81c10838a48376352c8ea088bd8c95b029419b326fb79aa10ec2cc7f5";

    /// The full example header published in Mux's docs
    /// (<https://www.mux.com/docs/core/verify-webhook-signatures>:
    /// `Mux-Signature: t=1565220904,v1=20c75c1180c701ee8a796e81507cfd5c932fc17cf63a4a55566fd38da3a2d3d2`).
    /// Mux publishes no body for it, so it is replayed as a
    /// well-formed-but-mismatching input rather than a happy path.
    const DOCS_EXAMPLE_HEADER: &str =
        "t=1565220904,v1=20c75c1180c701ee8a796e81507cfd5c932fc17cf63a4a55566fd38da3a2d3d2";

    fn verify_with(
        body: &[u8],
        header_value: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Mux,
            &[(SIGNATURE_HEADER, header_value)],
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, single matching v1.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("{TIME_FIELD}={TIME},{SCHEME}={signature}"),
            &Secret::new(SECRET),
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(TIME, Some(Duration::from_secs(300))),
        )
    }

    /// Mux's own published test vector verifies.
    #[test]
    fn official_elixir_sdk_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn docs_example_header_is_well_formed_but_mismatches() {
        // The `Mux-Signature` example from the docs must parse as a perfectly
        // valid header and come back as a plain signature mismatch — not a
        // MalformedHeader. This pins the header-shape parsing to an official
        // published value.
        let result = verify_with(
            BODY,
            DOCS_EXAMPLE_HEADER,
            &Secret::new(SECRET),
            clocked_at(1_565_220_904, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn comma_space_spelling_is_tolerated() {
        // Real integrations (proxy header-folding, hand-pasted requests) often
        // emit `t=..., v1=...` with a space after the comma; keys must not be
        // silently dropped.
        let value = format!("{TIME_FIELD}={TIME}, {SCHEME}={SIGNATURE}");
        assert_eq!(
            verify_with(
                BODY,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
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
    fn multiple_v1_signatures_accept_a_match() {
        // Signing-secret rotation: the header carries the old signature first
        // and the current one second; a match on *any* `v1` is accepted, as in
        // Mux's official SDKs.
        let value = format!(
            "{TIME_FIELD}={TIME},{SCHEME}=0000000000000000000000000000000000000000000000000000000000000000,{SCHEME}={SIGNATURE}"
        );
        assert_eq!(
            verify_with(
                BODY,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
    }

    #[test]
    fn unknown_schemes_and_fields_are_ignored() {
        // Forward compatibility: fields other than `t`/`v1` (including a
        // hypothetical future scheme) must not break verification.
        let value = format!("version=1,{TIME_FIELD}={TIME},v2=deadbeef,{SCHEME}={SIGNATURE}");
        assert_eq!(
            verify_with(
                BODY,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let result = verify(
            crate::Provider::Mux,
            &[("mux-signature", format!("t={TIME},v1={SIGNATURE}").as_str())],
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
        // Same signature, body mutated after signing: the signer glued the raw
        // body bytes into the signed string, so any change breaks it.
        assert_eq!(
            verify_fresh(b"payloaD", SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_time_fails_signature_check() {
        // `t` is part of the signed string, so a shifted timestamp with a
        // valid-looking signature must not verify.
        let result = verify_with(
            BODY,
            &format!("t={},v1={SIGNATURE}", TIME - 1),
            &Secret::new(SECRET),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify_with(
            BODY,
            &format!("t={TIME},v1={SIGNATURE}"),
            &Secret::new("not-the-signing-secret"),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing — beyond the 300s
        // tolerance the Mux SDKs apply.
        let result = verify_with(
            BODY,
            &format!("t={TIME},v1={SIGNATURE}"),
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
            &format!("t={TIME},v1={SIGNATURE}"),
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
                &format!("t={TIME},v1={SIGNATURE}"),
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
            &format!("t={TIME},v1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Mux,
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
                format!("{SCHEME}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `t=` timestamp",
                },
            ),
            // No `v1` field.
            (
                format!("{TIME_FIELD}={TIME}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1=` signature present",
                },
            ),
            // `v1` present but empty.
            (
                format!("{TIME_FIELD}={TIME},{SCHEME}="),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1=` prefix",
                },
            ),
            // `t` present but empty.
            (
                format!("{TIME_FIELD}=,{SCHEME}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty timestamp after `t=` prefix",
                },
            ),
            // Time is not a pure unix-seconds integer.
            (
                format!("{TIME_FIELD}=not-a-number,{SCHEME}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            // Sign-prefixed time is not pure ASCII digits.
            (
                format!("{TIME_FIELD}=+{TIME},{SCHEME}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            // All digits, but past u64 range.
            (
                format!("{TIME_FIELD}=99999999999999999999999,{SCHEME}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp overflows unix seconds",
                },
            ),
            // Ambiguous duplicate `t` field: reject, never first-wins.
            (
                format!(
                    "{TIME_FIELD}={TIME},{TIME_FIELD}={},{SCHEME}={SIGNATURE}",
                    TIME + 60
                ),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
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
            format!("t={TIME},v1=zzzz"),
            // Valid hex but odd-length.
            format!("t={TIME},v1=abc"),
            // Valid hex but not 32 bytes (SHA-1 length).
            format!("t={TIME},v1=40f2d4d8a1a0f6a9c9b1f4e2d3c4b5a67890abcd"),
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
}
