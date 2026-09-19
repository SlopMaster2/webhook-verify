//! Fintoc webhook signature verification.
//!
//! Scheme, per Fintoc's official documentation
//! (<https://docs.fintoc.com/docs/webhooks-validating> "Validate webhook
//! signatures"), corroborated by the `fintoc-node`/`fintoc-python` SDKs'
//! `WebhookSignature` verifiers
//! (<https://github.com/fintoc-com/fintoc-node>,
//! <https://github.com/fintoc-com/fintoc-python>):
//!
//! - Header: `Fintoc-Signature: t=<unix_ts>,v1=<hex_hmac>` — a
//!   comma-separated `key=value` list. `t` is the integer unix-seconds value
//!   set by the server; `v1` is the HMAC-SHA256 signature over
//!   `{t}.{raw_body}` and is the only scheme the docs define.
//! - Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears
//!   in the header, a literal dot, then the raw request body bytes, unmodified
//!   (the docs' reference code builds `f"{timestamp}.{request.body}"` and
//!   warns that re-parsing the JSON payload before verification can alter the
//!   string and break the signature).
//! - Algorithm: HMAC-SHA256 keyed by the webhook endpoint's secret as a plain
//!   UTF-8 string, hex-encoded, carried bare in the header (no
//!   `sha256=` prefix).
//! - Unknown fields and non-`v1` schemes are discarded for forward
//!   compatibility. Fintoc's docs define exactly one signature element and no
//!   rotation window, so a second `v1=` is treated as malformed rather than
//!   rotation (matching the Calendly/WorkOS/Coinbase treatment of their single
//!   signature fields).
//!
//! # Replay protection
//!
//! Fintoc's docs recommend a five-minute tolerance ("Use five minutes as the
//! default tolerance"), which matches the crate's shared default; the
//! symmetric window `|now - t| > max_age` applies via the injected clock.
//! The future-dated half of the symmetry is stricter than the docs' phrasing
//! but cannot reject a legitimate delivery.
//!
//! Note: the `t` value rides *inside* the single `Fintoc-Signature` header,
//! not in a separate HTTP header, so there is one signature-relevant header
//! listed for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying Fintoc's combined `t` and `v1` fields.
pub(crate) const SIGNATURE_HEADER: &str = "Fintoc-Signature";

/// The `t` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const TIME_FIELD: &str = "t";

/// The only signature scheme Fintoc defines, per its docs.
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

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &parsed.signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(parsed.timestamp, options)
}

/// A successfully parsed `Fintoc-Signature` header value.
struct ParsedHeader<'a> {
    /// Decoded unix timestamp in seconds.
    timestamp: u64,
    /// The raw timestamp substring as sent (used verbatim in the signed
    /// string).
    timestamp_raw: &'a str,
    /// The `v1=` signature decoded to its 32 bytes.
    signature: Vec<u8>,
}

/// Parses the header per Fintoc's documented algorithm: split on `,`, split
/// each element on the first `=`, keep `t` and `v1`, discard every other
/// element (including unknown/non-`v1` schemes).
///
/// Duplicate `t=` or `v1=` elements are rejected as ambiguous (`spec.md` §4.4)
/// rather than last-wins like the docs' reference code — this crate fails
/// closed on ambiguity. Fintoc's docs define exactly one signature element and
/// no rotation window, so a second `v1=` is treated as malformed rather than
/// rotation.
fn parse_header(value: &str) -> Result<ParsedHeader<'_>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut timestamp_raw: Option<&str> = None;
    let mut signature: Option<Vec<u8>> = None;

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
            if signature.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
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
            signature = Some(bytes);
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

    // `t` is "a Unix timestamp" (`spec.md` §3); route it through the shared
    // timestamp parser so sign-prefixed (`t=+1626102791`), whitespace-padded,
    // and overflowing values fail closed exactly like every other timestamped
    // provider (Slack, Zoom, Discord, SendGrid, Standard Webhooks, Coinbase,
    // Custom).
    let timestamp = parse_timestamp(SIGNATURE_HEADER, timestamp_raw)?;

    let signature = signature.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "no `v1=` signature present",
    })?;

    Ok(ParsedHeader {
        timestamp,
        timestamp_raw,
        signature,
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

    /// A signing key used verbatim as its UTF-8 bytes (Fintoc never decodes
    /// it).
    const SECRET: &str = "fintoc_test_webhook_secret";

    /// The example `link.credentials_changed` event body published in Fintoc's
    /// docs' "Rebuild the signed message" section (everything after the `.` in
    /// the `1626102791.{"id":"evt_DyzYBwdC07ao5MqG",...}` message example).
    /// Carried verbatim, re-parsing-free, as the signed material. The docs'
    /// message example pairs the same timestamp (1626102791) with this body.
    const BODY: &[u8] = b"{\"id\":\"evt_DyzYBwdC07ao5MqG\",\"type\":\"link.credentials_changed\",\"mode\":\"test\",\"created_at\":\"2021-07-12T15:11:09.875Z\",\"data\":{\"id\":\"link_00000000\",\"mode\":\"test\",\"active\":true,\"object\":\"link\",\"status\":\"active\",\"accounts\":null,\"username\":\"111111111\",\"holder_id\":\"111111111\",\"created_at\":\"2021-06-24T00:00:00.000Z\",\"link_token\":null,\"holder_type\":\"individual\",\"institution\":{\"id\":\"cl_banco_bbva\",\"name\":\"Banco BBVA\",\"country\":\"cl\"}},\"object\":\"event\"}";

    const TIME: u64 = 1_626_102_791;

    /// Locally constructed over the documented `{t}.{raw_body}` construction:
    /// `printf '1626102791.{"id":"evt_DyzYBwdC07ao5MqG",...}' \
    ///   | openssl dgst -sha256 -hmac "fintoc_test_webhook_secret"`.
    ///
    /// Cross-checked with Python's `hmac.new(b"fintoc_test_webhook_secret",
    /// b"1626102791." + body, hashlib.sha256)`. Fintoc publishes the message
    /// (`1626102791.{"id":"evt_DyzYBwdC07ao5MqG",...}`) and an example header
    /// (`t=1620870928,v1=4df951e0...`) as separate examples with no signing
    /// key, so no byte-exact signature is published; the vectors follow the
    /// documented recipe precisely.
    const SIGNATURE: &str = "c8a0131683463617be09145f5482567291f1169e019ab98df79009fcc052698f";

    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "79cdd9aa28469e0f94e2efbc05810b264642e802d43b78fd384a98f96f88ad3a";

    /// Locally constructed over `"éé🦀"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "2faefce431ac2502e5a09f930f13aea79c86f90f179e3d0f65389d1c1f460212";

    /// The full example header published in Fintoc's docs
    /// (<https://docs.fintoc.com/docs/webhooks-validating>:
    /// `Fintoc-Signature: t=1620870928,v1=4df951e0...f567f6d`). Fintoc
    /// publishes no body or signing key for it, so it is replayed as a
    /// well-formed-but-mismatching input rather than a happy path.
    const DOCS_EXAMPLE_HEADER: &str =
        "t=1620870928,v1=4df951e02db34a3f333bccad26d207993e9b14d78ac77cec026091991f567f6d";

    fn verify_with(
        body: &[u8],
        header_value: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Fintoc,
            &[(SIGNATURE_HEADER, header_value)],
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, matching v1.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("{TIME_FIELD}={TIME},{SCHEME}={signature}"),
            &Secret::new(SECRET),
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(TIME, Some(Duration::from_secs(300))),
        )
    }

    /// The locally constructed vector over the documented construction (and the
    /// docs' own example body) verifies, and the docs' published example header
    /// parses but mismatches.
    #[test]
    fn constructed_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn docs_example_header_is_well_formed_but_mismatches() {
        // Fintoc's published example header must parse as a perfectly valid
        // header and come back as a plain signature mismatch — not a
        // MalformedHeader. This pins the header-shape parsing to an official
        // published value.
        let result = verify_with(
            BODY,
            DOCS_EXAMPLE_HEADER,
            &Secret::new(SECRET),
            clocked_at(1_620_870_928, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_fresh(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_fresh("éé🦀".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
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
            crate::Provider::Fintoc,
            &[(
                "fintoc-signature",
                format!("t={TIME},v1={SIGNATURE}").as_str(),
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
        let flipped = format!("{}0{}", &SIGNATURE[..10], &SIGNATURE[11..]);
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
            verify_fresh(b"{\"id\":\"evt_tampered\"}", SIGNATURE),
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
            &Secret::new("not-the-webhook-secret"),
            clocked_at(TIME, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing.
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
    fn replay_documented_300s_tolerance_is_configurable() {
        // Fintoc's docs prescribe a five-minute tolerance; with a narrower
        // window configured, a `window+1`s-old delivery is rejected while a
        // `window`s-old one is accepted.
        let value = format!("t={TIME},v1={SIGNATURE}");
        let stale = verify_with(
            BODY,
            &value,
            &Secret::new(SECRET),
            clocked_at(TIME + 181, Some(Duration::from_secs(180))),
        );
        assert!(matches!(
            stale,
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
        let edge = verify_with(
            BODY,
            &value,
            &Secret::new(SECRET),
            clocked_at(TIME + 180, Some(Duration::from_secs(180))),
        );
        assert_eq!(edge, Ok(()));
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
            crate::Provider::Fintoc,
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
            // Ambiguous duplicate `v1` field: Fintoc documents no rotation
            // list, so reject rather than accept either value.
            (
                format!(
                    "{TIME_FIELD}={TIME},{SCHEME}=0000000000000000000000000000000000000000000000000000000000000000,{SCHEME}={SIGNATURE}"
                ),
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
