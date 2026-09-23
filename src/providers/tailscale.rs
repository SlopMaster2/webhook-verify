//! Tailscale webhook signature verification.
//!
//! Scheme, per Tailscale's official documentation
//! (<https://tailscale.com/docs/features/webhooks> "Verifying an event
//! signature") and Tailscale's official example verifier
//! (`github.com/tailscale/tailscale`, `docs/webhooks/example.go`):
//!
//! - Header: `Tailscale-Webhook-Signature: t=<unix_ts>,v1=<hex_hmac>[
//!   ,v1=<hex_hmac>...]` — a comma-separated `key=value` list. `t` is the
//!   epoch time in seconds when the event occurred; `v1` is the HMAC-SHA256
//!   signature over `{t}.{raw_body}` and is "the only supported scheme for
//!   the signature".
//! - Signed string: `"{t}.{raw_body}"` — the `t` value exactly as it appears
//!   in the header, a literal dot, then the raw request body bytes. The docs'
//!   phrasing ("you need to decode the request body for signing purposes")
//!   refers to the events payload being JSON-encoded on the wire, *not* to a
//!   transform of the signed bytes: the official Go verifier reads
//!   `io.ReadAll(req.Body)` verbatim into the HMAC and decodes the JSON only
//!   *after* the signature check, so the exact bytes received are the exact
//!   bytes signed. `t` must be in canonical decimal form (no leading zeros):
//!   the Go verifier signs the parsed integer re-formatted canonically
//!   (`fmt.Append(nil, timestamp.Unix())`), so a non-canonical `t` would sign
//!   a string the reference verifier can never produce; Tailscale emits only
//!   canonical values, so the gate cannot reject a legitimate delivery.
//! - Algorithm: HMAC-SHA256 keyed by the per-endpoint webhook secret (a
//!   case-sensitive signing secret shared between Tailscale and the endpoint
//!   creator) as a plain UTF-8 string, hex-encoded (lowercase, no prefix).
//! - Multiple `v1=` values are accepted during webhook-secret rotation
//!   (the official Go verifier accumulates every `v1` and accepts a match on
//!   *any* element); unknown schemes and fields are discarded for forward
//!   compatibility.
//!
//! # Replay protection
//!
//! The docs recommend treating an event whose timestamp is more than five
//! minutes old as a replay attack (the official Go verifier hard-codes a
//! five-minute threshold), so this provider uses the crate's shared symmetric
//! window: `|now - t|` against [`VerifyOptions::max_age`] (default 300s) using
//! the injected clock.
//!
//! Note: the `t` value rides *inside* the single `Tailscale-Webhook-Signature`
//! header, not in a separate HTTP header, so there is one signature-relevant
//! header listed for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying Tailscale's combined `t` and `v1` fields.
pub(crate) const SIGNATURE_HEADER: &str = "Tailscale-Webhook-Signature";

/// The `t` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const TIME_FIELD: &str = "t";

/// The only signature scheme Tailscale defines, per its docs and the official
/// Go verifier.
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
    // verbatim so whatever was actually signed is what gets verified. `parse_header`
    // has already gated `t` to its canonical decimal form, so the verbatim bytes
    // are byte-identical to what the official Go verifier signs (it re-formats
    // the parsed integer with `fmt.Append(nil, timestamp.Unix())`).
    let mut signed_string = Vec::with_capacity(parsed.timestamp_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(parsed.timestamp_raw.as_bytes());
    signed_string.push(b'.');
    signed_string.extend_from_slice(raw_body);

    let matched = parsed
        .signatures
        .iter()
        .any(|sig| verify_hmac_sha256(secret.as_bytes(), &signed_string, sig));

    if !matched {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(parsed.timestamp, options)
}

/// A successfully parsed `Tailscale-Webhook-Signature` header value.
struct ParsedHeader<'a> {
    /// Decoded unix timestamp in seconds.
    timestamp: u64,
    /// The raw timestamp substring as sent (used verbatim in the signed
    /// string).
    timestamp_raw: &'a str,
    /// Every `v1=` signature decoded to its 32 bytes.
    signatures: Vec<Vec<u8>>,
}

/// Parses the header per Tailscale's documented algorithm: split on `,`, split
/// each element on the first `=`, keep `t` and all `v1` values, discard every
/// other element (including unknown/non-`v1` schemes).
///
/// Duplicate `t=` elements are rejected as ambiguous (`spec.md` §4.4) rather
/// than last-wins like the official Go verifier's parser — this crate fails
/// closed on ambiguity.
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

    // `t` is "the epoch time in seconds when the event occurred" (`spec.md`
    // §3); route it through the shared timestamp parser so sign-prefixed
    // (`t=+1591664030`), whitespace-padded, and overflowing values fail closed
    // exactly like every other timestamped provider (Slack, Zoom, Discord,
    // SendGrid, Standard Webhooks, Coinbase, Mux, `Custom`). The official Go
    // verifier uses a lenient `strconv.ParseInt`; the strict shared parser is
    // intentionally stricter and cannot reject a legitimate delivery.
    let timestamp = parse_timestamp(SIGNATURE_HEADER, timestamp_raw)?;

    // The signed string reuses the raw `t` substring, and the official Go
    // verifier signs the parsed integer re-formatted *canonically* (`mac.Write(
    // fmt.Append(nil, timestamp.Unix()))`). `parse_timestamp` accepts any
    // pure-digit string, including non-canonical spellings such as leading
    // zeros (`t=01663781880`) — reusing those verbatim would sign a string the
    // reference verifier can never produce, so they are rejected to keep this
    // crate's signed string byte-identical to it for every accepted value.
    // Tailscale emits only canonical values, so this cannot reject a
    // legitimate delivery.
    if timestamp_raw.len() > 1 && timestamp_raw.as_bytes()[0] == b'0' {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "timestamp is not in canonical decimal form",
        });
    }

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

    /// The example secret used in Tailscale's official example verifier
    /// (`docs/webhooks/example.go`). Tailscale publishes no byte-exact numeric
    /// test vector, so the vectors below are locally constructed over exactly
    /// the construction documented there ("Create a string, `string_to_sign`,
    /// to sign by concatenating: the timestamp... the `.` character... the
    /// decoded event request body") and cross-checked with Python's `hmac`
    /// module.
    const SECRET: &str = "tskey-webhook-xxxxx";

    /// The webhook event body mirrors the shape of Tailscale's documented
    /// events payload (an array of JSON event objects; the example uses a
    /// `nodeCreated`/`test` event set). Only the raw bytes as received are
    /// signed — the official Go verifier reads the body verbatim.
    const BODY: &[u8] = b"[{\"type\":\"nodeCreated\",\"tailnet\":\"example.com\",\"message\":\"Node alice-workstation1.yak-bebop.ts.net created\"}]";

    /// Local signing instant, just past Tailscale's documented example
    /// timestamp (`t=1663781880`).
    const TIME: u64 = 1_784_000_000;

    /// Locally constructed over the exact `{t}.{raw_body}` construction the
    /// official docs and Go verifier use:
    /// `HMAC-SHA256("tskey-webhook-xxxxx", "1784000000." + BODY)`.
    const SIGNATURE: &str = "50eaf5dfcedb5f1c555a344d1e5318510a3fd2517389f992673ae17915546ba0";

    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "8535970d7094154352c09b6117fa588a9a9f5bc18045de5e5871104df2048dd9";

    /// Locally constructed over `t=0` (the canonical boundary of the decimal
    /// spellings the gate accepts — a single `0`, no leading zeros):
    /// `HMAC-SHA256("tskey-webhook-xxxxx", "0." + BODY)`, cross-checked with
    /// Python's `hmac` module.
    const EPOCH_TIMESTAMP_SIGNATURE: &str =
        "f35b9749f96bf79188206f1523fabde25c54ae287c98a1ddb5cca6bdf6ce9b99";

    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "3aa4efb090ca25916b82e054b73e15f783cb9fe5a1ac4e1af91fdddd260a622b";

    /// The full example header published in Tailscale's docs
    /// (<https://tailscale.com/docs/features/webhooks>:
    /// `Tailscale-Webhook-Signature:
    /// t=1663781880,v1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`).
    /// Tailscale publishes no body for it, so it is replayed as a
    /// well-formed-but-mismatching input rather than a happy path.
    const DOCS_EXAMPLE_HEADER: &str =
        "t=1663781880,v1=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn verify_with(
        body: &[u8],
        header_value: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Tailscale,
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

    /// Tailscale's documented construction verifies.
    #[test]
    fn documented_construction_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn docs_example_header_is_well_formed_but_mismatches() {
        // The `Tailscale-Webhook-Signature` example from the docs must parse as
        // a perfectly valid header and come back as a plain signature
        // mismatch — not a MalformedHeader. This pins the header-shape parsing
        // to an official published value.
        let result = verify_with(
            BODY,
            DOCS_EXAMPLE_HEADER,
            &Secret::new(SECRET),
            clocked_at(1_663_781_880, Some(Duration::from_secs(300))),
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
    fn canonical_zero_timestamp_still_verifies() {
        // The canonical gate rejects *leading zeros*, not the value zero: `t=0`
        // is the canonical decimal of epoch time and must still verify (with a
        // clock pinned to it), while `t=00` fails closed like any other
        // non-canonical spelling.
        let header = format!("{TIME_FIELD}=0,{SCHEME}={EPOCH_TIMESTAMP_SIGNATURE}");
        assert_eq!(
            verify_with(
                BODY,
                &header,
                &Secret::new(SECRET),
                clocked_at(0, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
        let non_canonical = format!("{TIME_FIELD}=00,{SCHEME}={EPOCH_TIMESTAMP_SIGNATURE}");
        assert_eq!(
            verify_with(
                BODY,
                &non_canonical,
                &Secret::new(SECRET),
                clocked_at(0, Some(Duration::from_secs(300))),
            ),
            Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "timestamp is not in canonical decimal form",
            })
        );
    }

    #[test]
    fn multiple_v1_signatures_accept_a_match() {
        // Webhook-secret rotation: the header carries the old signature first
        // and the current one second; a match on *any* `v1` is accepted, as in
        // Tailscale's official Go verifier.
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
            crate::Provider::Tailscale,
            &[(
                "tailscale-webhook-signature",
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
            verify_fresh(b"[{\"type\":\"nodeCreated\"}]", SIGNATURE),
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
        // Valid signature, delivered 301s after signing — beyond the 300s
        // tolerance the docs recommend (events older than five minutes are
        // "consider[ed]... as a replay attack").
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
            crate::Provider::Tailscale,
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
            // Leading-zero time parses as digits but is not canonical decimal
            // form; the Go verifier would sign the canonical re-format, so the
            // raw spelling must fail closed.
            (
                format!("{TIME_FIELD}=0{TIME},{SCHEME}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not in canonical decimal form",
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
