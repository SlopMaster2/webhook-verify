//! WorkOS webhook signature verification.
//!
//! Scheme, per WorkOS's official documentation
//! (<https://workos.com/docs/events/data-syncing/webhooks> "Sync data with
//! webhooks" — the manual-verification section) and the official SDKs' webhook
//! verifiers (e.g. `workos-go`'s `WebhookVerifier`):
//!
//! - Header: `WorkOS-Signature: t=<epoch_ms>,v1=<hex_hmac>` — a
//!   comma-separated `key=value` list. The docs: "There are two values to
//!   parse from the `WorkOS-Signature` header, delimited by a `,` character."
//!   `t` is the epoch-**milliseconds** value at which the event was issued
//!   (`issued_timestamp`), `v1` is the HMAC-SHA256 signature over
//!   `{t}.{raw_body}` and is the only scheme defined.
//! - Signed string: `"{t}.{raw_body}"` — the `t` element exactly as it appears
//!   in the header (never re-formatted from the parsed number), a literal dot,
//!   then the raw request body bytes, unmodified. The docs build the message
//!   as "`issued_timestamp`, the `.` character, the request's body", and warn
//!   that the HMAC is computed over the body as a UTF-8 string — the raw wire
//!   bytes, not a re-serialized parse.
//! - Algorithm: HMAC-SHA256 keyed by the webhook signing secret as a plain
//!   UTF-8 string, hex-encoded (the docs' reference:
//!   "Hash the string using HMAC SHA256, using the webhook secret as the key.
//!   The expected signature will be the hex digest of the hash.").
//! - The secret is the one generated for the webhook endpoint in the WorkOS
//!   dashboard — a plain string, used verbatim as the HMAC key. Never
//!   base64/hex-decoded.
//!
//! # Replay protection
//!
//! The SDKs apply a tolerance window in *seconds* (the docs: "an optional
//! parameter, tolerance, that sets the time validation for the webhook in
//! seconds. The SDK methods have default values for tolerance, usually 3–5
//! minutes"; the PHP SDK's default is `180`, the .NET example passes `300`),
//! so this provider applies the crate's shared symmetric window: `|now - t|`
//! against [`VerifyOptions::max_age`] (default 300s) using the injected clock.
//! Because WorkOS issues `t` in epoch **milliseconds**, the parsed value is
//! floored to whole seconds (`millis / 1000`) before the shared check — the
//! same treatment HubSpot's millisecond timestamp gets (spec §3, HubSpot row).
//! The sub-second truncation error (< 1s) is negligible against any configured
//! window and cannot widen one meaningfully. As with Slack, Zoom, Cloudflare,
//! Coinbase, and HubSpot, the symmetric check also rejects future-dated
//! timestamps, which no legitimate delivery produces.
//!
//! Note: the `t` value rides *inside* the single `WorkOS-Signature` header,
//! not in a separate HTTP header, so there is one signature-relevant header
//! listed for the adapters' duplicate-detection check.
//!
//! # Parsing policy
//!
//! The docs define exactly two comma-delimited elements (`t`, `v1`). Duplicate
//! `t` or `v1` elements are rejected as ambiguous (`spec.md` §4.4) rather than
//! first-wins like lenient SDK parsers — this crate fails closed on ambiguity.
//! Unknown elements (a hypothetical future field) are discarded for forward
//! compatibility, matching the crate-wide behavior for Mux and Coinbase.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::options::VerifyOptions;
use crate::core::replay::{check_replay, parse_millis};
use crate::core::secret::Secret;

/// The header carrying the combined `t` and `v1` fields.
///
/// Sent as `WorkOS-Signature`; HTTP header lookups are case-insensitive, so
/// the lowercase `workos-signature` spelling created by header-normalizing
/// servers also resolves.
pub(crate) const SIGNATURE_HEADER: &str = "WorkOS-Signature";

/// The `t` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const TIME_FIELD: &str = "t";

/// The `v1` field name inside [`SIGNATURE_HEADER`]'s comma-separated list.
const SIG_FIELD: &str = "v1";

/// Field separator inside [`SIGNATURE_HEADER`].
const FIELD_SEPARATOR: char = ',';

/// HMAC-SHA256 output length in bytes (what a 64-hex-char `v1` decodes to).
const SIGNATURE_LEN_BYTES: usize = 32;

/// The number of milliseconds in one second.
const MILLIS_PER_SECOND: u64 = 1000;

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
    let timestamp_millis = parse_millis(SIGNATURE_HEADER, &time_raw)?;
    let provided = parse_signature(&signature_value)?;

    // Signed string is `{t}.{raw_body}`; the time substring is reused verbatim
    // so whatever was actually signed is what gets verified (the sub-second
    // digits are part of the HMAC input even though the replay check floors
    // them).
    let mut signed_string = Vec::with_capacity(time_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(time_raw.as_bytes());
    signed_string.push(b'.');
    signed_string.extend_from_slice(raw_body);

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided) {
        return Err(VerifyError::SignatureMismatch);
    }

    // `t` is epoch milliseconds (13 digits), so floor to whole seconds for
    // the shared replay window (exactly what HubSpot's row does with its
    // millisecond timestamp; `spec.md` §3).
    check_replay(timestamp_millis / MILLIS_PER_SECOND, options)
}

/// Splits `WorkOS-Signature` into its `t` and `v1` values, verbatim.
///
/// The docs define the header as exactly two comma-delimited `key=value`
/// pairs. Unknown elements (any future field) are ignored. Absent fields fail
/// closed as `missing ...`; a present-but-empty `v1=` fails downstream and
/// distinctly (`signature value is empty`). A duplicate `t` or `v1` element is
/// rejected as ambiguous (`spec.md` §4.4) rather than first-wins like lenient
/// SDK parsers — this crate fails closed on ambiguity.
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
        // Keys are compared after trimming surrounding whitespace: the
        // comma-space spelling (`t=..., v1=...`) that proxy header-folding and
        // hand-copied values produce must not silently drop a recognized key.
        // Values are never trimmed — the timestamp is reused verbatim in the
        // signed string, so the raw bytes must stay byte-for-byte intact.
        let key = key.trim();

        if key == TIME_FIELD {
            if time.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                });
            }
            time = Some(val);
        } else if key == SIG_FIELD {
            if sig.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
                });
            }
            sig = Some(val);
        }
    }

    let time = time.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "missing `t` field",
    })?;
    let sig = sig.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "missing `v1` field",
    })?;

    Ok((time.to_string(), sig.to_string()))
}

/// Decodes the hex `v1` value into its 32 raw signature bytes.
///
/// WorkOS emits lowercase hex; `hex::decode` accepts both cases, which is fine
/// since the comparison against the expected HMAC is constant-time. Every
/// failure mode maps to a distinct error variant (`spec.md` §2.1).
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

    /// The webhook signing secret (the value the WorkOS dashboard generates
    /// for the endpoint), used verbatim as the HMAC key — a plain string,
    /// never decoded.
    const SECRET: &str = "test_signing_secret_abcdef";

    /// The epoch-milliseconds value WorkOS would put in the `t=` element for
    /// the vector below. Not a multiple of 1000 on purpose: it doubles as the
    /// sub-second-truncation boundary case (`1720000000554 / 1000 ==
    /// 1720000000`, so the literal signed string and the floored replay
    /// timestamp disagree only below one second).
    const TIME_MS: &str = "1720000000554";

    /// The whole-second "now" corresponding to [`TIME_MS`] (floored), used as
    /// the injected clock reading in replay tests.
    const TIME_SECS: u64 = 1_720_000_000;

    /// A Directory Sync webhook event shaped like WorkOS's published event
    /// format (<https://workos.com/docs/events/data-syncing/webhooks>,
    /// best-practices section: events include a top-level `event` field and
    /// full `data` objects with `created_at`/`updated_at`).
    const BODY: &[u8] = br#"{"id":"evt_01JEMSQQQ5QHD2VQVP1ZWS2KX3","event":"dsync.user.created","created_at":"2024-07-03T09:46:40.554Z","data":{"id":"directory_user_01JEMSQQQ5QHD2VQVP1ZWS2KX4","email":"grace.hopper@example.com","username":"gracehopper","firstName":"Grace","lastName":"Hopper","state":"active","directoryId":"directory_01JEMSQQQ5QHD2VQVP1ZWS2KX5","organizationId":"org_01JEMSQQQ5QHD2VQVP1ZWS2KX6","groups":["group_01JEMSQQQ5QHD2VQVP1ZWS2KX7"]}}"#;

    /// Locally constructed over `{TIME_MS}.{BODY}` with `SECRET`
    /// (HMAC-SHA256, hex-encoded) — `printf '%s' "{TIME_MS}.{BODY}" | openssl
    /// dgst -sha256 -hmac "{SECRET}"`, cross-checked against the docs'
    /// manual-verification recipe ("`issued_timestamp`, the `.` character,
    /// the request's body as a utf-8 decoded string") and WorkOS's official
    /// SDK verifiers, which sign `{t}.{body}` with the secret verbatim.
    /// WorkOS publishes no byte-exact example signature, so the vector is
    /// locally constructed over exactly the documented construction.
    const SIGNATURE: &str = "23e474ffaeb30a5348100baedfd6eb4caa6edac509127e4bc603b8f8810710c1";

    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "7fda9827a03e17205e6e9b7d7166f594b2c1acdea57b2154ec1362d89eb736f4";

    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "d880001053209ef3077d76763c36a949d06c404498e0fea9a84083406a5098df";

    fn verify_with(
        body: &[u8],
        header_value: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::WorkOS,
            &[(SIGNATURE_HEADER, header_value)],
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh timestamp (a sub-second `t`, flooring
    /// to the injected whole-second clock), single matching v1.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("{TIME_FIELD}={TIME_MS},{SIG_FIELD}={signature}"),
            &Secret::new(SECRET),
            // "now" == the signed timestamp floored to whole seconds: always
            // within tolerance.
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        )
    }

    /// The documented-recipe vector verifies (and so does the ms→s flooring:
    /// `1720000000554` ms truncates to `1720000000` s, matching "now").
    #[test]
    fn documented_recipe_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn comma_space_spelling_is_tolerated() {
        // Real integrations (proxy header-folding, hand-pasted requests) often
        // emit `t=..., v1=...` with a space after the comma; keys must not be
        // silently dropped (which would otherwise misreport a present `t=` as
        // missing).
        let value = format!("{TIME_FIELD}={TIME_MS}, {SIG_FIELD}={SIGNATURE}");
        assert_eq!(
            verify_with(
                BODY,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
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
    fn api_reference_shaped_header_is_well_formed_but_mismatches() {
        // The `WorkOS-Signature` shape `t=<digits>,v1=<hex>` is pinned by the
        // SDK reference documentation
        // (<https://workos-workos-node.mintlify.app/api/webhooks>,
        // `getTimestampAndSignatureHash('t=1234567890,v1=abcdef123456')`):
        // the docs' own example header must parse as a perfectly valid header
        // and come back as a plain signature mismatch — not a MalformedHeader.
        let result = verify_with(
            BODY,
            "t=1234567890,v1=5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e5f8c89c40d3c5a2e",
            &Secret::new(SECRET),
            clocked_at(1_234_567, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let result = verify(
            crate::Provider::WorkOS,
            &[(
                "workos-signature",
                format!("t={TIME_MS},v1={SIGNATURE}").as_str(),
            )],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
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
                br#"{"id":"evt_01JEMSQQQ5QHD2VQVP1ZWS2KX3","event":"dsync.user.created","created_at":"2024-07-03T09:46:40.554Z","data":{"id":"directory_user_01JEMSQQQ5QHD2VQVP1ZWS2KX4","email":"grace.hopper@example.com","username":"gracehopper","firstName":"Grace","lastName":"Hopper","state":"pending","directoryId":"directory_01JEMSQQQ5QHD2VQVP1ZWS2KX5","organizationId":"org_01JEMSQQQ5QHD2VQVP1ZWS2KX6","groups":["group_01JEMSQQQ5QHD2VQVP1ZWS2KX7"]}}"#,
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
            &format!("t={},v1={SIGNATURE}", 1_720_000_000_054u64),
            &Secret::new(SECRET),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            &Secret::new("not-the-signing-secret"),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing — beyond the crate's
        // default tolerance (WorkOS's SDKs suggest a similar window; the
        // docs' examples pass 180–300 seconds).
        let result = verify_with(
            BODY,
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME_SECS + 301, Some(Duration::from_secs(300))),
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
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME_SECS - 301, Some(Duration::from_secs(300))),
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
        // Exactly max_age old/new is still inside the closed window. The
        // millisecond `t` floors to `TIME_SECS`, so the comparison is against
        // the floored value.
        for now in [TIME_SECS - 300, TIME_SECS + 300] {
            let result = verify_with(
                BODY,
                &format!("t={TIME_MS},v1={SIGNATURE}"),
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
            &format!("t={TIME_MS},v1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME_SECS + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::WorkOS,
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
            // No `v1` field.
            (
                format!("{TIME_FIELD}={TIME_MS}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `v1` field",
                },
            ),
            // `v1` present but empty.
            (
                format!("{TIME_FIELD}={TIME_MS},{SIG_FIELD}="),
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
            // Time is not a pure epoch-milliseconds integer.
            (
                format!("{TIME_FIELD}=not-a-number,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not valid epoch milliseconds",
                },
            ),
            // Sign-prefixed time is not pure ASCII digits.
            (
                format!("{TIME_FIELD}=+{TIME_MS},{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not valid epoch milliseconds",
                },
            ),
            // All digits, but past u64 range.
            (
                format!("{TIME_FIELD}=99999999999999999999999,{SIG_FIELD}={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp overflows epoch milliseconds",
                },
            ),
            // Ambiguous duplicate `t` field: reject, never first-wins.
            (
                format!(
                    "{TIME_FIELD}={TIME_MS},{TIME_FIELD}={},{SIG_FIELD}={SIGNATURE}",
                    TIME_SECS + 60
                ),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                },
            ),
            // Ambiguous duplicate `v1` field: reject, never first-wins.
            (
                format!("{TIME_FIELD}={TIME_MS},{SIG_FIELD}={SIGNATURE},{SIG_FIELD}={SIGNATURE}"),
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
                clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            // Not hex at all.
            format!("t={TIME_MS},v1=zzzz"),
            // Valid hex but odd-length.
            format!("t={TIME_MS},v1=abc"),
            // Valid hex but not 32 bytes (SHA-1 length).
            format!("t={TIME_MS},v1=40f2d4d8a1a0f6a9c9b1f4e2d3c4b5a67890abcd"),
        ];
        for value in cases {
            let result = verify_with(
                BODY,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_fields_are_ignored_but_required_ones_are_enforced() {
        // Forward compatibility: unknown elements around a well-formed t/v1
        // pair must not break verification — only the documented `t` and `v1`
        // elements are consulted.
        let result = verify_with(
            BODY,
            &format!("version=1,t={TIME_MS},foo=bar,v1={SIGNATURE}"),
            &Secret::new(SECRET),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }
}
