//! Airwallex webhook signature verification.
//!
//! Scheme, per Airwallex's official documentation
//! (<https://www.airwallex.com/docs/developer-tools/webhooks/listen-for-webhook-events>
//! "Listen for webhook events" — the delivery-headers table, the "Check webhook
//! signatures" recipe, and the reference Java verifier):
//!
//! - Headers: `x-timestamp` (a Unix timestamp in **milliseconds**, e.g. the
//!   docs' `1357872222592`) and `x-signature` ("The `HMAC` hex digest of the
//!   concatenated timestamp and request body", sent only when the webhook is
//!   configured with a secret).
//! - Signed string: `"{x-timestamp}{raw_body}"` — the concatenation of the
//!   `x-timestamp` value exactly as it appears in its header, immediately
//!   followed by the raw request body bytes, **no separators**. The docs step
//!   through building `value_to_digest` by "concatenating the x-timestamp (as a
//!   string) and the actual JSON payload (the request's body, as a string)" in
//!   exactly that order, and their "Check the concatenation order" pitfall
//!   confirms the timestamp comes first.
//! - Algorithm: HMAC-SHA256, hex-encoded, keyed by the notification URL's
//!   **secret key** used verbatim as a plain string (the reference Java
//!   verifier keys `HmacUtils(HMAC_SHA_256, secret)` with the retrieved secret
//!   directly — never base64/hex-decoded). Each secret is unique to the URL it
//!   corresponds to; the header is only present on subscriptions configured
//!   with a secret.
//! - The docs warn to always use the original, unmodified request body when
//!   computing the signature and to verify before any JSON parsing — matching
//!   this crate's `raw_body` contract.
//!
//! # Replay protection
//!
//! `x-timestamp` is epoch **milliseconds**. The docs instruct callers, after a
//! matching signature, to "compute the difference between the current timestamp
//! and the received timestamp, then decide if the difference is within your
//! tolerance" — leaving the window to the verifier, so the shared symmetric
//! `|now - t| > max_age` window (default 300s) applies via the injected clock.
//! The timestamp is the first component of the HMAC-covered signed string, so
//! an attacker cannot freshen it. Because the value is epoch milliseconds, the
//! parsed value is floored to whole seconds (`millis / 1000`) before the shared
//! check — identical treatment to WorkOS's and HubSpot's millisecond timestamps
//! and to Ripple's unit-detecting floor (`spec.md` §3). The sub-second
//! truncation error (< 1s) is negligible against any configured window.
//!
//! Note: Airwallex sends the timestamp and signature in **two** separate
//! headers, so both are listed for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_millis};
use crate::core::secret::Secret;

/// The header carrying Airwallex's hex HMAC-SHA256 signature.
pub(crate) const SIGNATURE_HEADER: &str = "x-signature";

/// The header carrying the signed epoch-milliseconds timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "x-timestamp";

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

/// The number of milliseconds in one second.
const MILLIS_PER_SECOND: u64 = 1000;

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
    let timestamp_millis = parse_millis(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed string is `{x-timestamp}{raw_body}`: the timestamp substring is
    // reused verbatim so whatever was actually signed is what gets verified
    // (the docs' `value_to_digest` uses the header value "as a string").
    let mut signed_string = Vec::with_capacity(timestamp_raw.len() + raw_body.len());
    signed_string.extend_from_slice(timestamp_raw.as_bytes());
    signed_string.extend_from_slice(raw_body);

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided_signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    // `x-timestamp` is epoch milliseconds (13 digits), so floor to whole
    // seconds for the shared replay window — exactly what HubSpot's and
    // WorkOS's millisecond timestamps and Ripple's unit-detecting floor get
    // (`spec.md` §3).
    check_replay(timestamp_millis / MILLIS_PER_SECOND, options)
}

/// Decodes the hex `x-signature` value into its 32 raw signature bytes.
///
/// Every failure mode maps to a distinct error variant so callers can tell
/// malformed-request noise from signature-mismatch signals (`spec.md` §2.1).
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
    use super::{SIGNATURE_HEADER, TIMESTAMP_HEADER};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// The notification URL's secret key (the value the Airwallex web app
    /// exposes per webhook subscription), used verbatim as the HMAC key — a
    /// plain string, never decoded.
    const SECRET: &str = "dwuU84dOhCmZKxKakoJRW0n7sJk4Y0XPHRmBLXWOvM42P8z3qlxRny";

    /// The epoch-milliseconds value from Airwallex's own delivery-headers
    /// example (the docs show `1357872222592` as their illustrative
    /// `x-timestamp`). Not a multiple of 1000 on purpose: it doubles as the
    /// sub-second-truncation boundary case (`1357872222592 / 1000 ==
    /// 1357872222`, so the literal signed string and the floored replay
    /// timestamp disagree only below one second).
    const TIME_MS: &str = "1357872222592";

    /// The whole-second "now" corresponding to [`TIME_MS`] (floored), used as
    /// the injected clock reading in replay tests.
    const TIME_SECS: u64 = 1_357_872_222;

    /// A `payment_attempt.authorized` event shaped like Airwallex's published
    /// sample Webhook payload
    /// (<https://www.airwallex.com/docs/developer-tools/webhooks/listen-for-webhook-events>
    /// — the event fields `id`, `name`, `account_id`, `data.object`,
    /// `created_at`, `version`, carried verbatim as the raw body).
    const BODY: &[u8] = br#"{"id":"evt_100_2019102201540902013102020043_8321220011893766","name":"payment_attempt.authorized","account_id":"19621303213","data":{"object":{"payment_intent_id":"pi_09Y0F6n2zzMaxIW7DxAtCEyi","amount":"150.00","currency":"USD","status":"AUTHORISED"}},"created_at":"2019-10-22T01:54:09+0000","version":"2024-02-22"}"#;

    /// Locally constructed over `{TIME_MS}{BODY}` with `SECRET` (HMAC-SHA256,
    /// hex-encoded) — `printf '%s' "{TIME_MS}{BODY}" | openssl dgst -sha256
    /// -hmac "{SECRET}"`, cross-checked against Python's `hmac` module and the
    /// docs' reference Java verifier construction
    /// (`valueToDigest` = `x-timestamp` verbatim + body, keyed with `secret`
    /// directly). Airwallex publishes no byte-exact example signature, so the
    /// vector is locally constructed over exactly the documented construction.
    const SIGNATURE: &str = "59151be7df26a3f68ea91344ca9d4b521b5860f1922b7e4584a0e39a616aab5d";

    /// Locally constructed over `{TIME_MS}` with an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "707c0824e63290119c0c3b39b2edb7ee35e105b326a890072d3e9ff59deafad2";

    /// Locally constructed over `{TIME_MS}"héllo, 🦀 world!"` (unicode boundary
    /// case).
    const UNICODE_BODY_SIGNATURE: &str =
        "27f643d14085d6a06ef4ff665d521691072700feab281d506022739f8a602554";

    fn airwallex_headers(signature: &str, timestamp: &str) -> Vec<(String, String)> {
        vec![
            (SIGNATURE_HEADER.to_string(), signature.to_string()),
            (TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
        ]
    }

    fn verify_with(
        body: &[u8],
        signature: &str,
        timestamp: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Airwallex,
            &airwallex_headers(signature, timestamp),
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh timestamp (a sub-second `t`, flooring to
    /// the injected whole-second clock), matching signature.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            signature,
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        )
    }

    /// The documented-recipe vector verifies (and so does the ms→s flooring:
    /// `1357872222592` ms truncates to `1357872222` s, matching "now").
    #[test]
    fn documented_recipe_vector_verifies() {
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
    fn header_names_are_case_insensitive() {
        // The docs spell the headers lowercase (`x-timestamp`, `x-signature`);
        // HTTP header lookups are case-insensitive, so the canonical spelling
        // must resolve through the lowercase-to-titlecased lookup as well.
        let result = verify(
            crate::Provider::Airwallex,
            &[
                ("X-Signature", SIGNATURE.to_string().as_str()),
                ("X-Timestamp", TIME_MS),
            ],
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
        // Same signature, body mutated after signing: the signer glued the raw
        // body bytes into the signed string, so any change breaks it.
        let tampered = br#"{"id":"evt_100_2019102201540902013102020043_8321220011893766","name":"payment_attempt.authorized","account_id":"19621303213","data":{"object":{"payment_intent_id":"pi_09Y0F6n2zzMaxIW7DxAtCEyi","amount":"150.00","currency":"USD","status":"FAILED"}},"created_at":"2019-10-22T01:54:09+0000","version":"2024-02-22"}"#;
        assert_eq!(
            verify_fresh(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // The timestamp is glued into the signed string verbatim, so a
        // replayed-but-remembered timestamp with a valid-looking signature must
        // not verify.
        let result = verify_with(
            BODY,
            SIGNATURE,
            &(1_357_872_222_593u64.to_string()),
            &Secret::new(SECRET),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify_with(
            BODY,
            SIGNATURE,
            TIME_MS,
            &Secret::new("4c32ab9f14d8e7a2b01c9f3d5e7a81b2c4d6e8f0a1b2c3d4e5f60718293a4b5c"),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after the (floored) signing instant —
        // beyond the crate's default 300s tolerance (the docs leave the window
        // to the caller, so the shared default applies).
        let result = verify_with(
            BODY,
            SIGNATURE,
            TIME_MS,
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
            SIGNATURE,
            TIME_MS,
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
                SIGNATURE,
                TIME_MS,
                &Secret::new(SECRET),
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn replay_floor_matches_workos_treatment() {
        // The unsigned ms remainder must not leak into the window: a delivery
        // signed at 1357872222592 ms must survive a "now" at 1357872222299 ms
        // (the .299 differs by 707ms but the same whole second).
        let result = verify_with(
            BODY,
            SIGNATURE,
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        // `max_age: None` explicitly disables the recency check.
        let result = verify_with(
            BODY,
            SIGNATURE,
            TIME_MS,
            &Secret::new(SECRET),
            clocked_at(TIME_SECS + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify(
            crate::Provider::Airwallex,
            &[(TIMESTAMP_HEADER, TIME_MS.to_string().as_str())],
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
            crate::Provider::Airwallex,
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
            crate::Provider::Airwallex,
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
            // Garbage value: not valid hex.
            (
                "zzzz".to_string(),
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
            // Valid hex but odd-length.
            (
                "abc".to_string(),
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
            // Valid hex but not 32 bytes (SHA-1 length).
            (
                "40f2d4d8a1a0f6a9c9b1f4e2d3c4b5a67890abcd".to_string(),
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                &value,
                TIME_MS,
                &Secret::new(SECRET),
                clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn malformed_timestamp_header_errors_distinctly() {
        // The timestamp's shape is enforced by the shared epoch-milliseconds
        // parser with the same fail-closed rules as every other timestamped
        // provider.
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                "not-a-number".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not valid epoch milliseconds",
                },
            ),
            (
                format!("+{TIME_MS}"),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not valid epoch milliseconds",
                },
            ),
            (
                format!(" {TIME_MS}"),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not valid epoch milliseconds",
                },
            ),
            (
                "99999999999999999999999".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp overflows epoch milliseconds",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                SIGNATURE,
                &value,
                &Secret::new(SECRET),
                clocked_at(TIME_SECS, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
