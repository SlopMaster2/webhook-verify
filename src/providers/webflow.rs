//! Webflow webhook signature verification.
//!
//! Scheme, per Webflow's official documentation
//! (<https://developers.webflow.com/data/docs/working-with-webhooks>
//! "Validating request signatures" — the request-header reference, the manual
//! validation recipe, and the Node/Python reference verifiers):
//!
//! - Headers: `x-webflow-timestamp` (Unix epoch **milliseconds**) and
//!   `x-webflow-signature` (a SHA-256 HMAC hash of the signed string).
//! - Signed string: `"{timestamp}:{raw_body}"` — the `x-webflow-timestamp`
//!   value parsed to an integer (so its canonical decimal form), a literal
//!   colon, then the raw request body bytes, unmodified. Both reference
//!   verifiers parse the timestamp to an integer first (`parseInt(timestamp,
//!   10)` in Node, `int(timestamp)` in Python) before concatenating with `":"`,
//!   and the crate's shared pure-ASCII-digit epoch-milliseconds parser already
//!   canonicalizes the value the same way for any input it accepts.
//! - Algorithm: HMAC-SHA256, hex-encoded (the reference code compares a
//!   `digest('hex')` output against the header value).
//! - Key: the webhook's signing key — a site token secret (webhooks created
//!   through site settings via a site token after April 14, 2025) or the OAuth
//!   application's client secret (webhooks created through an OAuth app) —
//!   used verbatim as a plain UTF-8 string (the reference code keys
//!   `crypto.createHmac('sha256', clientSecret)` with the secret directly —
//!   never base64/hex-decoded).
//!
//! # Replay protection
//!
//! `x-webflow-timestamp` is epoch **milliseconds**. The docs instruct callers,
//! after a matching signature, to reject a request when
//! `currentTime - requestTimestamp` exceeds `300000` (5 minutes in
//! milliseconds) — the window matches this crate's default `max_age` (300s).
//! The timestamp is the first component of the HMAC-covered signed string, so
//! an attacker cannot freshen it. Because the value is epoch milliseconds, the
//! parsed value is floored to whole seconds (`millis / 1000`) before the
//! shared symmetric `|now - t| > max_age` check via the injected clock —
//! identical treatment to WorkOS's, Airwallex's, and HubSpot's millisecond
//! timestamps (`spec.md` §3). The sub-second truncation error (< 1s) is
//! negligible against any configured window.
//!
//! Note: Webflow sends the timestamp and signature in **two** separate
//! headers, so both are listed for the adapters' duplicate-detection check.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_millis};
use crate::core::secret::Secret;

/// The header carrying Webflow's hex HMAC-SHA256 signature.
///
/// Sent as `x-webflow-signature`; HTTP header lookups are case-insensitive,
/// so the `X-Webflow-Signature` spelling also resolves.
pub(crate) const SIGNATURE_HEADER: &str = "x-webflow-signature";

/// The header carrying the signed epoch-milliseconds timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "x-webflow-timestamp";

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

    // Signed string is `{timestamp}:{raw_body}`. The timestamp is formatted
    // from its parsed integer so the signed bytes are the canonical decimal
    // form both reference verifiers sign (`parseInt`/`int` then concatenate).
    // `parse_millis` already rejects sign-prefixed, whitespace-padded, empty,
    // or non-digit values, so for anything Webflow legitimately sends this is
    // byte-identical to the header value as sent.
    let mut signed_string =
        Vec::with_capacity(timestamp_millis.to_string().len() + 1 + raw_body.len());
    signed_string.extend_from_slice(timestamp_millis.to_string().as_bytes());
    signed_string.push(b':');
    signed_string.extend_from_slice(raw_body);

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided_signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    // `x-webflow-timestamp` is epoch milliseconds (13 digits), so floor to
    // whole seconds for the shared replay window — exactly what WorkOS's and
    // Airwallex's millisecond timestamps and HubSpot's row get
    // (`spec.md` §3).
    check_replay(timestamp_millis / MILLIS_PER_SECOND, options)
}

/// Decodes the hex `x-webflow-signature` value into its 32 raw signature bytes.
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

    /// The webhook's `secretKey` exactly as Webflow's own "Create Webhook"
    /// response example shows it (<https://developers.webflow.com/data/docs/
    /// working-with-webhooks>, Step 2's response —
    /// `"secretKey": "2b4acfd1c5518bf03c73a4889d197d77251353857c22694bf150b9e3402ba15f"`),
    /// used verbatim as the HMAC key — a plain string, never decoded.
    const SECRET: &str = "2b4acfd1c5518bf03c73a4889d197d77251353857c22694bf150b9e3402ba15f";

    /// The epoch-milliseconds value from Webflow's own delivery example (the
    /// docs show `1722370035277` as their illustrative `x-webflow-timestamp`
    /// next to the example signature). Not a multiple of 1000 on purpose: it
    /// doubles as the sub-second-truncation boundary case
    /// (`1722370035277 / 1000 == 1722370035`, so the literal signed string
    /// and the floored replay timestamp disagree only below one second).
    const TIME_MS: &str = "1722370035277";

    /// The whole-second "now" corresponding to [`TIME_MS`] (floored), used as
    /// the injected clock reading in replay tests.
    const TIME_SECS: u64 = 1_722_370_035;

    /// The `form_submission` example payload from Webflow's own Step 3
    /// delivery example (the docs show this JSON as the body alongside
    /// `x-webflow-timestamp: 1722370035277`), carried verbatim as the raw body.
    const BODY: &[u8] = br#"{"triggerType":"form_submission","payload":{"name":"Email Form","siteId":"65427cf400e02b306eaa049c","data":{"Email 2":"hello@gmail.com"},"submittedAt":"2024-07-30T20:07:15.220Z","id":"66a947f35b9d7ba400e22733","formId":"65429eadebe8a9f3a30f62d7"}}"#;

    /// Locally constructed over `{TIME_MS}:{BODY}` with `SECRET` (HMAC-SHA256,
    /// hex-encoded) — `printf '%s' "{TIME_MS}:{BODY}" | openssl dgst -sha256
    /// -hmac "{SECRET}"`, cross-checked against Python's `hmac` module and
    /// the docs' Node/Python reference verifiers' construction
    /// (`parseInt(timestamp,10) + ":" + rawBody`, keyed with the secret
    /// directly). Webflow publishes an example timestamp and signature but
    /// never the matching secret, so the vector is locally constructed over
    /// exactly the documented construction using the docs' own example
    /// `secretKey` and example body.
    const SIGNATURE: &str = "3d2c36d21a1f85c7812f702074afdf7ea44f45f49155d4c0704735d6366295f8";

    /// Locally constructed over `{TIME_MS}:` with an empty body (boundary
    /// case).
    const EMPTY_BODY_SIGNATURE: &str =
        "e6f6a2156649d51a027e104c828ba3b03b963621bf2f6366a62fc4ae987af1e0";

    /// Locally constructed over `{TIME_MS}:héllo, 🦀 world!` (unicode boundary
    /// case).
    const UNICODE_BODY_SIGNATURE: &str =
        "d8b8b809ad9f82a228a6220c135c851880e1c5265acab1c96413bd118abbfb2e";

    fn webflow_headers(signature: &str, timestamp: &str) -> Vec<(String, String)> {
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
            crate::Provider::Webflow,
            &webflow_headers(signature, timestamp),
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
    /// `1722370035277` ms truncates to `1722370035` s, matching "now").
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
        // The docs spell the headers lowercase (`x-webflow-timestamp`,
        // `x-webflow-signature`); HTTP header lookups are case-insensitive, so
        // the canonical spelling must resolve through the lowercase-to-titlecased
        // lookup as well.
        let result = verify(
            crate::Provider::Webflow,
            &[
                ("X-Webflow-Signature", SIGNATURE.to_string().as_str()),
                ("X-Webflow-Timestamp", TIME_MS),
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
        let tampered = br#"{"triggerType":"form_submission","payload":{"name":"Email Form","siteId":"65427cf400e02b306eaa049c","data":{"Email 2":"evil@attacker.com"},"submittedAt":"2024-07-30T20:07:15.220Z","id":"66a947f35b9d7ba400e22733","formId":"65429eadebe8a9f3a30f62d7"}}"#;
        assert_eq!(
            verify_fresh(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // The timestamp is glued into the signed string, so a
        // replayed-but-remembered timestamp with a valid-looking signature must
        // not verify.
        let result = verify_with(
            BODY,
            SIGNATURE,
            &(1_722_370_035_278u64.to_string()),
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
        // beyond the docs' own 300000ms window and the crate's default 300s
        // tolerance.
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
        // signed at 1722370035277 ms must survive a "now" at 1722370035299 ms
        // (the .299 differs by 22ms but the same whole second).
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
            crate::Provider::Webflow,
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
            crate::Provider::Webflow,
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
            crate::Provider::Webflow,
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
