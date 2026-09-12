//! HubSpot webhook signature verification (API v3, "Signature Version 3").
//!
//! Scheme, per HubSpot's official documentation
//! (<https://developers.hubspot.com/docs/api/webhooks/error-handling>,
//! "Signature Version 3") and its worked endpoint-confirmation example, plus
//! the reference implementation in HubSpot's official webhook examples:
//!
//! - Headers: `X-HubSpot-Request-Timestamp` (`<unix_epoch_millis>`) and
//!   `X-HubSpot-Signature-V3` (`<base64(HMAC-SHA256(...))>`)
//! - Signed string: `{request_method}{request_uri}{raw_body}{timestamp}` —
//!   the delivery's HTTP method, then the request URI, then the raw request
//!   body bytes, then the timestamp **exactly as it appears in its header**,
//!   all concatenated with no separators
//! - Algorithm: HMAC-SHA256, base64-encoded (standard alphabet, padded)
//! - Key: the app's "App secret", used as its UTF-8 bytes verbatim
//!
//! # Caller-supplied context
//!
//! Like Square and Twilio, verification cannot proceed from headers + body +
//! secret alone: the source string includes both the HTTP method and the
//! request URI. Callers pass them via [`VerifyOptions::request_method`] and
//! [`VerifyOptions::request_url`]. Omitting or emptying either fails closed
//! with [`VerifyError::MissingContext`] rather than degrading into a weaker
//! check — a method/URI-less check would accept deliveries forged for a
//! different endpoint.
//!
//! The URI is **not** reconstructed from request headers; it is the exact
//! string HubSpot signed for the delivery. HubSpot documents that *when
//! computing the signature* it decodes certain URL-encoded characters
//! (`%3A`, `%2F`, `%40`, `%26`, `%3D`, `%2B`, `%24`, `%60`, `%22`, `%2C`,
//! `%3B`, `%3E`, `%3C`, `%3F`) in the URI. A caller behind those encodings
//! must pass the URI in the same decoded form HubSpot used. The crate treats
//! `request_url` as an exact verbatim constant — it neither adds nor removes
//! encoding.
//!
//! # Replay protection
//!
//! HubSpot delivers the signing timestamp in **epoch milliseconds** — the one
//! timestamped provider here that does not use whole seconds. The signed
//! string always uses the raw header value verbatim; the recency check
//! converts to whole seconds (`millis / 1000`, dropping the sub-second
//! remainder, as the official Java reference's integer division does) and
//! applies the shared symmetric default window ([`VerifyOptions::max_age`],
//! injectable clock). HubSpot's own reference snippets use a one-sided
//! five-minute check; this crate applies its single audited symmetric replay
//! backend for consistency with every other provider (`spec.md` §3, HubSpot
//! row).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_millis};
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying HubSpot's v3 signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-HubSpot-Signature-V3";

/// The header carrying the signing timestamp (unix epoch **milliseconds**).
pub(crate) const TIMESTAMP_HEADER: &str = "X-HubSpot-Request-Timestamp";

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

    // Fail closed on missing caller context *before* touching the signature:
    // without the method and URI there is nothing to verify against, and
    // falling through would turn a configuration error into an attack-shaped
    // `SignatureMismatch`.
    let request_method = options
        .request_method
        .as_deref()
        .filter(|m| !m.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "HubSpot signs the request method; set VerifyOptions::request_method",
        })?;
    let request_uri = options
        .request_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "HubSpot signs the request URI; set VerifyOptions::request_url",
        })?;

    let provided = parse_signature(signature_value)?;
    let key = signing_key(secret.as_bytes())?;
    let timestamp = parse_millis(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed string is `{method}{uri}{raw_body}{timestamp_as_sent}`: the raw
    // timestamp substring is reused verbatim so whatever was actually signed
    // is what gets verified, and the raw body is passed through untouched.
    let mut signed_string = Vec::with_capacity(
        request_method.len() + request_uri.len() + raw_body.len() + timestamp_raw.len(),
    );
    signed_string.extend_from_slice(request_method.as_bytes());
    signed_string.extend_from_slice(request_uri.as_bytes());
    signed_string.extend_from_slice(raw_body);
    signed_string.extend_from_slice(timestamp_raw.as_bytes());

    if !verify_hmac_sha256(key, &signed_string, &provided) {
        return Err(VerifyError::SignatureMismatch);
    }

    // The timestamp arrives in epoch milliseconds; drop the sub-second
    // remainder (as HubSpot's official Java reference does) before the shared
    // recency check.
    check_replay(timestamp / 1000, options)
}

/// Returns the HMAC key bytes: the app secret as configured, used as its
/// UTF-8 bytes verbatim. Only an empty secret is rejected, failing closed with
/// [`VerifyError::InvalidSecret`].
fn signing_key(secret: &[u8]) -> Result<&[u8], VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "signature key is empty",
        });
    }
    Ok(secret)
}

/// Parses `X-HubSpot-Signature-V3` into its 32 decoded signature bytes.
///
/// The value carries no `algo=` prefix — it is bare base64. Every failure mode
/// maps to a distinct error variant so callers can tell malformed-request
/// noise from signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| VerifyError::BadEncoding {
            reason: "signature is not valid standard base64",
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
    use crate::verify;
    use std::time::Duration;

    /// HubSpot's documented "Confirm your webhook" example, copied verbatim
    /// from
    /// <https://developers.hubspot.com/docs/api/webhooks/error-handling>
    /// (Signature Version 3 section). The body is the minified single-line
    /// form used in HubSpot's own reference implementations and confirmed
    /// here by reproducing the published signature; the docs render it
    /// pretty-printed merely for display.
    const OFFICIAL_SECRET: &str = "cfc68c0b-4b4e-4ef8-b764-95350e4ea479";
    const OFFICIAL_METHOD: &str = "POST";
    const OFFICIAL_URL: &str = "https://webhook.site/335453f5-94b3-49d9-b684-a55354d4b8df";
    const OFFICIAL_BODY: &[u8] = br#"[{"eventId":531833541,"subscriptionId":3923621,"portalId":48807704,"appId":16111050,"occurredAt":1752613920733,"subscriptionType":"contact.creation","attemptNumber":0,"objectId":138017612137,"changeFlag":"CREATED","changeSource":"CRM_UI","sourceId":"userId:76023669"}]"#;
    /// Epoch **milliseconds**; the official value.
    const OFFICIAL_TIMESTAMP: &str = "1752613922216";
    /// The official signed result for the example above.
    const OFFICIAL_SIGNATURE: &str = "gbj1XPRvUt0noT7i7fXfTzOD4sLzQmf0VT28ZYq0EYg=";
    /// `OFFICIAL_TIMESTAMP / 1000`, the whole-second clock the recency check
    /// compares against.
    const OFFICIAL_TIMESTAMP_SECS: u64 = 1_752_613_922;

    const SECRET: &str = "hubspot-local-test-secret";
    const METHOD: &str = "POST";
    const URL: &str = "https://example.com/webhook";
    const BODY: &[u8] = br#"{"event":1}"#;
    /// Primary local vector: `{METHOD}{URL}{BODY}{1700000000000}`.
    const TIMESTAMP_MS: &str = "1700000000000";
    const TIMESTAMP_SECS: u64 = 1_700_000_000;
    /// Locally constructed:
    /// `printf '%s' '{method}{url}{body}{timestamp}' | openssl dgst -sha256
    /// -hmac "$SECRET" -binary | base64`. HubSpot publishes no frozen vectors
    /// for arbitrary inputs, so the recipe was pinned against the official
    /// example by reproducing it byte-for-byte before constructing these —
    /// see the module docs.
    const SIGNATURE: &str = "8R9Ufg3RZvGNdB71HcSGhGftUzKX6roNP8P3OSq2LvA=";
    /// Same recipe over an empty body at `1700000001000` ms.
    const SIGNATURE_EMPTY_BODY: &str = "G7gtUBsT6dHpb1i1e0U+jFuMqD/5J1ZNA558crOidsg=";
    const EMPTY_BODY_TIMESTAMP_MS: &str = "1700000001000";
    /// Same recipe over `"héllo, 🦀 world!"` at `1700000002000` ms.
    const SIGNATURE_UNICODE_BODY: &str = "pYtLRV8GRjVd3r5KlDc8OnyR1hcSlClLbH1FiIsTteo=";
    const UNICODE_BODY_TIMESTAMP_MS: &str = "1700000002000";
    const UNICODE_BODY: &str = "héllo, 🦀 world!";
    /// Same recipe at `1700000000999` ms (i.e. `1700000000.999` s): the
    /// truncation boundary for the ms → s conversion.
    const SIGNATURE_SUBSECOND: &str = "YzdVYXHlGTUmB/LKJJsDdQoB0dqCy/IdTqqOXZGYriw=";
    const SUBSECOND_TIMESTAMP_MS: &str = "1700000000999";

    fn hubspot_headers(signature: &str, timestamp: &str) -> Vec<(String, String)> {
        vec![
            (SIGNATURE_HEADER.to_string(), signature.to_string()),
            (TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
        ]
    }

    /// Runs `verify()` with the supplied method/URL context and `options`
    /// (which must include a clock when the signature is expected to reach
    /// the recency check).
    fn verify_with_options(
        body: &[u8],
        signature: &str,
        timestamp_ms: &str,
        method: &str,
        url: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::HubSpot,
            &hubspot_headers(signature, timestamp_ms),
            body,
            &Secret::new(SECRET),
            options
                .with_request_method(method)
                .with_request_url(url),
        )
    }

    /// The primary local context, replayed at `now_secs` with the default
    /// 300s window. Use for tests whose signature should verify.
    fn verify_pinned(
        body: &[u8],
        signature: &str,
        timestamp_ms: &str,
        now_secs: u64,
    ) -> Result<(), VerifyError> {
        verify_with_options(
            body,
            signature,
            timestamp_ms,
            METHOD,
            URL,
            clocked_at(now_secs, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn official_vector_verifies() {
        let result = verify(
            crate::Provider::HubSpot,
            &hubspot_headers(OFFICIAL_SIGNATURE, OFFICIAL_TIMESTAMP),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
            clocked_at(OFFICIAL_TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(OFFICIAL_METHOD)
                .with_request_url(OFFICIAL_URL),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn local_vector_verifies() {
        assert_eq!(verify_pinned(BODY, SIGNATURE, TIMESTAMP_MS, TIMESTAMP_SECS), Ok(()));
    }

    #[test]
    fn boundary_bodies_verify() {
        // Empty body (boundary case), at its own timestamp's clock.
        assert_eq!(
            verify_pinned(b"", SIGNATURE_EMPTY_BODY, EMPTY_BODY_TIMESTAMP_MS, 1_700_000_001),
            Ok(())
        );

        // Unicode body (boundary case): signed over raw UTF-8 bytes.
        assert_eq!(
            verify_pinned(
                UNICODE_BODY.as_bytes(),
                SIGNATURE_UNICODE_BODY,
                UNICODE_BODY_TIMESTAMP_MS,
                1_700_000_002,
            ),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify(
            crate::Provider::HubSpot,
            &[
                ("x-hubspot-signature-v3", SIGNATURE),
                ("X-HUBSPOT-REQUEST-TIMESTAMP", TIMESTAMP_MS),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}B{}", &SIGNATURE[..3], &SIGNATURE[4..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_pinned(BODY, &flipped, TIMESTAMP_MS, TIMESTAMP_SECS),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Signature was computed over `{"event":1}`; a one-character body
        // change must break verification.
        assert_eq!(
            verify_pinned(br#"{"event":2}"#, SIGNATURE, TIMESTAMP_MS, TIMESTAMP_SECS),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_method_fails() {
        // Signature was computed over the POST delivery; delivering the same
        // payload with a different method changes the source string.
        let result = verify_with_options(
            BODY,
            SIGNATURE,
            TIMESTAMP_MS,
            "GET",
            URL,
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_request_url_fails() {
        let result = verify_with_options(
            BODY,
            SIGNATURE,
            TIMESTAMP_MS,
            METHOD,
            "https://example.com/webhook/reborn",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::HubSpot,
            &hubspot_headers(SIGNATURE, TIMESTAMP_MS),
            BODY,
            &Secret::new("a different secret"),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let result = verify_with_options(
            BODY,
            SIGNATURE,
            TIMESTAMP_MS,
            METHOD,
            URL,
            clocked_at(TIMESTAMP_SECS + 301, Some(Duration::from_secs(300))),
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
        let result = verify_with_options(
            BODY,
            SIGNATURE,
            TIMESTAMP_MS,
            METHOD,
            URL,
            clocked_at(TIMESTAMP_SECS - 301, Some(Duration::from_secs(300))),
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
    fn milliseconds_within_tolerance_verify_at_window_edges() {
        for now in [TIMESTAMP_SECS - 300, TIMESTAMP_SECS + 300] {
            let result = verify_with_options(
                BODY,
                SIGNATURE,
                TIMESTAMP_MS,
                METHOD,
                URL,
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn subsecond_remainder_is_truncated_not_rounded() {
        // 1700000000999 ms == 1700000000.999 s: the official integer-division
        // recipe truncates, so a 1s window accepts it at the whole-second
        // clock value...
        let result = verify_with_options(
            BODY,
            SIGNATURE_SUBSECOND,
            SUBSECOND_TIMESTAMP_MS,
            METHOD,
            URL,
            clocked_at(1_700_000_000, Some(Duration::from_secs(1))),
        );
        assert_eq!(result, Ok(()));

        // ...but two whole seconds later is already past a 1s window.
        let result = verify_with_options(
            BODY,
            SIGNATURE_SUBSECOND,
            SUBSECOND_TIMESTAMP_MS,
            METHOD,
            URL,
            clocked_at(1_700_000_002, Some(Duration::from_secs(1))),
        );
        assert_eq!(
            result,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(2),
                max_age: Duration::from_secs(1),
            })
        );
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let result = verify_with_options(
            BODY,
            SIGNATURE,
            TIMESTAMP_MS,
            METHOD,
            URL,
            clocked_at(TIMESTAMP_SECS + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_request_method_fails_closed() {
        let result = verify(
            crate::Provider::HubSpot,
            &hubspot_headers(SIGNATURE, TIMESTAMP_MS),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default().with_request_url(URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "HubSpot signs the request method; set VerifyOptions::request_method",
            })
        );

        // An explicitly-empty method is treated the same as absent.
        let result = verify(
            crate::Provider::HubSpot,
            &hubspot_headers(SIGNATURE, TIMESTAMP_MS),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default()
                .with_request_method("")
                .with_request_url(URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "HubSpot signs the request method; set VerifyOptions::request_method",
            })
        );
    }

    #[test]
    fn missing_request_url_fails_closed() {
        let result = verify(
            crate::Provider::HubSpot,
            &hubspot_headers(SIGNATURE, TIMESTAMP_MS),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default().with_request_method(METHOD),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "HubSpot signs the request URI; set VerifyOptions::request_url",
            })
        );

        // An explicitly-empty URL is treated the same as absent.
        let result = verify(
            crate::Provider::HubSpot,
            &hubspot_headers(SIGNATURE, TIMESTAMP_MS),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default()
                .with_request_method(METHOD)
                .with_request_url(""),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "HubSpot signs the request URI; set VerifyOptions::request_url",
            })
        );
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify(
            crate::Provider::HubSpot,
            &[(TIMESTAMP_HEADER, TIMESTAMP_MS)],
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default()
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::HubSpot,
            &[(SIGNATURE_HEADER, SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default()
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );

        let both_missing = verify(
            crate::Provider::HubSpot,
            &Vec::<(String, String)>::new(),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default()
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(
            both_missing,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_signature_header_errors_distinctly() {
        let cases: Vec<(String, Result<(), VerifyError>)> = vec![
            (
                String::new(),
                Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                }),
            ),
            // Garbage value: not valid base64 at all.
            (
                "not base64!!".to_string(),
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                }),
            ),
            // Valid base64 alphabet but wrong decoded length (SHA-1 size).
            (
                "2jmj7l5rSw0yVb/vlWAYkK/YBwk=".to_string(),
                Err(VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                }),
            ),
        ];
        for (value, expected) in cases {
            let result = verify_pinned(BODY, &value, TIMESTAMP_MS, TIMESTAMP_SECS);
            assert_eq!(result, expected, "input: {value:?}");
        }

        // Padding is required: the same 32 bytes without the trailing `=`
        // must be rejected.
        let value = "8R9Ufg3RZvGNdB71HcSGhGftUzKX6roNP8P3OSq2LvA";
        let result = verify_pinned(BODY, value, TIMESTAMP_MS, TIMESTAMP_SECS);
        match result {
            Err(VerifyError::BadEncoding { .. }) => {}
            other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
        }
    }

    #[test]
    fn malformed_timestamp_header_errors_distinctly() {
        let cases: Vec<(String, Result<(), VerifyError>)> = vec![
            (
                String::new(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "header is empty",
                }),
            ),
            (
                "not-a-number".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not valid epoch milliseconds",
                }),
            ),
            (
                // Negative values are not representable as u64 millis; they
                // must error, not wrap or panic.
                "-1752613922216".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not valid epoch milliseconds",
                }),
            ),
            (
                // All digits, but past u64 range.
                "99999999999999999999999".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp overflows epoch milliseconds",
                }),
            ),
        ];
        for (value, expected) in cases {
            let result = verify_pinned(BODY, SIGNATURE, &value, TIMESTAMP_SECS);
            assert_eq!(result, expected, "input: {value:?}");
        }
    }

    #[test]
    fn empty_secret_fails_distinctly() {
        let result = verify(
            crate::Provider::HubSpot,
            &hubspot_headers(SIGNATURE, TIMESTAMP_MS),
            BODY,
            &Secret::new(""),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "signature key is empty",
            })
        );
    }
}