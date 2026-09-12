//! Square webhook signature verification.
//!
//! Scheme, per Square's official documentation ("Verify and Validate an Event
//! Notification",
//! <https://developer.squareup.com/docs/webhooks/step3validate>) and the
//! reference implementations in Square's official SDKs (e.g.
//! `square-python-sdk`'s `square/utils/webhooks_helper.py`,
//! `square-php-sdk`'s `WebhooksHelper`):
//!
//! - Header: `x-square-hmacsha256-signature: <base64(HMAC-SHA256(key,
//!   notification_url ++ raw_body))>`
//! - Signed string: the notification URL configured for the webhook
//!   subscription, immediately followed by the raw request body bytes — no
//!   separator between them. The URL is **not** reconstructed from request
//!   headers; it is the exact constant from the Square Developer portal.
//! - Algorithm: HMAC-SHA256, base64-encoded (standard alphabet, padded)
//! - Key: the subscription's signature key, used as its UTF-8 bytes verbatim.
//!
//! # The signature key is *not* hex-encoded
//!
//! Earlier drafts of `spec.md` §3 (and older third-party write-ups) describe
//! hex-decoding the key before use. That matched Square's retired key format;
//! every current official SDK hashes the key string as UTF-8 directly, and the
//! docs' own example key (`asdf1234`) is not valid hexadecimal. This
//! implementation follows the current official sources; see the spec entry for
//! the full provenance note.
//!
//! # Caller-supplied context
//!
//! This is the one shipped scheme where verification cannot proceed from
//! headers + body + secret alone: the signed content includes the endpoint
//! URL. Callers pass it via [`VerifyOptions::request_url`] (typically the
//! dashboard-configured constant). Omitting or emptying it fails closed with
//! [`VerifyError::MissingContext`] rather than degrading into a body-only
//! check — a body-only check would accept deliveries forged for a different
//! endpoint.
//!
//! # Replay protection
//!
//! Square signs no timestamp, so [`VerifyOptions::max_age`] and the injected
//! clock have **no effect** for this provider; that is documented behavior,
//! not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying Square's signature.
///
/// Square's docs and official SDKs spell this header lowercase
/// (`x-square-hmacsha256-signature`); the `HeaderMap` lookup is ASCII
/// case-insensitive, so the raw-bytes spelling surfaced in `VerifyError`
/// messages and adapter scans follows the provider's own spelling
/// (`spec.md` §3, Square row).
pub(crate) const SIGNATURE_HEADER: &str = "x-square-hmacsha256-signature";

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

    // Fail closed on missing caller context *before* touching the signature:
    // without the URL there is nothing to verify against, and falling through
    // would turn a configuration error into an attack-shaped
    // `SignatureMismatch`.
    let notification_url = options
        .request_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "Square signs the notification URL; set VerifyOptions::request_url",
        })?;

    let provided = parse_signature(value)?;
    let key = signing_key(secret.as_bytes())?;

    // Signed string is `{notification_url}{raw_body}`: URL bytes first, raw
    // body bytes appended unmodified.
    let mut signed_string = Vec::with_capacity(notification_url.len() + raw_body.len());
    signed_string.extend_from_slice(notification_url.as_bytes());
    signed_string.extend_from_slice(raw_body);

    if verify_hmac_sha256(key, &signed_string, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Returns the HMAC key bytes: the signature key exactly as configured.
///
/// Square's scheme uses the key string as UTF-8 bytes (see module docs); only
/// an empty key is rejected, failing closed with [`VerifyError::InvalidSecret`].
fn signing_key(secret: &[u8]) -> Result<&[u8], VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "signature key is empty",
        });
    }
    Ok(secret)
}

/// Parses `x-square-hmacsha256-signature` into its 32 decoded signature bytes.
///
/// Like Shopify's scheme the value carries no `algo=` prefix — it is bare
/// base64. Every failure mode maps to a distinct error variant so callers can
/// tell malformed-request noise from signature-mismatch signals (§2.1).
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
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::verify;
    use std::time::Duration;

    /// Official vector from Square's "Verify and Validate an Event Notification"
    /// documentation (<https://developer.squareup.com/docs/webhooks/step3validate>):
    /// the docs' own server-setup instructions end with this exact cURL command
    /// against a server configured with `NOTIFICATION_URL =
    /// 'https://example.com/webhook'` and `SIGNATURE_KEY = 'asdf1234'`.
    const OFFICIAL_URL: &str = "https://example.com/webhook";
    const OFFICIAL_KEY: &str = "asdf1234";
    const OFFICIAL_BODY: &[u8] = br#"{"hello":"world"}"#;
    const OFFICIAL_SIGNATURE: &str = "2kRE5qRU2tR+tBGlDwMEw2avJ7QM4ikPYD/PJ3bd9Og=";
    /// Locally constructed over an empty body (boundary case):
    /// `printf '%s' 'https://example.com/webhook' |
    ///  openssl dgst -sha256 -hmac 'asdf1234' -binary | base64`
    const EMPTY_BODY_SIGNATURE: &str = "ynbHtv7mmd+3xVChP9MsT9iQ4vULFz7Gx8Sq9SZy4QM=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case),
    /// same recipe as above.
    const UNICODE_BODY_SIGNATURE: &str = "kRB6TPxZKvkPG92MGNd+qTSjhIhhb1KBL3mc/6moa4A=";

    fn square_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        let options = VerifyOptions::default().with_request_url(OFFICIAL_URL);
        verify(
            crate::Provider::Square,
            &square_headers(signature),
            body,
            &Secret::new(OFFICIAL_KEY),
            options,
        )
    }

    #[test]
    fn official_vector_verifies() {
        assert_eq!(verify_with(OFFICIAL_BODY, OFFICIAL_SIGNATURE), Ok(()));
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_with(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_with("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let options = VerifyOptions::default().with_request_url(OFFICIAL_URL);
        let result = verify(
            crate::Provider::Square,
            &[("x-square-hmacsha256-signature", OFFICIAL_SIGNATURE)],
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_KEY),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}B{}", &OFFICIAL_SIGNATURE[..3], &OFFICIAL_SIGNATURE[4..]);
        assert_ne!(flipped, OFFICIAL_SIGNATURE);
        assert_eq!(
            verify_with(OFFICIAL_BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        assert_eq!(
            verify_with(br#"{"hello":"w0rld"}"#, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_notification_url_fails() {
        // A delivery signed for any other endpoint — here differing by a
        // single trailing slash — must not verify. This is the whole point of
        // URL-scoping the signature.
        let options = VerifyOptions::default().with_request_url("https://example.com/webhook/");
        let result = verify(
            crate::Provider::Square,
            &square_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_KEY),
            options,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let options = VerifyOptions::default().with_request_url(OFFICIAL_URL);
        let result = verify(
            crate::Provider::Square,
            &square_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new("another-subscription-key"),
            options,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn empty_secret_fails_closed_as_invalid_secret() {
        let options = VerifyOptions::default().with_request_url(OFFICIAL_URL);
        let result = verify(
            crate::Provider::Square,
            &square_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(""),
            options,
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "signature key is empty"
            })
        );
    }

    #[test]
    fn max_age_has_no_effect_for_square() {
        // Square signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            request_url: Some(OFFICIAL_URL.to_string()),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Square,
            &square_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_KEY),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_request_url_fails_closed_as_missing_context() {
        let result = verify(
            crate::Provider::Square,
            &square_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_KEY),
            VerifyOptions::default(),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Square signs the notification URL; set VerifyOptions::request_url"
            })
        );

        // An explicitly empty URL is equally unusable.
        let result = verify(
            crate::Provider::Square,
            &square_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_KEY),
            VerifyOptions::default().with_request_url(""),
        );
        assert!(matches!(result, Err(VerifyError::MissingContext { .. })));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let options = VerifyOptions::default().with_request_url(OFFICIAL_URL);
        let result = verify(
            crate::Provider::Square,
            &Vec::<(String, String)>::new(),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_KEY),
            options,
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_and_bad_encoding_errors_are_distinct() {
        let options = VerifyOptions::default().with_request_url(OFFICIAL_URL);
        let cases: &[(&str, VerifyError)] = &[
            (
                "",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // Garbage value: not valid base64 at all.
            (
                "not base64!!",
                VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                },
            ),
            // Valid base64 alphabet but wrong decoded length (SHA-1 size).
            (
                "2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Square,
                &[(SIGNATURE_HEADER, value)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_KEY),
                options.clone(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Padded standard-base64 engine rejects unpadded input.
        let value = OFFICIAL_SIGNATURE.trim_end_matches('=');
        let result = verify(
            crate::Provider::Square,
            &[(SIGNATURE_HEADER, value)],
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_KEY),
            options.clone(),
        );
        match result {
            Err(VerifyError::BadEncoding { .. }) => {}
            other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
        }
    }
}
