//! Zoom webhook signature verification.
//!
//! Scheme, per Zoom's official documentation
//! (<https://developers.zoom.us/docs/api/webhooks/> "Verify webhook events")
//! and their official sample app
//! (<https://github.com/zoom/webhook-sample-node.js>):
//!
//! - Headers: `x-zm-signature: v0=<hex_hmac>` and
//!   `x-zm-request-timestamp: <unix_ts>`
//! - Signed string: `"v0:{timestamp}:{raw_body}"` — the version number, the
//!   timestamp exactly as it appears in its header, and the raw request body
//!   bytes, joined by literal colons. Identical construction to Slack's scheme.
//! - Algorithm: HMAC-SHA256 with the webhook secret token, hex-encoded,
//!   prefixed `v0=` in the header. Treat the secret as a plain UTF-8 string;
//!   do not decode it first.
//!
//! # Replay protection
//!
//! Zoom signs a timestamp, enabling symmetric replay protection. The signed
//! timestamp is compared symmetrically (`|now - t|`) against
//! [`VerifyOptions::max_age`] (default 300s) using `now` from the injected
//! clock.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying Zoom's signature.
pub(crate) const SIGNATURE_HEADER: &str = "x-zm-signature";

/// The header carrying the signed unix timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "x-zm-request-timestamp";

/// The only signature scheme Zoom documents.
const SCHEME: &str = "v0";

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

    let provided_signature = parse_signature(signature_value)?;
    let timestamp = parse_timestamp(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed string is `v0:{timestamp_as_sent}:{raw_body}`; the raw timestamp
    // substring is reused verbatim so whatever was actually signed is what
    // gets verified.
    let mut signed_string =
        Vec::with_capacity(SCHEME.len() + 1 + timestamp_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(SCHEME.as_bytes());
    signed_string.push(b':');
    signed_string.extend_from_slice(timestamp_raw.as_bytes());
    signed_string.push(b':');
    signed_string.extend_from_slice(raw_body);

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided_signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(timestamp, options)
}

/// Parses the `v0=<hex>` signature header into its 32 decoded bytes.
///
/// Zoom documents exactly one scheme (`v0`); anything else is malformed
/// rather than silently accepted, to prevent downgrade attacks.
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let encoded = value
        .strip_prefix(SCHEME)
        .and_then(|rest| rest.strip_prefix('='))
        .ok_or(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "signature must start with the documented `v0=` scheme prefix",
        })?;

    if encoded.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "empty signature after `v0=` prefix",
        });
    }

    let bytes = hex::decode(encoded).map_err(|_| VerifyError::BadEncoding {
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

    /// Signing secret used to construct local test vectors.
    const SECRET: &str = "zoom_webhook_secret";
    /// Raw request body from a sample Zoom webhook event.
    const BODY: &[u8] = br#"{"event":"meeting.started","event_ts":1626230691572}"#;
    /// Timestamp matching the example headers in Zoom's docs.
    const TIMESTAMP: u64 = 1_739_923_528;

    /// Locally constructed over `BODY`:
    /// `printf 'v0:1739923528:{"event":"meeting.started","event_ts":1626230691572}' \
    ///   | openssl dgst -sha256 -hmac "zoom_webhook_secret"`
    const SIGNATURE: &str = "71276689c37d865ee24535dab72c05883e9d083978e8d3161202634051b15404";
    /// Locally constructed over an empty body (boundary case):
    /// `printf 'v0:1739923528:' | openssl dgst -sha256 -hmac "zoom_webhook_secret"`
    const EMPTY_BODY_SIGNATURE: &str =
        "fa287c1e8d522da8aa202f0b5f5ebfbb86499f21e3e355d8de79e9b59c7ad9dc";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case):
    /// `printf 'v0:1739923528:héllo, 🦀 world!' | openssl dgst -sha256 -hmac "zoom_webhook_secret"`
    const UNICODE_BODY_SIGNATURE: &str =
        "acdb345ab730d87b815b7f8c6d280399029aec15304310a172224d016aa9dff5";

    fn zoom_headers(timestamp: u64, signature: &str) -> Vec<(String, String)> {
        vec![
            (SIGNATURE_HEADER.to_string(), format!("v0={signature}")),
            (TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
        ]
    }

    fn verify_with(
        body: &[u8],
        signature_value: &str,
        timestamp_value: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Zoom,
            &[
                (SIGNATURE_HEADER, signature_value),
                (TIMESTAMP_HEADER, timestamp_value),
            ],
            body,
            &Secret::new(SECRET),
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, matching v0 signature.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("v0={signature}"),
            &TIMESTAMP.to_string(),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn constructed_vector_verifies() {
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
        let result = verify(
            crate::Provider::Zoom,
            &[
                ("x-zm-signature", format!("v0={SIGNATURE}").as_str()),
                ("x-zm-request-timestamp", TIMESTAMP.to_string().as_str()),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let flipped = format!("{}0{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_fresh(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        assert_eq!(
            verify_fresh(
                br#"{"event":"meeting.started","event_ts":1626230691572,"tampered":true}"#,
                SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        let result = verify_with(
            BODY,
            &format!("v0={SIGNATURE}"),
            &(TIMESTAMP - 1).to_string(),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Zoom,
            &zoom_headers(TIMESTAMP, SIGNATURE),
            BODY,
            &Secret::new("a_different_signing_secret"),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let options = clocked_at(TIMESTAMP + 301, Some(Duration::from_secs(300)));
        let result = verify_with(
            BODY,
            &format!("v0={SIGNATURE}"),
            &TIMESTAMP.to_string(),
            options,
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
        let options = clocked_at(TIMESTAMP - 301, Some(Duration::from_secs(300)));
        let result = verify_with(
            BODY,
            &format!("v0={SIGNATURE}"),
            &TIMESTAMP.to_string(),
            options,
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
        for now in [TIMESTAMP - 300, TIMESTAMP + 300] {
            let result = verify_with(
                BODY,
                &format!("v0={SIGNATURE}"),
                &TIMESTAMP.to_string(),
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let result = verify_with(
            BODY,
            &format!("v0={SIGNATURE}"),
            &TIMESTAMP.to_string(),
            clocked_at(TIMESTAMP + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify(
            crate::Provider::Zoom,
            &[("x-zm-request-timestamp", TIMESTAMP.to_string().as_str())],
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
            crate::Provider::Zoom,
            &[(SIGNATURE_HEADER, format!("v0={SIGNATURE}").as_str())],
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

        let both_missing = verify(
            crate::Provider::Zoom,
            &Vec::<(String, String)>::new(),
            BODY,
            &Secret::new(SECRET),
            Default::default(),
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
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                format!("v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "signature must start with the documented `v0=` scheme prefix",
                },
            ),
            (
                "v0".to_string(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "signature must start with the documented `v0=` scheme prefix",
                },
            ),
            (
                "v0=".to_string(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v0=` prefix",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                &value,
                &TIMESTAMP.to_string(),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            "v0=zzzz".to_string(),
            "v0=abc".to_string(),
            "v0=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ];
        for value in cases {
            let result = verify_with(
                BODY,
                &value,
                &TIMESTAMP.to_string(),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_timestamp_header_errors_distinctly() {
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
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                format!("-{TIMESTAMP}"),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                "99999999999999999999999".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp overflows unix seconds",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                &format!("v0={SIGNATURE}"),
                &value,
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
