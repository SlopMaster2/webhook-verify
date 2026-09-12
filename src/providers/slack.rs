//! Slack webhook signature verification.
//!
//! Scheme, per Slack's official documentation
//! (<https://docs.slack.dev/authentication/verifying-requests-from-slack>) and
//! their official Bolt SDK implementations (e.g.
//! <https://github.com/slackapi/bolt-js/blob/main/src/receivers/verify-request.ts>):
//!
//! - Headers: `X-Slack-Signature: v0=<hex_hmac>` and
//!   `X-Slack-Request-Timestamp: <unix_ts>`
//! - Signed string: `"v0:{timestamp}:{raw_body}"` — the version number, the
//!   timestamp exactly as it appears in its header, and the raw request body
//!   bytes, joined by literal colons. Treat the signing secret as a plain
//!   UTF-8 string; do not decode it first (per the docs).
//! - Algorithm: HMAC-SHA256 with the app's signing secret, hex-encoded,
//!   prefixed `v0=` in the header
//!
//! # Replay protection
//!
//! Slack explicitly recommends rejecting requests whose timestamp differs
//! from local time by more than five minutes. The signed timestamp is
//! compared symmetrically (`|now - t|`) against [`VerifyOptions::max_age`]
//! (default 300s) using `now` from the injected clock.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying Slack's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Slack-Signature";

/// The header carrying the signed unix timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "X-Slack-Request-Timestamp";

/// The only signature scheme Slack documents.
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
/// Slack documents exactly one scheme (`v0`); anything else is malformed
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

    /// Signing secret from the worked example in Slack's official docs
    /// (<https://docs.slack.dev/authentication/verifying-requests-from-slack>).
    const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    /// Raw request body from the same worked example.
    const BODY: &[u8] = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    /// Timestamp from the same worked example.
    const TIMESTAMP: u64 = 1_531_420_618;

    /// Official vector from Slack's documentation walkthrough:
    /// basestring `v0:{TIMESTAMP}:{BODY}` HMAC-SHA256'd with `{SECRET}`,
    /// published as
    /// `v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503`.
    /// Cross-checked locally with
    /// `openssl dgst -sha256 -hmac <secret>` over the same basestring.
    const SIGNATURE: &str = "a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    /// Locally constructed (same recipe/secret/timestamp) over an empty body
    /// (boundary case): `printf 'v0:1531420618:' | openssl dgst -sha256
    /// -hmac <secret>`.
    const EMPTY_BODY_SIGNATURE: &str =
        "55f41ec73231010289b54e669149ea021fccab11b5524355523533ce930cb739";
    /// Locally constructed (same recipe/secret/timestamp) over
    /// `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "1200938ebc09f4bb238038a89d972e3d1090cf006340a74e8312a69b4e5e46d5";

    fn slack_headers(timestamp: u64, signature: &str) -> [(String, String); 2] {
        [
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
            crate::Provider::Slack,
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
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn official_vector_verifies() {
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
            crate::Provider::Slack,
            &[
                ("x-slack-signature", format!("v0={SIGNATURE}").as_str()),
                ("x-slack-request-timestamp", TIMESTAMP.to_string().as_str()),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the hex alphabet so this exercises a
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
        assert_eq!(
            verify_fresh(
                b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&tampered=1",
                SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // The timestamp is part of the signed string, so a forged timestamp
        // must not verify even with a valid-looking signature attached.
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
            crate::Provider::Slack,
            &slack_headers(TIMESTAMP, SIGNATURE),
            BODY,
            &Secret::new("a_different_signing_secret"),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing — exactly the case
        // Slack's docs say must be rejected (> 5 minutes from local time).
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
        // Symmetric window: |now - ts| > max_age in either direction is
        // rejected, per Slack's own absolute-value check.
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
        // Exactly max_age old/new is still inside the closed window.
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
        // `max_age: None` explicitly disables the recency check.
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
            crate::Provider::Slack,
            &[("X-Slack-Request-Timestamp", TIMESTAMP.to_string().as_str())],
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
            crate::Provider::Slack,
            &[("X-Slack-Signature", format!("v0={SIGNATURE}").as_str())],
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
            crate::Provider::Slack,
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
                // A downgrade attempt via an unknown/future scheme version:
                // reject as malformed, never accept or ignore.
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
            // Not hex at all.
            "v0=zzzz".to_string(),
            // Valid hex but odd number of digits.
            "v0=abc".to_string(),
            // Valid hex but not 32 bytes (SHA-1 length).
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
                // Negative values are not representable as u64 unix seconds;
                // they must error, not wrap or panic.
                format!("-{TIMESTAMP}"),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // All digits, but past u64 range.
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
