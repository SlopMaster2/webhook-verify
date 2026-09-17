//! Twitch EventSub webhook signature verification.
//!
//! Scheme, per Twitch's official documentation
//! (<https://dev.twitch.tv/docs/eventsub/handling-webhook-events/>
//! "Verifying the signature"):
//!
//! - Headers: `Twitch-Eventsub-Message-Id`,
//!   `Twitch-Eventsub-Message-Timestamp` (RFC 3339, with nanoseconds), and
//!   `Twitch-Eventsub-Message-Signature: sha256=<hex_hmac>`.
//! - Signed string: `"{message_id}{message_timestamp}{raw_body}"` — the
//!   message id and timestamp **exactly as they appear in their headers**
//!   (concatenated with the raw body bytes; no separators). The timestamp's
//!   numeric grammar must never be re-serialized into the signed bytes — the
//!   verbatim header substring is what was signed.
//! - Algorithm: HMAC-SHA256 with the webhook secret, hex-encoded, prefixed
//!   `sha256=` in the header. Treat the secret as a plain UTF-8 string; do
//!   not decode it first.
//!
//! # Replay protection
//!
//! Twitch signs a timestamp, enabling symmetric replay protection. The signed
//! timestamp is compared symmetrically (`|now - t|`) against
//! [`VerifyOptions::max_age`] (default 300s) using `now` from the injected
//! clock. Twitch's own docs only demonstrate the checksum comparison and do
//! not prescribe a freshness window; applying the shared window here is
//! strictly stronger than their sample code and cannot reject a legitimate
//! delivery the provider considers valid (the timestamp is HMAC-covered, so
//! an attacker cannot freshen it).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_rfc3339_timestamp};
use crate::core::secret::Secret;

/// The header carrying the opaque per-delivery message id.
pub(crate) const MESSAGE_ID_HEADER: &str = "Twitch-Eventsub-Message-Id";

/// The header carrying the signed RFC 3339 message timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "Twitch-Eventsub-Message-Timestamp";

/// The header carrying Twitch's signature.
pub(crate) const SIGNATURE_HEADER: &str = "Twitch-Eventsub-Message-Signature";

/// The only signature scheme Twitch documents.
const SCHEME: &str = "sha256";

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
    let message_id = headers
        .get(MESSAGE_ID_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: MESSAGE_ID_HEADER,
        })?;
    // The id is otherwise opaque (no format grammar is imposed), but a
    // present-but-empty value is never a legitimate Twitch delivery and is
    // rejected as malformed rather than surfaced as a signature mismatch —
    // matching the fail-closed treatment of Standard Webhooks' opaque
    // `webhook-id` (`spec.md` §3).
    if message_id.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: MESSAGE_ID_HEADER,
            reason: "header is empty",
        });
    }
    let timestamp_raw = headers
        .get(TIMESTAMP_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: TIMESTAMP_HEADER,
        })?;

    let provided_signature = parse_signature(signature_value)?;
    let timestamp = parse_rfc3339_timestamp(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed string is `{message_id}{message_timestamp_as_sent}{raw_body}`;
    // the message id and timestamp substrings are reused verbatim so whatever
    // was actually signed is what gets verified. Twitch's sample compares the
    // HMAC over this exact concatenation (message id + message timestamp +
    // message body), with no separators added.
    let mut signed_string =
        Vec::with_capacity(message_id.len() + timestamp_raw.len() + raw_body.len());
    signed_string.extend_from_slice(message_id.as_bytes());
    signed_string.extend_from_slice(timestamp_raw.as_bytes());
    signed_string.extend_from_slice(raw_body);

    if !verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided_signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(timestamp, options)
}

/// Parses the `sha256=<hex>` signature header into its 32 decoded bytes.
///
/// Twitch documents exactly one scheme (`sha256`); anything else is malformed
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
            reason: "signature must start with the documented `sha256=` scheme prefix",
        })?;

    if encoded.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "empty signature after `sha256=` prefix",
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
    use super::{MESSAGE_ID_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// Signing secret used to construct local test vectors.
    const SECRET: &str = "twitch_webhook_secret";
    /// Raw request body shaped like the notification example in Twitch's
    /// "Verifying the signature" docs.
    const BODY: &[u8] = br#"{"subscription":{"id":"0f246fad-1356-49ee-b0a9-6a1c103fr0d1","type":"channel.follow","version":"1","status":"enabled","cost":0,"condition":{"broadcaster_user_id":"1337"},"transport":{"method":"webhook","callback":"https://example.com/webhooks/callback"}},"event":{"user_id":"666","user_login":"cool_user","user_name":"Cool_User","broadcaster_user_id":"1337","broadcaster_user_login":"cool_guy","broadcaster_user_name":"Cool_Guy","followed_at":"2020-07-15T18:16:11.17106713Z"}}"#;
    /// Opaque per-delivery message id. Twitch's docs specify signing over the
    /// message id value; the grammar (UUID-shaped here) is not validated —
    /// the value only needs to match what was signed.
    const MESSAGE_ID: &str = "b2f45e9d-85a3-4b8c-91c1-7c03b6b6e4f2";
    /// Message timestamp in the RFC 3339 (nanosecond) shape Twitch's docs
    /// use, matching unix seconds `1767225600`.
    const TIMESTAMP: &str = "2026-01-01T00:00:00.000000000Z";
    /// A second message id, used to prove the id binds into the signature.
    const MESSAGE_ID_2: &str = "66c04e26-9a7d-4b2c-9a6f-1d3c92f8ab04";

    /// Locally constructed over the concatenation `MESSAGE_ID + TIMESTAMP +
    /// BODY` (Twitch's documented construction), because Twitch publishes no
    /// worked HMAC example in its docs:
    /// ```
    /// ID='b2f45e9d-85a3-4b8c-91c1-7c03b6b6e4f2'
    /// TS='2026-01-01T00:00:00.000000000Z'
    /// printf '%s' "$ID$TS$BODY..." | openssl dgst -sha256 -hmac "twitch_webhook_secret"
    /// ```
    const SIGNATURE: &str = "2d32ac8112f5dac0c544d6f50241d69b0629635728f57ae69c92cb679e9083af";
    /// Locally constructed over `MESSAGE_ID + TIMESTAMP` (empty body):
    /// `printf '%s' "$ID$TS" | openssl dgst -sha256 -hmac "twitch_webhook_secret"`
    const EMPTY_BODY_SIGNATURE: &str =
        "e7c313855bdef158089b3345f3958e11cbccb9eca8a12334b8634699233f7fac";
    /// Locally constructed over `MESSAGE_ID + TIMESTAMP + "héllo, 🦀 world!"`
    /// (unicode boundary case):
    /// `printf '%s' "$ID$TS$UNI" | openssl dgst -sha256 -hmac "twitch_webhook_secret"`
    const UNICODE_BODY_SIGNATURE: &str =
        "ad3ff0d3e12651b6bd4ae6353d36c23a31d6503e7b0663a18f1380b6b7bb3c3a";
    /// Locally constructed over `MESSAGE_ID_2 + TIMESTAMP + BODY`, proving the
    /// message id participates in the signed string:
    /// `printf '%s' "$ID2$TS$BODY..." | openssl dgst -sha256 -hmac "twitch_webhook_secret"`
    const MESSAGE_ID_2_SIGNATURE: &str =
        "7833bbb41cb8aaaec7b3ac81c4a4eb178f33c9cf68021e42af5fde20b727a74f";
    /// A deliberately non-UUID id: the id is opaque, so any non-empty value is
    /// well-formed and must ride verbatim into the signed string.
    const GARBAGE_ID: &str = "garbage-id!!@#$%^&*()";
    /// Locally constructed over `GARBAGE_ID + TIMESTAMP + BODY` (proving the
    /// opaque id is signed verbatim):
    /// `printf '%s' "$GARBAGE$TS$BODY..." | openssl dgst -sha256 -hmac "twitch_webhook_secret"`
    const GARBAGE_ID_SIGNATURE: &str =
        "ee93a7009b27e1b493d81ded8f8a6ca9781906cfe036a007eeed62b466a85ff5";

    fn twitch_headers(message_id: &str, signature: &str) -> Vec<(String, String)> {
        vec![
            (MESSAGE_ID_HEADER.to_string(), message_id.to_string()),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP.to_string()),
            (SIGNATURE_HEADER.to_string(), format!("sha256={signature}")),
        ]
    }

    fn verify_with(
        message_id: &str,
        body: &[u8],
        signature_value: &str,
        timestamp_value: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Twitch,
            &[
                (MESSAGE_ID_HEADER, message_id),
                (TIMESTAMP_HEADER, timestamp_value),
                (SIGNATURE_HEADER, signature_value),
            ],
            body,
            &Secret::new(SECRET),
            options,
        )
    }

    fn verify_fresh(message_id: &str, body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            message_id,
            body,
            &format!("sha256={signature}"),
            TIMESTAMP,
            clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn constructed_vector_verifies() {
        assert_eq!(verify_fresh(MESSAGE_ID, BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn message_id_is_bound_into_signature() {
        // The same body/timestamp re-signed under a different message id must
        // verify with that id's own signature — the id is part of the signed
        // string, not merely an ignored header.
        assert_eq!(
            verify_fresh(MESSAGE_ID_2, BODY, MESSAGE_ID_2_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_fresh(MESSAGE_ID, b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_fresh(
                MESSAGE_ID,
                "héllo, 🦀 world!".as_bytes(),
                UNICODE_BODY_SIGNATURE
            ),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify(
            crate::Provider::Twitch,
            &[
                (
                    "twitch-eventsub-message-id",
                    MESSAGE_ID.to_string().as_str(),
                ),
                (
                    "twitch-eventsub-message-timestamp",
                    TIMESTAMP.to_string().as_str(),
                ),
                (
                    "twitch-eventsub-message-signature",
                    format!("sha256={SIGNATURE}").as_str(),
                ),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let flipped = format!("{}0{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_fresh(MESSAGE_ID, BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        assert_eq!(
            verify_fresh(
                MESSAGE_ID,
                br#"{"subscription":{"id":"0f246fad-1356-49ee-b0a9-6a1c103fr0d1","type":"channel.follow","version":"1","status":"enabled","cost":0,"condition":{"broadcaster_user_id":"1337","tampered":true},"transport":{"method":"webhook","callback":"https://example.com/webhooks/callback"}},"event":{"user_id":"666","user_login":"cool_user","user_name":"Cool_User","broadcaster_user_id":"1337","broadcaster_user_login":"cool_guy","broadcaster_user_name":"Cool_Guy","followed_at":"2020-07-15T18:16:11.17106713Z"}}"#,
                SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_message_id_fails() {
        // Signature was computed over MESSAGE_ID; sending it with a different
        // id must fail even though the id itself is never parsed.
        assert_eq!(
            verify_fresh(MESSAGE_ID_2, BODY, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn malformed_message_id_header_errors_distinctly() {
        // §5.5's empty-value case for the id. The id has no format grammar
        // (any non-empty value is opaque), but an empty identifier is never a
        // legitimate Twitch delivery, so it fails closed as MalformedHeader
        // rather than surfacing as a signature mismatch.
        let result = verify_with(
            "",
            BODY,
            &format!("sha256={SIGNATURE}"),
            TIMESTAMP,
            clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::MalformedHeader {
                header: MESSAGE_ID_HEADER,
                reason: "header is empty",
            })
        );
    }

    #[test]
    fn garbage_value_message_id_is_opaque_and_signed_verbatim() {
        // §5.5's garbage-value case for the id: unlike the signature and
        // timestamp headers, the id has no defined format to parse — any
        // non-empty value is well-formed. A garbage id must (a) NOT be
        // rejected as MalformedHeader and (b) verify only against a signature
        // made over that exact id, never against one made over the real id.
        assert_eq!(verify_fresh(GARBAGE_ID, BODY, GARBAGE_ID_SIGNATURE), Ok(()));
        assert_eq!(
            verify_fresh(GARBAGE_ID, BODY, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // The timestamp is signed verbatim: altering its spelling (here,
        // dropping the fractional seconds) changes the signed string even
        // though it still denotes the same instant.
        let result = verify_with(
            MESSAGE_ID,
            BODY,
            &format!("sha256={SIGNATURE}"),
            "2026-01-01T00:00:00Z",
            clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Twitch,
            &twitch_headers(MESSAGE_ID, SIGNATURE),
            BODY,
            &Secret::new("a_different_signing_secret"),
            clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let options = clocked_at(1_767_225_600 + 301, Some(Duration::from_secs(300)));
        let result = verify_with(
            MESSAGE_ID,
            BODY,
            &format!("sha256={SIGNATURE}"),
            TIMESTAMP,
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
        let options = clocked_at(1_767_225_600 - 301, Some(Duration::from_secs(300)));
        let result = verify_with(
            MESSAGE_ID,
            BODY,
            &format!("sha256={SIGNATURE}"),
            TIMESTAMP,
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
        for now in [1_767_225_600 - 300, 1_767_225_600 + 300] {
            let result = verify_with(
                MESSAGE_ID,
                BODY,
                &format!("sha256={SIGNATURE}"),
                TIMESTAMP,
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let result = verify_with(
            MESSAGE_ID,
            BODY,
            &format!("sha256={SIGNATURE}"),
            TIMESTAMP,
            clocked_at(1_767_225_600 + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify(
            crate::Provider::Twitch,
            &[
                (MESSAGE_ID_HEADER, MESSAGE_ID.to_string().as_str()),
                (TIMESTAMP_HEADER, TIMESTAMP.to_string().as_str()),
            ],
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

        let missing_message_id = verify(
            crate::Provider::Twitch,
            &[
                (TIMESTAMP_HEADER, TIMESTAMP.to_string().as_str()),
                (SIGNATURE_HEADER, format!("sha256={SIGNATURE}").as_str()),
            ],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_message_id,
            Err(VerifyError::MissingHeader {
                header: MESSAGE_ID_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::Twitch,
            &[
                (MESSAGE_ID_HEADER, MESSAGE_ID.to_string().as_str()),
                (SIGNATURE_HEADER, format!("sha256={SIGNATURE}").as_str()),
            ],
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
            crate::Provider::Twitch,
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
            (
                format!("sha384={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "signature must start with the documented `sha256=` scheme prefix",
                },
            ),
            (
                "sha256".to_string(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "signature must start with the documented `sha256=` scheme prefix",
                },
            ),
            (
                "sha256=".to_string(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `sha256=` prefix",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                MESSAGE_ID,
                BODY,
                &value,
                TIMESTAMP,
                clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            "sha256=zzzz".to_string(),
            "sha256=abc".to_string(),
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ];
        for value in cases {
            let result = verify_with(
                MESSAGE_ID,
                BODY,
                &value,
                TIMESTAMP,
                clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
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
                    reason: "timestamp is not a valid RFC 3339 timestamp",
                },
            ),
            (
                "2026-01-01T00:00:00".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid RFC 3339 timestamp",
                },
            ),
            (
                "2026-01-01 00:00:00Z".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid RFC 3339 timestamp",
                },
            ),
            (
                "2026-02-29T00:00:00Z".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid RFC 3339 timestamp",
                },
            ),
            (
                "2026-14-01T00:00:00Z".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid RFC 3339 timestamp",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                MESSAGE_ID,
                BODY,
                &format!("sha256={SIGNATURE}"),
                &value,
                clocked_at(1_767_225_600, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
