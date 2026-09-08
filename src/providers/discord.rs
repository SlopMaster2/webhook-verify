//! Discord interaction webhook signature verification.
//!
//! Scheme, per Discord's official documentation ("Validating Security Request
//! Headers", <https://docs.discord.com/developers/interactions/overview>) and
//! its bundled JavaScript/Python/Java reference implementations:
//!
//! - Headers: `X-Signature-Ed25519` (`<hex_signature>`) and
//!   `X-Signature-Timestamp` (`<unix_ts>`)
//! - Signed message: `{timestamp}{raw_body}` — the timestamp exactly as it
//!   appears in its header, immediately followed by the raw request body bytes
//! - Algorithm: Ed25519 detached signature verification against the
//!   application's **public key** from the Developer Portal, hex-encoded
//!
//! # Security model difference from every other provider here
//!
//! [`Secret`] does **not** hold a shared HMAC key for this provider. It holds
//! the hex-encoded 32-byte Ed25519 *public* key Discord shows on your
//! application's page in the Developer Portal. Verification is therefore not
//! proof that the sender holds a secret you also possess — it is proof the
//! payload was signed by the corresponding private key held by Discord. An
//! invalid or malformed public key fails closed with
//! [`VerifyError::InvalidSecret`].
//!
//! # Test-vector provenance
//!
//! Discord does not publish frozen test vectors: the current docs show
//! placeholder keys, and the official SDKs generate ephemeral keypairs at test
//! time (see e.g. `discord-interactions-js`' `SharedTestUtils.ts`). The vectors
//! below are therefore **locally constructed** with deterministic seeds using
//! this crate's own dependency stack, exercising exactly the construction the
//! official reference implementations perform. If Discord ever publishes fixed
//! vectors, they should replace these (see `spec.md` §3).
//!
//! # Replay protection
//!
//! The signed timestamp exists precisely so receivers can reject stale
//! requests, and `spec.md` §5.4 requires replay tests for any scheme that
//! signs one. Discord itself documents no recommended window, so this crate
//! applies the shared default tolerance ([`VerifyOptions::max_age`], 300s,
//! symmetric `|now - t|`, injectable clock). Callers who need to accept older
//! redelivered interactions can raise or disable the window explicitly.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_ed25519;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying the hex-encoded Ed25519 signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Signature-Ed25519";

/// The header carrying the signed unix timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "X-Signature-Timestamp";

/// Ed25519 public-key length in bytes; the configured secret must decode to
/// exactly this length.
const PUBLIC_KEY_LEN_BYTES: usize = 32;

/// Ed25519 signature length in bytes.
const SIGNATURE_LEN_BYTES: usize = 64;

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

    let public_key = decode_public_key(secret.as_bytes())?;
    let provided_signature = parse_signature(signature_value)?;
    let timestamp = parse_timestamp(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed message is `{timestamp_as_sent}{raw_body}`; the raw timestamp
    // substring is reused verbatim so whatever was actually signed is what
    // gets verified.
    let mut message = Vec::with_capacity(timestamp_raw.len() + raw_body.len());
    message.extend_from_slice(timestamp_raw.as_bytes());
    message.extend_from_slice(raw_body);

    if !verify_ed25519(&public_key, &message, &provided_signature) {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(timestamp, options)
}

/// Decodes the hex-encoded Ed25519 public key held in [`Secret`].
///
/// Unlike HMAC keys, an Ed25519 verifying key has a strict canonical shape;
/// anything that does not decode to exactly 32 bytes means the operator
/// pasted something other than the Developer Portal value, so fail closed
/// with [`VerifyError::InvalidSecret`] instead of attempting verification.
fn decode_public_key(secret: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let secret_str = core::str::from_utf8(secret).map_err(|_| VerifyError::InvalidSecret {
        reason: "public key must be a hex-encoded string",
    })?;
    let decoded = hex::decode(secret_str).map_err(|_| VerifyError::InvalidSecret {
        reason: "public key is not valid hexadecimal",
    })?;
    if decoded.len() != PUBLIC_KEY_LEN_BYTES {
        return Err(VerifyError::InvalidSecret {
            reason: "public key does not decode to 32 bytes",
        });
    }
    Ok(decoded)
}

/// Parses the hex-encoded 64-byte Ed25519 signature header into its bytes.
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
            reason: "signature does not decode to 64 bytes",
        });
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{PUBLIC_KEY_LEN_BYTES, SIGNATURE_HEADER, SIGNATURE_LEN_BYTES, TIMESTAMP_HEADER};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    use crate::verify;
    use ed25519_dalek::Signer;
    use std::time::Duration;

    /// Deterministic seed for locally constructed vectors. Fixed constants —
    /// not RNG output — so the vectors are reproducible forever; see the
    /// module docs on vector provenance.
    const VECTOR_SEED: [u8; 32] = [
        0x77, 0x65, 0x62, 0x68, 0x6f, 0x6f, 0x6b, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x2d,
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2d, 0x30, 0x30, 0x30,
        0x31, 0x37,
    ];

    /// Signs `{timestamp}{body}` exactly as Discord's documented recipe and
    /// returns `(hex_public_key, hex_signature)`.
    fn sign_locally(seed: &[u8; 32], timestamp: &str, body: &[u8]) -> (String, String) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let mut message = Vec::with_capacity(timestamp.len() + body.len());
        message.extend_from_slice(timestamp.as_bytes());
        message.extend_from_slice(body);
        let signature = signing_key.sign(&message);
        (
            hex::encode(signing_key.verifying_key().as_bytes()),
            hex::encode(signature.to_bytes()),
        )
    }

    fn verify_with(
        body: &[u8],
        public_key_hex: &str,
        signature_value: &str,
        timestamp_value: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Discord,
            &[
                (SIGNATURE_HEADER, signature_value),
                (TIMESTAMP_HEADER, timestamp_value),
            ],
            body,
            &Secret::new(public_key_hex),
            options,
        )
    }

    /// A valid PING-shaped delivery at the moment of signing.
    fn verify_fresh(
        body: &[u8],
        public_key_hex: &str,
        signature_hex: &str,
        timestamp: u64,
    ) -> Result<(), VerifyError> {
        verify_with(
            body,
            public_key_hex,
            signature_hex,
            &timestamp.to_string(),
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn ping_delivery_verifies() {
        // PING handshake body per Discord's endpoint-validation flow.
        let body = br#"{"id":"787053080478613555","token":"ThisIsATokenFromDiscordThatIsVeryLong","type":1,"version":1}"#;
        let timestamp = 1_758_600_000;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);
        assert_eq!(verify_fresh(body, &key_hex, &sig_hex, timestamp), Ok(()));
    }

    #[test]
    fn boundary_bodies_verify() {
        let timestamp = 1_758_600_001;

        // Empty body (boundary case).
        let (key_hex, empty_sig) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), b"");
        assert_eq!(verify_fresh(b"", &key_hex, &empty_sig, timestamp), Ok(()));

        // Unicode body (boundary case): signed over raw UTF-8 bytes.
        let unicode_body = "héllo, 🦀 world!".as_bytes();
        let (key_hex, unicode_sig) =
            sign_locally(&VECTOR_SEED, &timestamp.to_string(), unicode_body);
        assert_eq!(
            verify_fresh(unicode_body, &key_hex, &unicode_sig, timestamp),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let body = br#"{"type":1}"#;
        let timestamp = 1_758_600_002;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        // Lowercase header names resolve through the case-insensitive
        // lookup and verify normally.
        let result = verify(
            crate::Provider::Discord,
            &[
                ("x-signature-ed25519", sig_hex.as_str()),
                ("X-SIGNATURE-TIMESTAMP", timestamp.to_string().as_str()),
            ],
            body,
            &Secret::new(key_hex),
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let body = br#"{"type":1,"data":{"name":"woof"}}"#;
        let timestamp = 1_758_600_003;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        // Flip one character *within* the hex alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}0{}", &sig_hex[..10], &sig_hex[11..]);
        assert_ne!(flipped, sig_hex);
        assert_eq!(
            verify_fresh(body, &key_hex, &flipped, timestamp),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let body = br#"{"type":1,"data":{"name":"woof"}}"#;
        let timestamp = 1_758_600_004;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        assert_eq!(
            verify_fresh(
                br#"{"type":1,"data":{"name":"meow"}}"#,
                &key_hex,
                &sig_hex,
                timestamp
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        let body = br#"{"type":2,"version":1}"#;
        let timestamp = 1_758_600_005;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        // The timestamp is part of the signed message, so a forged timestamp
        // must not verify even with a valid-looking signature attached.
        let result = verify_with(
            body,
            &key_hex,
            &sig_hex,
            &(timestamp - 1).to_string(),
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_public_key_fails() {
        let body = br#"{"type":1}"#;
        let timestamp = 1_758_600_006;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        let other_seed = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let (other_key_hex, _) = sign_locally(&other_seed, &timestamp.to_string(), body);
        assert_ne!(other_key_hex, key_hex);
        assert_eq!(
            verify_fresh(body, &other_key_hex, &sig_hex, timestamp),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let body = br#"{"type":1}"#;
        let timestamp = 1_758_600_007;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        // Valid signature, delivered 301s after signing.
        let result = verify_with(
            body,
            &key_hex,
            &sig_hex,
            &timestamp.to_string(),
            clocked_at(timestamp + 301, Some(Duration::from_secs(300))),
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
        let body = br#"{"type":1}"#;
        let timestamp = 1_758_600_008;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        // Symmetric window: |now - ts| > max_age in either direction is
        // rejected.
        let result = verify_with(
            body,
            &key_hex,
            &sig_hex,
            &timestamp.to_string(),
            clocked_at(timestamp - 301, Some(Duration::from_secs(300))),
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
        let body = br#"{"type":1}"#;
        let timestamp = 1_758_600_009;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        // Exactly max_age old/new is still inside the closed window.
        for now in [timestamp - 300, timestamp + 300] {
            let result = verify_with(
                body,
                &key_hex,
                &sig_hex,
                &timestamp.to_string(),
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let body = br#"{"type":1}"#;
        let timestamp = 1_758_600_010;
        let (key_hex, sig_hex) = sign_locally(&VECTOR_SEED, &timestamp.to_string(), body);

        // `max_age: None` explicitly disables the recency check.
        let result = verify_with(
            body,
            &key_hex,
            &sig_hex,
            &timestamp.to_string(),
            clocked_at(timestamp + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify(
            crate::Provider::Discord,
            &[("X-Signature-Timestamp", "1758600000")],
            b"{}",
            &Secret::new("00".repeat(PUBLIC_KEY_LEN_BYTES)),
            Default::default(),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::Discord,
            &[(
                "X-Signature-Ed25519",
                "ab".repeat(SIGNATURE_LEN_BYTES).as_str(),
            )],
            b"{}",
            &Secret::new("00".repeat(PUBLIC_KEY_LEN_BYTES)),
            Default::default(),
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );

        let both_missing = verify(
            crate::Provider::Discord,
            &Vec::<(String, String)>::new(),
            b"{}",
            &Secret::new("00".repeat(PUBLIC_KEY_LEN_BYTES)),
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
        let cases: Vec<(String, Result<(), VerifyError>)> = vec![
            (
                String::new(),
                Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                }),
            ),
            // Not hex at all.
            (
                "zzzz".repeat(32),
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                }),
            ),
            // Valid hex but odd number of digits.
            (
                "abc".to_string(),
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                }),
            ),
            // Valid hex but not 64 bytes (a truncated signature).
            (
                "ab".repeat(63),
                Err(VerifyError::BadEncoding {
                    reason: "signature does not decode to 64 bytes",
                }),
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                b"{}",
                &"00".repeat(PUBLIC_KEY_LEN_BYTES),
                &value,
                "1758600000",
                Default::default(),
            );
            assert_eq!(result, expected, "input: {value:?}");
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
                    reason: "timestamp is not a valid unix timestamp",
                }),
            ),
            (
                // Negative values are not representable as u64 unix seconds;
                // they must error, not wrap or panic.
                "-1758600000".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                }),
            ),
            (
                // All digits, but past u64 range.
                "99999999999999999999999".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp overflows unix seconds",
                }),
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                b"{}",
                &"00".repeat(PUBLIC_KEY_LEN_BYTES),
                &"ab".repeat(SIGNATURE_LEN_BYTES),
                &value,
                Default::default(),
            );
            assert_eq!(result, expected, "input: {value:?}");
        }
    }

    #[test]
    fn invalid_secret_errors_distinctly() {
        let body = br#"{"type":1}"#;
        let timestamp = "1758600000";
        let signature = "ab".repeat(SIGNATURE_LEN_BYTES);

        let cases: Vec<(String, &'static str)> = vec![
            // Not hex at all.
            (
                "developer-portal-key".to_string(),
                "public key is not valid hexadecimal",
            ),
            // Valid hex but wrong length (truncated paste).
            ("abcd".to_string(), "public key does not decode to 32 bytes"),
            // Empty configuration.
            (String::new(), "public key does not decode to 32 bytes"),
        ];
        for (secret_value, reason) in cases {
            let result = verify_with(
                body,
                &secret_value,
                &signature,
                timestamp,
                Default::default(),
            );
            assert_eq!(
                result,
                Err(VerifyError::InvalidSecret { reason }),
                "input: {secret_value:?}"
            );
        }
    }
}
