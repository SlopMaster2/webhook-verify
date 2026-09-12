//! Paddle webhook signature verification.
//!
//! Scheme, per Paddle's official documentation
//! (<https://developer.paddle.com/webhooks/about/signature-verification>
//! "Verify webhook signatures") and the official Go SDK's `WebhookVerifier`
//! (<https://github.com/PaddleHQ/paddle-go-sdk/blob/main/webhook_verifier.go>):
//!
//! - Header: `Paddle-Signature: ts=<unix_ts>;h1=<hex_hmac>[;h1=<hex_hmac>...]`
//!   — a semicolon-separated `key=value` list. Multiple `h1` values may be
//!   present while Paddle rotates secrets; a match on *any* is accepted.
//! - Signed string: `"{timestamp}:{raw_body}"` — the timestamp exactly as it
//!   appears in the header, a literal colon, then the raw request body bytes.
//! - Algorithm: HMAC-SHA256 with the secret key for the notification
//!   destination (verbatim UTF-8 bytes, not decoded), hex-encoded.
//!
//! # Replay protection
//!
//! Paddle signs a timestamp, enabling symmetric replay protection. The signed
//! timestamp is compared symmetrically (`|now - t|`) against
//! [`VerifyOptions::max_age`] (default 300s) using `now` from the injected
//! clock. Paddle's docs recommend rejecting events over a few seconds old but
//! define no numeric window, so the shared default tolerance applies — mirror
//! the same policy as Zoom and Discord.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying Paddle's signature.
pub(crate) const SIGNATURE_HEADER: &str = "Paddle-Signature";

/// The key of the timestamp element inside the header.
const TS_KEY: &str = "ts";

/// The key of the signature element(s) inside the header.
const SIG_KEY: &str = "h1";

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

    // Signed string is `{timestamp_as_sent}:{raw_body}`; the raw timestamp
    // substring is reused verbatim so whatever was actually signed is what
    // gets verified.
    let mut signed_string = Vec::with_capacity(parsed.timestamp_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(parsed.timestamp_raw.as_bytes());
    signed_string.push(b':');
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

/// A successfully parsed `Paddle-Signature` header value.
struct ParsedHeader<'a> {
    /// Decoded unix timestamp in seconds.
    timestamp: u64,
    /// The raw timestamp substring as sent (used verbatim in the signed
    /// string).
    timestamp_raw: &'a str,
    /// Every `h1=` signature decoded to its 32 bytes.
    signatures: Vec<Vec<u8>>,
}

/// Parses the header per Paddle's documented format: split on `;`, split each
/// element on the first `=`, keep `ts` and every `h1` value, discard every
/// other element.
///
/// Duplicate `ts=` elements are rejected as ambiguous (`spec.md` §4.4) rather
/// than last-wins — this crate fails closed on ambiguity. Unknown keys are
/// discarded like Stripe's non-`v1` elements: no documented Paddle signature
/// can ride in them, and the signed string is fully determined by `ts` + the
/// raw body, so ignoring them cannot bypass the signature check.
fn parse_header(value: &str) -> Result<ParsedHeader<'_>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut timestamp_raw: Option<&str> = None;
    let mut signatures = Vec::new();

    for element in value.split(';') {
        // Elements without an `=` (or empty ones from stray semicolons) carry
        // no recognizable key and are discarded.
        let Some((key, val)) = element.split_once('=') else {
            continue;
        };

        if key == TS_KEY {
            if timestamp_raw.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                });
            }
            timestamp_raw = Some(val);
        } else if key == SIG_KEY {
            if val.is_empty() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `h1=` prefix",
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
        // All other keys (e.g. hypothetical future scheme versions) are
        // discarded by design, mirroring Stripe (§3) and Cloudflare (§3).
    }

    let timestamp_raw = match timestamp_raw {
        Some(raw) if !raw.is_empty() => raw,
        Some(_) => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "empty timestamp after `ts=` prefix",
            });
        }
        None => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "missing `ts=` timestamp",
            });
        }
    };

    // `ts` is unix seconds; route it through the shared timestamp parser so
    // sign-prefixed (`ts=+1710929255`), whitespace-padded, and overflowing
    // values fail closed exactly like every other timestamped provider
    // (Slack, Zoom, Discord, Stripe, SendGrid, Standard Webhooks, `Custom`).
    let timestamp = parse_timestamp(SIGNATURE_HEADER, timestamp_raw)?;

    if signatures.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "no `h1=` signature present",
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
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    use crate::verify;
    use std::time::Duration;

    /// Paddle's own published worked example, reproduced verbatim from the
    /// official Go SDK's webhook-verifier test
    /// (<https://github.com/PaddleHQ/paddle-go-sdk/blob/main/example_webhook_verifier_test.go>):
    /// secret key, request body, and header value. The `timestamp:body`
    /// HMAC-SHA256 construction is cross-checked independently (Python
    /// `hmac.new(secret, f"{ts}:{body}".encode(), hashlib.sha256)`).
    const SECRET: &str = "pdl_ntfset_01hsdn8d43dt7mezr1ef2jtbaw_hKkRiCGyyRhbFwIUuqiTBgI7gnWoV0Gr";
    const BODY: &[u8] = b"{\"data\":{\"id\":\"pri_01hsdn96k2hxjzsq5yerecdj9j\",\"name\":null,\"status\":\"active\",\"quantity\":{\"maximum\":999999,\"minimum\":1},\"tax_mode\":\"account_setting\",\"product_id\":\"pro_01hsdn8qp7yydry3x1yeg6a9rv\",\"unit_price\":{\"amount\":\"1000\",\"currency_code\":\"USD\"},\"custom_data\":null,\"description\":\"testing\",\"import_meta\":null,\"trial_period\":null,\"billing_cycle\":{\"interval\":\"month\",\"frequency\":1},\"unit_price_overrides\":[]},\"event_id\":\"evt_01hsdn97563968dy0szkmgjwh3\",\"event_type\":\"price.created\",\"occurred_at\":\"2024-03-20T10:07:35.590857Z\",\"notification_id\":\"ntf_01hsdn977e920kbgzt6r6c9rqc\"}";
    const TIMESTAMP: u64 = 1_710_929_255;
    const SIGNATURE: &str = "6c05ef8fa83c44d751be6d259ec955ce5638e2c54095bf128e408e2fce1589c8";

    /// Locally constructed companions over boundary bodies, generated with:
    /// `printf '1700000000:<body>' | openssl dgst -sha256 -hmac "boundary_secret"`.
    const BOUNDARY_SECRET: &str = "boundary_secret";
    const BOUNDARY_TS: u64 = 1_700_000_000;
    /// For the *empty* body:
    /// `printf '1700000000:' | openssl dgst -sha256 -hmac "boundary_secret"`.
    const EMPTY_BODY_SIGNATURE: &str =
        "51b829dc1421a2bde8f715d1e7efd9ad1ca9fd4b89a5c9567ebe725c5c340bc0";
    /// For the UTF-8 body `"héllo, 🦀 world!"`:
    /// `printf '1700000000:héllo, 🦀 world!' | openssl dgst -sha256 -hmac "boundary_secret"`.
    const UNICODE_BODY_SIGNATURE: &str =
        "b5e069100775ca148b72b0358d86fb6f1d79968c6eee684d5507798292c600f1";

    fn verify_with(
        body: &[u8],
        header_value: &str,
        options: VerifyOptions,
        secret: &str,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Paddle,
            &[(SIGNATURE_HEADER, header_value)],
            body,
            &Secret::new(secret),
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, single matching h1.
    fn verify_fresh(body: &[u8], signature: &str, secret: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("ts={TIMESTAMP};h1={signature}"),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            secret,
        )
    }

    /// Tests for the boundary schemes (which have their own timestamp secret).
    fn verify_fresh_boundary(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("ts={BOUNDARY_TS};h1={signature}"),
            clocked_at(BOUNDARY_TS, Some(Duration::from_secs(300))),
            BOUNDARY_SECRET,
        )
    }

    // --- 1. Official / local vectors -----------------------------------------

    #[test]
    fn official_sdk_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE, SECRET), Ok(()));
    }

    #[test]
    fn boundary_bodies_verify() {
        // Empty body — `printf '1700000000:' | openssl dgst -sha256 -hmac "boundary_secret"`.
        assert_eq!(verify_fresh_boundary(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_fresh_boundary("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify(
            crate::Provider::Paddle,
            &[(
                "paddle-signature",
                format!("ts={TIMESTAMP};h1={SIGNATURE}").as_str(),
            )],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rotation_any_matching_h1_is_accepted() {
        // During secret rotation Paddle sends one h1 per active secret (docs:
        // "more than one `h1` is returned while secrets are rotated out"); a
        // stale signature must not prevent the current one from verifying.
        // `stale` is a well-formed 32-byte hex value with a *different* key.
        let stale = "5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd";
        let opts = clocked_at(TIMESTAMP, Some(Duration::from_secs(300)));
        assert_eq!(
            verify_with(
                BODY,
                &format!("ts={TIMESTAMP};h1={stale};h1={SIGNATURE}"),
                opts.clone(),
                SECRET,
            ),
            Ok(())
        );
        assert_eq!(
            verify_with(
                BODY,
                &format!("ts={TIMESTAMP};h1={SIGNATURE};h1={stale}"),
                opts,
                SECRET,
            ),
            Ok(())
        );
    }

    #[test]
    fn unknown_keys_are_discarded() {
        // Undocumented elements ride along without affecting the signed string
        // or the signature check (mirrors Stripe's non-v1 handling).
        let value = format!("ts={TIMESTAMP};v9=deadbeef;h1={SIGNATURE}");
        assert_eq!(
            verify_with(BODY, &value, clocked_at(TIMESTAMP, None), SECRET),
            Ok(())
        );
    }

    // --- 2. Negative tests ---------------------------------------------------

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the hex alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}0{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_fresh(BODY, &flipped, SECRET),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        assert_eq!(
            verify_fresh(BODY, SIGNATURE, "pdl_ntfset_another_secret_key"),
            Err(VerifyError::SignatureMismatch)
        );
    }

    // --- 3. Tamper tests ------------------------------------------------------

    #[test]
    fn tampered_body_fails() {
        // Drop the trailing `}` from the JSON and splice in an extra field —
        // the signed string is `{ts}:{raw_body}`, so any body change breaks
        // the HMAC.
        let mut tampered = BODY[..BODY.len() - 1].to_vec();
        tampered.extend_from_slice(b"\"tampered\":true}");
        assert_eq!(
            verify_fresh(&tampered, SIGNATURE, SECRET),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // The timestamp is part of the signed string, so a forged ts must not
        // verify even with a valid-looking signature attached.
        let result = verify_with(
            BODY,
            &format!("ts={};h1={SIGNATURE}", TIMESTAMP - 1),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            SECRET,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    // --- 4. Replay tests ------------------------------------------------------

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let options = clocked_at(TIMESTAMP + 301, Some(Duration::from_secs(300)));
        let result = verify_with(
            BODY,
            &format!("ts={TIMESTAMP};h1={SIGNATURE}"),
            options,
            SECRET,
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
            &format!("ts={TIMESTAMP};h1={SIGNATURE}"),
            options,
            SECRET,
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
                &format!("ts={TIMESTAMP};h1={SIGNATURE}"),
                clocked_at(now, Some(Duration::from_secs(300))),
                SECRET,
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let result = verify_with(
            BODY,
            &format!("ts={TIMESTAMP};h1={SIGNATURE}"),
            clocked_at(TIMESTAMP + 86_400 * 365, None),
            SECRET,
        );
        assert_eq!(result, Ok(()));
    }

    // --- 5. Malformed-header battery -------------------------------------------

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Paddle,
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
    fn malformed_header_shapes_error_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                format!("h1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `ts=` timestamp",
                },
            ),
            (
                format!("ts=;h1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty timestamp after `ts=` prefix",
                },
            ),
            (
                // `Paddle-Signature` elements are `;`-separated (see
                // `parse_header`), so this is a well-formed `h1=` signature
                // coexisting with an unparsable `ts=` value. The bad
                // timestamp rejects the request; the signature field must
                // not be folded into the timestamp value (comma would let
                // `parse_header` swallow it as `ts`'s raw value).
                format!("ts=not-a-number;h1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // Ambiguous duplicate timestamp: reject, never last-wins.
                format!("ts={TIMESTAMP};ts={};h1={SIGNATURE}", TIMESTAMP + 60),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                },
            ),
            (
                format!("ts={TIMESTAMP}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `h1=` signature present",
                },
            ),
            (
                format!("ts={TIMESTAMP};h1="),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `h1=` prefix",
                },
            ),
            (
                // Timestamp-only negative values are not representable as u64
                // unix seconds; they must error, not wrap or panic.
                format!("ts=-{TIMESTAMP};h1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // Sign-prefixed values (`+`) parse fine as u64 but are not
                // "integer unix seconds"; rejected via the shared timestamp
                // parser, matching every other timestamped provider.
                format!("ts=+{TIMESTAMP};h1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                format!("ts=99999999999999999999;h1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp overflows unix seconds",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                &value,
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
                SECRET,
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            // Not hex at all.
            format!("ts={TIMESTAMP};h1=zzzz"),
            // Valid hex but odd number of digits.
            format!("ts={TIMESTAMP};h1=abc"),
            // Valid hex but not 32 bytes (SHA-1 length).
            format!("ts={TIMESTAMP};h1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            // One good sig must not mask a malformed sibling element.
            format!("ts={TIMESTAMP};h1={SIGNATURE};h1=nothex"),
        ];
        for value in cases {
            let result = verify_with(
                BODY,
                &value,
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
                SECRET,
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
