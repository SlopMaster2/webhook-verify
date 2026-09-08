//! Stripe webhook signature verification.
//!
//! Scheme, per Stripe's official documentation
//! (<https://docs.stripe.com/webhooks#verify-manually>) and their official
//! Node SDK (<https://github.com/stripe/stripe-node/blob/master/src/Webhooks.ts>):
//!
//! - Header: `Stripe-Signature: t=<unix_ts>,v1=<hex_hmac>[,v1=<hex_hmac>...]`
//! - Signed string: `"{t}.{raw_body}"` — the timestamp exactly as it appears
//!   in the header, a literal `.`, then the raw request body bytes
//! - Algorithm: HMAC-SHA256 with the endpoint secret (verbatim, including any
//!   `whsec_` prefix), hex-encoded
//! - Elements other than `t`/`v1` are discarded per the docs ("ignore all
//!   schemes that aren't `v1`", to prevent downgrade attacks)
//! - Multiple `v1=` values may be present during secret rotation; a match on
//!   *any* is accepted
//!
//! # Replay protection
//!
//! The signed timestamp is compared against [`VerifyOptions::max_age`]
//! (default 300s, matching Stripe's own SDK default) using `now` from the
//! injected clock. The comparison is symmetric (`|now - t|`): because `t` is
//! covered by the HMAC a legitimate sender never emits a timestamp far in the
//! future either, so a large positive skew is treated as out of tolerance
//! just like an old timestamp. This is stricter than Stripe's own SDKs (which
//! check age only); requests whose timestamps are within normal clock skew
//! are unaffected.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying Stripe's signature.
pub(crate) const SIGNATURE_HEADER: &str = "Stripe-Signature";

/// The only signature scheme accepted, per Stripe's downgrade-attack guidance.
const SCHEME: &str = "v1";

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

    // Signed string is `{timestamp_as_sent}.{raw_body}`; the raw timestamp
    // substring is reused verbatim so whatever was actually signed is what
    // gets verified.
    let mut signed_string = Vec::with_capacity(parsed.timestamp_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(parsed.timestamp_raw.as_bytes());
    signed_string.push(b'.');
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

/// A successfully parsed `Stripe-Signature` header value.
struct ParsedHeader<'a> {
    /// Decoded unix timestamp in seconds.
    timestamp: u64,
    /// The raw timestamp substring as sent (used verbatim in the signed
    /// string).
    timestamp_raw: &'a str,
    /// Every `v1=` signature decoded to its 32 bytes.
    signatures: Vec<Vec<u8>>,
}

/// Parses the header per Stripe's documented algorithm: split on `,`, split
/// each element on the first `=`, keep `t` and all `v1` values, discard every
/// other element.
///
/// Duplicate `t=` elements are rejected as ambiguous (`spec.md` §4.4) rather
/// than last-wins like Stripe's SDKs — this crate fails closed on ambiguity.
fn parse_header(value: &str) -> Result<ParsedHeader<'_>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut timestamp_raw: Option<&str> = None;
    let mut signatures = Vec::new();

    for element in value.split(',') {
        // Elements without an `=` (or empty ones from stray commas) carry no
        // recognizable prefix and are discarded per the official algorithm.
        let Some((key, val)) = element.split_once('=') else {
            continue;
        };

        if key == "t" {
            if timestamp_raw.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                });
            }
            timestamp_raw = Some(val);
        } else if key == SCHEME {
            if val.is_empty() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1=` prefix",
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
        // All other keys (e.g. legacy/fake `v0=`) are discarded by design.
    }

    let timestamp_raw = match timestamp_raw {
        Some(raw) if !raw.is_empty() => raw,
        Some(_) => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "empty timestamp after `t=` prefix",
            });
        }
        None => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "missing `t=` timestamp",
            });
        }
    };

    // `t` is "integer unix seconds" (`spec.md` §3); route it through the
    // shared timestamp parser so sign-prefixed (`t=+1700000000`),
    // whitespace-padded, and overflowing values fail closed exactly like
    // every other timestamped provider (Slack, Zoom, Discord, SendGrid,
    // Standard Webhooks, `Custom`).
    let timestamp = parse_timestamp(SIGNATURE_HEADER, timestamp_raw)?;

    if signatures.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "no `v1=` signature present",
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

    const SECRET: &str = "whsec_test_secret";
    const BODY: &[u8] = b"{\"id\":\"evt_test_webhook\",\"object\":\"event\"}";
    const TIMESTAMP: u64 = 1_700_000_000;
    /// Locally constructed:
    /// `printf '1700000000.{"id":"evt_test_webhook","object":"event"}' \
    ///   | openssl dgst -sha256 -hmac "whsec_test_secret"`
    ///
    /// Cross-checked against Python's `hmac.new(secret, f"{t}.{body}".encode(),
    /// hashlib.sha256)`; both constructions follow the recipe at
    /// <https://docs.stripe.com/webhooks#verify-manually>, which publishes no
    /// static test vector.
    const SIGNATURE: &str = "d95c6b7477fbd7e9f90b1b0ef5f9c7ac25abca5382460e0d988c2b2a5b71b990";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "316b9ab98c15bfa039d243f3196acee619cf29749a91a634e6a8154e2f7b6727";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "30d79a01345bc49a3460f5c4c0323dd4a6f8efd5828440954d17fda456e43da5";

    fn stripe_headers(timestamp: u64, signature: &str) -> [(String, String); 1] {
        [(
            SIGNATURE_HEADER.to_string(),
            format!("t={timestamp},v1={signature}"),
        )]
    }

    fn verify_with(
        body: &[u8],
        header_value: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Stripe,
            &[(SIGNATURE_HEADER, header_value)],
            body,
            &Secret::new(SECRET),
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, single matching v1.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            &format!("t={TIMESTAMP},v1={signature}"),
            // "now" == the signed timestamp: always within tolerance.
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
    fn header_name_and_key_case_insensitivity() {
        // Header lookup is case-insensitive; scheme key casing follows the
        // docs (`v1`) but a lowercase header name must work.
        let result = verify(
            crate::Provider::Stripe,
            &[(
                "stripe-signature",
                format!("t={TIMESTAMP},v1={SIGNATURE}").as_str(),
            )],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn unknown_scheme_elements_are_discarded() {
        // Per the docs, non-v1 schemes (e.g. the fake test-mode `v0=`) are
        // ignored rather than rejected or honored.
        let value = format!("t={TIMESTAMP},v0=deadbeef,v1={SIGNATURE}");
        assert_eq!(
            verify_with(BODY, &value, clocked_at(TIMESTAMP, None)),
            Ok(())
        );
    }

    #[test]
    fn rotation_any_matching_v1_is_accepted() {
        // During secret rotation Stripe sends one v1 per active secret; the
        // stale one does not match our secret but the current one must.
        let stale = "5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd";
        let opts = clocked_at(TIMESTAMP, Some(Duration::from_secs(300)));
        assert_eq!(
            verify_with(
                BODY,
                &format!("t={TIMESTAMP},v1={stale},v1={SIGNATURE}"),
                opts.clone()
            ),
            Ok(())
        );
        assert_eq!(
            verify_with(
                BODY,
                &format!("t={TIMESTAMP},v1={SIGNATURE},v1={stale}"),
                opts
            ),
            Ok(())
        );
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
                b"{\"id\":\"evt_test_webhook\",\"object\":\"eventX\"}",
                SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // The timestamp is part of the signed string, so a forged t must not
        // verify even with a valid-looking signature attached.
        let result = verify_with(
            BODY,
            &format!("t={},v1={SIGNATURE}", TIMESTAMP - 1),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Stripe,
            &stripe_headers(TIMESTAMP, SIGNATURE),
            BODY,
            &Secret::new("whsec_a_different_secret"),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing: rejected.
        let options = clocked_at(TIMESTAMP + 301, Some(Duration::from_secs(300)));
        let result = verify_with(BODY, &format!("t={TIMESTAMP},v1={SIGNATURE}"), options);
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
        // Symmetric window: a timestamp more than max_age in the future (only
        // possible via sender/receiver clock trouble) is also rejected.
        let options = clocked_at(TIMESTAMP - 301, Some(Duration::from_secs(300)));
        let result = verify_with(BODY, &format!("t={TIMESTAMP},v1={SIGNATURE}"), options);
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
                &format!("t={TIMESTAMP},v1={SIGNATURE}"),
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
            &format!("t={TIMESTAMP},v1={SIGNATURE}"),
            clocked_at(TIMESTAMP + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Stripe,
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
                format!("v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `t=` timestamp",
                },
            ),
            (
                format!("t=,v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty timestamp after `t=` prefix",
                },
            ),
            (
                format!("t=not-a-number,v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // Ambiguous duplicate timestamp: reject, never last-wins.
                format!("t={TIMESTAMP},t={},v1={SIGNATURE}", TIMESTAMP + 60),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple timestamps",
                },
            ),
            (
                format!("t={TIMESTAMP}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1=` signature present",
                },
            ),
            (
                format!("t={TIMESTAMP},v1="),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1=` prefix",
                },
            ),
            (
                // Timestamp-only negative values are not representable as u64
                // unix seconds; they must error, not wrap or panic.
                format!("t=-{TIMESTAMP},v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // Sign-prefixed values (`+`) parse fine as u64 but are not
                // "integer unix seconds"; rejected via the shared timestamp
                // parser, matching every other timestamped provider.
                format!("t=+{TIMESTAMP},v1={SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                format!("t=99999999999999999999,v1={SIGNATURE}"),
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
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            // Not hex at all.
            format!("t={TIMESTAMP},v1=zzzz"),
            // Valid hex but odd number of digits.
            format!("t={TIMESTAMP},v1=abc"),
            // Valid hex but not 32 bytes (SHA-1 length).
            format!("t={TIMESTAMP},v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            // One good sig must not mask a malformed sibling element.
            format!("t={TIMESTAMP},v1={SIGNATURE},v1=nothex"),
        ];
        for value in cases {
            let result = verify_with(
                BODY,
                &value,
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
