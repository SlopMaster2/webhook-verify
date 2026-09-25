//! PagerDuty v3 webhook signature verification.
//!
//! Scheme, per PagerDuty's "Verifying signatures" documentation
//! (<https://developer.pagerduty.com/docs/verifying-signatures>) and their
//! official Go SDK's reference implementation
//! (<https://github.com/PagerDuty/go-pagerduty/blob/main/webhookv3/webhookv3.go>):
//!
//! - Header: `X-PagerDuty-Signature: v1=<hex(HMAC-SHA256(secret, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified (PagerDuty signs
//!   the exact payload bytes; the signature stops matching if the body is
//!   reformatted before verification)
//! - Algorithm: HMAC-SHA256 with the webhook subscription's signing secret
//!   (its `delivery_method.secret`), hex-encoded, delivered with the literal
//!   `v1=` prefix
//! - Multiple `v1=` values may be present, comma-separated, during secret
//!   rotation; a match on *any* is accepted (the official SDK splits on `,`
//!   and verifies every element)
//!
//! # Replay protection
//!
//! PagerDuty does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256_any;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying PagerDuty's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-PagerDuty-Signature";

/// Required prefix of each signature element, per the official SDK.
const SIGNATURE_PREFIX: &str = "v1=";

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    _options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;

    let signatures = parse_signatures(value)?;

    // The HMAC is computed once and compared in constant time against every
    // presented signature; no early exit depends on *how* wrong one is.
    let matched = verify_hmac_sha256_any(
        secret.as_bytes(),
        raw_body,
        signatures.iter().map(|signature| signature.as_slice()),
    );

    if matched {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses the comma-separated `v1=<hex>` list into its decoded signature
/// bytes.
///
/// Mirrors the official Go SDK's algorithm: split the header on `,`, keep
/// every element with the literal `v1=` prefix, and discard the rest (the
/// SDK guards against downgrades by ignoring non-`v1` versions). Every
/// failure mode maps to a distinct error variant so callers can tell
/// malformed-request noise from signature-mismatch signals (`spec.md` §2.1).
fn parse_signatures(value: &str) -> Result<Vec<Vec<u8>>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut signatures = Vec::new();

    for element in value.split(',') {
        // `get(..len)` instead of slicing: a multibyte character straddling
        // the prefix boundary must yield an error, never a panic
        // (attacker-controlled).
        let hex_part = match element.get(..SIGNATURE_PREFIX.len()) {
            Some(prefix) if prefix == SIGNATURE_PREFIX => &element[SIGNATURE_PREFIX.len()..],
            // Elements without the `v1=` prefix (unknown versions, empty
            // segments from trailing commas) carry no recognizable scheme and
            // are discarded per the official algorithm — but if that leaves no
            // signatures at all, the header is malformed, not mismatched.
            _ => continue,
        };

        if hex_part.is_empty() {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "empty signature after `v1=` prefix",
            });
        }

        let bytes = hex::decode(hex_part).map_err(|_| VerifyError::BadEncoding {
            reason: "signature is not valid hexadecimal",
        })?;

        if bytes.len() != SIGNATURE_LEN_BYTES {
            return Err(VerifyError::BadEncoding {
                reason: "signature does not decode to 32 bytes",
            });
        }

        signatures.push(bytes);
    }

    if signatures.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "no `v1=` signature present",
        });
    }

    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::secret::Secret;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// From the official `go-pagerduty` SDK's `webhookv3` test suite
    /// (<https://github.com/PagerDuty/go-pagerduty/blob/main/webhookv3/webhookv3_test.go>),
    /// reproduced byte-for-byte: same secret, same payload, same expected
    /// signature.
    const OFFICIAL_SECRET: &str =
        "lDQHScfUeXUKaQRNF+8XIiDKZ7XX3itBAYzwU0TARw8lJqRnkKl2iB1anSb0Z+IK";
    const OFFICIAL_BODY: &[u8] = b"{\"event\":{\"id\":\"01BWDWL3NYY7LUFPZCC28QUCMK\",\"event_type\":\"incident.priority_updated\",\"resource_type\":\"incident\",\"occurred_at\":\"2021-04-26T17:36:27.458Z\",\"agent\":{\"html_url\":\"https://acme.pagerduty.com/users/PLH1HKV\",\"id\":\"PLH1HKV\",\"self\":\"https://api.pagerduty.com/users/PLH1HKV\",\"summary\":\"Tenex Engineer\",\"type\":\"user_reference\"},\"client\":null,\"data\":{\"id\":\"PGR0VU2\",\"type\":\"incident\",\"self\":\"https://api.pagerduty.com/incidents/PGR0VU2\",\"html_url\":\"https://acme.pagerduty.com/incidents/PGR0VU2\",\"number\":2,\"status\":\"triggered\",\"title\":\"A little bump in the road\",\"service\":{\"html_url\":\"https://acme.pagerduty.com/services/PF9KMXH\",\"id\":\"PF9KMXH\",\"self\":\"https://api.pagerduty.com/services/PF9KMXH\",\"summary\":\"API Service\",\"type\":\"service_reference\"},\"assignees\":[{\"html_url\":\"https://acme.pagerduty.com/users/PTUXL6G\",\"id\":\"PTUXL6G\",\"self\":\"https://api.pagerduty.com/users/PTUXL6G\",\"summary\":\"User 123\",\"type\":\"user_reference\"}],\"escalation_policy\":{\"html_url\":\"https://acme.pagerduty.com/escalation_policies/PUS0KTE\",\"id\":\"PUS0KTE\",\"self\":\"https://api.pagerduty.com/escalation_policies/PUS0KTE\",\"summary\":\"Default\",\"type\":\"escalation_policy_reference\"},\"teams\":[{\"html_url\":\"https://acme.pagerduty.com/teams/PFCVPS0\",\"id\":\"PFCVPS0\",\"self\":\"https://api.pagerduty.com/teams/PFCVPS0\",\"summary\":\"Engineering\",\"type\":\"team_reference\"}],\"priority\":{\"html_url\":\"https://acme.pagerduty.com/account/incident_priorities\",\"id\":\"PSO75BM\",\"self\":\"https://api.pagerduty.com/priorities/PSO75BM\",\"summary\":\"P1\",\"type\":\"priority_reference\"},\"urgency\":\"high\",\"conference_bridge\":{\"conference_number\":1000,\"conference_url\":\"https://example.com\"},\"resolve_reason\":null}}}";
    /// From the official `go-pagerduty` SDK test suite (the "valid" case).
    const OFFICIAL_SIGNATURE: &str =
        "0c0b9495b893a39e70d1fea2fe11fbe0a825f88b9f67846f6cc07dd2bc5476cd";
    /// From the official `go-pagerduty` SDK test suite (the "mismatch" case).
    const OFFICIAL_MISMATCH_SIGNATURE: &str =
        "7020c8a7ec668a9b7012bc3dd82e483394b038f4230acc6785efbf2a7d8bcaf5";
    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha256 -hmac "lDQHScfUeXUKaQRNF+8XIiDKZ7XX3itBAYzwU0TARw8lJqRnkKl2iB1anSb0Z+IK"`
    const EMPTY_BODY_SIGNATURE: &str =
        "78e1e119fe23813ce2fcfb10079cc89d6387b094902832639ccb5a8ff2fd6778";
    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha256 -hmac "lDQHScfUeXUKaQRNF+8XIiDKZ7XX3itBAYzwU0TARw8lJqRnkKl2iB1anSb0Z+IK"`
    const UNICODE_BODY_SIGNATURE: &str =
        "8e286dd135dc820406b2d9f248123abe6d3023ae56a55ffaaf23d3fda786bb0a";

    fn pagerduty_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("v1={signature}"))]
    }

    fn verify_official(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::PagerDuty,
            &pagerduty_headers(signature),
            body,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        )
    }

    #[test]
    fn official_vector_from_pagerduty_sdk() {
        assert_eq!(verify_official(OFFICIAL_BODY, OFFICIAL_SIGNATURE), Ok(()));
    }

    #[test]
    fn locally_constructed_boundary_bodies_verify() {
        assert_eq!(verify_official(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_official("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn rotation_list_accepts_any_matching_v1_element() {
        // PagerDuty supports key rotation by sending multiple comma-separated
        // `v1=` signatures; a match on any one must verify (the official SDK
        // splits on `,` and accepts any matching element).
        let rotated = format!(
            "v1={},v1={}",
            OFFICIAL_MISMATCH_SIGNATURE, OFFICIAL_SIGNATURE
        );
        let result = verify(
            crate::Provider::PagerDuty,
            &[(SIGNATURE_HEADER, rotated.as_str())],
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));

        // The same header with the *first* element matching also verifies,
        // and an all-wrong rotation list fails closed with SignatureMismatch.
        let rotated_first = format!(
            "v1={},v1={}",
            OFFICIAL_SIGNATURE, OFFICIAL_MISMATCH_SIGNATURE
        );
        assert_eq!(
            verify(
                crate::Provider::PagerDuty,
                &[(SIGNATURE_HEADER, rotated_first.as_str())],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            ),
            Ok(())
        );

        let all_wrong = format!(
            "v1={},v1={}",
            OFFICIAL_MISMATCH_SIGNATURE, OFFICIAL_MISMATCH_SIGNATURE
        );
        assert_eq!(
            verify(
                crate::Provider::PagerDuty,
                &[(SIGNATURE_HEADER, all_wrong.as_str())],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn non_v1_elements_are_discarded() {
        // The official SDK ignores anything that is not a `v1=` signature
        // (downgrade protection); unknown versions must not be verified and
        // must not abort a valid `v1=` element alongside them.
        let mixed = format!("v2=deadbeef,v1={}", OFFICIAL_SIGNATURE);
        let result = verify(
            crate::Provider::PagerDuty,
            &[(SIGNATURE_HEADER, mixed.as_str())],
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::PagerDuty,
            &[(
                "x-pagerduty-signature",
                "v1=0c0b9495b893a39e70d1fea2fe11fbe0a825f88b9f67846f6cc07dd2bc5476cd",
            )],
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let sig = format!(
            "{}{}{}",
            &OFFICIAL_SIGNATURE[..10],
            if OFFICIAL_SIGNATURE[10..11] == *"0" {
                "1"
            } else {
                "0"
            },
            &OFFICIAL_SIGNATURE[11..]
        );
        assert_ne!(sig, OFFICIAL_SIGNATURE);
        assert_eq!(
            verify_official(OFFICIAL_BODY, &sig),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::PagerDuty,
            &pagerduty_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn official_mismatch_vector_fails() {
        // The SDK's own "mismatch" test case (a validly-shaped signature the
        // SDK's tests expect to be rejected) must also be rejected here.
        assert_eq!(
            verify_official(OFFICIAL_BODY, OFFICIAL_MISMATCH_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let mut tampered = OFFICIAL_BODY.to_vec();
        tampered.push(b'0');
        assert_eq!(
            verify_official(&tampered, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn max_age_has_no_effect_for_pagerduty() {
        // PagerDuty signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. This pins the documented
        // "max_age ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::PagerDuty,
            &pagerduty_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::PagerDuty,
            &Vec::<(String, String)>::new(),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
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
        let cases: &[(&str, VerifyError)] = &[
            (
                "",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                "v1=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1=` prefix",
                },
            ),
            (
                "deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1=` signature present",
                },
            ),
            (
                "V1=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1=` signature present",
                },
            ),
            (
                "sha256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1=` signature present",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::PagerDuty,
                &[(SIGNATURE_HEADER, value)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: &[&str] = &[
            // Not hex at all.
            "v1=zzzz",
            // Valid hex but odd number of digits.
            "v1=abc",
            // Valid hex but not 32 bytes (SHA-1 length).
            "v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::PagerDuty,
                &[(SIGNATURE_HEADER, value)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
