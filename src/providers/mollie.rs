//! Mollie (next-gen) webhook signature verification.
//!
//! Scheme, per Mollie's official "Next-gen webhooks" documentation
//! (<https://docs.mollie.com/reference/webhooks-new>):
//!
//! - Header: `X-Mollie-Signature: sha256=<hex(HMAC-SHA256(secret, raw_body))>`
//! - Signed string: the unaltered raw request body bytes
//! - Algorithm: HMAC-SHA256, hex-encoded
//! - Key: the signing secret configured at webhook setup, used verbatim as
//!   its UTF-8 bytes (never decoded)
//!
//! The construction matches Mollie's official reference
//! implementations (`hash_hmac('sha256', $payload, $secret)` in
//! `mollie-api-php`'s `SignatureValidator`,
//! <https://github.com/mollie/mollie-api-php/blob/main/src/Webhooks/SignatureValidator.php>,
//! which strips the prefix with a `strpos(..., 'sha256=') === 0` check and
//! compares with `hash_equals`, and the equivalent `SignatureValidator`
//! helpers in the official Python and Go SDKs). Mollie's SDKs tolerate a
//! bare hex value without the prefix; this crate requires the documented
//! `sha256=` prefix exactly like GitHub (the signer always emits it).
//!
//! # Replay protection
//!
//! Mollie signs the body only — no timestamp — so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).
//!
//! # Key rotation
//!
//! During the documented 24-hour rotation window Mollie attaches **two**
//! `X-Mollie-Signature` headers per event, one per active secret
//! (<https://docs.mollie.com/reference/webhooks-new>, "Updating a live signing
//! secret"). [`HeaderMap`](crate::HeaderMap) is first-match-only by contract,
//! so this provider reads the **first** of those two values and the second is
//! inert — it is never parsed and never compared.
//!
//! What still verifies the window is keeping **both** secrets configured and
//! trying each: Mollie signs the first line with one of the two active
//! secrets, so [`verify_any`](crate::verify_any) over
//! `&[live, previous]` accepts the delivery whichever order the two lines
//! arrive in. A deployment that keeps only *one* of the two secrets does not —
//! it rejects every event for the 24 hours after a roll whenever the line it
//! holds is not the first one, and `SignatureMismatch` is indistinguishable
//! from a broken integration.
//!
//! The same pair through either framework adapter is
//! `VerifyLayer::with_fallback_secrets` (`tower`) or
//! `WebhookConfig::with_fallback_secrets` (`actix`), which run the identical
//! `spec.md` §2.1 aggregation (issue #259).
//!
//! Those two differing header lines are also why Mollie is the one provider
//! exempt from the `spec.md` §4.4 duplicate-header check: the shape is the
//! provider's own rotation mechanism, not a smuggled duplicate. The exemption
//! covers the ambiguity *scan* only — it grants no second chance to verify the
//! second value, which stays unread, and every other provider's header is still
//! scanned in full (the exemptions are listed by
//! `provider_sent_duplicate_headers` in `src/providers/mod.rs`).
//!
//! # Scope
//!
//! Only Mollie's next-gen signed webhooks are covered. Classic payment
//! webhooks (the `webhookUrl` deliveries that POST a single
//! `id=<resource_id>` form field) are unsigned and send no signature header.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Mollie's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Mollie-Signature";

/// Required prefix of the header value.
const SIGNATURE_PREFIX: &str = "sha256=";

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

    let provided = parse_signature(value)?;

    // The HMAC is computed after parsing succeeds and compared in constant
    // time; no early exit depends on *how* wrong the signature is.
    if verify_hmac_sha256(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `X-Mollie-Signature` into its 32 decoded signature bytes.
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

    // `get(..len)` instead of slicing: a multibyte character straddling the
    // prefix boundary must yield an error, never a panic (attacker-controlled).
    let hex_part = match value.get(..SIGNATURE_PREFIX.len()) {
        Some(prefix) if prefix == SIGNATURE_PREFIX => &value[SIGNATURE_PREFIX.len()..],
        _ => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "missing `sha256=` prefix",
            });
        }
    };

    if hex_part.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "empty signature after `sha256=` prefix",
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

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::secret::Secret;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::{verify, verify_any};
    use std::time::Duration;

    // Test-vector provenance (spec.md §3): Mollie's docs publish the header
    // shape (`sha256=4a4c6f3e...`) but no byte-exact secret/body/signature
    // triple, so the vectors below are locally constructed over the documented
    // construction and cross-checked with both `openssl dgst -sha256 -hmac`
    // and Python's `hashlib`/`hmac`. The primary body mirrors the
    // `payment-link.paid` simple-payload example event from Mollie's
    // next-gen webhooks docs. Replace the vectors if Mollie ever publishes
    // fixed ones.
    const TEST_SECRET: &str = "test-signing-secret";
    const PRIMARY_BODY: &[u8] = b"{\"resource\":\"event\",\"id\":\"event_GvJ8WHrp5isUdRub9CJyH\",\"type\":\"payment-link.paid\",\"entityId\":\"pl_qng5gbbv8NAZ5gpM5ZYgx\",\"createdAt\":\"2024-12-16T15:59:04.0Z\",\"_links\":{\"self\":{\"href\":\"https://api.mollie.com/v2/events/event_GvJ8WHrp5isUdRub9CJyH\",\"type\":\"application/hal+json\"},\"documentation\":{\"href\":\"https://docs.mollie.com/guides/webhooks\",\"type\":\"text/html\"}}}";
    const PRIMARY_SIGNATURE: &str =
        "726eb72833c59fe944cf728b37d95e900329c598cd77addfd1afeceb195e6a54";
    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha256 -hmac "test-signing-secret"`
    const EMPTY_BODY_SIGNATURE: &str =
        "e6002cfc6ef5b3af2909dacc72e87fecd37768d9031a517806765b06ec0ce4fe";
    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha256 -hmac "test-signing-secret"`
    const UNICODE_BODY_SIGNATURE: &str =
        "f5b3b6e67d67a56748d4ac80714c5ef7b66b79e28ffcf92c3a66d175d851b87f";

    fn mollie_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("sha256={signature}"))]
    }

    fn verify_official(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Mollie,
            &mollie_headers(signature),
            body,
            &Secret::new(TEST_SECRET),
            Default::default(),
        )
    }

    #[test]
    fn docs_example_event_with_constructed_signature_verifies() {
        assert_eq!(verify_official(PRIMARY_BODY, PRIMARY_SIGNATURE), Ok(()));
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
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Mollie,
            &[(
                "x-mollie-signature",
                "sha256=726eb72833c59fe944cf728b37d95e900329c598cd77addfd1afeceb195e6a54",
            )],
            PRIMARY_BODY,
            &Secret::new(TEST_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = PRIMARY_SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_official(PRIMARY_BODY, &upper), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let sig = format!(
            "{}{}{}",
            &PRIMARY_SIGNATURE[..10],
            if PRIMARY_SIGNATURE[10..11] == *"0" {
                "1"
            } else {
                "0"
            },
            &PRIMARY_SIGNATURE[11..]
        );
        assert_ne!(sig, PRIMARY_SIGNATURE);
        assert_eq!(
            verify_official(PRIMARY_BODY, &sig),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let tampered = b"{\"resource\":\"event\",\"id\":\"event_tampered\"}";
        assert_eq!(
            verify_official(tampered, PRIMARY_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Mollie,
            &mollie_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new("a different signing secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_mollie() {
        // Mollie signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. This pins the documented
        // "max_age ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Mollie,
            &mollie_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new(TEST_SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Mollie,
            &Vec::<(String, String)>::new(),
            PRIMARY_BODY,
            &Secret::new(TEST_SECRET),
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
                "sha256=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `sha256=` prefix",
                },
            ),
            (
                "deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "sha1=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "SHA256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "Sha256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Mollie,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: &[&str] = &[
            // Not hex at all.
            "sha256=zzzz",
            // Valid hex but odd number of digits.
            "sha256=abc",
            // Valid hex but not 32 bytes (SHA-1 length).
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::Mollie,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }

    // --- 24-hour signing-secret rotation window ------------------------------

    /// The secret whose signature sits on the *second* of Mollie's two rotation
    /// header lines. Distinct from [`TEST_SECRET`] so a test cannot pass by
    /// accidentally reusing one key.
    const PREVIOUS_SECRET: &str = "previous-signing-secret";

    /// Mollie's documented `X-Mollie-Signature` for `secret` over `body`:
    /// `sha256=` + hex HMAC-SHA256 of the raw body (`spec.md` §3). Computed
    /// rather than hardcoded so the two rotation lines stay genuine signatures
    /// of two genuinely different keys, and so the assertion about *which* one
    /// is checked cannot drift away from the construction.
    fn signature_for(secret: &str, body: &[u8]) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
            Ok(mac) => mac,
            // Unreachable for a constant test secret (HMAC accepts
            // arbitrary-length keys); kept panic-free to honor the crate-wide
            // clippy deny on unwrap/expect.
            Err(_) => panic!("HMAC-SHA256 with a constant test secret cannot fail"),
        };
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// The two `X-Mollie-Signature` lines Mollie attaches during its rotation
    /// window, `first` ahead of `second`, exactly as the docs describe
    /// (<https://docs.mollie.com/reference/webhooks-new>, "Updating a live
    /// signing secret").
    fn rotation_headers(first: &str, second: &str) -> Vec<(String, String)> {
        vec![
            (SIGNATURE_HEADER.to_string(), first.to_string()),
            (SIGNATURE_HEADER.to_string(), second.to_string()),
        ]
    }

    /// The two secrets the documented rotation workflow requires: the live one
    /// and the one being retired.
    fn rotation_secrets() -> [Secret; 2] {
        [Secret::new(TEST_SECRET), Secret::new(PREVIOUS_SECRET)]
    }

    #[test]
    fn the_rotation_window_verifies_with_both_secrets_configured() {
        // The documented workflow (module docs, `spec.md` §3): keep the
        // previous secret until the window closes and try each. Mollie signs
        // the *first* line with one of the two active secrets, so
        // `verify_any` over both accepts the delivery whichever order the two
        // lines arrive in — which is the operator's call and not something the
        // docs promise to fix.
        let orders = [
            (
                "live",
                rotation_headers(
                    &signature_for(TEST_SECRET, PRIMARY_BODY),
                    &signature_for(PREVIOUS_SECRET, PRIMARY_BODY),
                ),
            ),
            (
                "previous",
                rotation_headers(
                    &signature_for(PREVIOUS_SECRET, PRIMARY_BODY),
                    &signature_for(TEST_SECRET, PRIMARY_BODY),
                ),
            ),
        ];
        for (first_line_is, headers) in orders {
            assert_eq!(
                verify_any(
                    crate::Provider::Mollie,
                    &headers,
                    PRIMARY_BODY,
                    &rotation_secrets(),
                    Default::default(),
                ),
                Ok(()),
                "first line is signed by the {first_line_is} secret, so trying both must verify",
            );
        }
    }

    #[test]
    fn only_one_of_the_two_secrets_alone_cannot_cover_the_whole_window() {
        // The consequence of `HeaderMap` being first-match-only, and the reason
        // the module docs insist on configuring *both* secrets: whichever secret
        // does not sign the first line is rejected for the whole window. A
        // deployment that keeps only one of the two sees `SignatureMismatch` on
        // every event after a roll — indistinguishable from a broken
        // integration — and no rotation window is "unverifiable", just
        // single-secret deployments.
        let previous_first = rotation_headers(
            &signature_for(PREVIOUS_SECRET, PRIMARY_BODY),
            &signature_for(TEST_SECRET, PRIMARY_BODY),
        );
        assert_eq!(
            verify(
                crate::Provider::Mollie,
                &previous_first,
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            ),
            Err(VerifyError::SignatureMismatch),
            "the live secret alone cannot verify while the previous line comes first",
        );
        assert_eq!(
            verify(
                crate::Provider::Mollie,
                &previous_first,
                PRIMARY_BODY,
                &Secret::new(PREVIOUS_SECRET),
                Default::default(),
            ),
            Ok(()),
        );
    }

    #[test]
    fn the_second_rotation_line_is_never_read() {
        // The crisp form of "only the first value is read", and the claim
        // `spec.md` §4.4's exemption rationale must not get wrong: the second
        // `X-Mollie-Signature` line is inert. Corrupting it, replacing it with
        // an outright forgery, or dropping it entirely changes nothing about
        // the outcome — no crate API enumerates a second value of one header
        // name, because `HeaderMap` is first-match-only by contract.
        let genuine_first = signature_for(TEST_SECRET, PRIMARY_BODY);
        let second = signature_for(PREVIOUS_SECRET, PRIMARY_BODY);
        // A well-formed 32-byte signature for a key nobody holds: it decodes,
        // it is the right length, and it is simply not this body's MAC.
        let forged = format!("sha256={}", "0".repeat(64));

        // Only the first line matters, so the second can be anything at all.
        for second_value in [second.as_str(), forged.as_str(), "not-even-a-signature", ""] {
            assert_eq!(
                verify(
                    crate::Provider::Mollie,
                    &rotation_headers(&genuine_first, second_value),
                    PRIMARY_BODY,
                    &Secret::new(TEST_SECRET),
                    Default::default(),
                ),
                Ok(()),
                "second line {second_value:?} must not affect a genuine first line",
            );
        }

        // Dropping the second line is likewise indistinguishable, which is why
        // an adapter's duplicate-header scan exempting this header grants no
        // extra reach: nothing downstream ever sees the second value.
        assert_eq!(
            verify(
                crate::Provider::Mollie,
                &rotation_headers(&genuine_first, &second),
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            ),
            verify(
                crate::Provider::Mollie,
                &mollie_headers(PRIMARY_SIGNATURE),
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            ),
        );

        // And a corrupted *first* line still fails, so "the second line is
        // unread" is not a claim that the header is unverified — only the
        // duplicate is.
        assert_eq!(
            verify(
                crate::Provider::Mollie,
                &rotation_headers(&forged, &genuine_first),
                PRIMARY_BODY,
                &Secret::new(TEST_SECRET),
                Default::default(),
            ),
            Err(VerifyError::SignatureMismatch),
        );
    }
}
