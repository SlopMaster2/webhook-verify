//! Notion webhook signature verification.
//!
//! Scheme, per Notion's official documentation
//! (<https://developers.notion.com/reference/webhooks> "Understanding
//! webhook signatures") and the official JS SDK's `@notionhq/client`
//! `verifyWebhookSignature()` helper
//! (<https://github.com/makenotion/notion-sdk-js/blob/main/src/webhooks.ts>,
//! introduced in v5.23.0; matches the server-side delivery code
//! `sendWebhookRequest.ts`):
//!
//! - Header: `X-Notion-Signature: sha256=<hex(HMAC-SHA256(verification_token, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified — Notion's docs
//!   warn explicitly that re-serializing JSON changes the bytes and fails
//!   verification
//! - Algorithm: HMAC-SHA256 with the subscription's `verification_token` as
//!   the key (the token delivered during the one-time handshake, not the
//!   integration's API token), hex-encoded, prefixed `sha256=`
//!
//! The `sha256=` prefix is matched case-sensitively, exactly like GitHub's
//! `X-Hub-Signature-256` (spec.md §3); Notion's docs and SDK emit only the
//! literal lowercase form.
//!
//! # Replay protection
//!
//! Notion does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3). Notion recommends detecting
//! stale or duplicate events from the payload's own `timestamp`/`id` fields,
//! which is outside this crate's scope (payload parsing is a non-goal).
//!
//! Notion's one-time subscription *handshake* request carries no
//! `X-Notion-Signature` header (the body is just
//! `{"verification_token": "..."}`); callers must special-case that request
//! before calling [`crate::verify()`], which correctly reports a
//! `MissingHeader` for it.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Notion's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Notion-Signature";

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

/// Parses `X-Notion-Signature` into its 32 decoded signature bytes.
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
    use crate::verify;
    use std::time::Duration;

    /// The `verification_token` from Notion's official worked example
    /// (<https://developers.notion.com/reference/webhooks>, "Step 2 —
    /// Verifying the subscription").
    const OFFICIAL_TOKEN: &str = "secret_tMrlL1qK5vuQAh1b6cZGhFChZTSYJlce98V0pYn7yBl";
    /// The handshake-shaped body from the same worked example.
    const OFFICIAL_BODY: &[u8] =
        b"{\"verification_token\":\"secret_tMrlL1qK5vuQAh1b6cZGhFChZTSYJlce98V0pYn7yBl\"}";
    /// The exact `X-Notion-Signature` sample value published on the same docs
    /// page ("Sample `X-Notion-Signature` from Notion"). Reproducing it from
    /// the worked example: HMAC-SHA256(`OFFICIAL_TOKEN`, `OFFICIAL_BODY`),
    /// hex-encoded, prefixed `sha256=` — verified with `openssl dgst` and
    /// Python's `hmac` module, both matching the documented value.
    const OFFICIAL_SIGNATURE: &str =
        "461e8cbcba8a75c3edd866f0e71280f5a85cbf21eff040ebd10fe266df38a735";
    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha256 -hmac "$OFFICIAL_TOKEN"`
    const EMPTY_BODY_SIGNATURE: &str =
        "e482a3fd1ac21103ced304e676969d9e3a6ff10fec05de81820114a4bf2c6b74";
    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha256 -hmac "$OFFICIAL_TOKEN"`
    const UNICODE_BODY_SIGNATURE: &str =
        "f516318ddda4018ab37b6d7998777215e6e490e6ce7f95523dca495290cae68c";

    fn notion_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("sha256={signature}"))]
    }

    fn verify_official(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Notion,
            &notion_headers(signature),
            body,
            &Secret::new(OFFICIAL_TOKEN),
            Default::default(),
        )
    }

    #[test]
    fn official_vector_from_notion_docs() {
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
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Notion,
            &[(
                "x-notion-signature",
                "sha256=461e8cbcba8a75c3edd866f0e71280f5a85cbf21eff040ebd10fe266df38a735",
            )],
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_TOKEN),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = OFFICIAL_SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_official(OFFICIAL_BODY, &upper), Ok(()));
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
    fn tampered_body_fails() {
        let mut tampered = OFFICIAL_BODY.to_vec();
        tampered.extend_from_slice(b"\"extra\":true}");
        assert_eq!(
            verify_official(&tampered, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Notion,
            &notion_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new("secret_entirely_the_wrong_token"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_notion() {
        // Notion signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. This pins the documented
        // "max_age ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Notion,
            &notion_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Notion,
            &Vec::<(String, String)>::new(),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_TOKEN),
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
                crate::Provider::Notion,
                &[(SIGNATURE_HEADER, value)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_TOKEN),
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
                crate::Provider::Notion,
                &[(SIGNATURE_HEADER, value)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_TOKEN),
                Default::default(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
