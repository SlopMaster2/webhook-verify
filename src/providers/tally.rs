//! Tally webhook signature verification.
//!
//! Scheme, per Tally's official documentation
//! (<https://tally.so/help/webhooks> — the "Add a signing secret" section:
//! "the webhook requests will contain a Tally-Signature header. The value of
//! this header is a SHA256 cryptographic hash of the webhook payload", with
//! the reference construction
//! `createHmac('sha256', yourSigningSecret).update(payload).digest('base64')`):
//!
//! - Header: `Tally-Signature: <base64(HMAC-SHA256(secret, raw_body))>` — a
//!   bare base64 digest (standard alphabet with padding), no `sha256=`
//!   prefix and no timestamp; same shape as Shopify, Xero, and WooCommerce
//! - Signed string: the raw request body bytes, unmodified. Tally's own
//!   example hashes `JSON.stringify(webhookPayload)` after a runtime has
//!   already parsed the body — a re-serialization round-trip that reproduces
//!   the received bytes only when the parser preserves key order and
//!   whitespace. This crate hashes `raw_body` verbatim (`spec.md` §4), which
//!   is the signer's actual wire bytes, so callers must pass the untouched
//!   request body; any reformatting before verification breaks the digest.
//! - Algorithm: HMAC-SHA256, **base64**-encoded. Key: the webhook's signing
//!   secret (optional — if none is set, Tally sends unsigned requests) as its
//!   UTF-8 bytes, used verbatim — never decoded.
//!
//! # Replay protection
//!
//! Tally does not sign a timestamp, so replay protection cannot be provided at
//! the signature layer. [`VerifyOptions::max_age`] and the injected clock have
//! **no effect** for this provider; that is documented behavior, not an
//! oversight (`spec.md` §3). Tally retries failed deliveries on a back-off
//! schedule, so callers should dedupe on the payload's own `eventId`, which is
//! outside this crate's scope (payload parsing is a non-goal, §1).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying Tally's signature.
pub(crate) const SIGNATURE_HEADER: &str = "Tally-Signature";

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

/// Parses `Tally-Signature` into its 32 decoded signature bytes.
///
/// The value carries no `sha256=` prefix — it is bare base64. Every failure
/// mode maps to a distinct error variant so callers can tell malformed-request
/// noise from signature-mismatch signals (`spec.md` §2.1).
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
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    const SECRET: &str = "tally_test_signing_secret";
    /// The vector body mirrors the shape of Tally's published example webhook
    /// event (`spec.md` §3, Tally row): the always-included `eventId`,
    /// `eventType` (`FORM_RESPONSE`), `createdAt`, and the `data` envelope
    /// with the `responseId`/`submissionId`/`formId` IDs and a two-field slice
    /// of the `fields` array.
    const BODY: &[u8] = br#"{"eventId":"a4cb511e-d513-4fa5-baee-b815d718dfd1","eventType":"FORM_RESPONSE","createdAt":"2023-06-28T15:00:21.889Z","data":{"responseId":"2wgx4n","submissionId":"2wgx4n","formId":"VwbNEw","formName":"Webhook payload","createdAt":"2023-06-28T15:00:21.000Z","fields":[{"key":"question_3EKz4n","label":"Text","type":"INPUT_TEXT","value":"Hello"}]}}"#;
    /// Locally constructed:
    /// `printf '{...}' | openssl dgst -sha256 -hmac "tally_test_signing_secret" -binary | base64`
    ///
    /// Tally's docs describe the construction and publish an example event but
    /// no byte-exact secret/body/signature triple — the signing secret is
    /// endpoint-specific and shown only once at creation — so vectors here are
    /// locally constructed against the documented recipe and cross-checked
    /// with Python's `hashlib`/`hmac` (`spec.md` §3, Tally row). Replace if
    /// Tally ever publishes fixed vectors.
    const SIGNATURE: &str = "WlZVYEQ5tRffbwu/CEVRe5cJ+ecRYQ2l2o0BIcnjGGM=";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "4n14U9SEAmgMCzw2V7USWqGBOnIqQRzuTgCpcItEDEo=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "SQb4591hXcvjRXuqn3TYBkM1OxtGTlnLISHAqyjNbBQ=";

    fn tally_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Tally,
            &tally_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn constructed_vector_verifies() {
        assert_eq!(verify_with(BODY, SIGNATURE), Ok(()));
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
        let result = verify(
            crate::Provider::Tally,
            &[("tally-signature", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}B{}", &SIGNATURE[..3], &SIGNATURE[4..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Same shape with a forged response id — the signed string is the raw
        // body, so any byte change breaks the HMAC.
        let tampered =
            br#"{"eventId":"a4cb511e-d513-4fa5-baee-b815d718dfd1","eventType":"FORM_RESPONSE","createdAt":"2023-06-28T15:00:21.889Z","data":{"responseId":"forged","submissionId":"2wgx4n","formId":"VwbNEw","createdAt":"2023-06-28T15:00:21.000Z","fields":[]}}"#;
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Tally,
            &tally_headers(SIGNATURE),
            BODY,
            &Secret::new("a different signing secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_tally() {
        // Tally signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Tally,
            &tally_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Tally,
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
    fn malformed_and_bad_encoding_errors_are_distinct() {
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
                crate::Provider::Tally,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Strip the trailing `=` padding: still valid base64 text, but
        // 47 characters can never be a 32-byte digest, so it must fail
        // decoding (odd-length guard), not verify.
        let value = &SIGNATURE[..SIGNATURE.len() - 1];
        let result = verify(
            crate::Provider::Tally,
            &[(SIGNATURE_HEADER, value)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        match result {
            Err(VerifyError::BadEncoding { .. }) => {}
            other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
        }
    }
}
