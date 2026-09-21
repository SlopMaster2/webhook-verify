//! FastSpring webhook signature verification.
//!
//! Scheme, per FastSpring's official documentation
//! (<https://developer.fastspring.com/reference/message-security> — "Message
//! Security": "FastSpring servers will use that key to generate a hashed digest
//! of each webhook payload. The resulting digest will be encoded to base64 and
//! included in the X-FS-Signature header of the webhook", with the reference
//! construction
//! `createHmac('sha256', secret).update(body).digest().toString('base64')`):
//!
//! - Header: `X-FS-Signature: <base64(HMAC-SHA256(secret, raw_body))>` — a
//!   bare base64 digest (standard alphabet with padding), no `sha256=`
//!   prefix and no timestamp; same shape as Tally, Shopify, Xero, and
//!   WooCommerce. FastSpring's docs warn the header "is not case-sensitive
//!   and might be sent with varying case (all lowercase, or mixed case)" —
//!   lookup here is case-insensitive, covering that.
//! - Signed string: the raw request body bytes, unmodified. FastSpring's own
//!   Node sample hashes the raw request body before any JSON parser runs (the
//!   Express example is explicit: "you must valid before the json parser");
//!   this crate hashes `raw_body` verbatim (`spec.md` §4), so callers must
//!   pass the untouched request body; any reformatting before verification
//!   breaks the digest.
//! - Algorithm: HMAC-SHA256, **base64**-encoded. Key: the webhook's HMAC
//!   SHA256 Secret (optional — each webhook definition has that field, and
//!   payloads are sent unsigned when it is left blank) as its UTF-8 bytes,
//!   used verbatim — never decoded.
//!
//! # Replay protection
//!
//! FastSpring does not sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3). Callers must dedupe on the
//! payload's own `id` field, which is outside this crate's scope (payload
//! parsing is a non-goal, §1).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying FastSpring's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-FS-Signature";

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

/// Parses `X-FS-Signature` into its 32 decoded signature bytes.
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

    const SECRET: &str = "fastspring_test_signing_secret";
    /// The vector body mirrors the shape of a FastSpring `order.completed`
    /// webhook event (`spec.md` §3, FastSpring row): the top-level `id`,
    /// `live`, and `event` fields plus the `data.order` envelope with the
    /// order's `id`, `display`, `total`, `currency`, and `status`.
    const BODY: &[u8] = br#"{"id":"ord_8FD54F54448B4D8F903C","live":true,"event":"order.completed","data":{"order":{"id":"8FD54F54448B4D8F903C","display":"Order #27318 (3 items)","total":123.00,"currency":"USD","status":"completed"}}}"#;
    /// Locally constructed:
    /// `printf '{...}' | openssl dgst -sha256 -hmac "fastspring_test_signing_secret" -binary | base64`
    ///
    /// FastSpring's docs describe the construction and publish working sample
    /// code but no byte-exact secret/body/signature triple — the secret is
    /// endpoint-specific and set per webhook in the App, never shown again —
    /// so vectors here are locally constructed against the documented recipe
    /// and cross-checked with Python's `hashlib`/`hmac` and OpenSSL (`spec.md`
    /// §3, FastSpring row). Replace if FastSpring ever publishes fixed vectors.
    const SIGNATURE: &str = "0DvtDdX42pxIa4ZqIDxavw9TrV7xWpiF6GVWl+JFIGg=";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "byRLnTCL9rbY8reTmiHRHgi1wmCFEUjF1UUKIPkJ4k8=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "TKIHm6tEwCz93onhxjdWd/kQQMTMKd0BdS/xdCgGCLk=";

    fn fastspring_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::FastSpring,
            &fastspring_headers(signature),
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
        // FastSpring's docs warn the header "might be sent with varying case".
        let result = verify(
            crate::Provider::FastSpring,
            &[("x-fs-signature", SIGNATURE)],
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
        // Same shape with a forged order id — the signed string is the raw
        // body, so any byte change breaks the HMAC.
        let tampered =
            br#"{"id":"ord_8FD54F54448B4D8F903C","live":true,"event":"order.completed","data":{"order":{"id":"forged","display":"Order #27318 (3 items)","total":123.00,"currency":"USD","status":"completed"}}}"#;
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::FastSpring,
            &fastspring_headers(SIGNATURE),
            BODY,
            &Secret::new("a different signing secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_fastspring() {
        // FastSpring signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::FastSpring,
            &fastspring_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::FastSpring,
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
                crate::Provider::FastSpring,
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
            crate::Provider::FastSpring,
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
