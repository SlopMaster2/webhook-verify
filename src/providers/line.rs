//! LINE Messaging API webhook signature verification.
//!
//! Scheme, per LINE's official documentation
//! (<https://developers.line.biz/en/docs/messaging-api/verify-webhook-signature/>,
//! "Verify webhook signature") and the messaging-receipt overview
//! (<https://developers.line.biz/en/docs/messaging-api/receiving-messages/>):
//!
//! - Header: `x-line-signature: <base64(HMAC-SHA256(key, raw_body))>` — a
//!   bare base64 digest, no prefix and no timestamp.
//! - Signed string: the **exact string in the received webhook request body**
//!   — LINE's docs are explicit that any modification (deserialization,
//!   JSON formatting, escape-character interpretation, encoding changes) makes
//!   the signature fail, so verification must run against the raw bytes before
//!   any parsing. The crate hashes `raw_body` verbatim (`spec.md` §4).
//! - Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet with
//!   padding). Key: the channel's **Channel Secret**, used verbatim as its
//!   UTF-8 bytes. The docs publish a byte-exact example: the confirmation
//!   webhook body `{"destination":"U8e742f61d673b39c7fff3cecb7536ef0","events":[]}`
//!   with the channel secret `8c570fa6dd201bb328f1c1eac23a96d8` yields the
//!   signature `GhRKmvmHys4Pi8DxkF4+EayaH0OqtJtaZxgTD9fMDLs=` (their sample
//!   `openssl dgst -sha256 -hmac ... | openssl base64` command is reproduced
//!   in `spec.md` §3). The docs spell the header lowercase
//!   (`x-line-signature`), so the constant here follows that spelling;
//!   HTTP headers are case-insensitive and lookup resolves either form.
//!
//! LINE does not sign a timestamp, so replay protection cannot be provided at
//! the signature layer — the docs recommend handling replayed deliveries at
//! the application layer if needed. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying LINE's signature.
///
/// LINE's official docs spell this header lowercase
/// (`x-line-signature`); the `HeaderMap` lookup is ASCII case-insensitive, so
/// the raw-bytes spelling surfaced in `VerifyError` messages and adapter scans
/// follows the provider's own spelling (`spec.md` §3, LINE row).
pub(crate) const SIGNATURE_HEADER: &str = "x-line-signature";

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
    // time; no early exit depends on *how* wrong the signature is (LINE's own
    // SDK middleware validates the same way, against the untouched raw body).
    if verify_hmac_sha256(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `x-line-signature` into its 32 decoded signature bytes.
///
/// LINE sends bare base64 with no prefix. Every failure mode maps to a
/// distinct error variant so callers can tell malformed-request noise from
/// signature-mismatch signals (`spec.md` §2.1).
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

    // Vectors: the primary vector is the byte-exact example from LINE's own
    // docs (openssl command and signature both published there) — the only
    // official vector in this crate that needs no local construction. The
    // boundary vectors are locally constructed over the documented raw-body
    // base64 construction and cross-checked against both OpenSSL and Python's
    // `hmac` module (independent implementations).
    const SECRET: &str = "a3e7f1c4d9b2a8f5e6c3d1b4a7e9f2c8";

    /// A realistic Messaging API delivery (the exact bytes the platform
    /// signs — the docs' example is an empty `events` list, so this exercises
    /// the non-empty event path with the same shape).
    const BODY: &[u8] =
        b"{\"destination\":\"U8e742f61d673b39c7fff3cecb7536ef0\",\"events\":[{\"type\":\"message\",\"message\":{\"type\":\"text\",\"id\":\"325708\",\"text\":\"hello\"},\"webhookEventId\":\"01FZ74A0TDDPYRVKNK77X4X4QZ\",\"deliveryContext\":{\"isRedelivery\":false},\"timestamp\":1506296049877,\"source\":{\"type\":\"user\",\"userId\":\"Udeadbeefdeadbeefdeadbeefdeadbeef\"},\"replyToken\":\"nHuyWiB7yP5Zw52FIkcQobQuGDXCTA\",\"mode\":\"active\"}]}";

    /// The LINE Platform's own published example, byte-exact from
    /// <https://developers.line.biz/en/docs/messaging-api/verify-webhook-signature/>:
    /// body, channel secret, and signature all come from that page.
    const OFFICIAL_SECRET: &str = "8c570fa6dd201bb328f1c1eac23a96d8";
    const OFFICIAL_BODY: &[u8] =
        b"{\"destination\":\"U8e742f61d673b39c7fff3cecb7536ef0\",\"events\":[]}";
    const OFFICIAL_SIGNATURE: &str = "GhRKmvmHys4Pi8DxkF4+EayaH0OqtJtaZxgTD9fMDLs=";

    /// `printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64`
    const SIGNATURE: &str = "PHH4FG9nkoqrakC8QarjEZGOYTAUi2/2cp/z5IJ3eqc=";
    /// Locally constructed over an empty body (boundary case), cross-checked
    /// the same way.
    const EMPTY_BODY_SIGNATURE: &str = "whvxTqEJRLHRWiec2FuithTy5Vz8lBGb4uBhxZbme6I=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case),
    /// cross-checked the same way.
    const UNICODE_BODY_SIGNATURE: &str = "Q1+EBTqjbKUFzZSqtsQK19Rmkxmnb6W7kV7guRAeuXs=";

    fn line_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Line,
            &line_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn official_vector_verifies() {
        // The exact example from LINE's docs (signature, body, and secret all
        // published on the same page) — the definitive proof the wire scheme
        // is right.
        assert_eq!(
            verify(
                crate::Provider::Line,
                &[(SIGNATURE_HEADER, OFFICIAL_SIGNATURE)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            ),
            Ok(())
        );
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
        // The docs spell the header `x-line-signature`; both spellings resolve.
        assert_eq!(
            verify(
                crate::Provider::Line,
                &[("x-line-signature", OFFICIAL_SIGNATURE)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            ),
            Ok(())
        );
        assert_eq!(
            verify(
                crate::Provider::Line,
                &[("X-LINE-SIGNATURE", OFFICIAL_SIGNATURE)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            ),
            Ok(())
        );
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}A{}", &SIGNATURE[..3], &SIGNATURE[4..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let mut tampered = BODY.to_vec();
        tampered[0] = b'[';
        assert_eq!(
            verify_with(&tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Line,
            &line_headers(SIGNATURE),
            BODY,
            &Secret::new("0f8c1f2a3b4c5d6e7f8a9b0c1d2e3f4e"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_line() {
        // LINE signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Line,
            &line_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Line,
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
            // Valid base64 but wrong decoded length (a truncated/SHA-1-sized
            // digest decodes to 16 bytes — the trap a non-SHA-256 signature
            // would hit). The unpadded 32-byte spelling below also lands in
            // `BadEncoding`, but via the "not valid standard base64" reason
            // (LINE always pads), which the next case pins.
            (
                "AAAAAAAAAAAAAAAAAAAAAA==",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
            // Well-formed *content* missing canonical padding: the parse must
            // reject it rather than strip the padding and compare.
            (
                "GhRKmvmHys4Pi8DxkF4+EayaH0OqtJtaZxgTD9fMDLs",
                VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Line,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
