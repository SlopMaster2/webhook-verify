//! Meta webhook signature verification.
//!
//! Scheme, per Meta's official documentation
//! (<https://developers.facebook.com/docs/graph-api/webhooks/getting-started>
//! "Validating payloads", shared by Graph API, Messenger Platform, Instagram,
//! and WhatsApp Cloud API deliveries):
//!
//! - Header: `X-Hub-Signature-256: sha256=<hex(HMAC-SHA256(app_secret, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified
//! - Algorithm: HMAC-SHA256, hex-encoded (lowercase hex from Meta; decoding
//!   here is case-insensitive)
//!
//! The key is the app's **App Secret** from the App Dashboard, used verbatim
//! as its UTF-8 bytes — the same construction as GitHub's `X-Hub-Signature-256`
//! but with the Meta App Secret as the key.
//!
//! # Raw-body fidelity caveat
//!
//! Meta documents that it signs the payload's *escaped-unicode* serialization:
//! a non-ASCII character such as `äöå` is signed as its `\u00e4\u00f6\u00e5`
//! escape sequence, so the exact bytes received off the wire are the bytes
//! signed. The crate hashes `raw_body` verbatim (`spec.md` §4), which is
//! correct provided the caller passes the untouched request body — never a
//! reparsed/re-serialized JSON value, which would use a different (escaped vs.
//! literal) encoding for non-ASCII characters.
//!
//! # Replay protection
//!
//! Meta does **not** sign a timestamp, so replay protection cannot be provided
//! at the signature layer. [`VerifyOptions::max_age`] and the injected clock
//! have **no effect** for this provider; that is documented behavior, not an
//! oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Meta's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Hub-Signature-256";

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
    // time (Meta's reference code uses `crypto.timingSafeEqual`); no early
    // exit depends on *how* wrong the signature is.
    if verify_hmac_sha256(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `X-Hub-Signature-256` into its 32 decoded signature bytes.
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

    const SECRET: &str = "meta_app_secret_0123456789abcdef";
    /// The vector body mirrors the shape of Meta's documented WhatsApp Cloud
    /// API `messages` delivery (`spec.md` §3, Meta row). ASCII-only on
    /// purpose: Meta signs the escaped-unicode serialization of the payload,
    /// which for all-ASCII JSON is byte-identical to the raw body.
    const BODY: &[u8] = b"{\"object\":\"whatsapp_business_account\",\"entry\":[{\"id\":\"0\",\"changes\":[{\"value\":{\"messaging_product\":\"whatsapp\",\"metadata\":{\"display_phone_number\":\"16505551111\",\"phone_number_id\":\"1234567890\"},\"contacts\":[{\"profile\":{\"name\":\"Test User\"},\"wa_id\":\"16315551000\"}],\"messages\":[{\"from\":\"16315551000\",\"id\":\"wamid.HBgLMTYzMTU1NTEwMDAVO0IA\",\"timestamp\":\"1700000000\",\"text\":{\"body\":\"Hello\"}}]},\"field\":\"messages\"}]}]}";
    /// Locally constructed, independently cross-checked with Python
    /// `hmac.new(secret, body, hashlib.sha256).hexdigest()`:
    /// `openssl dgst -sha256 -hmac "meta_app_secret_0123456789abcdef"`.
    const SIGNATURE: &str = "3a8e2537f6da233150367098bf5edc43c2b8f89052773e2c4dfcdeb76c144bd8";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str =
        "6f3f902abbb7a91b15e5b7264bf5ac8610b8e620c6a04176cbde8bf353fcc981";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str =
        "3d96abd7a28a96205e4dc83c6b8c0cd548c8f9a67f9e3b4b550ff78de7c15fc9";

    fn meta_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("sha256={signature}"))]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Meta,
            &meta_headers(signature),
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
            crate::Provider::Meta,
            &[(
                "x-hub-signature-256".to_string(),
                format!("sha256={SIGNATURE}"),
            )],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_with(BODY, &upper), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the hex alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}0{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Same shape with a forged `"text":{"body":"Hello,Tampered"}` — the
        // signed string is the raw body, so any byte change breaks the HMAC.
        let tampered = b"{\"object\":\"whatsapp_business_account\",\"entry\":[{\"id\":\"0\",\"changes\":[{\"value\":{\"messaging_product\":\"whatsapp\",\"metadata\":{\"display_phone_number\":\"16505551111\",\"phone_number_id\":\"1234567890\"},\"contacts\":[{\"profile\":{\"name\":\"Test User\"},\"wa_id\":\"16315551000\"}],\"messages\":[{\"from\":\"16315551000\",\"id\":\"wamid.HBgLMTYzMTU1NTEwMDAVO0IA\",\"timestamp\":\"1700000000\",\"text\":{\"body\":\"Hello,Tampered\"}}]},\"field\":\"messages\"}]}]}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Meta,
            &meta_headers(SIGNATURE),
            BODY,
            &Secret::new("meta_app_secret_a_completely_different_key"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_meta() {
        // Meta signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Meta,
            &meta_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Meta,
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
            // Meta's legacy SHA-1 header is a separate `X-Hub-Signature`
            // name; a `sha1=` value in the `-256` header is not the documented
            // scheme and must fail closed.
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
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Meta,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
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
            // Valid hex but wrong decoded length (a 20-byte digest's 40 hex
            // chars is the trap a SHA-1-shaped forgery would hit; only 32
            // decoded bytes — 64 hex chars — can match).
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::Meta,
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
}
