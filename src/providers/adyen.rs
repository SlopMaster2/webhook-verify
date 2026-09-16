//! Adyen webhook signature verification.
//!
//! Scheme, per Adyen's official documentation
//! (<https://docs.adyen.com/development-resources/webhooks/secure-webhooks/verify-hmac-signatures>,
//! "Verify HMAC keys returned in the header") and the worked example in
//! <https://docs.adyen.com/classic-platforms/configure-notifications/signing-notifications-with-hmac>:
//!
//! - Header: `hmacsignature: <base64(HMAC-SHA256(key, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified. Adyen's docs are
//!   explicit: "Make sure that the request body is as it is—do not
//!   deserialize it".
//! - Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet with
//!   padding)
//! - Key: the Customer Area HMAC key is a **hex string**; Adyen's official
//!   libraries hex-decode it to raw bytes before using it as the MAC key
//!   (Java `HMACValidator.calculateHMAC` calls `Hex.decodeHex(key)`
//!   <https://github.com/Adyen/adyen-java-api-library/blob/master/src/main/java/com/adyen/util/HMACValidator.java>;
//!   Go `hmacvalidator` calls `hex.DecodeString(secret)`
//!   <https://github.com/Adyen/adyen-go-api-library/blob/main/src/hmacvalidator/hmacvalidator.go>).
//!   Using the hex characters themselves as the key is the classic Adyen
//!   integration bug, so a key that is not valid hexadecimal fails closed
//!   with [`VerifyError::InvalidSecret`].
//!
//! This variant covers the **header-based** scheme Adyen uses for its
//! non-payment webhooks — Adyen for Platforms / Banking, the Management API,
//! Recurring token lifecycle notifications, and classic-platform
//! notifications. It does **not** cover Adyen's Standard payments webhooks,
//! which place the signature inside the JSON body at
//! `notificationItems[].NotificationRequestItem.additionalData.hmacSignature`
//! and sign a colon-joined subset of fields rather than the raw body; a
//! body-embedded signature over a parsed-field string is outside this crate's
//! raw-body verification model (`spec.md` §1).
//!
//! The companion `protocol` header (`HmacSHA256`) is informational: it is not
//! covered by the HMAC and Adyen only ever sends `HmacSHA256`, so it is not
//! parsed. A future algorithm change would fail closed as a signature
//! mismatch rather than silently mis-verifying. Header lookup is
//! case-insensitive, so both the lowercase `hmacsignature` spelling current
//! docs use and the classic-platforms `HmacSignature` spelling resolve.
//!
//! # Replay protection
//!
//! Adyen's header-based scheme signs no timestamp, so replay protection cannot
//! be provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3). Adyen sends duplicates by
//! design and recommends identifying them from the payload's own
//! `eventCode`/`pspReference` fields, which is outside this crate's scope
//! (payload parsing is a non-goal, §1).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying Adyen's request-header HMAC signature.
pub(crate) const SIGNATURE_HEADER: &str = "HmacSignature";

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

    let key = decode_key(secret.as_bytes())?;
    let provided = parse_signature(value)?;

    // The HMAC is computed after both inputs parse and compared in constant
    // time; no early exit depends on *how* wrong the signature is.
    if verify_hmac_sha256(&key, raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Hex-decodes the Customer Area HMAC key held in [`Secret`].
///
/// Adyen's key is delivered as a hex string and the official libraries
/// hex-decode it to raw bytes before use; this reproduces that exactly.
/// Anything that is not valid (even-length) hexadecimal, or that decodes to
/// nothing, means the operator did not paste the Customer Area value — fail
/// closed with [`VerifyError::InvalidSecret`] rather than keying the HMAC with
/// an empty key that anyone could reproduce.
fn decode_key(secret: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let key = core::str::from_utf8(secret).map_err(|_| VerifyError::InvalidSecret {
        reason: "HMAC key must be a hex-encoded string",
    })?;
    let decoded = hex::decode(key).map_err(|_| VerifyError::InvalidSecret {
        reason: "HMAC key is not valid hexadecimal",
    })?;
    if decoded.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "HMAC key is empty",
        });
    }
    Ok(decoded)
}

/// Parses `HmacSignature` into its 32 decoded signature bytes.
///
/// Adyen sends bare base64 with no prefix. Every failure mode maps to a
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

    /// Adyen's published example HMAC key (hex, uppercase as the Customer Area
    /// displays it), from the classic-platforms "Signing notifications with
    /// HMAC" worked example.
    const SECRET: &str = "79A3EAF309C43708726A8C284C0D72618696A12E840DFA1DF3A158AFA3B577DA";

    /// The exact body from that same worked example (the Java sample's
    /// concatenated string literal, reproduced byte-for-byte).
    const BODY: &[u8] = br#"{"eventDate":"2018-07-09T12:07:27+02:00","eventType":"ACCOUNT_HOLDER_CREATED","executingUserKey":"ws","live":false,"pspReference":"9915311308462016","content":{"invalidFields":[],"pspReference":"9915311308462016","accountCode":"9915311308462024","accountHolderCode":"6750d8cf-80ab-4a34-b2c5-f8a1f37a79da","accountHolderDetails":{"bankAccountDetails":[],"email":"testEmail@gmail.com","individualDetails":{"name":{"firstName":"TestFirstName","gender":"MALE","lastName":"TestData"}},"merchantCategoryCode":"7999"},"accountHolderStatus":{"status":"Active","processingState":{"disabled":false,"processedFrom":{"currency":"EUR","value":0},"processedTo":{"currency":"EUR","value":0},"tierNumber":0},"payoutState":{"allowPayout":false,"disabled":false,"tierNumber":0},"events":[]},"legalEntity":"Individual","verification":{}}}"#;

    /// Adyen's documented signature for `SECRET` + `BODY` (base64 HMAC-SHA256
    /// over the raw body, keyed by the hex-decoded secret).
    const SIGNATURE: &str = "A2bHr0WPlKg1fJLVEDReVAdUDWt3znmsuYvp2KdihXY=";

    /// Locally constructed over an empty body (boundary case), cross-checked
    /// with `openssl dgst -sha256 -mac hmac -macopt hexkey:$SECRET`:
    /// `printf '' | openssl dgst -sha256 -mac hmac -macopt hexkey:$SECRET -binary | base64`.
    const EMPTY_BODY_SIGNATURE: &str = "bj6YUoJfEAI9ZNv1NOlgli/3UEmxJXwT+h1Im0Y0rjs=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case),
    /// cross-checked the same way.
    const UNICODE_BODY_SIGNATURE: &str = "yIQOuJSH1NPNGea+zt1UEK2tbHdb1GRmhbWQR8OJkHs=";

    fn adyen_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Adyen,
            &adyen_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn official_vector_verifies() {
        // Adyen's own worked example (classic-platforms HMAC guide).
        assert_eq!(verify_with(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn official_vector_verifies_with_informational_protocol_header() {
        // Adyen sends a `protocol: HmacSHA256` header alongside the signature.
        // It is not covered by the HMAC, so it is neither required nor parsed;
        // the delivery must verify with or without it.
        let headers = [(SIGNATURE_HEADER, SIGNATURE), ("protocol", "HmacSHA256")];
        assert_eq!(
            verify(
                crate::Provider::Adyen,
                &headers,
                BODY,
                &Secret::new(SECRET),
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
        // Current Adyen docs spell the header `hmacsignature`; the classic
        // docs spell it `HmacSignature`. HTTP headers are case-insensitive.
        let lowercase = verify(
            crate::Provider::Adyen,
            &[("hmacsignature", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(lowercase, Ok(()));

        let uppercase = verify(
            crate::Provider::Adyen,
            &[("HMACSIGNATURE", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(uppercase, Ok(()));
    }

    #[test]
    fn lowercase_hex_key_is_accepted() {
        // The Customer Area shows an uppercase hex key; `hex::decode` accepts
        // either case, and both must select the same raw key bytes.
        let lowercase_key = SECRET.to_ascii_lowercase();
        assert_ne!(lowercase_key, SECRET);
        let result = verify(
            crate::Provider::Adyen,
            &adyen_headers(SIGNATURE),
            BODY,
            &Secret::new(&lowercase_key),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
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
        // A different but well-formed hex key must surface as a forgery, not a
        // configuration error.
        let other_key = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify(
            crate::Provider::Adyen,
            &adyen_headers(SIGNATURE),
            BODY,
            &Secret::new(other_key),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn ascii_hex_key_is_not_accepted_as_raw_key() {
        // The classic Adyen bug: keying the HMAC with the *characters* of the
        // hex string instead of its decoded bytes. Such a "key" verifies
        // nothing, so the documented vector must fail against it — pinning
        // that this crate hex-decodes rather than using the ASCII characters.
        let ascii_keyed = verify(
            crate::Provider::Adyen,
            &adyen_headers(SIGNATURE),
            BODY,
            &Secret::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            Default::default(),
        );
        assert_eq!(ascii_keyed, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_adyen() {
        // Adyen signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Adyen,
            &adyen_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Adyen,
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
    fn invalid_secret_errors_distinctly() {
        // Not hex at all.
        let result = verify(
            crate::Provider::Adyen,
            &adyen_headers(SIGNATURE),
            BODY,
            &Secret::new("not-hex-!"),
            Default::default(),
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "HMAC key is not valid hexadecimal"
            })
        );

        // Odd-length hex: valid alphabet, but not a whole number of bytes.
        let result = verify(
            crate::Provider::Adyen,
            &adyen_headers(SIGNATURE),
            BODY,
            &Secret::new("abc"),
            Default::default(),
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "HMAC key is not valid hexadecimal"
            })
        );

        // Empty key: hex-decodable, but an empty MAC key is a misconfiguration
        // anyone could reproduce, so it fails closed.
        let result = verify(
            crate::Provider::Adyen,
            &adyen_headers(SIGNATURE),
            BODY,
            &Secret::new(""),
            Default::default(),
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "HMAC key is empty"
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
                crate::Provider::Adyen,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
