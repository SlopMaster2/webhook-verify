//! Typeform webhook signature verification.
//!
//! Scheme, per Typeform's official "Secure your webhooks" documentation
//! (<https://developers.typeform.com/developers/webhooks/secure-your-webhooks/>)
//! and the reference implementations shipped on that page (Ruby, Node,
//! Python, Swift, PHP):
//!
//! - Header: `Typeform-Signature: sha256=<base64(HMAC-SHA256(secret, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified
//! - Algorithm: HMAC-SHA256 keyed with the webhook secret's UTF-8 bytes,
//!   **base64**-encoded (standard alphabet, padded), with a literal `sha256=`
//!   prefix — the docs' reference code always prefixes (`sha256=` +
//!   `Base64.strict_encode64(hash)`), and the docs' validation sample rejects
//!   any algorithm prefix other than `sha256`
//!
//! The prefix is matched case-sensitively, exactly like GitHub's `sha256=`
//! (`spec.md` §3): Typeform's docs and reference code emit only the literal
//! lowercase form.
//!
//! # Replay protection
//!
//! Typeform does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
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

/// The header carrying Typeform's signature.
pub(crate) const SIGNATURE_HEADER: &str = "Typeform-Signature";

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

/// Parses `Typeform-Signature` into its 32 decoded signature bytes.
///
/// The value is `<base64_hmac>` behind a required `sha256=` prefix. Every
/// failure mode maps to a distinct error variant so callers can tell
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
    let b64_part = match value.get(..SIGNATURE_PREFIX.len()) {
        Some(prefix) if prefix == SIGNATURE_PREFIX => &value[SIGNATURE_PREFIX.len()..],
        _ => {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "missing `sha256=` prefix",
            });
        }
    };

    if b64_part.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "empty signature after `sha256=` prefix",
        });
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_part)
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

    const SECRET: &str = "typeform_webhook_secret_2026";
    /// A `form_response` webhook body shaped like Typeform's documented
    /// example payload
    /// (<https://developers.typeform.com/developers/webhooks/example-payload/>).
    const BODY: &[u8] = b"{\"event_type\":\"form_response\",\"form_response\":{\"form_id\":\"aBcDefGhIj\",\"token\":\"8lBh6Y7h2qOHo\",\"submitted_at\":\"2023-01-27T15:40:21Z\"}}";
    /// The full header value — docs' format is always `sha256=<base64_hmac>`
    /// (<https://developers.typeform.com/developers/webhooks/secure-your-webhooks/>).
    /// The base64 half is locally constructed:
    /// `printf '%s' '{"event_type":"form_response","form_response":{"form_id":"aBcDefGhIj","token":"8lBh6Y7h2qOHo","submitted_at":"2023-01-27T15:40:21Z"}}' | openssl dgst -sha256 -hmac "typeform_webhook_secret_2026" -binary | base64`
    ///
    /// Typeform's docs describe the scheme and ship reference code
    /// (`crypto.createHmac('sha256', secret).update(payload).digest('base64')`,
    /// prefixed with `sha256=`) but publish no byte-exact example signature,
    /// so vectors here are locally constructed against the documented recipe.
    const SIGNATURE: &str = "sha256=SxAJUw6vn/KWUnuo8L+etZQ1+P6nGF+4t92qCVhABgo=";
    /// The `sha256=` prefix, for porcelain around the base64 half in tests.
    const PREFIX: &str = "sha256=";
    /// Full header value locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "sha256=II452V+uMzi3uR9Gec1eAyP+3WaWGkbAEgFf0OX5qVE=";
    /// Full header value locally constructed over `"héllo, 🦀 world!"`
    /// (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "sha256=VQ6N4wREQNQC1ME+LkvCypCv2AGrF4rv8EZMNK1XTlQ=";

    fn typeform_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Typeform,
            &typeform_headers(signature),
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
            crate::Provider::Typeform,
            &[("typeform-signature", SIGNATURE)],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 half so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let (prefix, b64) = SIGNATURE.split_at(PREFIX.len());
        let flipped = format!("{prefix}{}B{}", &b64[..3], &b64[4..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_with(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let tampered = b"{\"event_type\":\"form_response\",\"form_response\":{\"form_id\":\"aBcDefGhIj\",\"token\":\"8lBh6Y7h2qOHo\",\"submitted_at\":\"2023-01-27T15:40:22Z\"}}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Typeform,
            &typeform_headers(SIGNATURE),
            BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_typeform() {
        // Typeform signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Typeform,
            &typeform_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Typeform,
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
            (
                "sha256=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `sha256=` prefix",
                },
            ),
            (
                "SxAJUw6vn/KWUnuo8L+etZQ1+P6nGF+4t92qCVhABgo=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "SHA256=SxAJUw6vn/KWUnuo8L+etZQ1+P6nGF+4t92qCVhABgo=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            // Garbage value: syntactically prefixed but not valid base64.
            (
                "sha256=not base64!!",
                VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                },
            ),
            // Valid base64 alphabet but wrong decoded length (SHA-1 size).
            (
                "sha256=2jmj7l5rSw0yVb/vlWAYkK/YBwk=",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Typeform,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Padding is required: the same 32 bytes without the trailing `=`
        // must be rejected, matching Shopify's scheme.
        let value = "sha256=SxAJUw6vn/KWUnuo8L+etZQ1+P6nGF+4t92qCVhABgo";
        let result = verify(
            crate::Provider::Typeform,
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
