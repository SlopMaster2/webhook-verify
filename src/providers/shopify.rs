//! Shopify webhook signature verification.
//!
//! Scheme, per Shopify's official documentation
//! (<https://shopify.dev/docs/apps/build/webhooks/subscribe/https>):
//!
//! - Header: `X-Shopify-Hmac-Sha256: <base64(HMAC-SHA256(secret, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified
//! - Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet with
//!   padding) — not hex, a common bug source (`spec.md` §3)
//!
//! # Replay protection
//!
//! Shopify does not sign a timestamp, so replay protection cannot be provided
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
use base64::Engine;

/// The header carrying Shopify's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Shopify-Hmac-Sha256";

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

/// Parses `X-Shopify-Hmac-Sha256` into its 32 decoded signature bytes.
///
/// Unlike GitHub's scheme the value carries no `algo=` prefix — it is bare
/// base64. Every failure mode maps to a distinct error variant so callers can
/// tell malformed-request noise from signature-mismatch signals (§2.1).
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

    const SECRET: &str = "It's a Secret to Everybody";
    const BODY: &[u8] = b"Hello, World!";
    /// Locally constructed:
    /// `printf 'Hello, World!' | openssl dgst -sha256 -hmac "It's a Secret to Everybody" | base64`
    ///
    /// Shopify's docs describe the scheme but publish no concrete test vector,
    /// so vectors here are locally constructed against the documented recipe.
    const SIGNATURE: &str = "dXEH6g6yUJ/CESIczphLijdXC211hsIsRvQ3nIsEPhc=";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "ZqDAdN6qD0ierWU34NMvmjRLkLvtpwW27UXs07QT+0A=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "gVdy+Iv4lQx0V7V4VvSzPKnQfn73pQZGsGe0phP3NcQ=";

    fn shopify_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Shopify,
            &shopify_headers(signature),
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
            crate::Provider::Shopify,
            &[("x-shopify-hmac-sha256", SIGNATURE)],
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
        assert_eq!(
            verify_with(b"Hello, World?", SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Shopify,
            &shopify_headers(SIGNATURE),
            BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_shopify() {
        // Shopify signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Shopify,
            &shopify_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Shopify,
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
                crate::Provider::Shopify,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        let value = "dXEH6g6yUJ/CESIczphLijdXC211hsIsRvQ3nIsEPhc";
        let result = verify(
            crate::Provider::Shopify,
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
