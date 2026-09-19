//! X (formerly Twitter) webhook signature verification.
//!
//! Scheme, per X's official webhook security documentation
//! (<https://docs.x.com/x-api/account-activity/guides/account-activity-webhooks> —
//! "Securing webhooks") and the reference implementations shipped there
//! (Python, Ruby):
//!
//! - Header: `x-twitter-webhooks-signature:
//!   sha256=<base64(HMAC-SHA256(consumer_secret, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified
//! - Algorithm: HMAC-SHA256 keyed with the app's **consumer secret** (the API
//!   secret key) as its UTF-8 bytes, **base64**-encoded (standard alphabet,
//!   padded), with a literal `sha256=` prefix — the docs' reference code
//!   always prefixes (`sha256=` + `base64.b64encode(hmac(...).digest())`)
//!
//! The prefix is matched case-sensitively, exactly like GitHub's `sha256=`
//! (`spec.md` §3): X's docs and reference implementations emit only the
//! literal lowercase form.
//!
//! The consumer secret is the app's API secret key — never the bearer token
//! or an access token — used verbatim as UTF-8 bytes.
//!
//! # Replay protection
//!
//! X does **not** sign a timestamp, so replay protection cannot be provided at
//! the signature layer. [`VerifyOptions::max_age`] and the injected clock have
//! **no effect** for this provider; that is documented behavior, not an
//! oversight (`spec.md` §3).
//!
//! The Challenge-Response Check (CRC) used to validate the webhook URL also
//! lives on this scheme (`response_token = sha256=<base64_hmac>` of the
//! `crc_token`), but it is a *response* the caller computes for an inbound GET,
//! not a delivery signature this crate verifies — it is out of scope here, and
//! this provider only covers the per-delivery `x-twitter-webhooks-signature`.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying X's webhook signature.
pub(crate) const SIGNATURE_HEADER: &str = "x-twitter-webhooks-signature";

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

/// Parses `x-twitter-webhooks-signature` into its 32 decoded signature bytes.
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

    const SECRET: &str = "X-Consumer-Secret-8f2e1a7b4c9d0e3f5a6b7c8d9e0f1a2b";
    /// A `tweet_create_event` webhook body shaped like X's documented example
    /// payload
    /// (<https://docs.x.com/x-api/account-activity/guides/account-activity-webhooks>).
    const BODY: &[u8] = b"{\"for_user_id\":\"1234567890123456789\",\"tweet_create_events\":[{\"id\":\"118139294120500103\",\"text\":\"Hello world!\",\"user\":{\"id\":\"1234567890123456789\",\"screen_name\":\"slopmaster\"}}]}";
    /// The full header value — docs' format is always `sha256=<base64_hmac>`
    /// (<https://docs.x.com/x-api/account-activity/guides/account-activity-webhooks>,
    /// "Securing webhooks"). The base64 half is locally constructed:
    /// `printf '%s' '<body>' | openssl dgst -sha256 -hmac '<consumer secret>' -binary | base64`
    ///
    /// X's docs describe the scheme and ship reference code
    /// (`base64.b64encode(hmac.new(consumer_secret, body, hashlib.sha256).digest())`,
    /// prefixed `sha256=`) but publish no byte-exact example signature, so
    /// vectors here are locally constructed against the documented recipe and
    /// cross-checked with OpenSSL.
    const SIGNATURE: &str = "sha256=wKAeP9GiJsaFuQJdxOljWIpG7W4b0IJshW59aJtfNZ0=";
    /// The `sha256=` prefix, for porcelain around the base64 half in tests.
    const PREFIX: &str = "sha256=";
    /// Full header value for the CRC-`response_token` construction
    /// (`sha256=<base64_hmac>` of the `crc_token`), confirming the shared
    /// primitive with the delivery header.
    const CRC_RESPONSE_TOKEN: &str = "sha256=7e5EieVqz/ISXFbkHvQMGoKzMmPHro8BdQP9CL7itxU=";
    /// Full header value locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "sha256=anCVED7r2qo5FRzb7lbVYvH7hgVD7P5MJJptjxOpyw0=";
    /// Full header value locally constructed over `"héllo, 🦀 world!"`
    /// (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "sha256=EW+ir6jOMaM1QZu6WObefMCPF2X99/Ts3qn7jr38BRM=";

    fn x_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::X,
            &x_headers(signature),
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
    fn consumer_secret_used_verbatim_not_base64_decoded() {
        // The consumer secret is a plain opaque string used verbatim as the
        // HMAC key's UTF-8 bytes — it must NOT be hex/base64-decoded first.
        let result = verify(
            crate::Provider::X,
            &x_headers(SIGNATURE),
            BODY,
            &Secret::new("X-Consumer-Secret-8f2e1a7b4c9d0e3f5a6b7c8d9e0f1a2b="),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::X,
            &[("X-Twitter-Webhooks-Signature", SIGNATURE)],
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
        let tampered = b"{\"for_user_id\":\"1234567890123456789\",\"tweet_create_events\":[{\"id\":\"118139294120500104\",\"text\":\"Hello world!\",\"user\":{\"id\":\"1234567890123456789\",\"screen_name\":\"slopmaster\"}}]}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::X,
            &x_headers(SIGNATURE),
            BODY,
            &Secret::new("a different consumer secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_x() {
        // X signs no timestamp: even a zero-second tolerance must not reject a
        // validly signed delivery. Pins the documented behavior.
        let options = VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::X,
            &x_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::X,
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
                "wKAeP9GiJsaFuQJdxOljWIpG7W4b0IJshW59aJtfNZ0=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
            (
                "SHA256=wKAeP9GiJsaFuQJdxOljWIpG7W4b0IJshW59aJtfNZ0=",
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
                crate::Provider::X,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Padding is required: the same 32 bytes without the trailing `=`
        // must be rejected, matching Shopify's scheme.
        let value = "sha256=wKAeP9GiJsaFuQJdxOljWIpG7W4b0IJshW59aJtfNZ0";
        let result = verify(
            crate::Provider::X,
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

    #[test]
    fn crc_response_token_uses_the_same_primitive() {
        // The CRC response_token is `sha256<base64_hmac>` of the crc_token
        // with the same consumer secret — the exact construction verified for
        // deliveries, so reusing the provider's parser must accept it over a
        // crc_token-as-body (the docs link the two verifications explicitly).
        let crc_token = b"challenge_string";
        let result = verify(
            crate::Provider::X,
            &[(SIGNATURE_HEADER, CRC_RESPONSE_TOKEN)],
            crc_token,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }
}
