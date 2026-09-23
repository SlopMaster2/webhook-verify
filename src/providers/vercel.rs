//! Vercel webhook signature verification.
//!
//! Scheme, per Vercel's official documentation
//! (<https://vercel.com/docs/webhooks/webhooks-api> "Securing webhooks" and
//! the request-header reference
//! <https://vercel.com/docs/headers/request-headers#x-vercel-signature>):
//!
//! - Header: `x-vercel-signature: <hex_hmac>` — a bare lowercase hex digest,
//!   no prefix and no timestamp; the reference verifier compares
//!   `crypto.createHmac('sha1', secret).update(rawBody).digest('hex')` output
//!   directly against the header value. Same shape as Dropbox, Razorpay, and
//!   Lemon Squeezy, but keyed with **SHA-1** rather than the SHA-256 most
//!   providers use (the built-in providers' SHA-1 schemes are Twilio,
//!   Mailchimp Transactional, Intercom, Expo EAS, and this one — Twilio and
//!   Mailchimp Transactional sign a different construction (URL + form
//!   params, base64), and Intercom and Expo deliver their raw-body digest
//!   behind a `sha1=` prefix; Vercel's header is the bare digest). Covers
//!   requests from Webhooks, Log Drains, and integration webhooks alike.
//! - Signed string: raw request body bytes, unmodified. Vercel's docs verify
//!   the signature *before* `JSON.parse` and warn that URL-encoding or
//!   otherwise re-encoding the body breaks the HMAC — the crate hashes
//!   `raw_body` verbatim (`spec.md` §4).
//! - Algorithm: HMAC-SHA1, hex-encoded. Key: the webhook secret shown when
//!   creating an account webhook, or the Integration Secret (Client Secret)
//!   for integration webhooks, as its UTF-8 bytes — matching the documented
//!   construction.
//!
//! # Replay protection
//!
//! Vercel does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha1;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Vercel's signature.
pub(crate) const SIGNATURE_HEADER: &str = "x-vercel-signature";

/// HMAC-SHA1 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 20;

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
    // time (Vercel's own reference code uses `crypto.timingSafeEqual`); no
    // early exit depends on *how* wrong the signature is.
    if verify_hmac_sha1(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `x-vercel-signature` into its 20 decoded signature bytes.
///
/// Vercel sends bare hex with no prefix. Every failure mode maps to a
/// distinct error variant so callers can tell malformed-request noise from
/// signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let bytes = hex::decode(value).map_err(|_| VerifyError::BadEncoding {
        reason: "signature is not valid hexadecimal",
    })?;

    if bytes.len() != SIGNATURE_LEN_BYTES {
        return Err(VerifyError::BadEncoding {
            reason: "signature does not decode to 20 bytes",
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

    const SECRET: &str = "vercel_secret_key_0123456789";
    /// The vector body mirrors the shape of Vercel's documented
    /// `project.created` event (`spec.md` §3, Vercel row).
    const BODY: &[u8] = b"{\"id\":\"2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e\",\"type\":\"project.created\",\"createdAt\":1799999999000,\"data\":{\"id\":\"Qmabc123def456ghi789jkl\",\"name\":\"my-project\"}}";
    /// Locally constructed, independently cross-checked with Python
    /// `hmac.new(secret, body, hashlib.sha1).hexdigest()`:
    /// `printf '{"id":...}' | openssl dgst -sha1 -hmac "vercel_secret_key_0123456789"`.
    const SIGNATURE: &str = "5765cf41dc4a50b60ebdf45baf2f2f2486f49179";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "efed4b9480877dbffb6cd89ff9c958d4b43b7e85";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "a3b3a77dcd720d6e01a03ab63e52762de5926632";

    fn vercel_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Vercel,
            &vercel_headers(signature),
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
            crate::Provider::Vercel,
            &[("X-Vercel-Signature", SIGNATURE)],
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
        // Same shape with a forged `"stage":"preview"` — the signed string is
        // the raw body, so any byte change breaks the HMAC.
        let tampered =
            b"{\"id\":\"2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e\",\"type\":\"project.created\",\"createdAt\":1799999999000,\"stage\":\"preview\",\"data\":{\"id\":\"Qmabc123def456ghi789jkl\",\"name\":\"my-project\"}}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Vercel,
            &vercel_headers(SIGNATURE),
            BODY,
            &Secret::new("vercel_secret_key_an_entirely_different_key"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_vercel() {
        // Vercel signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Vercel,
            &vercel_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Vercel,
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
            // Garbage value: not valid hexadecimal at all.
            (
                "not hex!!",
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
            // Valid hex but wrong decoded length (HMAC-SHA256 size = 32 bytes
            // = 64 hex chars — the trap Vercel's SHA-1 scheme catches).
            (
                "5765cf41dc4a50b60ebdf45baf2f2f2486f491795765cf41dc4a50b60ebdf45baf2f2f2486f49179",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 20 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Vercel,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Guard the odd-length path as well: an odd number of hex digits can
        // never be a 20-byte digest, so it must fail decoding, not verify.
        let value = &SIGNATURE[..39];
        let result = verify(
            crate::Provider::Vercel,
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
