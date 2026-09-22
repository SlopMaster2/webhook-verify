//! Recharge webhook signature verification.
//!
//! Scheme, per Recharge's official "Validating webhooks" documentation
//! (<https://docs.getrecharge.com/docs/webhooks-overview>):
//!
//! - Header: `X-Recharge-Hmac-Sha256: <hex_sha256>`
//! - Signed string: the API Client Secret's UTF-8 bytes **concatenated with**
//!   the raw request body bytes — no separator, secret first. Recharge's docs
//!   are explicit about both details: "client secret string needs to be
//!   concatenated with request body string and placed before it in order for
//!   validation to work!", and `request_body` "must be in JSON string format.
//!   Validation will fail even if one space is lost in process of JSON string
//!   generating" — a raw-body-only contract, matching this crate's `raw_body`
//!   (`spec.md` §4, never re-serialize).
//! - Algorithm: **plain SHA-256** — not HMAC, despite the header name. The
//!   header is called `X-Recharge-Hmac-Sha256` but every reference recipe in
//!   the docs hashes the raw concatenation with a bare SHA-256 (OpenSSL
//!   `echo -n secret body | openssl dgst -sha256`, Python
//!   `hashlib.sha256(secret; body)`, PHP `hash('sha256', secret.body)`, Ruby
//!   `Digest::SHA256.hexdigest(secret + body)`); this is the classic trap the
//!   header name sets.
//! - Encoding: lowercase hex, no `sha256=` prefix, no timestamp.
//!
//! The signing key is the **API Client Secret** (per merchant API token,
//! shown in the API token's Edit page) — not the API token itself, per the
//! docs' explicit warning.
//!
//! # Replay protection
//!
//! Recharge does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_sha256_prepended_key;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Recharge's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Recharge-Hmac-Sha256";

/// SHA-256 output length in bytes.
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

    // The digest is computed after parsing succeeds and compared in constant
    // time; no early exit depends on *how* wrong the signature is.
    if verify_sha256_prepended_key(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `X-Recharge-Hmac-Sha256` into its 32 decoded digest bytes.
///
/// Recharge sends bare hex with no prefix. Every failure mode maps to a
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

    const SECRET: &str = "shjk_test_client_secret_0123456789abcdef";
    /// A body mirroring Recharge's `order/created` webhook payload shape
    /// (`spec.md` §3): compact JSON, exactly as posted.
    const BODY: &[u8] = b"{\"id\":734031438,\"type\":\"order/created\",\"shop_id\":438291,\"order\":{\"id\":123456789,\"customer\":{\"id\":8991507},\"status\":\"queued\",\"total_price\":\"19.99\",\"currency\":\"USD\"}}";
    /// Locally constructed over `SECRET || BODY` per the documented recipe
    /// (`sha256(secret || body)`, secret first, no separator) and
    /// cross-checked with `printf '<secret><body>' | openssl dgst -sha256`,
    /// Python `hashlib.sha256(secret + body)`, PHP `hash('sha256', secret.body)`,
    /// and Ruby `Digest::SHA256.hexdigest(secret + body)` — all four official
    /// reference recipes agree. Recharge publishes no byte-exact fixed vector,
    /// so this replaces it until one ships.
    const SIGNATURE: &str = "9e99d3bdb37c9b7621f929bd402fe24abf3961dab7dd0821a6fd0414a2dd0ca8";
    /// Locally constructed over `SECRET || ""` (empty-body boundary case) with
    /// the same cross-checked recipe; equals `sha256(SECRET)` alone.
    const EMPTY_BODY_SIGNATURE: &str =
        "f0c98ba3f7ea9373f788bb7b444bbae03a8e723dae0097296c7cf8dc3fa1e13e";
    /// Locally constructed over `SECRET || "héllo, 🦀 world!"` (unicode
    /// boundary case) with the same cross-checked recipe.
    const UNICODE_BODY_SIGNATURE: &str =
        "42317fe9be5fc915d7e849081d643a2460a0850b1a1d4d2489adeb47aae20e0e";
    /// `sha256(BODY || SECRET)` — the reverse-order concatenation, which
    /// Recharge's docs explicitly warn "will result in fake false". Pins that
    /// the secret is prepended, never appended.
    const REVERSED_ORDER_SIGNATURE: &str =
        "d84ac262efa5b07e603eecf77b1f6d6468b448caf09bbf79d4c243ba84d93795";
    /// `HMAC-SHA256(SECRET, BODY)` — what the `Hmac-Sha256` header name
    /// tempts integrators to compute. The scheme is a bare digest, so the
    /// genuine HMAC must be rejected (`spec.md` §3).
    const HMAC_SIGNATURE: &str = "2deb536c47dd0c7ca2e372c812c708a785c2d08849c7e058352d4f109aa24fe2";

    fn recharge_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Recharge,
            &recharge_headers(signature),
            body,
            &Secret::new(SECRET),
            Default::default(),
        )
    }

    #[test]
    fn documented_construction_verifies() {
        // The primary cross-checked vector over the documented recipe
        // (sha256(secret || body), secret first). Also pins the empty and
        // unicode boundary bodies.
        assert_eq!(verify_with(BODY, SIGNATURE), Ok(()));
        assert_eq!(verify_with(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_with("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Recharge,
            &[("x-recharge-hmac-sha256", SIGNATURE)],
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
    fn not_an_hmac_despite_the_header_name() {
        // The whole point of this provider: `X-Recharge-Hmac-Sha256` is a
        // plain sha256(secret + body), and a genuine HMAC over the same
        // key/body is a different digest and must fail closed. Pins the
        // documented gotcha so a "simplification" to `verify_hmac_sha256`
        // breaks this test, not a production integration.
        assert_eq!(
            verify_with(BODY, HMAC_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn reversed_concatenation_order_fails() {
        // Recharge's docs: putting the client secret after the request body
        // "will result in fake false" — the secret must be prepended.
        assert_eq!(
            verify_with(BODY, REVERSED_ORDER_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
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
        // Recharge: validation fails "even if one space is lost" — a
        // whitespace-only mutation is enough to break the digest.
        let tampered = b"{\"id\":734031438,\"type\":\"order/created\",\"shop_id\":438291,\"order\":{\"id\":123456789,\"customer\":{\"id\":8991507},\"status\":\"queued\",\"total_price\":\" 19.99\",\"currency\":\"USD\"}}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        // The API token is a common mistake; only the API Client Secret
        // verifies.
        let result = verify(
            crate::Provider::Recharge,
            &recharge_headers(SIGNATURE),
            BODY,
            &Secret::new("sk_test_api_token"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_recharge() {
        // Recharge signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Recharge,
            &recharge_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Recharge,
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
            // Valid hex but wrong decoded length (SHA-1 size = 20 bytes = 40 hex chars).
            (
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 32 bytes",
                },
            ),
            // A `sha256=`-prefixed GitHub-style value is not Recharge's bare-hex
            // shape and must fail closed.
            (
                "sha256=9e99d3bdb37c9b7621f929bd402fe24abf3961dab7dd0821a6fd0414a2dd0ca8",
                VerifyError::BadEncoding {
                    reason: "signature is not valid hexadecimal",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Recharge,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Odd-length hex — `hex::decode` errors as not-valid-hex, but pin the
        // BadEncoding class (not a panic) rather than the exact reason string.
        let value = "abc";
        let result = verify(
            crate::Provider::Recharge,
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
