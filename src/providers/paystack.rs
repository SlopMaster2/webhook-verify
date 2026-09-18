//! Paystack webhook signature verification.
//!
//! Scheme, per Paystack's official documentation
//! (<https://paystack.com/docs/payments/webhooks/> "Verify event origin →
//! Signature validation"):
//!
//! - Header: `x-paystack-signature: <hex_hmac>` — a bare lowercase hex
//!   digest, no prefix and no timestamp; same shape as Dropbox, Razorpay, and
//!   Lemon Squeezy, but keyed with **SHA-512** rather than the SHA-256 most
//!   providers use.
//! - Signed string: raw request body bytes, unmodified. The docs' own Node
//!   sample hashes `JSON.stringify(req.body)`, which only works when a
//!   framework happens to reproduce Paystack's exact bytes; the crate hashes
//!   `raw_body` verbatim (`spec.md` §4), which is the only construction that
//!   survives a non-normalizing proxy.
//! - Algorithm: HMAC-SHA512, hex-encoded. Key: the Paystack secret key from
//!   the dashboard ("Settings → API Keys & Webhooks") as its UTF-8 bytes,
//!   matching the documented construction
//!   (`crypto.createHmac("sha512", secret).update(body).digest("hex")`).
//!
//! # Replay protection
//!
//! Paystack does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer (the docs recommend IP allow-listing as a
//! complement to signature validation). [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha512;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Paystack's signature.
pub(crate) const SIGNATURE_HEADER: &str = "x-paystack-signature";

/// HMAC-SHA512 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 64;

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
    if verify_hmac_sha512(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `x-paystack-signature` into its 64 decoded signature bytes.
///
/// Paystack sends bare hex with no prefix. Every failure mode maps to a
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
            reason: "signature does not decode to 64 bytes",
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

    const SECRET: &str = "sk_test_7a3b9c4d1e2f";
    /// The vector body mirrors the shape of Paystack's documented
    /// `charge.success` event (`spec.md` §3, Paystack row).
    const BODY: &[u8] = b"{\"event\":\"charge.success\",\"data\":{\"id\":302900482,\"domain\":\"test\",\"status\":\"success\",\"reference\":\"PV5096CSH7\",\"amount\":10000,\"currency\":\"NGN\"}}";
    /// Locally constructed, independently cross-checked with Python
    /// `hmac.new(secret, body, hashlib.sha512).hexdigest()`:
    /// `printf '{"event":...}' | openssl dgst -sha512 -hmac "sk_test_7a3b9c4d1e2f"`.
    const SIGNATURE: &str = "29795fd38f4944d2a1b94792f8864e1db77a8af5036d840c62a0d51cdc1545ec9b9920294057700a2eb6193c458a3f2c8e04ca4a8e7e43aafd2932d520aba8ba";
    /// Locally constructed over an empty body (boundary case).
    const EMPTY_BODY_SIGNATURE: &str = "132e822d55348526d0815ecf734d50c7dd482d4603df3836855c2bcc32f9f6d5842957ec1843999d4549b45cc7cd6adb021151caa0471d380112d7148caaab3a";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "e1e1cdbb139d2667fbcb93a7d0b1c897cae15e9c271d42b3a5597fb881c81496f0dc01d815db5e0dd1d081aee69a2c13bec2f5fce854698fe6bf9b178a03bdd0";

    fn paystack_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    fn verify_with(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Paystack,
            &paystack_headers(signature),
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
            crate::Provider::Paystack,
            &[("X-Paystack-Signature", SIGNATURE)],
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
        // Same shape with a forged `status: "failed"` — the signed string is
        // the raw body, so any byte change breaks the HMAC.
        let tampered =
            b"{\"event\":\"charge.success\",\"data\":{\"id\":302900482,\"domain\":\"test\",\"status\":\"failed\",\"reference\":\"PV5096CSH7\",\"amount\":10000,\"currency\":\"NGN\"}}";
        assert_eq!(
            verify_with(tampered, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Paystack,
            &paystack_headers(SIGNATURE),
            BODY,
            &Secret::new("sk_test_a_different_secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_paystack() {
        // Paystack signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Paystack,
            &paystack_headers(SIGNATURE),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Paystack,
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
            // = 64 hex chars — the trap Paystack's SHA-512 scheme catches).
            (
                "29795fd38f4944d2a1b94792f8864e1db77a8af5036d840c62a0d51cdc1545ec",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 64 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Paystack,
                &[(SIGNATURE_HEADER, value)],
                BODY,
                &Secret::new(SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        // Guard the odd-length path as well: an odd number of hex digits can
        // never be a 64-byte digest, so it must fail decoding, not verify.
        let value = &SIGNATURE[..127];
        let result = verify(
            crate::Provider::Paystack,
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
