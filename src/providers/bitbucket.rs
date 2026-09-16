//! Bitbucket Cloud webhook signature verification.
//!
//! Scheme, per Bitbucket Cloud's official "Manage webhooks" documentation
//! (<https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/>,
//! "The value of the header [is] formatted as `method=signature` as defined by
//! WebSub"; today Bitbucket sends HMACs using `sha256`):
//!
//! - Header: `X-Hub-Signature: sha256=<hex(HMAC-SHA256(secret, raw_body))>`
//! - Signed string: the raw request body bytes, unmodified — the docs stress
//!   that "the payload is passed verbatim into the HMAC generation" and that
//!   reformatting the body produces a different signature
//! - Algorithm: HMAC-SHA256, hex-encoded (lowercase hex from Bitbucket;
//!   decoding here is case-insensitive)
//!
//! The `sha256=` prefix is matched case-sensitively, exactly like GitHub
//! (`spec.md` §3): WebSub method names are lowercase and Bitbucket's docs and
//! examples emit only the literal lowercase form. The docs note Bitbucket
//! "might use another hash in the future"; when that happens this provider
//! fails closed on the unknown prefix rather than silently mis-verifying.
//!
//! # Replay protection
//!
//! Bitbucket does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider (`spec.md` §3). The
//! `X-Hub-Signature` header is only present when a secret is configured on
//! the webhook; otherwise it is absent entirely and `verify()` reports
//! `MissingHeader`.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Bitbucket's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Hub-Signature";

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

/// Parses `X-Hub-Signature` into its 32 decoded signature bytes.
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

    const OFFICIAL_SECRET: &str = "It's a Secret to Everybody";

    /// Bitbucket Cloud's official worked example — "Testing the webhook
    /// payload validation" in the "Manage webhooks" docs
    /// (<https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/>),
    /// reproduced with the docs' exact `secret`, `payload`, and expected
    /// `sha256=` signature.
    const OFFICIAL_BODY: &[u8] = b"Hello World!";
    const OFFICIAL_SIGNATURE: &str =
        "a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9";

    /// The docs' second worked example, from the JavaScript sample code in the
    /// same page: a JSON payload signed over the exact received bytes.
    const OFFICIAL_JSON_BODY: &[u8] = b"{\"hello\":\"world\",\"webhook\":\"secret\"}";
    const OFFICIAL_JSON_SIGNATURE: &str =
        "c48e50b1d349b665dd7bf48bd243f22d5a22758c3f86714f0774aac3cab8fc5e";

    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha256 -hmac "It's a Secret to Everybody"`
    const EMPTY_BODY_SIGNATURE: &str =
        "66a0c074deaa0f489ead6537e0d32f9a344b90bbeda705b6ed45ecd3b413fb40";
    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha256 -hmac "It's a Secret to Everybody"`
    const UNICODE_BODY_SIGNATURE: &str =
        "815772f88bf8950c7457b57856f4b33ca9d07e7ef7a50646b067b4a613f735c4";

    fn bitbucket_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("sha256={signature}"))]
    }

    fn verify_official(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Bitbucket,
            &bitbucket_headers(signature),
            body,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        )
    }

    #[test]
    fn official_vector_from_bitbucket_docs() {
        assert_eq!(verify_official(OFFICIAL_BODY, OFFICIAL_SIGNATURE), Ok(()));
    }

    #[test]
    fn official_json_vector_from_bitbucket_docs() {
        // The docs' JS sample signs a JSON body; the signature is over the
        // exact received bytes (`{"hello":"world","webhook":"secret"}`), not a
        // re-serialized form.
        assert_eq!(
            verify_official(OFFICIAL_JSON_BODY, OFFICIAL_JSON_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn locally_constructed_boundary_bodies_verify() {
        assert_eq!(verify_official(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_official("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Bitbucket,
            &[(
                "x-hub-signature",
                "sha256=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9",
            )],
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = OFFICIAL_SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_official(OFFICIAL_BODY, &upper), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let sig = format!(
            "{}{}{}",
            &OFFICIAL_SIGNATURE[..10],
            if OFFICIAL_SIGNATURE[10..11] == *"0" {
                "1"
            } else {
                "0"
            },
            &OFFICIAL_SIGNATURE[11..]
        );
        assert_ne!(sig, OFFICIAL_SIGNATURE);
        assert_eq!(
            verify_official(OFFICIAL_BODY, &sig),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        let tampered = b"Hello World?";
        assert_eq!(
            verify_official(tampered, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Bitbucket,
            &bitbucket_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_bitbucket() {
        // Bitbucket signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. This pins the documented
        // "max_age ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Bitbucket,
            &bitbucket_headers(OFFICIAL_SIGNATURE),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Bitbucket,
            &Vec::<(String, String)>::new(),
            OFFICIAL_BODY,
            &Secret::new(OFFICIAL_SECRET),
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
            (
                "Sha256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha256=` prefix",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Bitbucket,
                &[(SIGNATURE_HEADER, value)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
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
            // Valid hex but not 32 bytes (SHA-1 length).
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::Bitbucket,
                &[(SIGNATURE_HEADER, value)],
                OFFICIAL_BODY,
                &Secret::new(OFFICIAL_SECRET),
                Default::default(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
