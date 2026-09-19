//! CircleCI (outbound webhooks) signature verification.
//!
//! Scheme, per CircleCI's official documentation
//! (<https://circleci.com/docs/guides/integration/outbound-webhooks> "Outbound
//! webhooks", the "Validate webhooks as they come in" section) and their
//! reference Python verifier, which the docs reproduce verbatim:
//!
//! - Header: `circleci-signature: v1=<hex_hmac>[,v2=...][,v3=...]` — a
//!   comma-separated list of **versioned** signatures. The version tag rides
//!   in the `key=value` element itself, so a delivery can carry several
//!   versions at once.
//! - Signed string: the raw request body bytes, unmodified (the docs' sample
//!   computes `hmac(secret, body)` over the body as received; the reference
//!   verifier takes the raw request body).
//! - Algorithm: HMAC-SHA256, hex-encoded, keyed by the webhook's configured
//!   signing secret (the "secret token" set when creating the webhook)
//!   verbatim as its UTF-8 bytes.
//! - Version selection: the docs state "the latest (and only) signature
//!   version is `v1`" and direct integrators to "only check the latest
//!   signature type to prevent downgrade attacks." This provider therefore
//!   verifies the `v1` element and discards any other version (`v2`, `v3`,
//!   ...) for forward compatibility, mirroring how the reference
//!   implementation indexes `['v1']` out of the key/value pairs.
//!
//! # Replay protection
//!
//! CircleCI does **not** sign a timestamp, so replay protection cannot be
//! provided at the signature layer. [`VerifyOptions::max_age`] and the
//! injected clock have **no effect** for this provider; that is documented
//! behavior, not an oversight (`spec.md` §3).
//!
//! # Parsing policy
//!
//! The docs define one `v1` element per delivery. A duplicate `v1` element is
//! rejected as ambiguous (`spec.md` §4.4) rather than last-wins like the
//! reference implementation's dict literal — this crate fails closed on
//! ambiguity. Unknown elements and versions are discarded for forward
//! compatibility.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying CircleCI's versioned signature list.
pub(crate) const SIGNATURE_HEADER: &str = "circleci-signature";

/// The only signature version CircleCI defines, per its docs.
const SCHEME: &str = "v1";

/// Field separator inside [`SIGNATURE_HEADER`].
const FIELD_SEPARATOR: char = ',';

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

    // The HMAC is computed over the raw body bytes and compared in constant
    // time; no early exit depends on *how* wrong the signature is.
    if verify_hmac_sha256(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses the `v1` element out of `circleci-signature` into its 32 decoded
/// signature bytes.
///
/// Mirrors the docs' reference algorithm: split the header on `,`, index out
/// the `v1` key/value pair, and ignore every other version for
/// forward compatibility (the docs: "only check the latest signature type to
/// prevent downgrade attacks"; `v1` is currently the only version). A
/// duplicate `v1` element is ambiguous and fails closed. Every failure mode
/// maps to a distinct error variant so callers can tell malformed-request
/// noise from signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut signature: Option<&str> = None;

    for element in value.split(FIELD_SEPARATOR) {
        let Some((key, val)) = element.split_once('=') else {
            continue;
        };
        // Keys are compared after trimming surrounding whitespace: the
        // comma-space spelling (`v1=<sig>, v2=<sig>`) that hand-copied values
        // produce must not silently drop a recognized key. Values are never
        // trimmed — the signature is hex, so surrounding whitespace is not
        // valid encoding anyway.
        let key = key.trim();

        if key == SCHEME {
            if signature.is_some() {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
                });
            }
            signature = Some(val);
        }
    }

    let signature = signature.ok_or(VerifyError::MalformedHeader {
        header: SIGNATURE_HEADER,
        reason: "missing `v1` field",
    })?;

    if signature.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "signature value is empty",
        });
    }

    let bytes = hex::decode(signature).map_err(|_| VerifyError::BadEncoding {
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

    /// From the official webhook-reference docs
    /// (<https://circleci.com/docs/guides/integration/outbound-webhooks> "the
    /// following will return True / False"), reproduced byte-for-byte: same
    /// body, same secret, same expected signature.
    const VECTOR_SECRET: &str = "secret";
    const VECTOR_BODY: &[u8] = b"hello world";
    const VECTOR_SIGNATURE: &str =
        "734cc62f32841568f45715aeb9f4d7891324e6d948e4c6c60c0621cdac48623a";

    /// The second published vector (secret `another-secret`, body `lalala`).
    const SECOND_VECTOR_SECRET: &str = "another-secret";
    const SECOND_VECTOR_BODY: &[u8] = b"lalala";
    const SECOND_VECTOR_SIGNATURE: &str =
        "daa220016c8f29a8b214fbfc3671aeec2145cfb1e6790184ffb38b6d0425fa00";

    /// The third published vector (secret `hunter123`, body
    /// `an-important-request-payload`).
    const THIRD_VECTOR_SECRET: &str = "hunter123";
    const THIRD_VECTOR_BODY: &[u8] = b"an-important-request-payload";
    const THIRD_VECTOR_SIGNATURE: &str =
        "9be2242094a9a8c00c64306f382a7f9d691de910b4a266f67bd314ef18ac49fa";

    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha256 -hmac "circleci-secret"`
    const EMPTY_BODY_SIGNATURE: &str =
        "920a71de005939117bb9f7de1f4a982b1df5a0a1a54b80fc7eed1c6e3abb93e4";
    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha256 -hmac "circleci-secret"`
    const UNICODE_BODY_SIGNATURE: &str =
        "aad72b29aceb303d8789efcc78a59f1a9d14b6a436b575e2cf71985db2bec8a0";

    /// The second documented official example: hmac("secret", "foo").
    const VALID_EXAMPLE_SIGNATURE: &str =
        "773ba44693c7553d6ee20f61ea5d2757a9a4f4a44d2841ae4e95b52e4cd62db4";

    fn circleci_headers(value: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), value.to_string())]
    }

    fn verify_with(body: &[u8], secret: &str, value: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::CircleCi,
            &circleci_headers(value),
            body,
            &Secret::new(secret),
            Default::default(),
        )
    }

    #[test]
    fn official_vectors_verify() {
        // All three published example tuples from the docs.
        assert_eq!(
            verify_with(
                VECTOR_BODY,
                VECTOR_SECRET,
                &format!("v1={VECTOR_SIGNATURE}")
            ),
            Ok(())
        );
        assert_eq!(
            verify_with(
                SECOND_VECTOR_BODY,
                SECOND_VECTOR_SECRET,
                &format!("v1={SECOND_VECTOR_SIGNATURE}"),
            ),
            Ok(())
        );
        assert_eq!(
            verify_with(
                THIRD_VECTOR_BODY,
                THIRD_VECTOR_SECRET,
                &format!("v1={THIRD_VECTOR_SIGNATURE}"),
            ),
            Ok(())
        );
        // The docs' "will return True" example runs through the same path.
        assert_eq!(
            verify_with(
                b"foo",
                VECTOR_SECRET,
                &format!("v1={VALID_EXAMPLE_SIGNATURE}")
            ),
            Ok(())
        );
    }

    #[test]
    fn locally_constructed_boundary_bodies_verify() {
        assert_eq!(
            verify_with(
                b"",
                "circleci-secret",
                &format!("v1={EMPTY_BODY_SIGNATURE}")
            ),
            Ok(())
        );
        assert_eq!(
            verify_with(
                "héllo, 🦀 world!".as_bytes(),
                "circleci-secret",
                &format!("v1={UNICODE_BODY_SIGNATURE}"),
            ),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::CircleCi,
            &[(
                String::from("CircleCI-Signature"),
                format!("v1={VECTOR_SIGNATURE}"),
            )],
            VECTOR_BODY,
            &Secret::new(VECTOR_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = VECTOR_SIGNATURE.to_ascii_uppercase();
        assert_eq!(
            verify_with(VECTOR_BODY, VECTOR_SECRET, &format!("v1={upper}")),
            Ok(())
        );
    }

    #[test]
    fn additional_versions_and_unknown_elements_are_discarded() {
        // The docs' example header shows a multi-version list
        // (`v1=...,v2=...,v3=...`); only the current `v1` version is checked,
        // and unknown elements are ignored for forward compatibility.
        let mixed = format!("v2=deadbeef,foo=bar,v1={VECTOR_SIGNATURE},v3=deadbeef",);
        assert_eq!(verify_with(VECTOR_BODY, VECTOR_SECRET, &mixed), Ok(()));
        // Comma-space spelling that proxy header-folding produces.
        let spaced = format!("v1={VECTOR_SIGNATURE}, v2=deadbeef");
        assert_eq!(verify_with(VECTOR_BODY, VECTOR_SECRET, &spaced), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the hex alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!(
            "{}{}{}",
            &VECTOR_SIGNATURE[..10],
            if VECTOR_SIGNATURE[10..11] == *"0" {
                "1"
            } else {
                "0"
            },
            &VECTOR_SIGNATURE[11..]
        );
        assert_ne!(flipped, VECTOR_SIGNATURE);
        assert_eq!(
            verify_with(VECTOR_BODY, VECTOR_SECRET, &format!("v1={flipped}")),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::CircleCi,
            &circleci_headers(&format!("v1={VECTOR_SIGNATURE}")),
            VECTOR_BODY,
            &Secret::new("a different secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn tampered_body_fails() {
        // Same header, one body byte changed — the signed string is the raw
        // body, so any change breaks the HMAC.
        let tampered = b"hello world!";
        assert_eq!(
            verify_with(tampered, VECTOR_SECRET, &format!("v1={VECTOR_SIGNATURE}")),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn max_age_has_no_effect_for_circleci() {
        // CircleCI signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented "max_age
        // ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::CircleCi,
            &circleci_headers(&format!("v1={VECTOR_SIGNATURE}")),
            VECTOR_BODY,
            &Secret::new(VECTOR_SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::CircleCi,
            &Vec::<(String, String)>::new(),
            VECTOR_BODY,
            &Secret::new(VECTOR_SECRET),
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
            // No `v1` element at all.
            (
                "v2=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `v1` field",
                },
            ),
            // Element with no `=` is not a recognizable version pair.
            (
                "deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `v1` field",
                },
            ),
            // A duplicate `v1` element is ambiguous, not last-wins.
            (
                &format!("v1={VECTOR_SIGNATURE},v1={VALID_EXAMPLE_SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "multiple signatures",
                },
            ),
            (
                "v1=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "signature value is empty",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::CircleCi,
                &[(SIGNATURE_HEADER, value)],
                VECTOR_BODY,
                &Secret::new(VECTOR_SECRET),
                Default::default(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: &[&str] = &[
            // Not hex at all.
            "v1=zzzz",
            // Valid hex but odd number of digits.
            "v1=abc",
            // Valid hex but only 16 bytes (SHA-1 length).
            "v1=deadbeefdeadbeefdeadbeefdeadbeef",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::CircleCi,
                &[(SIGNATURE_HEADER, value)],
                VECTOR_BODY,
                &Secret::new(VECTOR_SECRET),
                Default::default(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
