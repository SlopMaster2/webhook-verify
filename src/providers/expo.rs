//! Expo (EAS) webhook signature verification.
//!
//! Scheme, per Expo's official EAS webhook documentation
//! (<https://docs.expo.dev/eas/webhooks/> and its source in the `expo/expo`
//! repo, `docs/pages/eas/webhooks.mdx`):
//!
//! - Header: `expo-signature: sha1=<hex(HMAC-SHA1(secret, raw_body))>` — the
//!   docs call the header value a "hex-encoded HMAC-SHA1 digest of the request
//!   body, using your webhook secret as the HMAC key", and the reference
//!   verification sample compares the header against `sha1=${hmac.digest('hex')}`,
//!   i.e. a `sha1=`-prefixed lowercase hex digest over the raw request body —
//!   the same `sha1=` shape GitHub/Bitbucket use for `sha256=`.
//! - Signed string: the raw request body bytes, unmodified — Expo's reference
//!   sample feeds the exact body text (`bodyParser.text({ type: '*/*' })` then
//!   `hmac.update(req.body)`) into a constant-time comparison, so any
//!   reformatting or re-encoding of the payload changes the signature.
//! - Algorithm: HMAC-SHA1, hex-encoded (lowercase hex from Expo; decoding here
//!   is case-insensitive). Like Intercom and Twilio, Expo still legitimately
//!   mandates SHA-1 — the HMAC is keyed with the shared webhook secret, which
//!   HMAC's keyed use makes immune to SHA-1's collision attacks.
//! - Key: the webhook signing secret configured with `eas webhook:create`
//!   (the docs require it to be at least 16 characters long) as its UTF-8
//!   bytes verbatim.
//!
//! The `sha1=` prefix is matched case-sensitively, exactly like Intercom's
//! `X-Hub-Signature` and GitHub's/Bitbucket's `sha256=` (`spec.md` §3): Expo
//! emits only the literal lowercase form, and an unknown scheme fails closed
//! as `MalformedHeader` rather than silently mis-verifying.
//!
//! Covers EAS Build and EAS Submit webhook deliveries (the two events EAS
//! signs). Expo signs no timestamp, so replay protection cannot be provided at
//! the signature layer; [`VerifyOptions::max_age`] and the injected clock have
//! **no effect** for this provider (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha1;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;

/// The header carrying Expo's signature.
pub(crate) const SIGNATURE_HEADER: &str = "expo-signature";

/// Required prefix of the header value.
const SIGNATURE_PREFIX: &str = "sha1=";

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
    // time; no early exit depends on *how* wrong the signature is.
    if verify_hmac_sha1(secret.as_bytes(), raw_body, &provided) {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Parses `expo-signature` into its 20 decoded signature bytes.
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
                reason: "missing `sha1=` prefix",
            });
        }
    };

    if hex_part.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "empty signature after `sha1=` prefix",
        });
    }

    let bytes = hex::decode(hex_part).map_err(|_| VerifyError::BadEncoding {
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

    /// Expo documents the construction and ships a reference constant-time
    /// verification sample (`sha1=${hmac.digest('hex')}`) on its EAS webhooks
    /// page (source linked in the module docs above), but publishes no
    /// byte-exact example signature — the sample's secret is operator-chosen,
    /// so no fixed body+signature pair exists to copy. Vectors are therefore
    /// locally constructed over exactly the documented construction (`sha1=` +
    /// lowercase hex of `HMAC-SHA1(secret, raw_body)`), cross-checked with
    /// `openssl dgst -sha1 -hmac` and Python's `hmac` module. Replace them if
    /// Expo ever publishes fixed vectors.
    const OFFICIAL_SECRET: &str = "expo-webhook-signing-secret";

    /// Body mirrors the shape of the build webhook payload example on the same
    /// docs page (`id`, `accountName`, `projectName`, `platform`, `status`,
    /// `createdAt`) — a real delivery is a JSON object but its exact bytes are
    /// what get signed, so the vector body is the exact byte string that was
    /// hashed.
    const PRIMARY_BODY: &[u8] =
        b"{\"id\":\"147a3212-49fd-446f-b4e3-a6519acf264a\",\"accountName\":\"dsokal\",\"projectName\":\"example\",\"platform\":\"android\",\"status\":\"errored\",\"createdAt\":\"2021-11-24T09:53:01.155Z\"}";

    /// Locally constructed with:
    /// `printf '%s' '{"id":"147a3212-...' | openssl dgst -sha1 -hmac "expo-webhook-signing-secret"`
    const PRIMARY_SIGNATURE: &str = "ea60c41f2ea4e610786914c37b8737cea2818a61";

    /// Locally constructed with:
    /// `printf '' | openssl dgst -sha1 -hmac "expo-webhook-signing-secret"`
    const EMPTY_BODY_SIGNATURE: &str = "2884a01d7d3d33bc4131319e713cf2cf8e221169";

    /// Locally constructed with:
    /// `printf 'héllo, 🦀 world!' | openssl dgst -sha1 -hmac "expo-webhook-signing-secret"`
    const UNICODE_BODY_SIGNATURE: &str = "003c75803c34eacdc9c048b02b95fa0c313c2081";

    fn expo_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), format!("sha1={signature}"))]
    }

    fn verify_primary(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Expo,
            &expo_headers(signature),
            body,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        )
    }

    #[test]
    fn vector_over_documented_construction_verifies() {
        // The primary vector: HMAC-SHA1 over the exact received JSON bytes,
        // keyed with the webhook secret verbatim, `sha1=`-prefixed hex.
        assert_eq!(verify_primary(PRIMARY_BODY, PRIMARY_SIGNATURE), Ok(()));
    }

    #[test]
    fn locally_constructed_boundary_bodies_verify() {
        assert_eq!(verify_primary(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_primary("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Expo,
            &[(
                "Expo-Signature",
                format!("sha1={PRIMARY_SIGNATURE}").as_str(),
            )],
            PRIMARY_BODY,
            &Secret::new(OFFICIAL_SECRET),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let upper = PRIMARY_SIGNATURE.to_ascii_uppercase();
        assert_eq!(verify_primary(PRIMARY_BODY, &upper), Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let sig = format!(
            "{}{}{}",
            &PRIMARY_SIGNATURE[..10],
            if PRIMARY_SIGNATURE[10..11] == *"0" {
                "1"
            } else {
                "0"
            },
            &PRIMARY_SIGNATURE[11..]
        );
        assert_ne!(sig, PRIMARY_SIGNATURE);
        assert_eq!(
            verify_primary(PRIMARY_BODY, &sig),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        // Same construction but a single byte of the body differs — the JSON
        // must not be re-serialized before hashing, so any byte change
        // invalidates the signature.
        let tampered = b"{\"id\":\"147a3212-49fd-446f-b4e3-a6519acf264a\",\"accountName\":\"dsokal\",\"projectName\":\"example\",\"platform\":\"ios\",\"status\":\"errored\",\"createdAt\":\"2021-11-24T09:53:01.155Z\"}";
        assert_ne!(tampered, PRIMARY_BODY);
        assert_eq!(
            verify_primary(tampered, PRIMARY_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Expo,
            &expo_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new("a different webhook secret"),
            Default::default(),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn max_age_has_no_effect_for_expo() {
        // Expo signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. This pins the documented
        // "max_age ignored" behavior against regressions.
        let options = crate::core::VerifyOptions {
            max_age: Some(Duration::ZERO),
            ..crate::core::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Expo,
            &expo_headers(PRIMARY_SIGNATURE),
            PRIMARY_BODY,
            &Secret::new(OFFICIAL_SECRET),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let result = verify(
            crate::Provider::Expo,
            &Vec::<(String, String)>::new(),
            PRIMARY_BODY,
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
                "sha1=",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `sha1=` prefix",
                },
            ),
            (
                "deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
            (
                "sha256=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
            (
                "SHA1=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
            (
                "Sha1=deadbeef",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "missing `sha1=` prefix",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Expo,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
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
            "sha1=zzzz",
            // Valid hex but odd number of digits.
            "sha1=abc",
            // Valid hex but not 20 bytes (SHA-256 length).
            "sha1=e638ec02cbe287c03d108e3a714e9ec6ba1bf92ed7a9cf5e63f6e4e942e8c7c6",
            // Valid hex but wrong length (40 bytes).
            "sha1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        for &value in cases {
            let result = verify(
                crate::Provider::Expo,
                &[(SIGNATURE_HEADER, value)],
                PRIMARY_BODY,
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
