//! PayPal REST webhook signature verification.
//!
//! # Availability
//!
//! Compiled only with the `paypal` crate feature. Without the feature,
//! [`crate::Provider::PayPal`] keeps its fail-closed
//! [`crate::VerifyError::UnsupportedProvider`] stub.
//!
//! # Scheme
//!
//! Source: PayPal's official webhook integration documentation,
//! "Self verification method"
//! (<https://developer.paypal.com/api/rest/webhooks/rest/#message-verification>):
//!
//! - Headers: `PayPal-Transmission-Id`, `PayPal-Transmission-Time`,
//!   `PayPal-Transmission-Sig`, `PayPal-Cert-Url`, `PayPal-Auth-Algo`
//! - Signed string: the transmission ID (verbatim from its header), the
//!   transmission time (verbatim from its header), the webhook ID, and the
//!   CRC-32 checksum of the **raw** body — joined with `|`, in that order:
//!   `{transmission_id}|{transmission_time}|{webhook_id}|{crc32}`. The CRC-32
//!   (IEEE 802.3, the same polynomial zlib/gzip/PNG use) is rendered in
//!   **decimal** form. The raw body bytes are checksummed — never a
//!   re-serialized version (`spec.md` §4).
//! - Algorithm: RSASSA-PKCS1-v1_5 with SHA-256 — PayPal's
//!   `SHA256withRSA`. The [`PayPal-Auth-Algo`](AUTH_ALGO_HEADER) header must
//!   carry `SHA256withRSA` (matched case-insensitively); anything else fails
//!   closed, so a future algorithm change surface as a rejection rather than
//!   being silently accepted.
//! - Signature encoding: base64 (standard alphabet, padded) of the RSA
//!   signature bytes.
//! - Key material: the certificate pointed to by
//!   [`PayPal-Cert-Url`](CERT_URL_HEADER). This crate **never fetches it**
//!   (`spec.md` §7, no network calls): the caller supplies an already-vetted
//!   certificate (typically one downloaded from a personally allow-listed
//!   `PayPal-Cert-Url` value) as
//!   [`VerifyingKeyMaterial::X509Certificate`](crate::VerifyingKeyMaterial)
//!   via [`VerifyOptions::verifying_material`](crate::VerifyOptions).
//!   Accepts DER or PEM encoding; any X.509 certificate type (e.g. ECDSA)
//!   fails closed with [`crate::VerifyError::InvalidSecret`] — only the
//!   embedded RSA public key is used, and no chain validation or hostname
//!   checking is performed.
//!
//!   ```
//!   use std::fs;
//!   use webhook_verify::{VerifyError, VerifyOptions, VerifyingKeyMaterial};
//!
//!   # fn run() -> Result<(), VerifyError> {
//!   # let cert_pem = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
//!   let opts = VerifyOptions::default()
//!       .with_webhook_id("your-webhook-subscription-id")
//!       .with_verifying_material(VerifyingKeyMaterial::X509Certificate(cert_pem.to_vec()));
//!   # let _ = opts;
//!   # Ok(())
//!   # }
//!   ```
//!
//! # Security model
//!
//! Like Discord and SendGrid, this scheme uses a *public* key: verification
//! proves the payload was signed by PayPal's private key, not that the sender
//! shares a secret with you. The [`crate::Secret`] argument is accepted for
//! API uniformity and ignored. The webhook ID is
//! [`VerifyOptions::webhook_id`](crate::VerifyOptions::webhook_id) — it does
//! not travel in the request and must match the subscription configured in
//! the PayPal Developer Portal.
//!
//! # Replay protection
//!
//! PayPal's docs ["Compare timestamps to prevent replay
//! attacks"](https://developer.paypal.com/community/blog/paypal-has-updated-its-webhook-verification-endpoint/)
//! but define no numeric window, so this crate applies the shared default
//! tolerance ([`crate::VerifyOptions::max_age`], 300s, symmetric
//! `|now - t|`, injectable clock). The transmission time is parsed as an
//! RFC 3339 instant, so the window applies to the UTC instant even when an
//! explicit `±HH:MM` offset is present.
//!
//! # Test-vector provenance
//!
//! The transmission ID, transmission time, webhook ID, and event body are
//! PayPal's own published example values (the "Postback method" sample on
//! `<https://developer.paypal.com/api/rest/webhooks/rest/#self-verification-method>`).
//! PayPal publishes no byte-exact *signed* test vector (the docs' example
//! signature is over a transmission string built from a body the docs stress
//! must be the exact received bytes, which cannot be reconstructed), so the
//! certificate and signature are locally generated for this test over exactly
//! the documented `{transmission_id}|{transmission_time}|{webhook_id}|{crc32}`
//! construction; the private key is **not** committed. The CRC-32 was
//! cross-checked independently with Python's `zlib.crc32`.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::ToString;
use alloc::vec::Vec;
use base64::Engine;

use crate::core::VerifyOptions;
use crate::core::crypto::{
    RsaSha256Check, check_rsa_pkcs1v15_sha256, extract_rsa_pubkey_from_x509,
};
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::options::VerifyingKeyMaterial;
use crate::core::replay::{check_replay, parse_rfc3339_timestamp};
use crate::core::secret::Secret;

/// `PayPal-Transmission-Id`: unique ID of the HTTP transmission; forms the
/// first field of the signed string.
pub(crate) const TRANSMISSION_ID_HEADER: &str = "PayPal-Transmission-Id";

/// `PayPal-Transmission-Time`: RFC 3339 transmission time; forms the second
/// field of the signed string and drives replay protection.
pub(crate) const TRANSMISSION_TIME_HEADER: &str = "PayPal-Transmission-Time";

/// `PayPal-Transmission-Sig`: base64 RSASSA-PKCS1-v1_5 SHA-256 signature.
pub(crate) const TRANSMISSION_SIG_HEADER: &str = "PayPal-Transmission-Sig";

/// `PayPal-Cert-Url`: URL of the X.509 certificate that carries the signing
/// key. Required-but-not-fetched: this crate never performs network I/O
/// (`spec.md` §7), so the caller supplies that certificate via
/// [`VerifyOptions::verifying_material`].
pub(crate) const CERT_URL_HEADER: &str = "PayPal-Cert-Url";

/// `PayPal-Auth-Algo`: the signature algorithm, always `SHA256withRSA` today.
pub(crate) const AUTH_ALGO_HEADER: &str = "PayPal-Auth-Algo";

/// The only [`AUTH_ALGO_HEADER`] value this crate can verify.
const EXPECTED_AUTH_ALGO: &str = "SHA256withRSA";

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    _secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let transmission_id =
        headers
            .get(TRANSMISSION_ID_HEADER)
            .ok_or(VerifyError::MissingHeader {
                header: TRANSMISSION_ID_HEADER,
            })?;
    let transmission_time =
        headers
            .get(TRANSMISSION_TIME_HEADER)
            .ok_or(VerifyError::MissingHeader {
                header: TRANSMISSION_TIME_HEADER,
            })?;
    let signature_value =
        headers
            .get(TRANSMISSION_SIG_HEADER)
            .ok_or(VerifyError::MissingHeader {
                header: TRANSMISSION_SIG_HEADER,
            })?;
    let cert_url = headers
        .get(CERT_URL_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: CERT_URL_HEADER,
        })?;
    let auth_algo = headers
        .get(AUTH_ALGO_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: AUTH_ALGO_HEADER,
        })?;

    // Present-but-empty values fail closed as MalformedHeader ("header is
    // empty"), matching every other limited-value header in this module and
    // the shared malformed-header bar (spec.md §5.5): an empty
    // transmission_id would otherwise surface a guaranteed mismatch as
    // SignatureMismatch, an empty transmission_time would fall through to the
    // timestamp parser as a generic RFC 3339 error, and an empty cert_url
    // would sneak past unvalidated.
    if transmission_id.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: TRANSMISSION_ID_HEADER,
            reason: "header is empty",
        });
    }
    if transmission_time.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: TRANSMISSION_TIME_HEADER,
            reason: "header is empty",
        });
    }
    if cert_url.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: CERT_URL_HEADER,
            reason: "header is empty",
        });
    }

    // The webhook ID is not a header; it is operator configuration. An empty
    // value is misconfiguration too — reject it as MissingContext rather than
    // surfacing the resulting (guaranteed) mismatch as an attack signal,
    // mirroring Square/Twilio's empty-context handling.
    let webhook_id = options
        .webhook_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "PayPal requires VerifyOptions::webhook_id",
        })?;

    let verifying_key = verifying_key(options)?;
    check_auth_algo(auth_algo)?;
    let provided_signature = parse_signature(signature_value)?;
    let timestamp = parse_rfc3339_timestamp(TRANSMISSION_TIME_HEADER, transmission_time)?;

    // Signed string: `{transmission_id}|{transmission_time}|{webhook_id}|
    // {crc32}` — the header substrings verbatim plus the decimal CRC-32 of
    // the raw body bytes (spec.md §3, PayPal row).
    let crc = crate::core::crypto::crc32_body(raw_body);
    let mut message = Vec::with_capacity(
        transmission_id.len() + transmission_time.len() + webhook_id.len() + 16 + 3,
    );
    message.extend_from_slice(transmission_id.as_bytes());
    message.push(b'|');
    message.extend_from_slice(transmission_time.as_bytes());
    message.push(b'|');
    message.extend_from_slice(webhook_id.as_bytes());
    message.push(b'|');
    message.extend_from_slice(crc.to_string().as_bytes());

    match check_rsa_pkcs1v15_sha256(&verifying_key, &message, &provided_signature) {
        RsaSha256Check::Verified => {}
        // Base64 decoded fine but the bytes are not an RSASSA-PKCS1-v1_5
        // signature of the key's length.
        RsaSha256Check::BadSignature => {
            return Err(VerifyError::BadEncoding {
                reason: "signature is not a valid RSASSA-PKCS1-v1_5 signature",
            });
        }
        RsaSha256Check::Mismatch => return Err(VerifyError::SignatureMismatch),
    }

    // `cert_url` is required (fail-closed on a request stripped of it or
    // carrying an empty one) but never fetched or parsed beyond that
    // presence/non-empty check (spec.md §7: no network I/O).
    check_replay(timestamp, options)
}

/// Validates the [`AUTH_ALGO_HEADER`] value: only `SHA256withRSA` is
/// supported, matched case-insensitively. Anything else fails closed.
fn check_auth_algo(value: &str) -> Result<(), VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: AUTH_ALGO_HEADER,
            reason: "header is empty",
        });
    }
    if !value.eq_ignore_ascii_case(EXPECTED_AUTH_ALGO) {
        return Err(VerifyError::MalformedHeader {
            header: AUTH_ALGO_HEADER,
            reason: "unsupported auth algorithm (expected SHA256withRSA)",
        });
    }
    Ok(())
}

/// Pulls the RSA public key out of the caller-supplied
/// [`VerifyingKeyMaterial::X509Certificate`].
fn verifying_key(options: &VerifyOptions) -> Result<rsa::RsaPublicKey, VerifyError> {
    let material = options
        .verifying_material
        .as_ref()
        .ok_or(VerifyError::MissingContext {
            reason: "PayPal requires VerifyOptions::verifying_material",
        })?;
    match material {
        VerifyingKeyMaterial::X509Certificate(cert_bytes) => {
            extract_rsa_pubkey_from_x509(cert_bytes)
        }
        VerifyingKeyMaterial::EcdsaP256PublicKey(_) => Err(VerifyError::InvalidSecret {
            reason: "verifying_material must be X509Certificate for PayPal",
        }),
    }
}

/// Parses the base64-encoded RSA signature header into its raw bytes.
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: TRANSMISSION_SIG_HEADER,
            reason: "header is empty",
        });
    }

    base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| VerifyError::BadEncoding {
            reason: "signature is not valid standard base64",
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_ALGO_HEADER, CERT_URL_HEADER, TRANSMISSION_ID_HEADER, TRANSMISSION_SIG_HEADER,
        TRANSMISSION_TIME_HEADER,
    };
    use crate::core::error::VerifyError;
    use crate::core::options::{VerifyOptions, VerifyingKeyMaterial};
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    use crate::verify;
    use alloc::vec;
    use base64::Engine;
    use std::time::Duration;

    // --- official-construction vector -----------------------------------------
    //
    // Body, transmission ID/time, and webhook ID are PayPal's published
    // "Postback method" example values; the certificate and signature are
    // locally generated over the documented construction (see module docs).

    const TRANSMISSION_ID: &str = "db49fb10-1343-11ef-ac58-e32457403f67";
    const TRANSMISSION_TIME: &str = "2024-05-16T05:19:23Z";
    /// Unix seconds of TRANSMISSION_TIME (2024-05-16T05:19:23Z).
    const TRANSMISSION_TIME_UNIX: u64 = 1_715_836_763;
    const WEBHOOK_ID: &str = "0NH55953DH663215D";
    const CERT_URL: &str = "https://example.invalid/cert-url";
    const SIGNATURE_B64: &str = "aGYe/s6lwrASh2zyTRIAz8Edo705ezMKekirejT08ev3VXdWAkq4JWADiNPUGelx5qrEKxC7mPIHmAwQ5hOT6unhY9n33M/DbXTKGsuITPdXRA7qYVmc2wsIp68BpzB6pC6+5vt/YLQvflsrwrutGa0KyZc5FinuYNN8pTNomv4uiygasWqfnDyKViKQPNZecowag6tY/9pj7+bgBu/joBpYUq0+cQxfGqNnlvywBJ7HCOf4edeTIvM/c1CvvAHGtNTU54kLjWGue640twn6iXPL8tnaABZ8Fr9m0z87v8oY0vBobERV0Yu8thUToKhvQEFF26Rckqy07VVddg1CmA==";
    const CERT_PEM: &[u8] = include_bytes!("../../tests/data/paypal_test_cert.pem");
    const OTHER_CERT_PEM: &[u8] = include_bytes!("../../tests/data/paypal_other_cert.pem");
    const BODY: &[u8] = include_bytes!("../../tests/data/paypal_docs_body.json");
    /// Independent CRC-32 of BODY (Python `zlib.crc32`), decimal.
    const CRC32_DECIMAL: u32 = 1_529_064_350;

    const HEADERS: [(&str, &str); 5] = [
        (TRANSMISSION_ID_HEADER, TRANSMISSION_ID),
        (TRANSMISSION_TIME_HEADER, TRANSMISSION_TIME),
        (TRANSMISSION_SIG_HEADER, SIGNATURE_B64),
        (CERT_URL_HEADER, CERT_URL),
        (AUTH_ALGO_HEADER, "SHA256withRSA"),
    ];

    /// Options providing the caller-supplied PayPal context, "now" pinned to
    /// the vector's transmission time.
    fn vector_options() -> VerifyOptions {
        clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_webhook_id(WEBHOOK_ID)
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()))
    }

    /// Runs `verify()` with the caller-supplied options and a `&[(&str, &str)]`
    /// header list, lifted into the owned pairs the [`crate::HeaderMap`] impl
    /// wants so the test literals stay terse.
    fn verify_vector_with(
        options: VerifyOptions,
        headers: &[(&str, &str)],
    ) -> Result<(), VerifyError> {
        let owned: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        verify(
            crate::Provider::PayPal,
            &owned,
            BODY,
            &Secret::new("unused"),
            options,
        )
    }

    #[test]
    fn vector_verifies() {
        assert_eq!(verify_vector_with(vector_options(), &HEADERS), Ok(()));
    }

    #[test]
    fn secret_argument_is_ignored() {
        // Public-key scheme: any (even pathological) secret is accepted and
        // unused, like SendGrid/Discord.
        let secret = Secret::new("");
        let owned: Vec<(String, String)> = HEADERS
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        assert_eq!(
            verify(
                crate::Provider::PayPal,
                &owned,
                BODY,
                &secret,
                vector_options()
            ),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let lowercase: [(&str, &str); 5] = [
            ("paypal-transmission-id", TRANSMISSION_ID),
            ("paypal-transmission-time", TRANSMISSION_TIME),
            ("paypal-transmission-sig", SIGNATURE_B64),
            ("paypal-cert-url", CERT_URL),
            ("paypal-auth-algo", "SHA256withRSA"),
        ];
        assert_eq!(verify_vector_with(vector_options(), &lowercase), Ok(()));
    }

    // --- negative: signature / key mismatches ---------------------------------

    #[test]
    fn negative_flipped_signature_byte_fails() {
        let mut sig = match base64::engine::general_purpose::STANDARD.decode(SIGNATURE_B64) {
            Ok(bytes) => bytes,
            Err(_) => panic!("test-vector base64 must decode"),
        };
        sig[0] ^= 0x01;
        let tampered = base64::engine::general_purpose::STANDARD.encode(sig);
        let headers = [
            (TRANSMISSION_ID_HEADER, TRANSMISSION_ID),
            (TRANSMISSION_TIME_HEADER, TRANSMISSION_TIME),
            (TRANSMISSION_SIG_HEADER, tampered.as_str()),
            (CERT_URL_HEADER, CERT_URL),
            (AUTH_ALGO_HEADER, "SHA256withRSA"),
        ];
        assert_eq!(
            verify_vector_with(vector_options(), &headers),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn negative_wrong_certificate_fails() {
        // A different (valid) PayPal-style certificate's key cannot verify
        // the signature.
        let options = clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_webhook_id(WEBHOOK_ID)
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(
                OTHER_CERT_PEM.to_vec(),
            ));
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn negative_wrong_webhook_id_fails() {
        // The webhook ID is part of the signed string; a forged one must not
        // verify even with a genuine signature/body.
        let options = clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_webhook_id("A-DIFFERENT-WEBHOOK-ID")
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()));
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::SignatureMismatch)
        );
    }

    // --- tamper: valid signature + modified request ---------------------------

    #[test]
    fn tampered_body_fails() {
        // Change one character in place (`"id"` → `"iD"`): length unchanged,
        // so the failure must come from the signature check.
        let mut body = BODY.to_vec();
        let idx = body
            .windows(4)
            .position(|w| w == b"\"id\"")
            .unwrap_or_else(|| panic!("fixture body must contain a bare id key"))
            + 2;
        body[idx] = body[idx].to_ascii_uppercase();
        assert_ne!(body, BODY);
        let owned: Vec<(String, String)> = HEADERS
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        assert_eq!(
            verify(
                crate::Provider::PayPal,
                &owned,
                &body,
                &Secret::new("unused"),
                vector_options(),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_transmission_id_fails() {
        // The transmission ID is part of the signed string verbatim.
        let headers = [
            (
                TRANSMISSION_ID_HEADER,
                "00000000-0000-0000-0000-000000000000",
            ),
            (TRANSMISSION_TIME_HEADER, TRANSMISSION_TIME),
            (TRANSMISSION_SIG_HEADER, SIGNATURE_B64),
            (CERT_URL_HEADER, CERT_URL),
            (AUTH_ALGO_HEADER, "SHA256withRSA"),
        ];
        assert_eq!(
            verify_vector_with(vector_options(), &headers),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_transmission_time_fails_signature_check() {
        // A forged transmission time alters the signed string, so it must fail
        // the signature check (this is the replay-vector variant: same
        // signature, different timestamp).
        let headers = [
            (TRANSMISSION_ID_HEADER, TRANSMISSION_ID),
            (TRANSMISSION_TIME_HEADER, "2024-05-16T05:19:24Z"),
            (TRANSMISSION_SIG_HEADER, SIGNATURE_B64),
            (CERT_URL_HEADER, CERT_URL),
            (AUTH_ALGO_HEADER, "SHA256withRSA"),
        ];
        assert_eq!(
            verify_vector_with(vector_options(), &headers),
            Err(VerifyError::SignatureMismatch)
        );
    }

    // --- replay protection -----------------------------------------------------

    #[test]
    fn replay_old_transmission_time_out_of_tolerance() {
        let options = clocked_at(TRANSMISSION_TIME_UNIX + 301, Some(Duration::from_secs(300)))
            .with_webhook_id(WEBHOOK_ID)
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()));
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_future_transmission_time_out_of_tolerance() {
        let options = clocked_at(TRANSMISSION_TIME_UNIX - 301, Some(Duration::from_secs(300)))
            .with_webhook_id(WEBHOOK_ID)
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()));
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_within_tolerance_verifies_at_window_edges() {
        for now in [TRANSMISSION_TIME_UNIX - 300, TRANSMISSION_TIME_UNIX + 300] {
            let options = clocked_at(now, Some(Duration::from_secs(300)))
                .with_webhook_id(WEBHOOK_ID)
                .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()));
            assert_eq!(verify_vector_with(options, &HEADERS), Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_transmission_time() {
        let options = clocked_at(TRANSMISSION_TIME_UNIX + 86_400 * 365, None)
            .with_webhook_id(WEBHOOK_ID)
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()));
        assert_eq!(verify_vector_with(options, &HEADERS), Ok(()));
    }

    // --- malformed / missing headers -------------------------------------------

    #[test]
    fn missing_headers_error_distinctly() {
        for (missing, expected) in [
            (
                TRANSMISSION_ID_HEADER,
                VerifyError::MissingHeader {
                    header: TRANSMISSION_ID_HEADER,
                },
            ),
            (
                TRANSMISSION_TIME_HEADER,
                VerifyError::MissingHeader {
                    header: TRANSMISSION_TIME_HEADER,
                },
            ),
            (
                TRANSMISSION_SIG_HEADER,
                VerifyError::MissingHeader {
                    header: TRANSMISSION_SIG_HEADER,
                },
            ),
            (
                CERT_URL_HEADER,
                VerifyError::MissingHeader {
                    header: CERT_URL_HEADER,
                },
            ),
            (
                AUTH_ALGO_HEADER,
                VerifyError::MissingHeader {
                    header: AUTH_ALGO_HEADER,
                },
            ),
        ] {
            let headers: Vec<(&str, &str)> = HEADERS
                .iter()
                .copied()
                .filter(|(name, _)| *name != missing)
                .collect();
            assert_eq!(
                verify_vector_with(vector_options(), &headers),
                Err(expected),
                "missing {missing}"
            );
        }
    }

    #[test]
    fn malformed_signature_header_errors_distinctly() {
        let cases: Vec<(&str, Result<(), VerifyError>)> = vec![
            (
                "",
                Err(VerifyError::MalformedHeader {
                    header: TRANSMISSION_SIG_HEADER,
                    reason: "header is empty",
                }),
            ),
            // Not base64 at all.
            (
                "****not base64****",
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                }),
            ),
            // Incorrect padding for standard base64.
            (
                "QUJDRA",
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                }),
            ),
            // Valid base64 of bytes that are not an RSA signature.
            (
                "3q2+7w==",
                Err(VerifyError::BadEncoding {
                    reason: "signature is not a valid RSASSA-PKCS1-v1_5 signature",
                }),
            ),
        ];

        for (value, expected) in cases {
            let headers = [
                (TRANSMISSION_ID_HEADER, TRANSMISSION_ID),
                (TRANSMISSION_TIME_HEADER, TRANSMISSION_TIME),
                (TRANSMISSION_SIG_HEADER, value),
                (CERT_URL_HEADER, CERT_URL),
                (AUTH_ALGO_HEADER, "SHA256withRSA"),
            ];
            assert_eq!(
                verify_vector_with(vector_options(), &headers),
                expected,
                "input: {value:?}"
            );
        }
    }

    #[test]
    fn malformed_transmission_time_header_errors_distinctly() {
        // An empty value is rejected with the shared "header is empty" reason
        // (spec.md §3: any present-but-empty PayPal header fails closed with
        // that message), not the RFC 3339 parse error.
        let empty = Err(VerifyError::MalformedHeader {
            header: TRANSMISSION_TIME_HEADER,
            reason: "header is empty",
        });
        let malformed_time = Err(VerifyError::MalformedHeader {
            header: TRANSMISSION_TIME_HEADER,
            reason: "timestamp is not a valid RFC 3339 timestamp",
        });
        let cases: Vec<(&str, Result<(), VerifyError>)> = vec![
            ("", empty),
            ("not-a-timestamp", malformed_time),
            ("1715836763", malformed_time),
            ("2024-05-16T25:19:23Z", malformed_time),
            ("2024-05-16T05:19:23+25:00", malformed_time),
        ];

        for (value, expected) in cases {
            let headers = [
                (TRANSMISSION_ID_HEADER, TRANSMISSION_ID),
                (TRANSMISSION_TIME_HEADER, value),
                (TRANSMISSION_SIG_HEADER, SIGNATURE_B64),
                (CERT_URL_HEADER, CERT_URL),
                (AUTH_ALGO_HEADER, "SHA256withRSA"),
            ];
            assert_eq!(
                verify_vector_with(vector_options(), &headers),
                expected,
                "input: {value:?}"
            );
        }
    }

    #[test]
    fn malformed_transmission_id_header_errors_distinctly() {
        let empty = Err(VerifyError::MalformedHeader {
            header: TRANSMISSION_ID_HEADER,
            reason: "header is empty",
        });
        let cases: Vec<(&str, Result<(), VerifyError>)> = vec![
            ("", empty),
            // No defined format to parse — any non-empty value is well-formed
            // and just yields an unverifiable (or verifiable) message, so this
            // is genuinely a SignatureMismatch, not a parse error.
            (
                "***not-a-transmission-id***",
                Err(VerifyError::SignatureMismatch),
            ),
        ];

        for (value, expected) in cases {
            let headers = [
                (TRANSMISSION_ID_HEADER, value),
                (TRANSMISSION_TIME_HEADER, TRANSMISSION_TIME),
                (TRANSMISSION_SIG_HEADER, SIGNATURE_B64),
                (CERT_URL_HEADER, CERT_URL),
                (AUTH_ALGO_HEADER, "SHA256withRSA"),
            ];
            assert_eq!(
                verify_vector_with(vector_options(), &headers),
                expected,
                "input: {value:?}"
            );
        }
    }

    #[test]
    fn malformed_cert_url_header_errors_distinctly() {
        let empty = Err(VerifyError::MalformedHeader {
            header: CERT_URL_HEADER,
            reason: "header is empty",
        });
        let cases: Vec<(&str, Result<(), VerifyError>)> = vec![
            ("", empty),
            // The value is required-but-not-fetched (spec.md §7): it plays no
            // part in the signed string and is never parsed, so any non-empty
            // value is indistinguishable from a real one and the vector still
            // verifies.
            ("***not-a-url***", Ok(())),
        ];

        for (value, expected) in cases {
            let headers = [
                (TRANSMISSION_ID_HEADER, TRANSMISSION_ID),
                (TRANSMISSION_TIME_HEADER, TRANSMISSION_TIME),
                (TRANSMISSION_SIG_HEADER, SIGNATURE_B64),
                (CERT_URL_HEADER, value),
                (AUTH_ALGO_HEADER, "SHA256withRSA"),
            ];
            assert_eq!(
                verify_vector_with(vector_options(), &headers),
                expected,
                "input: {value:?}"
            );
        }
    }

    #[test]
    fn malformed_auth_algo_header_errors_distinctly() {
        let cases: Vec<(&str, Result<(), VerifyError>)> = vec![
            (
                "",
                Err(VerifyError::MalformedHeader {
                    header: AUTH_ALGO_HEADER,
                    reason: "header is empty",
                }),
            ),
            (
                "SHA1withRSA",
                Err(VerifyError::MalformedHeader {
                    header: AUTH_ALGO_HEADER,
                    reason: "unsupported auth algorithm (expected SHA256withRSA)",
                }),
            ),
            (
                "garbage-value",
                Err(VerifyError::MalformedHeader {
                    header: AUTH_ALGO_HEADER,
                    reason: "unsupported auth algorithm (expected SHA256withRSA)",
                }),
            ),
            // Case-insensitive match is accepted: the value changes nothing
            // about the signed string, so a genuine signature still verifies.
            ("sha256withrsa", Ok(())),
        ];

        for (value, expected) in cases {
            let headers = [
                (TRANSMISSION_ID_HEADER, TRANSMISSION_ID),
                (TRANSMISSION_TIME_HEADER, TRANSMISSION_TIME),
                (TRANSMISSION_SIG_HEADER, SIGNATURE_B64),
                (CERT_URL_HEADER, CERT_URL),
                (AUTH_ALGO_HEADER, value),
            ];
            assert_eq!(
                verify_vector_with(vector_options(), &headers),
                expected,
                "input: {value:?}"
            );
        }
    }

    // --- operator context (verifying material / webhook ID) ---------------------

    #[test]
    fn missing_webhook_id_errors_as_missing_context() {
        let options = clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()));
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::MissingContext {
                reason: "PayPal requires VerifyOptions::webhook_id"
            })
        );
    }

    #[test]
    fn empty_webhook_id_errors_as_missing_context() {
        // An explicitly empty webhook ID is operator misconfiguration, not an
        // attack signal: PayPal never signs `{id}|{time}||{crc}`, so without
        // this guard every request would surface as a SignatureMismatch.
        let options = clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(CERT_PEM.to_vec()))
            .with_webhook_id("");
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::MissingContext {
                reason: "PayPal requires VerifyOptions::webhook_id"
            })
        );
    }

    #[test]
    fn missing_verifying_material_errors_as_missing_context() {
        let options = clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_webhook_id(WEBHOOK_ID);
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::MissingContext {
                reason: "PayPal requires VerifyOptions::verifying_material"
            })
        );
    }

    #[test]
    fn wrong_material_variant_errors_as_invalid_secret() {
        // A bare key where a certificate is required is operator
        // misconfiguration, not a forgery.
        let options = clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_webhook_id(WEBHOOK_ID)
            .with_verifying_material(VerifyingKeyMaterial::EcdsaP256PublicKey(vec![
                0x30, 0x59, 0x13,
            ]));
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::InvalidSecret {
                reason: "verifying_material must be X509Certificate for PayPal"
            })
        );
    }

    #[test]
    fn malformed_certificate_errors_as_invalid_secret() {
        let options = clocked_at(TRANSMISSION_TIME_UNIX, Some(Duration::from_secs(300)))
            .with_webhook_id(WEBHOOK_ID)
            .with_verifying_material(VerifyingKeyMaterial::X509Certificate(
                b"definitely not a certificate".to_vec(),
            ));
        assert_eq!(
            verify_vector_with(options, &HEADERS),
            Err(VerifyError::InvalidSecret {
                reason: "certificate is not a valid X.509 certificate"
            })
        );
    }

    #[test]
    fn signed_string_uses_decimal_crc_of_raw_body() {
        // Pins the construction itself rather than only its end-to-end
        // behaviour: the CRC-32 field is the *decimal* rendering of the
        // raw-body checksum (Python-verified constant).
        assert_eq!(crate::core::crypto::crc32_body(BODY), CRC32_DECIMAL);
    }
}
