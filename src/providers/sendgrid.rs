//! SendGrid (Twilio) Event Webhook signature verification.
//!
//! # Availability
//!
//! Compiled only with the `sendgrid` crate feature. Without the feature,
//! [`crate::Provider::SendGrid`] keeps its fail-closed
//! [`crate::VerifyError::UnsupportedProvider`] stub.
//!
//! # Scheme
//!
//! Per Twilio's official documentation, "Signature Verification" for the
//! Email Event Webhook
//! (<https://www.twilio.com/docs/sendgrid/for-developers/tracking-events/getting-started-event-webhook-signature-verification>)
//! and its canonical reference implementation `sendgrid-go`
//! `helpers/eventwebhook/eventwebhook.go`
//! (<https://github.com/sendgrid/sendgrid-go/blob/main/helpers/eventwebhook/eventwebhook.go>):
//!
//! - Headers: `X-Twilio-Email-Event-Webhook-Signature` and
//!   `X-Twilio-Email-Event-Webhook-Timestamp` (`<unix_ts>`)
//! - Signed message: the raw timestamp header bytes immediately followed by
//!   the raw request body bytes — `{timestamp}{raw_body}`, no separator. The
//!   message is hashed with SHA-256 and the digest verified as an ECDSA P-256
//!   signature.
//! - Signature encoding: base64 of the ASN.1 DER form of the ECDSA signature,
//!   i.e. a DER `SEQUENCE { INTEGER r, INTEGER s }`.
//! - Key: the "Verification Key" shown in SendGrid's Event Webhook settings
//!   is a base64 encoding of the ECDSA P-256 public key in
//!   `SubjectPublicKeyInfo` DER form (Go decodes it and calls
//!   `x509.ParsePKIXPublicKey`). Callers pass the **decoded DER bytes** (not
//!   the base64 string) via [`crate::VerifyOptions::verifying_material`]:
//!
//!   ```
//!   use base64::Engine as _;
//!   use webhook_verify::{VerifyError, VerifyOptions, VerifyingKeyMaterial};
//!
//!   # fn run() -> Result<(), VerifyError> {
//!   # let dashboard_verification_key =
//!   #     "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE83T4O/n84iotIvIW4mdBgQ/7dAfSmpqIM8kF9mN1flpVKS3GRqe62gw+2fNNRaINXvVpiglSI8eNEc6wEA3F+g==";
//!   let key_der = base64::engine::general_purpose::STANDARD
//!       .decode(dashboard_verification_key)
//!       .map_err(|_| VerifyError::InvalidSecret {
//!           reason: "verifying key is not valid base64",
//!       })?;
//!   let opts = VerifyOptions::default()
//!       .with_verifying_material(VerifyingKeyMaterial::EcdsaP256PublicKey(key_der));
//!   # let _ = opts;
//!   # Ok(())
//!   # }
//!   ```
//!
//! # Security model
//!
//! Like Discord, this scheme uses a *public* key: verification proves the
//! payload was signed by SendGrid's private key, not that the sender shares a
//! secret with you. The [`crate::Secret`] argument is accepted for API
//! uniformity and ignored. The key material is supplied by the caller — this
//! crate never fetches it over the network (`spec.md` §1).
//!
//! # Replay protection
//!
//! Twilio signs a timestamp precisely so receivers can reject stale events.
//! It documents no numeric window, so this crate applies the shared default
//! tolerance ([`crate::VerifyOptions::max_age`], 300s, symmetric `|now - t|`,
//! injectable clock). Callers needing to accept older redelivered events can
//! widen or disable the window explicitly.
//!
//! # Test-vector provenance
//!
//! The primary vector is SendGrid's own (`sendgrid-go`
//! `helpers/eventwebhook/eventwebhook_test.go`): key, signature, and
//! timestamp are reproduced verbatim, and the body is byte-identical to Go's
//! `json.Marshal` output for the canonical event (map keys sorted, no HTML
//! escaping) plus the trailing `\r\n`. The remaining vectors are locally
//! constructed with deterministic seeds, signing exactly the
//! `{timestamp}{body}` construction the official SDK performs.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;
use base64::Engine;

use crate::core::VerifyOptions;
use crate::core::crypto::{EcdsaP256Check, check_ecdsa_p256};
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::options::VerifyingKeyMaterial;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying the base64-encoded DER ECDSA signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Twilio-Email-Event-Webhook-Signature";

/// The header carrying the signed unix timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "X-Twilio-Email-Event-Webhook-Timestamp";

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    _secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let signature_value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;
    let timestamp_raw = headers
        .get(TIMESTAMP_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: TIMESTAMP_HEADER,
        })?;

    let verifying_key = verifying_key(options)?;
    let provided_signature = parse_signature(signature_value)?;
    let timestamp = parse_timestamp(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed message is `{timestamp_as_sent}{raw_body}` verbatim: the raw
    // timestamp substring is reused so whatever was actually signed is what
    // gets hashed.
    let mut message = Vec::with_capacity(timestamp_raw.len() + raw_body.len());
    message.extend_from_slice(timestamp_raw.as_bytes());
    message.extend_from_slice(raw_body);

    match check_ecdsa_p256(verifying_key, &message, &provided_signature) {
        EcdsaP256Check::Verified => {}
        // Config material that the SendGrid scheme cannot use → operator
        // misconfiguration; fail closed and keep the variant distinct so it
        // surfaces in logs.
        EcdsaP256Check::BadKey => {
            return Err(VerifyError::InvalidSecret {
                reason: "verifying key is not a valid ECDSA P-256 public key",
            });
        }
        // Base64 decoded fine, but the bytes are not DER ECDSA → wire error.
        EcdsaP256Check::BadSignature => {
            return Err(VerifyError::BadEncoding {
                reason: "signature is not valid DER-encoded ECDSA",
            });
        }
        EcdsaP256Check::Mismatch => return Err(VerifyError::SignatureMismatch),
    }

    check_replay(timestamp, options)
}

/// Pulls the ECDSA P-256 verifying key out of the caller-supplied
/// [`crate::VerifyOptions::verifying_material`].
fn verifying_key(options: &VerifyOptions) -> Result<&[u8], VerifyError> {
    let material = options
        .verifying_material
        .as_ref()
        .ok_or(VerifyError::MissingContext {
            reason: "SendGrid requires VerifyOptions::verifying_material",
        })?;
    match material {
        VerifyingKeyMaterial::EcdsaP256PublicKey(key) => Ok(key),
        VerifyingKeyMaterial::X509Certificate(_) => Err(VerifyError::InvalidSecret {
            reason: "verifying_material must be EcdsaP256PublicKey for SendGrid",
        }),
    }
}

/// Parses the base64-encoded DER ECDSA signature header into its raw bytes.
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
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
    use super::{SIGNATURE_HEADER, TIMESTAMP_HEADER};
    use crate::core::crypto::{EcdsaP256Check, check_ecdsa_p256};
    use crate::core::error::VerifyError;
    use crate::core::options::{VerifyOptions, VerifyingKeyMaterial};
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use base64::Engine;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use std::time::Duration;

    /// The verification key from the official `sendgrid-go` test
    /// (base64 of the SPKI DER bytes its X.509 parser consumes).
    const OFFICIAL_PUBLIC_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE83T4O/n84iotIvIW4mdBgQ/7dAfSmpqIM8kF9mN1flpVKS3GRqe62gw+2fNNRaINXvVpiglSI8eNEc6wEA3F+g==";

    /// The signature from the same official test (base64 of the DER bytes).
    const OFFICIAL_SIGNATURE_B64: &str = "MEUCIGHQVtGj+Y3LkG9fLcxf3qfI10QysgDWmMOVmxG0u6ZUAiEAyBiXDWzM+uOe5W0JuG+luQAbPIqHh89M15TluLtEZtM=";

    /// The signed timestamp from the same official test.
    const OFFICIAL_TIMESTAMP: &str = "1600112502";

    /// Deterministic seed for locally constructed vectors — fixed constants,
    /// not RNG output, so the vectors are reproducible forever.
    const VECTOR_SEED: [u8; 32] = [
        0x77, 0x65, 0x62, 0x68, 0x6f, 0x6f, 0x6b, 0x2d, 0x76, 0x65, 0x72, 0x69, 0x66, 0x79, 0x2d,
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2d, 0x30, 0x30, 0x30,
        0x32, 0x34,
    ];

    /// The body of the official test: Go computes it with `json.Marshal` over
    /// the canonical event map (keys sorted, no HTML escaping), 325 bytes,
    /// then appends `\r\n` (327 bytes total). Byte-exact reproduction.
    fn official_body() -> Vec<u8> {
        let mut body: Vec<u8> = br#"[{"email":"hello@world.com","event":"dropped","reason":"Bounced Address","sg_event_id":"ZHJvcC0xMDk5NDkxOS1MUnpYbF9OSFN0T0doUTRrb2ZTbV9BLTA","sg_message_id":"LRzXl_NHStOGhQ4kofSm_A.filterdrecv-p3mdw1-756b745b58-kmzbl-18-5F5FC76C-9.0","smtp-id":"<LRzXl_NHStOGhQ4kofSm_A@ismtpd0039p1iad1.sendgrid.net>","timestamp":1600112492}]"#
            .to_vec();
        body.push(b'\r');
        body.push(b'\n');
        body
    }

    /// Test-only panicking helpers: these operate on compile-time constants
    /// and locally generated keys, so failure means a broken test fixture,
    /// not an attacker-controlled input.
    fn b64_decode(value: &str) -> Vec<u8> {
        match base64::engine::general_purpose::STANDARD.decode(value) {
            Ok(bytes) => bytes,
            Err(_) => panic!("test-vector base64 must decode"),
        }
    }

    /// Signs `{timestamp}{body}` with the deterministic seed exactly as the
    /// official SDK and returns `(spki_der_key, base64_der_signature)`.
    fn sign_locally(timestamp: &str, body: &[u8]) -> (Vec<u8>, String) {
        let signing_key: p256::ecdsa::SigningKey = match SigningKey::from_slice(&VECTOR_SEED) {
            Ok(key) => key,
            Err(_) => panic!("VECTOR_SEED must be a valid nonzero scalar"),
        };
        let mut message = Vec::with_capacity(timestamp.len() + body.len());
        message.extend_from_slice(timestamp.as_bytes());
        message.extend_from_slice(body);
        let signature: p256::ecdsa::Signature = signing_key.sign(&message);
        (
            spki_of(signing_key.verifying_key()),
            b64_encode(signature.to_der().as_ref()),
        )
    }

    /// The `SubjectPublicKeyInfo` DER prefix for an ECDSA P-256 key: SEQUENCE
    /// of { AlgorithmIdentifier (id-ecPublicKey, prime256v1), BIT STRING }
    /// whose payload is the 65-byte uncompressed point. The prefix up to the
    /// point is fixed for this curve and equivalent to what the official key
    /// decodes to (see `spki_header_matches_official_key`).
    const P256_SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    fn spki_of(verifying_key: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
        let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + 65);
        spki.extend_from_slice(P256_SPKI_PREFIX);
        spki.extend_from_slice(verifying_key.to_sec1_point(false).as_bytes());
        spki
    }

    #[test]
    fn spki_header_matches_official_key() {
        // Guards the hand-rolled P256_SPKI_PREFIX: the official verification
        // key decodes to exactly `prefix || 65-byte point`, so if the prefix
        // ever drifts from the canonical shape the crypto path it feeds is
        // itself suspect. (This test failing is a fixture bug, not a
        // verification weakness — verification only *parses* SPKI.)
        let official = b64_decode(OFFICIAL_PUBLIC_KEY_B64);
        assert!(official.starts_with(P256_SPKI_PREFIX));
        assert_eq!(official.len(), P256_SPKI_PREFIX.len() + 65);
    }

    fn b64_encode(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn official_key_der() -> Vec<u8> {
        b64_decode(OFFICIAL_PUBLIC_KEY_B64)
    }

    /// Verifies the *official* key/body with an arbitrary signature/timestamp
    /// header, "now" pinned to the official timestamp.
    fn verify_official(signature: &str, timestamp: &str, body: &[u8]) -> Result<(), VerifyError> {
        verify(
            crate::Provider::SendGrid,
            &[(SIGNATURE_HEADER, signature), (TIMESTAMP_HEADER, timestamp)],
            body,
            &Secret::new("ignored"),
            clocked_at(1_600_112_502, Some(Duration::from_secs(300))).with_verifying_material(
                VerifyingKeyMaterial::EcdsaP256PublicKey(official_key_der()),
            ),
        )
    }

    fn verify_with(
        body: &[u8],
        material: VerifyingKeyMaterial,
        signature_value: &str,
        timestamp_value: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::SendGrid,
            &[
                (SIGNATURE_HEADER, signature_value),
                (TIMESTAMP_HEADER, timestamp_value),
            ],
            body,
            &Secret::new("ignored"),
            options.with_verifying_material(material),
        )
    }

    fn verify_fresh(
        body: &[u8],
        key_der: Vec<u8>,
        signature: &str,
        timestamp: u64,
    ) -> Result<(), VerifyError> {
        verify_with(
            body,
            VerifyingKeyMaterial::EcdsaP256PublicKey(key_der),
            signature,
            &timestamp.to_string(),
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn official_vector_verifies() {
        // The provider's own test vector, fed through the full `verify()`.
        assert_eq!(
            verify_official(OFFICIAL_SIGNATURE_B64, OFFICIAL_TIMESTAMP, &official_body()),
            Ok(())
        );
    }

    #[test]
    fn boundary_bodies_verify() {
        let timestamp = 1_758_600_000;

        // Empty body (boundary case): `{timestamp}` alone is signed.
        let (key, empty_sig) = sign_locally(&timestamp.to_string(), b"");
        assert_eq!(verify_fresh(b"", key, &empty_sig, timestamp), Ok(()));

        // Unicode body (boundary case): signed over raw UTF-8 bytes.
        let unicode_body = "héllo, 🦀 world!".as_bytes();
        let (key, unicode_sig) = sign_locally(&timestamp.to_string(), unicode_body);
        assert_eq!(
            verify_fresh(unicode_body, key, &unicode_sig, timestamp),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let body = b"{}";
        let timestamp = 1_758_600_001;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);
        let result = verify(
            crate::Provider::SendGrid,
            &[
                ("x-twilio-email-event-webhook-signature", sig.as_str()),
                (
                    "X-TWILIO-EMAIL-EVENT-WEBHOOK-TIMESTAMP",
                    timestamp.to_string().as_str(),
                ),
            ],
            body,
            &Secret::new("ignored"),
            clocked_at(timestamp, Some(Duration::from_secs(300)))
                .with_verifying_material(VerifyingKeyMaterial::EcdsaP256PublicKey(key_der)),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Official vector, exactly one byte flipped. The DER signature is
        // `SEQUENCE { INTEGER r, INTEGER s }`; flipping `s`'s second content
        // byte (index 39, 0xc8 → 0xc9) keeps the MSB of the scalar set, so
        // the result stays canonical DER and the scalar stays below the curve
        // order — exercising a wrong-but-well-formed signature →
        // SignatureMismatch (not a decode error). index 38 (0x00) must not be
        // flipped to a small value: that would clear the MSB and make the DER
        // non-canonical, which is a *different* failure mode (BadEncoding).
        let mut sig_der = b64_decode(OFFICIAL_SIGNATURE_B64);
        assert_eq!(sig_der[37], 0x21); // s INTEGER length tag follows
        assert_eq!(sig_der[38], 0x00); // s requires the 33-byte leading zero
        assert_eq!(sig_der[39], 0xc8); // s's MSB is set after the leading byte
        sig_der[39] = 0xc9;
        let tampered = b64_encode(&sig_der);
        assert_ne!(tampered, OFFICIAL_SIGNATURE_B64);
        assert_eq!(
            verify_official(&tampered, OFFICIAL_TIMESTAMP, &official_body()),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn negative_tampered_body_fails() {
        let body = official_body();
        // Change one character in place (`"email"` → `"emAil"`) so the length
        // is unchanged and the failure must come from the signature check.
        let mut tampered = body.clone();
        tampered[5] = tampered[5].to_ascii_uppercase();
        assert_ne!(tampered, body);
        assert_eq!(
            verify_official(OFFICIAL_SIGNATURE_B64, OFFICIAL_TIMESTAMP, &tampered),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn negative_tampered_timestamp_fails_signature_check() {
        let body = b"{}";
        let timestamp = 1_758_600_002;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);

        // The timestamp is part of the signed message, so a forged timestamp
        // must not verify even with a valid signature for the real one.
        let result = verify_with(
            body,
            VerifyingKeyMaterial::EcdsaP256PublicKey(key_der),
            &sig,
            &(timestamp - 1).to_string(),
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn negative_wrong_key_fails() {
        let body = b"{}";
        let timestamp = 1_758_600_003;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);
        let other_seed = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let other_key = match SigningKey::from_slice(&other_seed) {
            Ok(key) => spki_of(key.verifying_key()),
            Err(_) => panic!("other_seed must be a valid scalar"),
        };
        assert_ne!(other_key, key_der);
        assert_eq!(
            verify_fresh(body, other_key, &sig, timestamp),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let body = b"{}";
        let timestamp = 1_758_600_004;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);
        // Valid signature, delivered 301s after signing.
        let result = verify_with(
            body,
            VerifyingKeyMaterial::EcdsaP256PublicKey(key_der),
            &sig,
            &timestamp.to_string(),
            clocked_at(timestamp + 301, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_future_timestamp_out_of_tolerance() {
        let body = b"{}";
        let timestamp = 1_758_600_005;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);
        // Symmetric window: |now - ts| > max_age in either direction.
        let result = verify_with(
            body,
            VerifyingKeyMaterial::EcdsaP256PublicKey(key_der),
            &sig,
            &timestamp.to_string(),
            clocked_at(timestamp - 301, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn replay_within_tolerance_verifies_at_window_edges() {
        let body = b"{}";
        let timestamp = 1_758_600_006;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);
        for now in [timestamp - 300, timestamp + 300] {
            let result = verify_with(
                body,
                VerifyingKeyMaterial::EcdsaP256PublicKey(key_der.clone()),
                &sig,
                &timestamp.to_string(),
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let body = b"{}";
        let timestamp = 1_758_600_007;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);
        // `max_age: None` explicitly disables the recency check.
        let result = verify_with(
            body,
            VerifyingKeyMaterial::EcdsaP256PublicKey(key_der),
            &sig,
            &timestamp.to_string(),
            clocked_at(timestamp + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let material = VerifyingKeyMaterial::EcdsaP256PublicKey(official_key_der());
        let base_options = clocked_at(1_600_112_502, Some(Duration::from_secs(300)));

        let missing_signature = verify(
            crate::Provider::SendGrid,
            &[(TIMESTAMP_HEADER, OFFICIAL_TIMESTAMP)],
            b"{}",
            &Secret::new("ignored"),
            base_options
                .clone()
                .with_verifying_material(material.clone()),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::SendGrid,
            &[(SIGNATURE_HEADER, OFFICIAL_SIGNATURE_B64)],
            b"{}",
            &Secret::new("ignored"),
            base_options
                .clone()
                .with_verifying_material(material.clone()),
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );

        let both_missing = verify(
            crate::Provider::SendGrid,
            &Vec::<(String, String)>::new(),
            b"{}",
            &Secret::new("ignored"),
            base_options.with_verifying_material(material),
        );
        assert_eq!(
            both_missing,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_signature_header_errors_distinctly() {
        let key_der = official_key_der();
        let body = official_body();
        let cases: Vec<(String, Result<(), VerifyError>)> = vec![
            (
                String::new(),
                Err(VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                }),
            ),
            // Not base64 at all.
            (
                "****not base64****".to_string(),
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                }),
            ),
            // Incorrect padding for standard base64.
            (
                "MEUCIQD".to_string(),
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid standard base64",
                }),
            ),
            // Valid base64 of bytes that are not DER ECDSA.
            (
                b64_encode(&[0xde, 0xad, 0xbe, 0xef]),
                Err(VerifyError::BadEncoding {
                    reason: "signature is not valid DER-encoded ECDSA",
                }),
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                &body[..],
                VerifyingKeyMaterial::EcdsaP256PublicKey(key_der.clone()),
                &value,
                OFFICIAL_TIMESTAMP,
                clocked_at(1_600_112_502, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, expected, "input: {value:?}");
        }
    }

    #[test]
    fn malformed_timestamp_header_errors_distinctly() {
        let key_der = official_key_der();
        let cases: Vec<(String, Result<(), VerifyError>)> = vec![
            (
                String::new(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "header is empty",
                }),
            ),
            (
                "not-a-number".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                }),
            ),
            (
                // Negative values are not representable as u64 unix seconds.
                "-1600112502".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                }),
            ),
            (
                // All digits, but past u64 range.
                "99999999999999999999999".to_string(),
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp overflows unix seconds",
                }),
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                &b"{}"[..],
                VerifyingKeyMaterial::EcdsaP256PublicKey(key_der.clone()),
                OFFICIAL_SIGNATURE_B64,
                &value,
                clocked_at(1_600_112_502, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, expected, "input: {value:?}");
        }
    }

    #[test]
    fn missing_or_wrong_material_errors_distinctly() {
        let body = b"{}";
        let timestamp = 1_758_600_008;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);

        // Wrong variant: an X.509 certificate where a bare key is required.
        let wrong_variant = verify_with(
            body,
            VerifyingKeyMaterial::X509Certificate(key_der.clone()),
            &sig,
            &timestamp.to_string(),
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            wrong_variant,
            Err(VerifyError::InvalidSecret {
                reason: "verifying_material must be EcdsaP256PublicKey for SendGrid"
            })
        );

        // Missing material entirely → operator misconfiguration, fail closed.
        let missing_material = verify(
            crate::Provider::SendGrid,
            &[
                (SIGNATURE_HEADER, sig.as_str()),
                (TIMESTAMP_HEADER, timestamp.to_string().as_str()),
            ],
            body,
            &Secret::new("ignored"),
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            missing_material,
            Err(VerifyError::MissingContext {
                reason: "SendGrid requires VerifyOptions::verifying_material"
            })
        );

        // Malformed material: not parseable as SPKI.
        let garbage_key = verify_with(
            body,
            VerifyingKeyMaterial::EcdsaP256PublicKey(vec![0xde, 0xad, 0xbe, 0xef]),
            &sig,
            &timestamp.to_string(),
            clocked_at(timestamp, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            garbage_key,
            Err(VerifyError::InvalidSecret {
                reason: "verifying key is not a valid ECDSA P-256 public key"
            })
        );
    }

    #[test]
    fn crypto_helper_classifies_errors() {
        let body = b"{}";
        let timestamp = 1_758_600_009;
        let (key_der, sig) = sign_locally(&timestamp.to_string(), body);
        let sig_der = b64_decode(&sig);
        let mut message = Vec::with_capacity(timestamp.to_string().len() + body.len());
        message.extend_from_slice(timestamp.to_string().as_bytes());
        message.extend_from_slice(body);

        assert_eq!(
            check_ecdsa_p256(&key_der, &message, &sig_der),
            EcdsaP256Check::Verified
        );
        // Garbage key, valid signature bytes.
        assert_eq!(
            check_ecdsa_p256(b"not a key", &message, &sig_der),
            EcdsaP256Check::BadKey
        );
        // Garbage signature bytes, valid key.
        assert_eq!(
            check_ecdsa_p256(&key_der, &message, b"not a signature"),
            EcdsaP256Check::BadSignature
        );
        // Mismatch: valid key + valid DER signature over a different message.
        let mut wrong = message.clone();
        wrong.push(b'x');
        assert_eq!(
            check_ecdsa_p256(&key_der, &wrong, &sig_der),
            EcdsaP256Check::Mismatch
        );
    }
}
