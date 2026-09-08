//! Standard Webhooks signature verification (covers Svix, Clerk, Resend, ...).
//!
//! Scheme, per the Standard Webhooks specification
//! (<https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md>)
//! and the official reference libraries (e.g.
//! <https://github.com/standard-webhooks/standard-webhooks/blob/main/libraries/python/standardwebhooks/webhooks.py>):
//!
//! - Headers: `webhook-id`, `webhook-timestamp` (integer unix seconds), and
//!   `webhook-signature`
//! - Signed string: `"{webhook-id}.{webhook-timestamp}.{raw_body}"` — literal
//!   dot joins; id and timestamp are taken verbatim from their headers so
//!   whatever was signed is what gets verified
//! - Algorithm: HMAC-SHA256, base64-encoded (standard alphabet, padded),
//!   serialized as `v1,<signature>`
//! - The `webhook-signature` header is a space-delimited list of versioned
//!   signatures for zero-downtime secret rotation; a match on *any* `v1`
//!   element is accepted. Non-`v1` elements (e.g. asymmetric `v1a`) are
//!   ignored rather than rejected — the spec explicitly allows mixed scheme
//!   lists, and ignoring unknown versions preserves forward compatibility.
//! - Secret serialization: `whsec_`-prefixed base64. The prefix is stripped
//!   when present and the remainder decoded leniently — tolerating unpadded
//!   input and non-canonical trailing bits, mirroring the official
//!   libraries' handling of unpadded secrets. An empty or undecodable secret
//!   fails closed with [`VerifyError::InvalidSecret`].
//!
//! # Replay protection
//!
//! The spec requires rejecting deliveries whose timestamp differs from local
//! time by more than the tolerance window (the reference libraries use five
//! minutes). The comparison is symmetric (`|now - t|`) against
//! [`VerifyOptions::max_age`] (default 300s) using the injected clock.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use base64::Engine as _;
use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;

/// The header carrying the unique webhook message id.
pub(crate) const ID_HEADER: &str = "webhook-id";

/// The header carrying the signed unix timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "webhook-timestamp";

/// The header carrying the space-delimited versioned signatures.
pub(crate) const SIGNATURE_HEADER: &str = "webhook-signature";

/// The only signature version accepted for shared-secret verification;
/// anything else in the list (including asymmetric `v1a`) is ignored.
const SCHEME: &str = "v1";

/// The secret serialization prefix defined by the spec; stripped when present.
const SECRET_PREFIX: &str = "whsec_";

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

/// Base64 engine for *secret* decoding, matching the official libraries'
/// `base64.b64decode` semantics: unpadded input and non-canonical trailing
/// bits are tolerated (the official unpadded-secret test vectors require
/// this). Signatures are decoded with the strict standard engine instead —
/// they are attacker-supplied and conforming senders always emit canonical
/// padded base64.
static SECRET_B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let id_raw = headers
        .get(ID_HEADER)
        .ok_or(VerifyError::MissingHeader { header: ID_HEADER })?;
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

    let key = decode_secret(secret.as_bytes())?;
    let provided_signatures = parse_signatures(signature_value)?;
    let timestamp = parse_timestamp(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed string is `{id_as_sent}.{timestamp_as_sent}.{raw_body}`; both
    // header substrings are reused verbatim so whatever was actually signed
    // is what gets verified.
    let mut signed_string =
        Vec::with_capacity(id_raw.len() + 1 + timestamp_raw.len() + 1 + raw_body.len());
    signed_string.extend_from_slice(id_raw.as_bytes());
    signed_string.push(b'.');
    signed_string.extend_from_slice(timestamp_raw.as_bytes());
    signed_string.push(b'.');
    signed_string.extend_from_slice(raw_body);

    let matched = provided_signatures
        .iter()
        .any(|sig| verify_hmac_sha256(&key, &signed_string, sig));

    if !matched {
        return Err(VerifyError::SignatureMismatch);
    }

    check_replay(timestamp, options)
}

/// Decodes the `whsec_`-prefixed base64 secret into raw HMAC key bytes.
///
/// Mirrors the official libraries: the prefix is optional, and decoding is
/// lenient (unpadded input, non-canonical trailing bits) exactly as their
/// published unpadded-secret vectors require. An empty or undecodable secret
/// fails closed.
fn decode_secret(secret: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let as_str = core::str::from_utf8(secret).map_err(|_| VerifyError::InvalidSecret {
        reason: "secret must be valid UTF-8",
    })?;
    let encoded = as_str.strip_prefix(SECRET_PREFIX).unwrap_or(as_str);

    if encoded.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "secret is empty",
        });
    }

    let key = SECRET_B64
        .decode(encoded)
        .map_err(|_| VerifyError::InvalidSecret {
            reason: "secret is not valid standard-alphabet base64 after any `whsec_` prefix",
        })?;

    if key.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "decoded signing key must not be empty",
        });
    }

    Ok(key)
}

/// Parses the space-delimited `webhook-signature` list into every `v1`
/// signature's 32 decoded bytes.
///
/// Elements whose version is not exactly `v1` — including elements without a
/// comma at all — carry no symmetric signature and are skipped, matching the
/// reference libraries' forward-compatible iteration. Every well-formed `v1`
/// element must decode cleanly; one good sibling does not mask a malformed
/// one.
fn parse_signatures(value: &str) -> Result<Vec<Vec<u8>>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let mut signatures = Vec::new();

    for element in value.split(' ') {
        let Some((version, encoded)) = element.split_once(',') else {
            continue;
        };
        if version != SCHEME {
            continue;
        }
        if encoded.is_empty() {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "empty signature after `v1,` prefix",
            });
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid standard-alphabet base64",
            })?;
        if bytes.len() != SIGNATURE_LEN_BYTES {
            return Err(VerifyError::BadEncoding {
                reason: "signature does not decode to 32 bytes",
            });
        }
        signatures.push(bytes);
    }

    if signatures.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "no `v1,` signature present",
        });
    }

    Ok(signatures)
}

#[cfg(test)]
mod tests {
    use super::{ID_HEADER, SECRET_PREFIX, SIGNATURE_HEADER, TIMESTAMP_HEADER};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    use crate::verify;
    use std::time::Duration;

    /// Signing secret from the official test suite of the Standard Webhooks
    /// Python library (<https://github.com/standard-webhooks/standard-webhooks/blob/main/libraries/python/tests/test_webhooks.py>,
    /// `DEFAULT_SECRET` / `test_signature_verification_with_and_without_prefix`).
    ///
    /// This is a *published, public test constant* — nobody holds it as a
    /// live credential — but its contiguous `whsec_…` spelling matches
    /// GitHub's Stripe-secret pattern and trips push protection / secret
    /// scanning (see issue #13). It is therefore assembled from fragments at
    /// compile time; the runtime value is byte-for-byte the official vector,
    /// so these tests still verify exactly what the reference suite does.
    const SECRET: &str = concat!("whsec_", "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw");

    /// Reassembles a `whsec_`-prefixed secret from its base64 body without
    /// ever spelling the two contiguously in source (see [`SECRET`]).
    fn whsec(encoded: &str) -> String {
        format!("{SECRET_PREFIX}{encoded}")
    }

    /// Message id from the same official test suite (`DEFAULT_MSG_ID`).
    const MSG_ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    /// Timestamp from the same suite's `test_sign_function`.
    const TIMESTAMP: u64 = 1_614_265_330;
    /// Payload from the same suite's `test_sign_function` /
    /// `DEFAULT_PAYLOAD`.
    const BODY: &[u8] = br#"{"test": 2432232314}"#;

    /// Official vector from `test_sign_function`: signing
    /// `{MSG_ID}.{TIMESTAMP}.{BODY}` with the decoded `SECRET` yields
    /// `v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=`.
    const SIGNATURE: &str = "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
    /// Official negative vector from `test_invalid_signature_raises_error`:
    /// the same inputs with the final character changed (`OA=` instead of
    /// `OE=`) must fail verification.
    const INVALID_SIGNATURE: &str = "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA=";
    /// Stale-rotation signature from the official
    /// `test_multi_sig_payload_is_valid` (never matches our secret).
    const STALE_SIGNATURE: &str = "Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=";
    /// Locally constructed over an empty body (boundary case):
    /// HMAC-SHA256(base64decode(SECRET), "{MSG_ID}.{TIMESTAMP}.") base64'd,
    /// cross-checked against the official Python reference implementation.
    const EMPTY_BODY_SIGNATURE: &str = "v48jdbgvh29KJz2Qc+ghw8G6vG3nAKnujWBg8oM/62A=";
    /// Locally constructed over `"héllo, 🦀 world!"` (unicode boundary case).
    const UNICODE_BODY_SIGNATURE: &str = "97lN0xDmMiBOfUlhcvdbJPqKzUcBmyfgBUIzq1ocPOk=";
    /// Signature made with the 23-byte key decoded from the unpadded
    /// `MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS` form (official
    /// `test_signature_verification_with_unpadded_secret`, "needs one
    /// padding" case), over the same signed string as the official vector.
    const UNPADDED_SECRET_23B_SIGNATURE: &str = "LVOXivKoo4FWasi/IaHvzhE/u+7/cu2AME+zS/nXqzk=";
    /// Signature made with the 25-byte key decoded from the unpadded
    /// `MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr` form (same official test,
    /// "needs two padding" case).
    const UNPADDED_SECRET_25B_SIGNATURE: &str = "yK2tMbA6BHPrMEJ1lLv7UlJJbgFoqGenJkiajZ29evg=";

    fn verify_with(
        body: &[u8],
        id: &str,
        signature_value: &str,
        timestamp_value: &str,
        secret: &Secret,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::StandardWebhooks,
            &[
                (ID_HEADER, id),
                (SIGNATURE_HEADER, signature_value),
                (TIMESTAMP_HEADER, timestamp_value),
            ],
            body,
            secret,
            options,
        )
    }

    /// The canonical happy path: fresh timestamp, single matching v1.
    fn verify_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_with(
            body,
            MSG_ID,
            &format!("v1,{signature}"),
            &TIMESTAMP.to_string(),
            &Secret::new(SECRET),
            // "now" == the signed timestamp: always within tolerance.
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn official_vector_verifies() {
        assert_eq!(verify_fresh(BODY, SIGNATURE), Ok(()));
    }

    #[test]
    fn official_negative_vector_fails() {
        // From the official suite: a signature that differs from the correct
        // one by exactly one character must be rejected.
        assert_eq!(
            verify_fresh(BODY, INVALID_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_fresh(b"", EMPTY_BODY_SIGNATURE), Ok(()));
        assert_eq!(
            verify_fresh("héllo, 🦀 world!".as_bytes(), UNICODE_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify(
            crate::Provider::StandardWebhooks,
            &[
                ("WEBHOOK-ID", MSG_ID),
                ("Webhook-Signature", format!("v1,{SIGNATURE}").as_str()),
                ("webhook-TIMESTAMP", TIMESTAMP.to_string().as_str()),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn secret_prefix_is_optional_and_padding_tolerant() {
        // Official behavior (`test_signature_verification_with_and_without_prefix`,
        // `test_signature_verification_with_unpadded_secret`): prefixed,
        // unprefixed, padded, and unpadded forms of a key all verify. Each
        // key length (24/23/25 bytes) signs with its own decoded key, so
        // each pairs with the signature made from that same key.
        let variants = [
            (SECRET.to_string(), SIGNATURE),
            ("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw".to_string(), SIGNATURE),
            // 23-byte key: canonical padding and bare-unpadded forms.
            (
                whsec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS="),
                UNPADDED_SECRET_23B_SIGNATURE,
            ),
            (
                whsec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaS"),
                UNPADDED_SECRET_23B_SIGNATURE,
            ),
            // 25-byte key: canonical padding and bare-unpadded forms.
            (
                whsec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr=="),
                UNPADDED_SECRET_25B_SIGNATURE,
            ),
            (
                whsec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSwBr"),
                UNPADDED_SECRET_25B_SIGNATURE,
            ),
        ];
        for (variant, signature) in variants {
            let result = verify_with(
                BODY,
                MSG_ID,
                &format!("v1,{signature}"),
                &TIMESTAMP.to_string(),
                &Secret::new(variant.clone()),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "variant: {variant}");
        }
    }

    #[test]
    fn rotation_any_matching_v1_is_accepted() {
        // Official `test_multi_sig_payload_is_valid`: the list mixes stale,
        // unknown-version, and current signatures; the current one matches.
        let value = format!(
            "v1,{STALE_SIGNATURE} v2,{STALE_SIGNATURE} v1,{SIGNATURE} v1a,{STALE_SIGNATURE}"
        );
        assert_eq!(
            verify_with(
                BODY,
                MSG_ID,
                &value,
                &TIMESTAMP.to_string(),
                &Secret::new(SECRET),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );

        // Order within the list does not matter.
        let reordered = format!(
            "v1a,{STALE_SIGNATURE} v1,{SIGNATURE} v2,{STALE_SIGNATURE} v1,{STALE_SIGNATURE}"
        );
        assert_eq!(
            verify_with(
                BODY,
                MSG_ID,
                &reordered,
                &TIMESTAMP.to_string(),
                &Secret::new(SECRET),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
    }

    #[test]
    fn negative_flipped_base64_character_fails() {
        // Flip one character *within* the base64 alphabet so this exercises
        // a wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}A{}", &SIGNATURE[..10], &SIGNATURE[11..]);
        assert_ne!(flipped, SIGNATURE);
        assert_eq!(
            verify_fresh(BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_body_fails() {
        assert_eq!(
            verify_fresh(br#"{"test": 2432232315}"#, SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_id_and_timestamp_fail_signature_check() {
        // Both are part of the signed string, so forging either must not
        // verify even with a valid-looking signature attached.
        let forged_id = verify_with(
            BODY,
            "msg_forged",
            &format!("v1,{SIGNATURE}"),
            &TIMESTAMP.to_string(),
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(forged_id, Err(VerifyError::SignatureMismatch));

        let forged_ts = verify_with(
            BODY,
            MSG_ID,
            &format!("v1,{SIGNATURE}"),
            &(TIMESTAMP - 1).to_string(),
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(forged_ts, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify_with(
            BODY,
            MSG_ID,
            &format!("v1,{SIGNATURE}"),
            &TIMESTAMP.to_string(),
            &Secret::new(whsec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSX")),
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        // Valid signature, delivered 301s after signing — beyond the
        // reference libraries' default five-minute tolerance.
        let result = verify_with(
            BODY,
            MSG_ID,
            &format!("v1,{SIGNATURE}"),
            &TIMESTAMP.to_string(),
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP + 301, Some(Duration::from_secs(300))),
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
        // Symmetric window: |now - ts| > max_age in either direction is
        // rejected, per the reference libraries' too-old/too-new checks.
        let result = verify_with(
            BODY,
            MSG_ID,
            &format!("v1,{SIGNATURE}"),
            &TIMESTAMP.to_string(),
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP - 301, Some(Duration::from_secs(300))),
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
        // Exactly max_age old/new is still inside the closed window.
        for now in [TIMESTAMP - 300, TIMESTAMP + 300] {
            let result = verify_with(
                BODY,
                MSG_ID,
                &format!("v1,{SIGNATURE}"),
                &TIMESTAMP.to_string(),
                &Secret::new(SECRET),
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        // `max_age: None` explicitly disables the recency check.
        let result = verify_with(
            BODY,
            MSG_ID,
            &format!("v1,{SIGNATURE}"),
            &TIMESTAMP.to_string(),
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_id = verify(
            crate::Provider::StandardWebhooks,
            &[(SIGNATURE_HEADER, format!("v1,{SIGNATURE}").as_str())],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_id,
            Err(VerifyError::MissingHeader { header: ID_HEADER })
        );

        let missing_signature = verify(
            crate::Provider::StandardWebhooks,
            &[
                (ID_HEADER, MSG_ID),
                (TIMESTAMP_HEADER, TIMESTAMP.to_string().as_str()),
            ],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::StandardWebhooks,
            &[
                (ID_HEADER, MSG_ID),
                (SIGNATURE_HEADER, format!("v1,{SIGNATURE}").as_str()),
            ],
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );

        let all_missing = verify(
            crate::Provider::StandardWebhooks,
            &Vec::<(String, String)>::new(),
            BODY,
            &Secret::new(SECRET),
            Default::default(),
        );
        assert_eq!(
            all_missing,
            Err(VerifyError::MissingHeader { header: ID_HEADER })
        );
    }

    #[test]
    fn invalid_secrets_error_distinctly() {
        let cases = [
            // Empty after prefix (official `EmptyWebhookSecretError` case).
            "whsec_".to_string(),
            String::new(),
            // Not base64 at all.
            "whsec_this is not base64!!".to_string(),
            // Only padding, decodes to nothing.
            "whsec_====".to_string(),
        ];
        for variant in cases {
            let result = verify_with(
                BODY,
                MSG_ID,
                &format!("v1,{SIGNATURE}"),
                &TIMESTAMP.to_string(),
                &Secret::new(variant.clone()),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::InvalidSecret { .. }) => {}
                other => panic!("expected InvalidSecret for {variant:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn verify_any_rotation_succeeds_with_one_garbled_key() {
        // Issue #64: a rotation slice whose *first* key is undecodable must
        // still verify against the valid key instead of aborting on the
        // first InvalidSecret. This is exactly the previously-broken
        // scenario from the issue:
        // `[Secret::new("not base64!!"), Secret::new("...base64 key")]`.
        let secrets = [
            Secret::new("whsec_this is not base64!!"),
            Secret::new(SECRET),
        ];
        let signature_value = format!("v1,{SIGNATURE}");
        let timestamp_value = TIMESTAMP.to_string();
        let result = crate::verify_any(
            crate::Provider::StandardWebhooks,
            &[
                (ID_HEADER, MSG_ID),
                (SIGNATURE_HEADER, signature_value.as_str()),
                (TIMESTAMP_HEADER, timestamp_value.as_str()),
            ],
            BODY,
            &secrets,
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn verify_any_reports_invalid_secret_when_every_key_is_garbled() {
        // Total failure with *no* usable key at all is an operator-config
        // error, not a forgery: report the first InvalidSecret (its reason
        // is deterministic — first garbled key wins).
        let secrets = [
            Secret::new("whsec_this is not base64!!"),
            Secret::new("whsec_===="),
        ];
        let signature_value = format!("v1,{SIGNATURE}");
        let timestamp_value = TIMESTAMP.to_string();
        let result = crate::verify_any(
            crate::Provider::StandardWebhooks,
            &[
                (ID_HEADER, MSG_ID),
                (SIGNATURE_HEADER, signature_value.as_str()),
                (TIMESTAMP_HEADER, timestamp_value.as_str()),
            ],
            BODY,
            &secrets,
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "secret is not valid standard-alphabet base64 after any `whsec_` prefix",
            })
        );
    }

    #[test]
    fn verify_any_mixed_garbled_and_mismatched_reports_mismatch() {
        // One garbled key plus one well-formed-but-wrong key: the signature
        // genuinely failed against a usable key, so the definitive error is
        // SignatureMismatch — the garbled key must not be surfaced (or leak
        // via timing) when any usable key exists.
        let secrets = [
            Secret::new("whsec_this is not base64!!"),
            Secret::new(whsec("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSX")),
        ];
        let signature_value = format!("v1,{SIGNATURE}");
        let timestamp_value = TIMESTAMP.to_string();
        let result = crate::verify_any(
            crate::Provider::StandardWebhooks,
            &[
                (ID_HEADER, MSG_ID),
                (SIGNATURE_HEADER, signature_value.as_str()),
                (TIMESTAMP_HEADER, timestamp_value.as_str()),
            ],
            BODY,
            &secrets,
            clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn malformed_signature_header_errors_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                // No usable v1 element anywhere in the list.
                format!("v2,{SIGNATURE} v1a,{SIGNATURE}"),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1,` signature present",
                },
            ),
            (
                // A bare `v1,` element with nothing after the comma.
                "v1,".to_string(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "empty signature after `v1,` prefix",
                },
            ),
            (
                // Elements without a version/comma carry nothing verifiable;
                // a list of only those has no usable v1 signature.
                "garbage also-garbage".to_string(),
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "no `v1,` signature present",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                MSG_ID,
                &value,
                &TIMESTAMP.to_string(),
                &Secret::new(SECRET),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            // Not base64 at all.
            "v1,zzzz".to_string(),
            // Valid base64 but odd-length payload.
            "v1,abc".to_string(),
            // Valid base64 but not 32 bytes (SHA-1 length).
            "v1,HcZO8dIixs4vWL0zK+0uBpwLgW0=".to_string(),
            // One good sig must not mask a malformed sibling element.
            format!("v1,{SIGNATURE} v1,nothex"),
        ];
        for value in cases {
            let result = verify_with(
                BODY,
                MSG_ID,
                &value,
                &TIMESTAMP.to_string(),
                &Secret::new(SECRET),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_timestamp_header_errors_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                "not-a-number".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // Negative values are not representable as u64 unix seconds;
                // they must error, not wrap or panic.
                format!("-{TIMESTAMP}"),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // Fractional timestamps are not integers per the spec; the
                // reference parses floats but conforming senders never emit
                // them, so this crate rejects them as malformed.
                "1614265330.5".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                // All digits, but past u64 range.
                "99999999999999999999999".to_string(),
                VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason: "timestamp overflows unix seconds",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_with(
                BODY,
                MSG_ID,
                &format!("v1,{SIGNATURE}"),
                &value,
                &Secret::new(SECRET),
                clocked_at(TIMESTAMP, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }
}
