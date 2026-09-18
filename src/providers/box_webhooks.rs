//! Box webhook signature verification.
//!
//! Scheme, per Box's official documentation
//! (<https://developer.box.com/guides/webhooks/v2/signatures-v2> "Verify Box
//! webhook signatures") and the reference implementation in Box's Java SDK
//! (the `BoxWebhookSignatureValidator` class and the `WebhookValidationTest`
//! test that pins the byte-exact vectors below,
//! <https://github.com/box/box-java-sdk/blob/main/doc/webhooks.md>):
//!
//! - Headers: `BOX-DELIVERY-TIMESTAMP` (RFC 3339, e.g.
//!   `2020-01-01T00:00:00-07:00`), `BOX-SIGNATURE-PRIMARY`, and
//!   `BOX-SIGNATURE-SECONDARY`. Box sends **two** signatures on every
//!   delivery — one per configured key — so rolling from the primary to the
//!   secondary key needs no downtime: a delivery verifies when **either**
//!   header matches the [`Secret`](crate::core::secret::Secret) the caller
//!   holds. Both headers are required (Box always sends both); an attacker
//!   who knows neither key cannot strip one to dodge a mismatch.
//! - Signed string: `"{raw_body}{delivery_timestamp}"` — the raw body bytes
//!   followed by the delivery timestamp **exactly as it appears in its
//!   header**, with no separators (Box's reference implementation
//!   concatenates the raw body and the timestamp verbatim). The timestamp's
//!   numeric grammar must never be re-serialized into the signed bytes — the
//!   verbatim header substring is what was signed.
//! - Algorithm: HMAC-SHA256, **base64**-encoded (standard alphabet, padded),
//!   carried bare in each header (no `sha256=` prefix). Key: the
//!   primary/secondary webhook signing key as its UTF-8 string bytes,
//!   **not** base64-decoded — Box's reference implementation keys the HMAC
//!   with the key string verbatim.
//!
//! Box also sends `BOX-SIGNATURE-VERSION` (`1`) and
//! `BOX-SIGNATURE-ALGORITHM` (`HmacSHA256`). Neither is required to verify,
//! but when present each must match its documented value or the request is
//! rejected as malformed — Box's reference validator refuses deliveries that
//! declare an unexpected algorithm, and mirroring that strictness here costs
//! nothing.
//!
//! # Replay protection
//!
//! Box signs a timestamp, enabling symmetric replay protection. The signed
//! timestamp is compared symmetrically (`|now - t|`) against
//! [`VerifyOptions::max_age`] (default 300s) using `now` from the injected
//! clock. Box's docs recommend a ten-minute freshness window; the crate's
//! shared default is strictly stronger, and the timestamp is HMAC-covered so
//! an attacker cannot freshen it (`spec.md` §3). Callers wanting Box's
//! prescribed window can match it with
//! `VerifyOptions::with_max_age(Some(Duration::from_secs(600)))`.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_rfc3339_timestamp};
use crate::core::secret::Secret;
use base64::Engine;

/// The header carrying the signed RFC 3339 delivery timestamp.
pub(crate) const TIMESTAMP_HEADER: &str = "BOX-DELIVERY-TIMESTAMP";

/// The header carrying the primary signature.
pub(crate) const PRIMARY_SIGNATURE_HEADER: &str = "BOX-SIGNATURE-PRIMARY";

/// The header carrying the secondary signature.
pub(crate) const SECONDARY_SIGNATURE_HEADER: &str = "BOX-SIGNATURE-SECONDARY";

/// The header declaring the signature-version scheme (`1`).
pub(crate) const SIGNATURE_VERSION_HEADER: &str = "BOX-SIGNATURE-VERSION";

/// The header declaring the signing algorithm (`HmacSHA256`).
pub(crate) const SIGNATURE_ALGORITHM_HEADER: &str = "BOX-SIGNATURE-ALGORITHM";

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let timestamp_raw = headers
        .get(TIMESTAMP_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: TIMESTAMP_HEADER,
        })?;
    let primary_raw = headers
        .get(PRIMARY_SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: PRIMARY_SIGNATURE_HEADER,
        })?;
    let secondary_raw =
        headers
            .get(SECONDARY_SIGNATURE_HEADER)
            .ok_or(VerifyError::MissingHeader {
                header: SECONDARY_SIGNATURE_HEADER,
            })?;

    validate_optional_metadata(headers)?;

    let primary = parse_signature(PRIMARY_SIGNATURE_HEADER, primary_raw)?;
    let secondary = parse_signature(SECONDARY_SIGNATURE_HEADER, secondary_raw)?;
    let timestamp = parse_rfc3339_timestamp(TIMESTAMP_HEADER, timestamp_raw)?;

    // Signed string is `{raw_body}{timestamp_as_sent}`; the timestamp
    // substring is reused verbatim so whatever was actually signed is what
    // gets verified (Box's `payload || deliveryTimestamp` concatenation).
    let mut signed_string = Vec::with_capacity(raw_body.len() + timestamp_raw.len());
    signed_string.extend_from_slice(raw_body);
    signed_string.extend_from_slice(timestamp_raw.as_bytes());

    // Box signs every delivery with both current keys, so the caller's single
    // `Secret` — whichever key it is during a rotation — must match one of the
    // two headers. Both comparisons run, and neither comparison's result
    // depends on the other, so no early exit splits on *how* it fails.
    let primary_ok = verify_hmac_sha256(secret.as_bytes(), &signed_string, &primary);
    let secondary_ok = verify_hmac_sha256(secret.as_bytes(), &signed_string, &secondary);
    if primary_ok || secondary_ok {
        check_replay(timestamp, options)
    } else {
        Err(VerifyError::SignatureMismatch)
    }
}

/// Rejects deliveries that declare an unexpected signature version or
/// algorithm. The headers are optional in Box's scheme, so their *absence* is
/// tolerated; a present-but-wrong value is Box-side misconfiguration and
/// fails closed rather than being silently accepted.
fn validate_optional_metadata(headers: &dyn HeaderMap) -> Result<(), VerifyError> {
    if let Some(version) = headers.get(SIGNATURE_VERSION_HEADER) {
        if version != "1" {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_VERSION_HEADER,
                reason: "BOX-SIGNATURE-VERSION must be `1`",
            });
        }
    }
    if let Some(algorithm) = headers.get(SIGNATURE_ALGORITHM_HEADER) {
        if algorithm != "HmacSHA256" {
            return Err(VerifyError::MalformedHeader {
                header: SIGNATURE_ALGORITHM_HEADER,
                reason: "BOX-SIGNATURE-ALGORITHM must be `HmacSHA256`",
            });
        }
    }
    Ok(())
}

/// Parses one of the `BOX-SIGNATURE-PRIMARY`/`BOX-SIGNATURE-SECONDARY` values
/// into its 32 decoded signature bytes.
///
/// The value carries no `sha256=` prefix — it is bare base64. Every failure
/// mode maps to a distinct error variant so callers can tell malformed-request
/// noise from signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(header: &'static str, value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header,
            reason: "header is empty",
        });
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
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
    use super::{PRIMARY_SIGNATURE_HEADER, SECONDARY_SIGNATURE_HEADER, TIMESTAMP_HEADER};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// The example payload from Box's webhook documentation and the
    /// `WebhookValidationTest` reference test in `box-java-sdk`
    /// (<https://github.com/box/box-java-sdk>, commit
    /// `f64caf5a801b30b336fbf70c4559547fed618b59`, file
    /// `webhooks/src/test/java/com/box/sdk/WebhookValidationTest.java`).
    const BODY: &[u8] = b"{\"type\":\"webhook_event\",\"webhook\":{\"id\":\"1234567890\"},\"trigger\":\"FILE.UPLOADED\",\"source\":{\"id\":\"1234567890\",\"type\":\"file\",\"name\":\"Test.txt\"}}";
    /// The example delivery timestamp from the same reference test, matching
    /// unix seconds `1577862000`. It is signed **verbatim** — including its
    /// `-07:00` offset spelling.
    const TIMESTAMP: &str = "2020-01-01T00:00:00-07:00";
    /// Box's published example signature over `BODY || TIMESTAMP` keyed by the
    /// primary webhook key, asserted verbatim by the reference test. Note the
    /// two secrets the docs *display* on developer.box.com and in the
    /// `webhooks.md` walkthrough (`4py2I9eSFb0ezXH5iPeQRcFK1LRLCdip` /
    /// `Aq5EEEjAu4ssbz8n9UMu7EerI0LKj2TL`) do **not** reproduce it — the
    /// secrets the reference implementation actually keys with are
    /// `SamplePrimaryKey`/`SampleSecondaryKey`, and those both reproduce the
    /// published signatures byte-for-byte (cross-checked with
    /// `openssl dgst -sha256 -hmac <key> -binary | base64`).
    const PRIMARY_SIGNATURE: &str = "6TfeAW3A1PASkgboxxA5yqHNKOwFyMWuEXny/FPD5hI=";
    /// Box's published example signature over the same bytes keyed by the
    /// secondary webhook key.
    const SECONDARY_SIGNATURE: &str = "v+1CD1Jdo3muIcbpv5lxxgPglOqMfsNHPV899xWYydo=";
    const PRIMARY_SECRET: &str = "SamplePrimaryKey";
    const SECONDARY_SECRET: &str = "SampleSecondaryKey";

    /// Signatures over `BODY || TIMESTAMP` for the replay-window boundary
    /// tests. Each is keyed by `PRIMARY_SECRET`, locally constructed with
    /// OpenSSL over the concatenation, mirroring the frozen vector's method:
    /// - `1577861000` (`2019-12-31T23:43:20-07:00`): 1000s before "now".
    /// - `1577861900` (`2019-12-31T23:58:20-07:00`): 100s before "now" —
    ///   inside the default 300s window.
    /// - `1577863000` (`2020-01-01T00:16:40-07:00`): 1000s after "now".
    const OLD_SIGNATURE: &str = "x412KRJe2go9Sw1LPm9Tpxd3FDGpHEM1djdrV2T/bts=";
    const OLD_TIMESTAMP: &str = "2019-12-31T23:43:20-07:00";
    const RECENT_SIGNATURE: &str = "SYkzWDnr4FuDFaXaIZF3bLF3Er+Pn6IlmnFnocxB7f0=";
    const RECENT_TIMESTAMP: &str = "2019-12-31T23:58:20-07:00";
    const FUTURE_SIGNATURE: &str = "ElBf8WEzSxcg0sAC9WNmb37Bi/DVDdW0guu1f1zxDLc=";
    const FUTURE_TIMESTAMP: &str = "2020-01-01T00:16:40-07:00";

    fn box_headers(primary: &str, secondary: &str, timestamp: &str) -> Vec<(String, String)> {
        vec![
            (PRIMARY_SIGNATURE_HEADER.to_string(), primary.to_string()),
            (
                SECONDARY_SIGNATURE_HEADER.to_string(),
                secondary.to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), timestamp.to_string()),
        ]
    }

    fn verify_with(
        body: &[u8],
        primary: &str,
        secondary: &str,
        timestamp: &str,
        secret: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Box,
            &box_headers(primary, secondary, timestamp),
            body,
            &Secret::new(secret),
            options,
        )
    }

    fn verify_fresh(secret: &str) -> Result<(), VerifyError> {
        verify_with(
            BODY,
            PRIMARY_SIGNATURE,
            SECONDARY_SIGNATURE,
            TIMESTAMP,
            secret,
            clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn official_delivery_verifies_with_primary_key() {
        assert_eq!(verify_fresh(PRIMARY_SECRET), Ok(()));
    }

    #[test]
    fn official_delivery_verifies_with_secondary_key() {
        assert_eq!(verify_fresh(SECONDARY_SECRET), Ok(()));
    }

    #[test]
    fn single_signature_header_is_rejected() {
        // A delivery carrying only one of the two signature headers fails
        // closed as incomplete: Box signs every delivery with both current
        // keys, so a lone header is either truncated in transit or stripped by
        // an attacker who knows one key but not the other.
        let with_primary_only = vec![
            (
                PRIMARY_SIGNATURE_HEADER.to_string(),
                PRIMARY_SIGNATURE.to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP.to_string()),
        ];
        assert_eq!(
            verify(
                crate::Provider::Box,
                &with_primary_only,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: SECONDARY_SIGNATURE_HEADER
            })
        );

        let with_secondary_only = vec![
            (
                SECONDARY_SIGNATURE_HEADER.to_string(),
                SECONDARY_SIGNATURE.to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP.to_string()),
        ];
        assert_eq!(
            verify(
                crate::Provider::Box,
                &with_secondary_only,
                BODY,
                &Secret::new(SECONDARY_SECRET),
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: PRIMARY_SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn rejects_wrong_key() {
        assert_eq!(
            verify_fresh("definitely-not-the-webhook-key"),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let mut tampered = BODY.to_vec();
        tampered.push(b' ');
        assert_eq!(
            verify_with(
                &tampered,
                PRIMARY_SIGNATURE,
                SECONDARY_SIGNATURE,
                TIMESTAMP,
                PRIMARY_SECRET,
                clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_re_serialized_timestamp() {
        // `2020-01-01T07:00:00Z` is the *same instant* as `TIMESTAMP`, so a
        // re-serialized timestamp would pass the replay window — but the
        // signed bytes differ, proving the verbatim header substring is what
        // is HMAC-covered (never its numeric re-encoding).
        let headers = vec![
            (
                PRIMARY_SIGNATURE_HEADER.to_string(),
                PRIMARY_SIGNATURE.to_string(),
            ),
            (
                SECONDARY_SIGNATURE_HEADER.to_string(),
                SECONDARY_SIGNATURE.to_string(),
            ),
            (
                TIMESTAMP_HEADER.to_string(),
                "2020-01-01T07:00:00Z".to_string(),
            ),
        ];
        assert_eq!(
            verify(
                crate::Provider::Box,
                &headers,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        // Flip the leading base64 character of the primary signature.
        let flipped = if PRIMARY_SIGNATURE.starts_with('6') {
            "7".to_string() + &PRIMARY_SIGNATURE[1..]
        } else {
            "6".to_string() + &PRIMARY_SIGNATURE[1..]
        };
        assert_eq!(
            verify_with(
                BODY,
                &flipped,
                SECONDARY_SIGNATURE,
                TIMESTAMP,
                PRIMARY_SECRET,
                clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn accepts_recent_timestamp_inside_window() {
        assert_eq!(
            verify_with(
                BODY,
                RECENT_SIGNATURE,
                RECENT_SIGNATURE,
                RECENT_TIMESTAMP,
                PRIMARY_SECRET,
                clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_old_timestamp_outside_window() {
        assert!(
            matches!(
                verify_with(
                    BODY,
                    OLD_SIGNATURE,
                    OLD_SIGNATURE,
                    OLD_TIMESTAMP,
                    PRIMARY_SECRET,
                    clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
                ),
                Err(VerifyError::TimestampOutOfTolerance { .. })
            ),
            "an old signed timestamp must be rejected as out of tolerance"
        );
    }

    #[test]
    fn rejects_future_timestamp_outside_window() {
        // The window is symmetric: a delivery stamped 1000s *after* "now" is
        // just as much a replay/clock-skew signal as one stamped before.
        assert!(
            matches!(
                verify_with(
                    BODY,
                    FUTURE_SIGNATURE,
                    FUTURE_SIGNATURE,
                    FUTURE_TIMESTAMP,
                    PRIMARY_SECRET,
                    clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
                ),
                Err(VerifyError::TimestampOutOfTolerance { .. })
            ),
            "a future signed timestamp must be rejected as out of tolerance"
        );
    }

    #[test]
    fn missing_timestamp_header() {
        let headers = vec![
            (
                PRIMARY_SIGNATURE_HEADER.to_string(),
                PRIMARY_SIGNATURE.to_string(),
            ),
            (
                SECONDARY_SIGNATURE_HEADER.to_string(),
                SECONDARY_SIGNATURE.to_string(),
            ),
        ];
        assert_eq!(
            verify(
                crate::Provider::Box,
                &headers,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );
    }

    #[test]
    fn missing_primary_signature_header() {
        let headers = vec![
            (
                SECONDARY_SIGNATURE_HEADER.to_string(),
                SECONDARY_SIGNATURE.to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP.to_string()),
        ];
        assert_eq!(
            verify(
                crate::Provider::Box,
                &headers,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: PRIMARY_SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn missing_secondary_signature_header() {
        let headers = vec![
            (
                PRIMARY_SIGNATURE_HEADER.to_string(),
                PRIMARY_SIGNATURE.to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP.to_string()),
        ];
        assert_eq!(
            verify(
                crate::Provider::Box,
                &headers,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                Default::default(),
            ),
            Err(VerifyError::MissingHeader {
                header: SECONDARY_SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn empty_signature_is_malformed() {
        assert_eq!(
            verify_with(
                BODY,
                "",
                SECONDARY_SIGNATURE,
                TIMESTAMP,
                PRIMARY_SECRET,
                Default::default(),
            ),
            Err(VerifyError::MalformedHeader {
                header: PRIMARY_SIGNATURE_HEADER,
                reason: "header is empty"
            })
        );
    }

    #[test]
    fn invalid_base64_signature_is_bad_encoding() {
        assert_eq!(
            verify_with(
                BODY,
                "not-base64!!!",
                SECONDARY_SIGNATURE,
                TIMESTAMP,
                PRIMARY_SECRET,
                Default::default(),
            ),
            Err(VerifyError::BadEncoding {
                reason: "signature is not valid standard base64"
            })
        );
    }

    #[test]
    fn wrong_length_base64_signature_is_bad_encoding() {
        // Valid base64 of 16 bytes (half an HMAC-SHA256 digest).
        assert_eq!(
            verify_with(
                BODY,
                "c2lnbmF0dXJlLWxlbmd0aC0xNg==",
                SECONDARY_SIGNATURE,
                TIMESTAMP,
                PRIMARY_SECRET,
                Default::default(),
            ),
            Err(VerifyError::BadEncoding {
                reason: "signature does not decode to 32 bytes"
            })
        );
    }

    #[test]
    fn malformed_timestamp_is_rejected() {
        assert_eq!(
            verify_with(
                BODY,
                PRIMARY_SIGNATURE,
                SECONDARY_SIGNATURE,
                "2020-01-01",
                PRIMARY_SECRET,
                Default::default(),
            ),
            Err(VerifyError::MalformedHeader {
                header: TIMESTAMP_HEADER,
                reason: "timestamp is not a valid RFC 3339 timestamp"
            })
        );
    }

    #[test]
    fn declared_version_and_algorithm_are_validated_when_present() {
        // Modern Box deliveries carry the version/algorithm metadata; the
        // documented values verify fine alongside the byte-exact vectors.
        let good = {
            let mut headers = box_headers(PRIMARY_SIGNATURE, SECONDARY_SIGNATURE, TIMESTAMP);
            headers.push(("BOX-SIGNATURE-VERSION".to_string(), "1".to_string()));
            headers.push((
                "BOX-SIGNATURE-ALGORITHM".to_string(),
                "HmacSHA256".to_string(),
            ));
            headers
        };
        assert_eq!(
            verify(
                crate::Provider::Box,
                &good,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                clocked_at(1_577_862_000, Some(Duration::from_secs(300))),
            ),
            Ok(())
        );

        let bad_version = {
            let mut headers = box_headers(PRIMARY_SIGNATURE, SECONDARY_SIGNATURE, TIMESTAMP);
            headers.push(("BOX-SIGNATURE-VERSION".to_string(), "2".to_string()));
            headers
        };
        assert_eq!(
            verify(
                crate::Provider::Box,
                &bad_version,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                Default::default(),
            ),
            Err(VerifyError::MalformedHeader {
                header: "BOX-SIGNATURE-VERSION",
                reason: "BOX-SIGNATURE-VERSION must be `1`"
            })
        );

        let bad_algorithm = {
            let mut headers = box_headers(PRIMARY_SIGNATURE, SECONDARY_SIGNATURE, TIMESTAMP);
            headers.push((
                "BOX-SIGNATURE-ALGORITHM".to_string(),
                "HmacSHA1".to_string(),
            ));
            headers
        };
        assert_eq!(
            verify(
                crate::Provider::Box,
                &bad_algorithm,
                BODY,
                &Secret::new(PRIMARY_SECRET),
                Default::default(),
            ),
            Err(VerifyError::MalformedHeader {
                header: "BOX-SIGNATURE-ALGORITHM",
                reason: "BOX-SIGNATURE-ALGORITHM must be `HmacSHA256`"
            })
        );
    }
}
