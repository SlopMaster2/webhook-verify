//! User-configurable HMAC schemes ([`CustomScheme`], `spec.md` §2.2).
//!
//! Lets callers verify a long-tail provider (or an internal sender) without
//! waiting on a crate release, by describing the scheme declaratively:
//! hash algorithm, signature header, encoding, optional prefix, optional
//! timestamp header for replay protection, and a function building the
//! signed string.
//!
//! # Security model
//!
//! Custom schemes get exactly the same guarantees as built-in providers:
//! HMAC construction and constant-time comparison run through the audited
//! helpers in [`crate::core::crypto`]; parsing paths fail closed with
//! structured errors instead of panicking. What is *not* covered is choosing
//! the scheme itself — a mis-described scheme (e.g. signing a re-serialized
//! body instead of raw bytes) will verify nothing useful. Configure
//! `signed_string` to reproduce the provider's documented recipe exactly.
//! `signed_string` is a plain `fn`, so it cannot capture values from its
//! environment; if the scheme signs request context (such as a URL), read it
//! out of `headers` inside the function — for
//! [`VerifyOptions::request_url`] contents, construct your scheme headers to
//! carry the URL.
//!
//! # Example
//!
//! ```
//! use webhook_verify::{verify, CustomScheme, Encoding, HashAlg, Provider, Secret};
//!
//! // A fictional provider that signs the raw body with HMAC-SHA256 and
//! // sends it hex-encoded in `X-Webhook-Sig`.
//! let scheme = CustomScheme {
//!     hash: HashAlg::Sha256,
//!     signature_header: "X-Webhook-Sig",
//!     timestamp_header: None,
//!     encoding: Encoding::Hex,
//!     prefix: None,
//!     signed_string: |_headers, raw_body| raw_body.to_vec(),
//! };
//!
//! let result = verify(
//!     Provider::Custom(scheme),
//!     &[("X-Webhook-Sig", "0e7320e558b4421b7aa464a9027132b7176c02adf16ed36778ce302d6f2a6ac3")],
//!     b"payload",
//!     &Secret::new("shared-secret"),
//!     Default::default(),
//! );
//!
//! assert!(result.is_ok());
//! ```

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;
use core::fmt;

use crate::core::VerifyOptions;
use crate::core::crypto::{verify_hmac_sha1, verify_hmac_sha256, verify_hmac_sha512};
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_timestamp};
use crate::core::secret::Secret;
use base64::Engine;

/// HMAC hash algorithms available to a [`CustomScheme`] (`spec.md` §2.2).
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlg {
    /// HMAC-SHA256; 32-byte digest.
    Sha256,
    /// HMAC-SHA1; 20-byte digest. As Twilio's docs note, HMAC construction
    /// is not affected by SHA-1 collision attacks given a secret key — but
    /// prefer SHA-256 unless the sender's scheme mandates SHA-1.
    Sha1,
    /// HMAC-SHA512; 64-byte digest.
    Sha512,
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlg::Sha256 => f.write_str("SHA-256"),
            HashAlg::Sha1 => f.write_str("SHA-1"),
            HashAlg::Sha512 => f.write_str("SHA-512"),
        }
    }
}

impl HashAlg {
    /// Digest output length in bytes; decoded signatures must match it.
    fn digest_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha1 => 20,
            HashAlg::Sha512 => 64,
        }
    }
}

/// Wire encoding of the signature in its header (`spec.md` §2.2).
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Lower/uppercase hexadecimal (both accepted by the decoder).
    Hex,
    /// Standard base64 alphabet with padding.
    Base64,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Encoding::Hex => f.write_str("hex"),
            Encoding::Base64 => f.write_str("base64"),
        }
    }
}

/// A user-configured HMAC verification scheme for providers not yet built in
/// (`spec.md` §2.2). Also the prototyping shape new built-in providers are
/// implemented against before promotion into the [`Provider`](crate::Provider)
/// enum.
///
/// All comparisons are constant-time and all decoding fails closed, exactly
/// as for built-in providers.
///
/// [`PartialEq`] compares the declarative configuration only; `signed_string`
/// is excluded — function pointers have no meaningful or reliable equality.
#[must_use]
#[derive(Debug, Clone, Copy)]
pub struct CustomScheme {
    /// HMAC hash algorithm the sender uses.
    pub hash: HashAlg,
    /// Name of the header carrying the encoded signature.
    pub signature_header: &'static str,
    /// Name of the header carrying the unix-seconds timestamp, when the
    /// sender signs one. Setting this enables replay protection with the
    /// shared symmetric tolerance (`|now - t| <= max_age`, default 300s);
    /// leaving it `None` disables replay checks for this scheme, mirroring
    /// built-ins like GitHub whose schemes sign no timestamp.
    pub timestamp_header: Option<&'static str>,
    /// Encoding of the signature value in its header.
    pub encoding: Encoding,
    /// Literal prefix required before the encoded signature (e.g. `"v0="`
    /// or `"sha256="`). When set, a header not starting with it is rejected
    /// as malformed rather than leniently accepted — prevents downgrade
    /// confusion between scheme versions.
    pub prefix: Option<&'static str>,
    /// Builds the exact byte string the sender HMACs, from the request
    /// headers and the **raw** body bytes. Read any additional signed inputs
    /// (timestamps, URL context) out of `headers`; never re-serialize or
    /// normalize `raw_body`.
    pub signed_string: fn(&dyn HeaderMap, &[u8]) -> Vec<u8>,
}

impl PartialEq for CustomScheme {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.signature_header == other.signature_header
            && self.timestamp_header == other.timestamp_header
            && self.encoding == other.encoding
            && self.prefix == other.prefix
    }
}

impl Eq for CustomScheme {}

impl core::hash::Hash for CustomScheme {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
        self.signature_header.hash(state);
        self.timestamp_header.hash(state);
        self.encoding.hash(state);
        self.prefix.hash(state);
    }
}

pub(crate) fn verify(
    scheme: &CustomScheme,
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let signature_value =
        headers
            .get(scheme.signature_header)
            .ok_or(VerifyError::MissingHeader {
                header: scheme.signature_header,
            })?;

    // The timestamp header is fetched up front so a missing one is reported
    // as such even when the signature would also have failed — matching how
    // built-in timestamped schemes report. Its value is parsed after the
    // signature, same parse order as the built-ins.
    let timestamp_raw = match scheme.timestamp_header {
        Some(timestamp_header) => Some((
            timestamp_header,
            headers
                .get(timestamp_header)
                .ok_or(VerifyError::MissingHeader {
                    header: timestamp_header,
                })?,
        )),
        None => None,
    };

    let provided_signature = parse_signature(scheme, signature_value)?;

    let timestamp = match timestamp_raw {
        Some((timestamp_header, raw)) => Some(parse_timestamp(timestamp_header, raw)?),
        None => None,
    };

    let signed_string = (scheme.signed_string)(headers, raw_body);

    let matched = match scheme.hash {
        HashAlg::Sha256 => {
            verify_hmac_sha256(secret.as_bytes(), &signed_string, &provided_signature)
        }
        HashAlg::Sha1 => verify_hmac_sha1(secret.as_bytes(), &signed_string, &provided_signature),
        HashAlg::Sha512 => {
            verify_hmac_sha512(secret.as_bytes(), &signed_string, &provided_signature)
        }
    };

    if !matched {
        return Err(VerifyError::SignatureMismatch);
    }

    if let Some(timestamp) = timestamp {
        check_replay(timestamp, options)?;
    }

    Ok(())
}

/// Decodes the signature header value per the scheme's prefix and encoding.
fn parse_signature(scheme: &CustomScheme, value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: scheme.signature_header,
            reason: "header is empty",
        });
    }

    let encoded = match scheme.prefix {
        Some(prefix) => value
            .strip_prefix(prefix)
            .ok_or(VerifyError::MalformedHeader {
                header: scheme.signature_header,
                reason: "signature does not start with the configured scheme prefix",
            })?,
        None => value,
    };

    if encoded.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: scheme.signature_header,
            reason: "empty signature after prefix",
        });
    }

    let bytes = match scheme.encoding {
        Encoding::Hex => hex::decode(encoded).map_err(|_| VerifyError::BadEncoding {
            reason: "signature is not valid hexadecimal",
        })?,
        Encoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid base64",
            })?,
    };

    if bytes.len() != scheme.hash.digest_len() {
        return Err(VerifyError::BadEncoding {
            reason: "signature length does not match the hash algorithm's digest size",
        });
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{CustomScheme, Encoding, HashAlg};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::providers::Provider;
    use crate::test_helpers::clocked_at;
    use crate::verify;
    use std::time::Duration;

    /// Signing secret from the worked example in Slack's official docs
    /// (<https://docs.slack.dev/authentication/verifying-requests-from-slack>);
    /// also the anchor vector proving `CustomScheme` can express a real
    /// documented scheme bit-for-bit.
    const SLACK_SECRET: &str = "8f742231b10e8888abcd99yyyzzz85a5";
    /// Raw body from the same worked example.
    const SLACK_BODY: &[u8] = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    const SLACK_TIMESTAMP: u64 = 1_531_420_618;
    /// Official published signature for that example:
    /// `v0=a2114d57...` (Slack docs, same URL as above).
    const SLACK_SIGNATURE: &str =
        "a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";

    /// Key/data of RFC 4231 test case 2 (HMAC-SHA256/SHA512) and RFC 2202
    /// test case 2 (HMAC-SHA1); digests below cross-checked locally against
    /// those RFCs and re-encoded to base64 with `base64(1)` semantics.
    const RFC_KEY: &str = "Jefe";
    const RFC_DATA: &[u8] = b"what do ya want for nothing?";

    /// A fictional sender signing `"{timestamp}.{raw_body}"` with
    /// HMAC-SHA256, hex-encoded behind a `sha256=` prefix, timestamp in its
    /// own header. Locally constructed deterministic vectors.
    mod ts_scheme {
        pub const SECRET: &str = "custom_shared_secret";
        pub const HEADER: &str = "X-Example-Signature";
        pub const TS_HEADER: &str = "X-Example-Timestamp";
        pub const TIMESTAMP: u64 = 1_700_000_000;
        pub const PING_BODY: &[u8] = b"{\"event\":\"ping\"}";
        /// HMAC-SHA256 over `1700000000.{PING_BODY}`.
        pub const PING_SIG: &str =
            "9db1e644e50830b54efa1992679fb889d28ae7d6e4474cb4ca27e867091021f8";
        /// Over an empty body (boundary case).
        pub const EMPTY_BODY_SIG: &str =
            "e859e71951a27e39c00f05e1cdb40c1b0d13171f43f635f10e5ccab222b3e67b";
        /// Over `"héllo, 🦀 world!"` (unicode boundary case).
        pub const UNICODE_BODY_SIG: &str =
            "a651431edb322282434426d3e5bbb1c39eadd68e32d68e7604b28f3deee73791";
    }

    fn ts_signed_string(headers: &dyn crate::HeaderMap, raw_body: &[u8]) -> Vec<u8> {
        let ts = headers.get(ts_scheme::TS_HEADER).unwrap_or_default();
        let mut signed = Vec::with_capacity(ts.len() + 1 + raw_body.len());
        signed.extend_from_slice(ts.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(raw_body);
        signed
    }

    fn ts_scheme_config() -> CustomScheme {
        CustomScheme {
            hash: HashAlg::Sha256,
            signature_header: ts_scheme::HEADER,
            timestamp_header: Some(ts_scheme::TS_HEADER),
            encoding: Encoding::Hex,
            prefix: Some("sha256="),
            signed_string: ts_signed_string,
        }
    }

    fn verify_custom(
        scheme: &CustomScheme,
        headers: &dyn crate::HeaderMap,
        body: &[u8],
        secret: &str,
        options: VerifyOptions,
    ) -> Result<(), VerifyError> {
        verify(
            Provider::Custom(*scheme),
            headers,
            body,
            &Secret::new(secret),
            options,
        )
    }

    // --- 1. Official vectors ------------------------------------------------

    /// Slack's documented `v0=` scheme, expressed through `CustomScheme`,
    /// verified against the signature Slack's own docs publish for this
    /// exact secret/body/timestamp triple.
    #[test]
    fn reproduces_official_slack_vector() {
        let scheme = CustomScheme {
            hash: HashAlg::Sha256,
            signature_header: "X-Slack-Signature",
            timestamp_header: Some("X-Slack-Request-Timestamp"),
            encoding: Encoding::Hex,
            prefix: Some("v0="),
            signed_string: |headers, raw_body| {
                // `v0:{timestamp}:{raw_body}` — timestamp verbatim from its
                // header, per Slack's docs.
                let ts = headers.get("X-Slack-Request-Timestamp").unwrap_or_default();
                let mut signed = Vec::with_capacity(3 + ts.len() + 1 + raw_body.len());
                signed.extend_from_slice(b"v0:");
                signed.extend_from_slice(ts.as_bytes());
                signed.push(b':');
                signed.extend_from_slice(raw_body);
                signed
            },
        };

        let result = verify_custom(
            &scheme,
            &[
                (
                    "X-Slack-Signature",
                    format!("v0={SLACK_SIGNATURE}").as_str(),
                ),
                ("X-Slack-Request-Timestamp", "1531420618"),
            ],
            SLACK_BODY,
            SLACK_SECRET,
            clocked_at(SLACK_TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    /// Raw-body schemes across all three hash algorithms, checked against
    /// RFC 4231 / RFC 2202 digests (hex), plus base64 encodings of the same
    /// digests.
    #[test]
    fn rfc_vectors_across_hash_and_encoding_combinations() {
        let raw_body_scheme = |hash, encoding| CustomScheme {
            hash,
            signature_header: "X-Raw-Sig",
            timestamp_header: None,
            encoding,
            prefix: None,
            signed_string: |_headers, raw_body| raw_body.to_vec(),
        };

        // (hash, encoding, expected signature header value)
        let cases: &[(HashAlg, Encoding, &str)] = &[
            (
                HashAlg::Sha256,
                Encoding::Hex,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64,
                "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM=",
            ),
            (
                HashAlg::Sha1,
                Encoding::Hex,
                "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            ),
            (
                HashAlg::Sha1,
                Encoding::Base64,
                "7/zfauXrL6LSdBbV8YTfnCWafHk=",
            ),
            (
                HashAlg::Sha512,
                Encoding::Hex,
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64,
                "Fkt6e/z4GeLjlfvnO1bgo4e9ZCIugx/WECcM1+olBVSXWL91wFqZSm0DT2X48Ob9yuqxo01Ka0tjbgcKOLznNw==",
            ),
        ];

        for &(hash, encoding, signature) in cases {
            let scheme = raw_body_scheme(hash, encoding);
            let result = verify_custom(
                &scheme,
                &[("X-Raw-Sig", signature)],
                RFC_DATA,
                RFC_KEY,
                Default::default(),
            );
            assert_eq!(result, Ok(()), "{hash:?} + {encoding:?}");
        }
    }

    // --- Boundary bodies on the local timestamped scheme --------------------

    fn ts_headers(timestamp: u64, signature: &str) -> [(String, String); 2] {
        [
            (ts_scheme::HEADER.to_string(), format!("sha256={signature}")),
            (ts_scheme::TS_HEADER.to_string(), timestamp.to_string()),
        ]
    }

    fn verify_ts_fresh(body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify_custom(
            &ts_scheme_config(),
            &ts_headers(ts_scheme::TIMESTAMP, signature),
            body,
            ts_scheme::SECRET,
            // "now" == signed timestamp: always within tolerance.
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        )
    }

    #[test]
    fn boundary_bodies_verify() {
        assert_eq!(verify_ts_fresh(b"", ts_scheme::EMPTY_BODY_SIG), Ok(()));
        assert_eq!(
            verify_ts_fresh("héllo, 🦀 world!".as_bytes(), ts_scheme::UNICODE_BODY_SIG),
            Ok(())
        );
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify_custom(
            &ts_scheme_config(),
            &[
                (
                    "x-example-signature",
                    format!("sha256={}", ts_scheme::PING_SIG).as_str(),
                ),
                ("X-EXAMPLE-TIMESTAMP", "1700000000"),
            ],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    // --- 2. Negative tests ---------------------------------------------------

    #[test]
    fn flipped_signature_byte_fails() {
        // Swap the first hex character for another in-alphabet one so this
        // exercises a wrong-but-well-formed signature, not a decoding error.
        let first = &ts_scheme::PING_SIG[..1];
        let replacement = if first == "9" { "a" } else { "9" };
        let flipped = format!("{replacement}{}", &ts_scheme::PING_SIG[1..]);
        assert_ne!(flipped, ts_scheme::PING_SIG);
        assert_eq!(
            verify_ts_fresh(ts_scheme::PING_BODY, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        assert_eq!(
            verify_ts_fresh_with_secret(
                ts_scheme::PING_BODY,
                ts_scheme::PING_SIG,
                "another secret"
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    fn verify_ts_fresh_with_secret(
        body: &[u8],
        signature: &str,
        secret: &str,
    ) -> Result<(), VerifyError> {
        verify_custom(
            &ts_scheme_config(),
            &ts_headers(ts_scheme::TIMESTAMP, signature),
            body,
            secret,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        )
    }

    // --- 3. Tamper tests ------------------------------------------------------

    #[test]
    fn tampered_body_fails() {
        assert_eq!(
            verify_ts_fresh(
                b"{\"event\":\"ping\",\"tampered\":true}",
                ts_scheme::PING_SIG
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature_check() {
        // The timestamp is inside the signed string, so changing it must not
        // verify even though it stays within replay tolerance.
        let result = verify_custom(
            &ts_scheme_config(),
            &ts_headers(ts_scheme::TIMESTAMP - 1, ts_scheme::PING_SIG),
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    // --- 4. Replay tests -------------------------------------------------------

    #[test]
    fn stale_timestamp_rejected() {
        let result = verify_custom(
            &ts_scheme_config(),
            &ts_headers(ts_scheme::TIMESTAMP, ts_scheme::PING_SIG),
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP + 301, Some(Duration::from_secs(300))),
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
    fn future_timestamp_rejected_symmetrically() {
        let result = verify_custom(
            &ts_scheme_config(),
            &ts_headers(ts_scheme::TIMESTAMP, ts_scheme::PING_SIG),
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP - 301, Some(Duration::from_secs(300))),
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
    fn window_edges_are_in_tolerance() {
        for now in [ts_scheme::TIMESTAMP - 300, ts_scheme::TIMESTAMP + 300] {
            let result = verify_custom(
                &ts_scheme_config(),
                &ts_headers(ts_scheme::TIMESTAMP, ts_scheme::PING_SIG),
                ts_scheme::PING_BODY,
                ts_scheme::SECRET,
                clocked_at(now, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_skips_replay_check() {
        let result = verify_custom(
            &ts_scheme_config(),
            &ts_headers(ts_scheme::TIMESTAMP, ts_scheme::PING_SIG),
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP + 86_400 * 365, None),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn no_timestamp_header_means_no_replay_requirements() {
        // Schemes without a timestamp behave like GitHub/Linear: no clock is
        // consulted and no timestamp header is required. The raw-body scheme
        // from the RFC vectors is exactly this shape.
        let scheme = CustomScheme {
            hash: HashAlg::Sha256,
            signature_header: "X-Raw-Sig",
            timestamp_header: None,
            encoding: Encoding::Hex,
            prefix: None,
            signed_string: |_headers, raw_body| raw_body.to_vec(),
        };
        let result = verify_custom(
            &scheme,
            &[(
                "X-Raw-Sig",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            )],
            RFC_DATA,
            RFC_KEY,
            VerifyOptions {
                max_age: Some(Duration::ZERO),
                clock: None,
                request_url: None,
                form_params: None,
                verifying_material: None,
                webhook_id: None,
            },
        );
        assert_eq!(result, Ok(()));
    }

    // --- 5. Malformed-header battery -------------------------------------------

    #[test]
    fn missing_headers_error_distinctly() {
        let missing_signature = verify_custom(
            &ts_scheme_config(),
            &[(ts_scheme::TS_HEADER.to_string(), "1700000000".to_string())],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: ts_scheme::HEADER
            })
        );

        let missing_timestamp = verify_custom(
            &ts_scheme_config(),
            &[(
                ts_scheme::HEADER.to_string(),
                format!("sha256={}", ts_scheme::PING_SIG),
            )],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: ts_scheme::TS_HEADER
            })
        );
    }

    #[test]
    fn malformed_signature_plus_missing_timestamp_reports_missing_header() {
        // When the signature is present but malformed *and* the timestamp
        // header is absent, the timestamp header (like all built-in
        // timestamped schemes) is reported as missing rather than the
        // signature as malformed — the header lookup precedes parsing.
        let result = verify_custom(
            &ts_scheme_config(),
            &[(ts_scheme::HEADER.to_string(), "garbage".to_string())],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingHeader {
                header: ts_scheme::TS_HEADER
            })
        );
    }

    #[test]
    fn malformed_signature_values_error_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: ts_scheme::HEADER,
                    reason: "header is empty",
                },
            ),
            (
                // Missing the configured prefix entirely.
                ts_scheme::PING_SIG.to_string(),
                VerifyError::MalformedHeader {
                    header: ts_scheme::HEADER,
                    reason: "signature does not start with the configured scheme prefix",
                },
            ),
            (
                // A different scheme version's prefix: reject, never accept.
                format!("sha512={}", ts_scheme::PING_SIG),
                VerifyError::MalformedHeader {
                    header: ts_scheme::HEADER,
                    reason: "signature does not start with the configured scheme prefix",
                },
            ),
            (
                "sha256=".to_string(),
                VerifyError::MalformedHeader {
                    header: ts_scheme::HEADER,
                    reason: "empty signature after prefix",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_custom(
                &ts_scheme_config(),
                &[
                    (ts_scheme::HEADER.to_string(), value.clone()),
                    (ts_scheme::TS_HEADER.to_string(), "1700000000".to_string()),
                ],
                ts_scheme::PING_BODY,
                ts_scheme::SECRET,
                clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn bad_encoding_errors_distinctly() {
        let cases: Vec<String> = vec![
            // Not hex at all.
            "sha256=zzzz".to_string(),
            // Valid hex but wrong digest length for SHA-256 (20-byte SHA-1 size).
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        ];
        for value in cases {
            let result = verify_custom(
                &ts_scheme_config(),
                &[
                    (ts_scheme::HEADER.to_string(), value.clone()),
                    (ts_scheme::TS_HEADER.to_string(), "1700000000".to_string()),
                ],
                ts_scheme::PING_BODY,
                ts_scheme::SECRET,
                clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }

        // Base64 encoding path rejects non-base64 garbage distinctly too.
        let b64_scheme = CustomScheme {
            encoding: Encoding::Base64,
            ..ts_scheme_config()
        };
        let result = verify_custom(
            &b64_scheme,
            &[
                (ts_scheme::HEADER.to_string(), "sha256=!!!".to_string()),
                (ts_scheme::TS_HEADER.to_string(), "1700000000".to_string()),
            ],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        match result {
            Err(VerifyError::BadEncoding { .. }) => {}
            other => panic!("expected BadEncoding, got {other:?}"),
        }
    }

    #[test]
    fn malformed_timestamps_error_distinctly() {
        let cases: Vec<(String, VerifyError)> = vec![
            (
                String::new(),
                VerifyError::MalformedHeader {
                    header: ts_scheme::TS_HEADER,
                    reason: "header is empty",
                },
            ),
            (
                "not-a-number".to_string(),
                VerifyError::MalformedHeader {
                    header: ts_scheme::TS_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                "-5".to_string(),
                VerifyError::MalformedHeader {
                    header: ts_scheme::TS_HEADER,
                    reason: "timestamp is not a valid unix timestamp",
                },
            ),
            (
                "99999999999999999999999".to_string(),
                VerifyError::MalformedHeader {
                    header: ts_scheme::TS_HEADER,
                    reason: "timestamp overflows unix seconds",
                },
            ),
        ];
        for (value, expected) in cases {
            let result = verify_custom(
                &ts_scheme_config(),
                &[
                    (
                        ts_scheme::HEADER.to_string(),
                        format!("sha256={}", ts_scheme::PING_SIG),
                    ),
                    (ts_scheme::TS_HEADER.to_string(), value.clone()),
                ],
                ts_scheme::PING_BODY,
                ts_scheme::SECRET,
                clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }
    }

    #[test]
    fn empty_prefix_behaves_as_no_prefix() {
        let scheme = CustomScheme {
            prefix: Some(""),
            ..ts_scheme_config()
        };
        let headers = [
            (
                ts_scheme::HEADER.to_string(),
                ts_scheme::PING_SIG.to_string(),
            ),
            (ts_scheme::TS_HEADER.to_string(), "1700000000".to_string()),
        ];
        let result = verify_custom(
            &scheme,
            &headers,
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }
}
