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
//! **Ambiguity-check gap:** The tower/actix adapters scan only
//! [`signature_header`](CustomScheme::signature_header) and
//! [`timestamp_header`](CustomScheme::timestamp_header) for conflicting
//! duplicate values (per `spec.md` §4.4). If `signed_string` reads
//! *additional* headers, duplicates in those are **not** detected. See the
//! [`CustomScheme`] struct docs for details.
//!
//! **Replay-check caveat:** Setting `timestamp_header` runs the shared replay
//! window (`|now - t| <= max_age`) against whatever the header says — but the
//! check only *binds* when `signed_string` copies that value into the bytes
//! it returns. A closure that signs the body alone leaves the timestamp
//! attacker-rewriteable: replaying a captured request with a freshened
//! timestamp header still verifies (the header is not part of the HMAC
//! input), silently defeating the protection. The built-in timestamped
//! providers wire the timestamp into the signed string by construction; a
//! `Custom` scheme must do so deliberately — see
//! [`CustomScheme::with_timestamp_header`].
//!
//! **Timestamp-unit caveat:** The shared window compares in seconds, so the
//! header's unit must be declared — [`TimestampUnit::Seconds`] (the default)
//! or [`TimestampUnit::Millis`] via
//! [`CustomScheme::with_timestamp_unit`]. Both units parse as a digit run, so
//! an undeclared millisecond sender is rejected as
//! `TimestampOutOfTolerance` rather than as a malformed header, with a `skew`
//! that looks like a tolerance misconfiguration. Six of the 58 built-in
//! providers timestamp in milliseconds (HubSpot, Contentful, WorkOS, Ripple,
//! Airwallex, Webflow).
//!
//! # Example
//!
//! ```
//! use webhook_verify::{verify, CustomScheme, Encoding, HashAlg, Provider, Secret, TimestampUnit};
//!
//! // A fictional provider that signs the raw body with HMAC-SHA256 and
//! // sends it hex-encoded in `X-Webhook-Sig`.
//! let scheme = CustomScheme {
//!     hash: HashAlg::Sha256,
//!     signature_header: "X-Webhook-Sig",
//!     timestamp_header: None,
//!     timestamp_unit: TimestampUnit::Seconds,
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
use crate::core::replay::{check_replay, parse_millis, parse_timestamp};
use crate::core::secret::Secret;
use base64::Engine;

/// Milliseconds in one second, for flooring a `TimestampUnit::Millis` header
/// down to the whole seconds the shared replay window compares in. Same
/// constant the built-in millisecond providers divide by.
const MILLIS_PER_SECOND: u64 = 1000;

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

/// Unit of the timestamp a [`CustomScheme`] reads from its
/// [`timestamp_header`](CustomScheme::timestamp_header) (`spec.md` §2.2).
///
/// The shared replay window compares against a wall clock in **seconds**
/// (`|now - t| <= max_age`), so the unit has to be declared for the comparison
/// to mean anything. Declaring the wrong one does not fail closed on a
/// malformed value — a 13-digit epoch-milliseconds stamp is a perfectly valid
/// `u64` — it just compares a millisecond value against a seconds-valued
/// clock and rejects every delivery with a `skew` on the order of 5.6e10
/// seconds. Worse, the resulting `TimestampOutOfTolerance` reads like a
/// tolerance problem, so the tempting fix is to widen `max_age`, which makes
/// the check permanently vacuous and silently drops replay protection. Say
/// which unit the sender actually sends.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TimestampUnit {
    /// Integer unix **seconds** since the epoch (issue #273). The default, and
    /// what most senders use: Slack, Stripe, Zoom, Sentry, and most of the 58
    /// built-in providers timestamp in whole seconds.
    #[default]
    Seconds,
    /// Integer unix **milliseconds** since the epoch, floored to whole seconds
    /// before the replay comparison. Six built-in providers need this:
    /// HubSpot, Contentful, WorkOS, Ripple, Airwallex, and Webflow
    /// (`spec.md` §3).
    Millis,
}

impl fmt::Display for TimestampUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimestampUnit::Seconds => f.write_str("seconds"),
            TimestampUnit::Millis => f.write_str("milliseconds"),
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
/// **Ambiguity-check caveat.** Framework adapters (`tower`, `actix`) reject
/// duplicate headers whose values differ — but they only scan the headers
/// listed by the crate's adapter ambiguity check, which for `Custom` is
/// limited to [`signature_header`](Self::signature_header) and
/// [`timestamp_header`](Self::timestamp_header). If `signed_string` reads
/// *additional* headers from the map (e.g. a nonce, a URL, or a second
/// timestamp), duplicate values in those extra headers are **not** detected.
/// An attacker who can inject a conflicting value for such a header can cause
/// the proxy and verifier to disagree on the signed input — the exact
/// scenario `spec.md` §4.4 exists to prevent. When designing a custom scheme,
/// either limit `signed_string` to the two declared headers, or accept that
/// the adapter cannot guard against proxy disagreement on undeclared headers.
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
    /// Name of the header carrying the timestamp, when the sender signs one.
    /// Setting this enables replay protection with the shared symmetric
    /// tolerance (`|now - t| <= max_age`, default 300s); leaving it `None`
    /// disables replay checks for this scheme, mirroring built-ins like GitHub
    /// whose schemes sign no timestamp.
    ///
    /// The value is interpreted in the unit named by
    /// [`timestamp_unit`](Self::timestamp_unit) — whole seconds unless that is
    /// set to [`TimestampUnit::Millis`].
    ///
    /// **The replay check only binds when `signed_string` copies this
    /// header's value into the signed bytes** — see
    /// [`CustomScheme::with_timestamp_header`].
    pub timestamp_header: Option<&'static str>,
    /// Unit of [`timestamp_header`](Self::timestamp_header)'s value.
    ///
    /// Ignored when `timestamp_header` is `None` (no replay check runs, so
    /// there is no value to interpret). Defaults to
    /// [`TimestampUnit::Seconds`] via [`TimestampUnit`]'s `Default` impl;
    /// declare [`TimestampUnit::Millis`] for a sender that timestamps in
    /// epoch milliseconds, as HubSpot, Contentful, WorkOS, Ripple, Airwallex,
    /// and Webflow all do.
    pub timestamp_unit: TimestampUnit,
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
    ///
    /// **Note:** If this function reads headers beyond
    /// [`signature_header`](Self::signature_header) and
    /// [`timestamp_header`](Self::timestamp_header), the framework adapters'
    /// duplicate-header ambiguity check will **not** cover them — see the
    /// struct-level safety note.
    pub signed_string: fn(&dyn HeaderMap, &[u8]) -> Vec<u8>,
}

impl PartialEq for CustomScheme {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
            && self.signature_header == other.signature_header
            && self.timestamp_header == other.timestamp_header
            && self.timestamp_unit == other.timestamp_unit
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
        self.timestamp_unit.hash(state);
        self.encoding.hash(state);
        self.prefix.hash(state);
    }
}

impl CustomScheme {
    /// Creates a scheme from the required fields, leaving the optional
    /// `timestamp_header` and `prefix` unset (`None`) and
    /// `timestamp_unit` at its default of [`TimestampUnit::Seconds`].
    ///
    /// Configure the optional fields with
    /// [`CustomScheme::with_timestamp_header`],
    /// [`CustomScheme::with_timestamp_unit`], and
    /// [`CustomScheme::with_prefix`] when the sender's scheme uses them.
    ///
    /// # Example
    ///
    /// ```
    /// use webhook_verify::{CustomScheme, Encoding, HashAlg};
    ///
    /// let scheme = CustomScheme::new(
    ///     HashAlg::Sha256,
    ///     "X-Webhook-Sig",
    ///     Encoding::Hex,
    ///     |_headers, raw_body| raw_body.to_vec(),
    /// );
    /// ```
    ///
    /// [`CustomScheme`] is itself `#[must_use]`, so the returned scheme is
    /// always flagged if discarded.
    pub fn new(
        hash: HashAlg,
        signature_header: &'static str,
        encoding: Encoding,
        signed_string: fn(&dyn HeaderMap, &[u8]) -> Vec<u8>,
    ) -> Self {
        Self {
            hash,
            signature_header,
            timestamp_header: None,
            timestamp_unit: TimestampUnit::Seconds,
            encoding,
            prefix: None,
            signed_string,
        }
    }

    /// Sets the timestamp header, enabling replay protection with the shared
    /// symmetric tolerance (`|now - t| <= max_age`, default 300s).
    ///
    /// The value is read in **unix seconds** unless the unit is changed with
    /// [`CustomScheme::with_timestamp_unit`] — set that too when the sender
    /// timestamps in milliseconds.
    ///
    /// **Replay protection only binds if `signed_string` incorporates the
    /// timestamp value into the signed bytes.** The replay check runs against
    /// the header value alone; a closure that signs the body only leaves the
    /// timestamp attacker-rewriteable — an attacker replaying a captured
    /// request can rewrite this header to any fresh in-window value and the
    /// signature still verifies, silently defeating the protection. Include
    /// the timestamp in `signed_string`'s output (as the built-in
    /// timestamped schemes do by construction, e.g. Slack's
    /// `v0:{timestamp}:{raw_body}`) before relying on this setting.
    pub fn with_timestamp_header(mut self, timestamp_header: &'static str) -> Self {
        self.timestamp_header = Some(timestamp_header);
        self
    }

    /// Sets the unit [`timestamp_header`](Self::timestamp_header)'s value is
    /// expressed in, for the shared replay comparison (issue #273).
    ///
    /// Only meaningful together with
    /// [`CustomScheme::with_timestamp_header`]; a scheme with no timestamp
    /// header never reaches the comparison, so the unit is inert. The default
    /// is [`TimestampUnit::Seconds`], so this is a no-op for the majority of
    /// senders — call it with [`TimestampUnit::Millis`] only for a sender that
    /// stamps in epoch milliseconds.
    ///
    /// Declaring the wrong unit is not a benign no-op: both units parse as a
    /// plain digit run, so a millisecond value read as seconds still passes
    /// parsing and then fails the comparison, and a seconds value read as
    /// milliseconds is floored toward 1970 and fails the same way. Both
    /// surface as `TimestampOutOfTolerance` with an implausible `skew`, which
    /// is the signal this field exists to remove.
    ///
    /// # Example
    ///
    /// A HubSpot-shaped sender: `X-HubSpot-Request-Timestamp` is epoch
    /// milliseconds, and the signed bytes are `"{ts}:{raw_body}"` in the exact
    /// decimal form the header carried.
    ///
    /// ```
    /// use webhook_verify::{CustomScheme, Encoding, HashAlg, TimestampUnit};
    ///
    /// let scheme = CustomScheme::new(
    ///     HashAlg::Sha256,
    ///     "X-HubSpot-Signature",
    ///     Encoding::Hex,
    ///     |headers, raw_body| {
    ///         let ts = headers
    ///             .get("X-HubSpot-Request-Timestamp")
    ///             .unwrap_or_default();
    ///         let mut signed = Vec::with_capacity(ts.len() + 1 + raw_body.len());
    ///         signed.extend_from_slice(ts.as_bytes());
    ///         signed.push(b':');
    ///         signed.extend_from_slice(raw_body);
    ///         signed
    ///     },
    /// )
    /// .with_timestamp_header("X-HubSpot-Request-Timestamp")
    /// .with_timestamp_unit(TimestampUnit::Millis);
    ///
    /// assert_eq!(scheme.timestamp_unit, TimestampUnit::Millis);
    /// ```
    pub fn with_timestamp_unit(mut self, timestamp_unit: TimestampUnit) -> Self {
        self.timestamp_unit = timestamp_unit;
        self
    }

    /// Sets the literal prefix required before the encoded signature (e.g.
    /// `"v0="` or `"sha256="`). When set, a header not starting with it is
    /// rejected as malformed rather than leniently accepted.
    pub fn with_prefix(mut self, prefix: &'static str) -> Self {
        self.prefix = Some(prefix);
        self
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

    // The unit is resolved here, before the comparison, because both parsers
    // accept the other's values (a digit run parses either way) — picking the
    // right one is the whole point of `TimestampUnit`. `parse_millis` also
    // carries millisecond-specific diagnostics, and the shared replay window
    // is in seconds, so `Millis` floors exactly as the six built-in
    // millisecond providers do (`spec.md` §3).
    let timestamp = match timestamp_raw {
        Some((timestamp_header, raw)) => Some(match scheme.timestamp_unit {
            TimestampUnit::Seconds => parse_timestamp(timestamp_header, raw)?,
            TimestampUnit::Millis => parse_millis(timestamp_header, raw)? / MILLIS_PER_SECOND,
        }),
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
    use super::{CustomScheme, Encoding, HashAlg, TimestampUnit};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::providers::Provider;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
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

    /// The same fictional sender, but timestamping in epoch **milliseconds**
    /// the way HubSpot, Contentful, WorkOS, Ripple, Airwallex, and Webflow all
    /// do — the six built-in providers that call `parse_millis`
    /// (`spec.md` §3). This is the configuration issue #273 says the API
    /// could not previously express.
    mod ms_scheme {
        pub const SECRET: &str = "custom_shared_secret";
        pub const HEADER: &str = "X-Example-Signature";
        pub const TS_HEADER: &str = "X-Example-Timestamp";
        /// The same instant `ts_scheme::TIMESTAMP` names, in milliseconds.
        pub const TIMESTAMP_MILLIS: u64 = 1_700_000_000_123;
        pub const PING_BODY: &[u8] = b"{\"event\":\"ping\"}";
        /// HMAC-SHA256 over `1700000000123.{PING_BODY}`, cross-checked
        /// against Python's `hmac`/`hashlib`.
        pub const PING_SIG: &str =
            "325311d7e44a82a8ee6aa561285a9bcb71dea12d5c4b0bb89bc57fae4d511d73";
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
            timestamp_unit: TimestampUnit::Seconds,
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
            timestamp_unit: TimestampUnit::Seconds,
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
            timestamp_unit: TimestampUnit::Seconds,
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
            timestamp_unit: TimestampUnit::Seconds,
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
                request_method: None,
                form_params: None,
                verifying_material: None,
                webhook_id: None,
            },
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn declared_timestamp_header_not_signed_leaves_replay_bypassable() {
        // The documented replay-check caveat (module docs + the
        // `timestamp_header`/`with_timestamp_header` docs), pinned so the
        // limitation stays deliberate: a scheme may declare a
        // `timestamp_header` whose value its `signed_string` never copies
        // into the HMAC input. The replay window then runs against the header
        // alone — stale headers are rejected, but an attacker replaying a
        // captured request merely rewrites the header to a fresh in-window
        // value and the signature still verifies. This test demonstrates both
        // halves so the caveat cannot silently drift from the behavior.
        let unsigned_ts_scheme = CustomScheme {
            hash: HashAlg::Sha256,
            signature_header: "X-Raw-Sig",
            // Declared, so a timestamp header is required and replay-checked...
            timestamp_header: Some("X-Raw-Timestamp"),
            timestamp_unit: TimestampUnit::Seconds,
            encoding: Encoding::Hex,
            prefix: None,
            // ...but the signed bytes cover the body only, not the stamp.
            signed_string: |_headers, raw_body| raw_body.to_vec(),
        };
        let raw_sig = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let now = 1_700_000_000u64;
        let options = clocked_at(now, Some(Duration::from_secs(300)));

        // Half 1: with the *original, stale* header the replay check rejects.
        let stale = verify_custom(
            &unsigned_ts_scheme,
            &[("X-Raw-Sig", raw_sig), ("X-Raw-Timestamp", "1000000000")],
            RFC_DATA,
            RFC_KEY,
            options.clone(),
        );
        assert_eq!(
            stale,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(700_000_000),
                max_age: Duration::from_secs(300),
            })
        );

        // Half 2: the attacker rewrites the header to a fresh value. The
        // signature (over the body only) still matches and the window passes
        // — replay protection is silently defeated. Only copying the stamp
        // into `signed_string`'s output (as `ts_signed_string` does) closes
        // this; the built-in timestamped schemes do so by construction.
        let freshened = verify_custom(
            &unsigned_ts_scheme,
            &[("X-Raw-Sig", raw_sig), ("X-Raw-Timestamp", "1700000000")],
            RFC_DATA,
            RFC_KEY,
            options,
        );
        assert_eq!(freshened, Ok(()));
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

    // --- CustomScheme::new() convenience constructor ------------------------

    #[test]
    fn new_constructor_sets_required_fields_and_defaults_optional_ones() {
        let scheme = CustomScheme::new(
            HashAlg::Sha256,
            "X-Webhook-Sig",
            Encoding::Hex,
            ts_signed_string,
        );

        assert_eq!(scheme.hash, HashAlg::Sha256);
        assert_eq!(scheme.signature_header, "X-Webhook-Sig");
        assert_eq!(scheme.encoding, Encoding::Hex);
        assert_eq!(scheme.timestamp_header, None);
        assert_eq!(scheme.prefix, None);
        assert_eq!(
            scheme.signed_string as *const () as usize, ts_signed_string as *const () as usize,
            "the constructor must preserve the caller's signed_string fn"
        );
    }

    #[test]
    fn with_timestamp_header_sets_replay_enabled_scheme() {
        let scheme = CustomScheme::new(
            HashAlg::Sha256,
            ts_scheme::HEADER,
            Encoding::Hex,
            ts_signed_string,
        )
        .with_timestamp_header(ts_scheme::TS_HEADER)
        .with_prefix("sha256=");

        assert_eq!(scheme.timestamp_header, Some(ts_scheme::TS_HEADER));
        assert_eq!(scheme.prefix, Some("sha256="));

        // The builder-built scheme verifies identically to the struct-literal
        // configuration (same fields, same signed_string fn).
        assert_eq!(scheme, ts_scheme_config());

        let result = verify_custom(
            &scheme,
            &[
                (
                    ts_scheme::HEADER.to_string(),
                    format!("sha256={}", ts_scheme::PING_SIG),
                ),
                (ts_scheme::TS_HEADER.to_string(), "1700000000".to_string()),
            ],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn new_constructor_without_timestamp_skips_replay_checks() {
        // A scheme built via `new()` (no timestamp header) matches
        // GitHub/Linear-style raw-body verification with no clock consulted.
        let scheme = CustomScheme::new(
            HashAlg::Sha256,
            "X-Webhook-Sig",
            Encoding::Hex,
            |_headers, raw_body| raw_body.to_vec(),
        );
        let result = verify_custom(
            &scheme,
            &[(
                "X-Webhook-Sig".to_string(),
                // HMAC-SHA256 over b"payload" with key "shared-secret".
                "0e7320e558b4421b7aa464a9027132b7176c02adf16ed36778ce302d6f2a6ac3".to_string(),
            )],
            b"payload",
            "shared-secret",
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    // --- TimestampUnit (issue #273) -----------------------------------------

    /// A millisecond scheme verifies, and the `Millis` value is floored to
    /// whole seconds for the shared replay window.
    ///
    /// The millisecond stamp is `1700000000123`, i.e. the same instant as
    /// `ts_scheme::TIMESTAMP` plus 123ms, so a clock at `1_700_000_000` gives a
    /// floored skew of 0. Without the floor the same value would read as
    /// ~56.6 billion seconds into the future and be rejected.
    #[test]
    fn millisecond_scheme_verifies_and_floors_to_whole_seconds() {
        let scheme = CustomScheme {
            timestamp_unit: TimestampUnit::Millis,
            ..ts_scheme_config()
        };
        let result = verify_custom(
            &scheme,
            &[
                (
                    ms_scheme::HEADER.to_string(),
                    format!("sha256={}", ms_scheme::PING_SIG),
                ),
                (
                    ms_scheme::TS_HEADER.to_string(),
                    "1700000000123".to_string(),
                ),
            ],
            ms_scheme::PING_BODY,
            ms_scheme::SECRET,
            clocked_at(
                ms_scheme::TIMESTAMP_MILLIS / 1000,
                Some(Duration::from_secs(300)),
            ),
        );
        assert_eq!(result, Ok(()));
    }

    /// The millisecond path honours the same symmetric window at its edges as
    /// the seconds path: `max_age` itself verifies, one second past it does
    /// not. Pinning the boundary is what proves the flooring happens *before*
    /// the comparison rather than the value being compared as milliseconds.
    #[test]
    fn millisecond_scheme_replay_window_edges() {
        let scheme = CustomScheme {
            timestamp_unit: TimestampUnit::Millis,
            ..ts_scheme_config()
        };
        let headers = [
            (
                ms_scheme::HEADER.to_string(),
                format!("sha256={}", ms_scheme::PING_SIG),
            ),
            (
                ms_scheme::TS_HEADER.to_string(),
                "1700000000123".to_string(),
            ),
        ];
        let at = |now| {
            verify_custom(
                &scheme,
                &headers,
                ms_scheme::PING_BODY,
                ms_scheme::SECRET,
                clocked_at(now, Some(Duration::from_secs(300))),
            )
        };

        let base = ms_scheme::TIMESTAMP_MILLIS / 1000;
        assert_eq!(at(base + 300), Ok(()), "exactly max_age old must verify");
        assert_eq!(at(base - 300), Ok(()), "exactly max_age ahead must verify");

        let stale = match at(base + 301) {
            Ok(()) => panic!("301s old must be rejected, but it verified"),
            Err(error) => error,
        };
        assert!(
            matches!(stale, VerifyError::TimestampOutOfTolerance { .. }),
            "301s old must be rejected, got {stale:?}"
        );
        // The reported skew is measured in seconds, not milliseconds: the
        // flooring is what makes `skew` mean what `max_age` is denominated in.
        assert!(
            matches!(stale, VerifyError::TimestampOutOfTolerance { skew, .. }
                if skew == Duration::from_secs(301)),
            "skew must be floored seconds, got {stale:?}"
        );
    }

    /// Declaring the unit wrong is the footgun issue #273 is about, and it
    /// must fail *closed in both directions* rather than silently pass.
    ///
    /// A millisecond value read as seconds compares ~56.6 billion seconds
    /// into the future; a seconds value read as milliseconds floors toward
    /// 1970 and compares ~53.9 years in the past. Both are `u64` digit runs,
    /// so neither trips a parse error — which is exactly why the unit has to
    /// be declared rather than sniffed.
    #[test]
    fn a_mismatched_timestamp_unit_never_verifies() {
        let ms_stamp = "1700000000123";
        let secs_stamp = "1700000000";
        let now = 1_700_000_000;

        // Millisecond stamp, scheme left at the Seconds default.
        let read_as_seconds = CustomScheme::new(
            HashAlg::Sha256,
            ms_scheme::HEADER,
            Encoding::Hex,
            ts_signed_string,
        )
        .with_timestamp_header(ms_scheme::TS_HEADER)
        .with_prefix("sha256=");
        let misread = verify_custom(
            &read_as_seconds,
            &[
                (
                    ms_scheme::HEADER.to_string(),
                    format!("sha256={}", ms_scheme::PING_SIG),
                ),
                (ms_scheme::TS_HEADER.to_string(), ms_stamp.to_string()),
            ],
            ms_scheme::PING_BODY,
            ms_scheme::SECRET,
            clocked_at(now, Some(Duration::from_secs(300))),
        );
        assert!(
            matches!(misread, Err(VerifyError::TimestampOutOfTolerance { .. })),
            "a millisecond stamp read as seconds must be rejected, got {misread:?}"
        );

        // Seconds stamp, scheme declared as Millis.
        let read_as_millis = CustomScheme {
            timestamp_unit: TimestampUnit::Millis,
            ..ts_scheme_config()
        };
        let misread = verify_custom(
            &read_as_millis,
            &[
                (
                    ms_scheme::HEADER.to_string(),
                    format!("sha256={}", ts_scheme::PING_SIG),
                ),
                (ms_scheme::TS_HEADER.to_string(), secs_stamp.to_string()),
            ],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(now, Some(Duration::from_secs(300))),
        );
        assert!(
            matches!(misread, Err(VerifyError::TimestampOutOfTolerance { .. })),
            "a seconds stamp read as milliseconds must be rejected, got {misread:?}"
        );
    }

    /// A millisecond header that isn't a digit run is still a malformed
    /// header, and the diagnostic names the *millisecond* unit — the operator
    /// debugging it is looking at an epoch-ms sender, not a seconds one.
    #[test]
    fn malformed_millisecond_header_reports_the_declared_unit() {
        let scheme = CustomScheme {
            timestamp_unit: TimestampUnit::Millis,
            ..ts_scheme_config()
        };
        let misparsed = verify_custom(
            &scheme,
            &[
                (
                    ms_scheme::HEADER.to_string(),
                    format!("sha256={}", ms_scheme::PING_SIG),
                ),
                (
                    ms_scheme::TS_HEADER.to_string(),
                    "not-a-timestamp".to_string(),
                ),
            ],
            ms_scheme::PING_BODY,
            ms_scheme::SECRET,
            clocked_at(1_700_000_000, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            misparsed,
            Err(VerifyError::MalformedHeader {
                header: ts_scheme::TS_HEADER,
                reason: "timestamp is not valid epoch milliseconds",
            }),
        );
    }

    /// A tampered body still fails on the signature check *before* the replay
    /// comparison, so the unit never becomes a way to skip the HMAC.
    #[test]
    fn millisecond_scheme_still_rejects_a_tampered_body() {
        let scheme = CustomScheme {
            timestamp_unit: TimestampUnit::Millis,
            ..ts_scheme_config()
        };
        let result = verify_custom(
            &scheme,
            &[
                (
                    ms_scheme::HEADER.to_string(),
                    format!("sha256={}", ms_scheme::PING_SIG),
                ),
                (
                    ms_scheme::TS_HEADER.to_string(),
                    "1700000000123".to_string(),
                ),
            ],
            b"{\"event\":\"pong\"}",
            ms_scheme::SECRET,
            clocked_at(
                ms_scheme::TIMESTAMP_MILLIS / 1000,
                Some(Duration::from_secs(300)),
            ),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    /// The unit defaults to seconds everywhere a caller does not say
    /// otherwise, so no existing scheme changes behavior (issue #273's
    /// backward-compatibility requirement) and the `Default` impl the field
    /// doc points at agrees.
    #[test]
    fn timestamp_unit_defaults_to_seconds() {
        assert_eq!(TimestampUnit::default(), TimestampUnit::Seconds);
        assert_eq!(ts_scheme_config().timestamp_unit, TimestampUnit::Seconds);
        assert_eq!(
            CustomScheme::new(
                HashAlg::Sha256,
                "X-Webhook-Sig",
                Encoding::Hex,
                |_headers, raw_body| raw_body.to_vec(),
            )
            .timestamp_unit,
            TimestampUnit::Seconds
        );

        // The builder sets what it says, in both directions, and composes
        // with the other optional setters without disturbing them.
        let scheme = CustomScheme::new(
            HashAlg::Sha256,
            "X-Webhook-Sig",
            Encoding::Hex,
            ts_signed_string,
        )
        .with_timestamp_header("X-Ts")
        .with_timestamp_unit(TimestampUnit::Millis)
        .with_prefix("sha256=");
        assert_eq!(scheme.timestamp_unit, TimestampUnit::Millis);
        assert_eq!(scheme.timestamp_header, Some("X-Ts"));
        assert_eq!(scheme.prefix, Some("sha256="));
    }

    /// The declared unit is part of the scheme's identity, so it has to
    /// participate in `PartialEq` and `Hash` alongside the other declarative
    /// fields — two schemes differing only in unit are different schemes, and
    /// a caller keying a map by scheme must not collapse them.
    #[test]
    fn timestamp_unit_participates_in_equality_and_hash() {
        use crate::test_helpers::hash_of;

        let seconds = ts_scheme_config();
        let millis = CustomScheme {
            timestamp_unit: TimestampUnit::Millis,
            ..ts_scheme_config()
        };
        assert_ne!(seconds, millis, "timestamp_unit participates in equality");
        assert_ne!(
            hash_of(&seconds),
            hash_of(&millis),
            "timestamp_unit participates in Hash"
        );
    }

    /// A `Millis` unit is inert without a timestamp header: no replay check
    /// runs, so the value is never parsed and a malformed one is not read.
    #[test]
    fn millisecond_unit_without_a_timestamp_header_is_inert() {
        let scheme = CustomScheme {
            timestamp_header: None,
            timestamp_unit: TimestampUnit::Millis,
            // Raw-body signing, so nothing reads a timestamp header at all.
            signed_string: |_headers, raw_body| raw_body.to_vec(),
            ..ts_scheme_config()
        };
        let result = verify_custom(
            &scheme,
            &[(
                ts_scheme::HEADER.to_string(),
                // HMAC-SHA256 over b"payload" with key "shared-secret", behind
                // the `sha256=` prefix `ts_scheme_config` requires.
                "sha256=0e7320e558b4421b7aa464a9027132b7176c02adf16ed36778ce302d6f2a6ac3"
                    .to_string(),
            )],
            b"payload",
            "shared-secret",
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn timestamp_unit_display_names_the_unit() {
        assert_eq!(TimestampUnit::Seconds.to_string(), "seconds");
        assert_eq!(TimestampUnit::Millis.to_string(), "milliseconds");
    }

    #[test]
    fn hash_agrees_with_partial_eq_fields() {
        // `CustomScheme`'s `Hash` is hand-written and must stay in lockstep
        // with the declarative `PartialEq` (spec.md §2.2: the declarative
        // fields participate in `PartialEq`/`Hash`; `signed_string` is
        // excluded). If a field ever joins one impl but not the other,
        // equal-but-differently-hashed (or unequal-but-hash-equal) schemes
        // silently break callers that store them in sets or maps. The
        // `signed_string` fns below behave differently (`ts_signed_string`
        // emits `{ts}.{body}`, `noop` emits nothing) yet are equal — and
        // must hash equal too. The test's summing hasher cannot collide on
        // the differing discriminants/payloads, so the negative assertion is
        // also deterministic.
        use crate::test_helpers::hash_of;

        fn noop_signed_string(_headers: &dyn crate::HeaderMap, _raw_body: &[u8]) -> Vec<u8> {
            Vec::new()
        }

        let a = ts_scheme_config();
        let b = CustomScheme {
            signed_string: noop_signed_string,
            ..a
        };
        assert_eq!(a, b, "signed_string is excluded from equality");
        assert_eq!(hash_of(&a), hash_of(&b), "Hash must agree with PartialEq");

        // A declarative-field difference is equality difference — and must be
        // a hash difference too (neither impl may ignore a field the other
        // compares).
        let c = CustomScheme { prefix: None, ..a };
        assert_ne!(a, c, "prefix participates in equality");
        assert_ne!(hash_of(&a), hash_of(&c), "prefix participates in Hash");
    }
}
