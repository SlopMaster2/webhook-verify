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
//! **Ambiguity-check gap:** The tower/actix adapters scan
//! [`signature_header`](CustomScheme::signature_header),
//! [`timestamp_header`](CustomScheme::timestamp_header), and every name in
//! [`signed_headers`](CustomScheme::signed_headers) for conflicting duplicate
//! values (per `spec.md` §4.4). A header `signed_string` reads but the scheme
//! did **not** declare there still gets no duplicate detection — declare every
//! header the closure folds into the signed bytes. See the [`CustomScheme`]
//! struct docs for details.
//!
//! **Declared header names must be valid HTTP field names:** a
//! `signature_header` or `timestamp_header` containing a space, a stray
//! control byte, or a non-ASCII character is not a `field-name = token`
//! (RFC 9110 §5.1), so the ambiguity scan cannot look it up and reports it as
//! ambiguous on **every** request — a `400` with an empty body through the
//! adapters, and a "reject this request" verdict for a caller driving
//! [`ambiguous_signature_header_in`](crate::ambiguous_signature_header_in)
//! themselves, including for a header table that holds no duplicate at all.
//! Meanwhile `verify()` called on a pair table still *reads* the same name,
//! because the crate's own `HeaderMap` impls compare names as plain
//! case-insensitive strings. Fail-closed is the right direction, so this is
//! documented rather than changed; see
//! [`CustomScheme::signature_header`].
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
//!     signed_headers: &[],
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
use crate::core::replay::{MILLIS_PER_SECOND, check_replay, parse_millis, parse_timestamp};
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
///
/// Each variant names one exact decoder — an alphabet, and whether canonical
/// padding is required. That exactness is the point: the variants do *not*
/// blur into "accept anything base64ish", so a scheme configured with the
/// wrong one rejects the delivery as
/// [`VerifyError::BadEncoding`] rather than verifying it under a
/// configuration the caller did not ask for. Each variant's docs name the
/// cells it does not cover, and between them the variants cover the whole
/// alphabet × padding matrix a base64 sender can spell a digest with.
///
/// No built-in provider needs any variant beyond [`Encoding::Hex`] and
/// [`Encoding::Base64`]; these exist for the long-tail senders
/// [`CustomScheme`] exists to cover (`spec.md` §2.2).
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Lower/uppercase hexadecimal (both accepted by the decoder).
    Hex,
    /// Standard base64 alphabet (`+` and `/`) with canonical padding, as in
    /// RFC 4648 §4.
    Base64,
    /// URL-safe base64 alphabet (`-` and `_` in place of `+` and `/`) with
    /// canonical padding, as in RFC 4648 §5.
    ///
    /// The two alphabets differ *only* in those two characters, so a digest
    /// whose encoding happens to contain neither decodes identically under
    /// both — but only *some* digests are so spelled. Each full 6-bit group is
    /// `+`/`/` with probability 2/64, so a digest is spelled the same way
    /// under both alphabets with probability `(62/64)^groups`, where `groups`
    /// is the number of full 6-bit groups in its base64 form (26 for SHA-1's
    /// 20-byte digest, 42 for SHA-256's 32, 85 for SHA-512's 64): about **44%**
    /// for SHA-1, **26%** for SHA-256, and **7%** for SHA-512. The two
    /// spellings therefore differ on most SHA-256 and SHA-512 digests, which
    /// is why picking the wrong variant is usually caught immediately; it is
    /// a SHA-1-sized digest that is spelled the same way under both often
    /// enough for a wrong `Encoding` to verify authentic bytes by accident.
    Base64Url,
    /// Standard base64 alphabet (`+` and `/`) with the trailing padding
    /// **omitted**, the shape RFC 4648 §3.2 calls unpadded and JWS calls
    /// "base64url without padding".
    ///
    /// Padding is never data-dependent, so unlike [`Encoding::Base64Url`]
    /// this variant differs from [`Encoding::Base64`] on every signature it
    /// is given: a 32-byte digest is 44 characters padded and 43 unpadded.
    ///
    /// This is the standard alphabet, so it does **not** cover the URL-safe
    /// alphabet; [`Encoding::Base64Url`] does not cover the missing padding
    /// either. The one cell that needs both at once is
    /// [`Encoding::Base64UrlNoPad`].
    Base64NoPad,
    /// URL-safe alphabet (`-` and `_` in place of `+` and `/`) with the
    /// trailing padding **omitted** — the `base64` crate's
    /// `URL_SAFE_NO_PAD`, and the shape JWS §2 calls "base64url" and most
    /// JWT libraries emit.
    ///
    /// This is the only variant that names **both** halves of the
    /// alphabet × padding matrix, so it is the one a scheme needs when a
    /// sender puts a digest in a URL, a header, or any other
    /// non-base64-alphabet context and omits the `=` padding. It rejects
    /// the padded spelling ([`Encoding::Base64Url`]) and the standard
    /// alphabet's `+`/`/` ([`Encoding::Base64NoPad`]) alike, exactly as each
    /// of those rejects what it does not name.
    ///
    /// As with [`Encoding::Base64Url`], the two alphabets coincide on some
    /// digests (that variant's docs give the per-digest rate), so a scheme
    /// configured with `Base64Url` instead of this one goes undetected on
    /// those digests and is caught by its first authentic delivery on the rest.
    /// The other direction is not so forgiving: this variant's confusion
    /// partner is `Base64Url`, and that mismatch is caught on **every** digest,
    /// because padding is never data-dependent — a 32-byte digest is 44
    /// characters padded and 43 unpadded, whatever its contents.
    Base64UrlNoPad,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Encoding::Hex => f.write_str("hex"),
            Encoding::Base64 => f.write_str("base64"),
            Encoding::Base64Url => f.write_str("base64url"),
            Encoding::Base64NoPad => f.write_str("base64-nopad"),
            Encoding::Base64UrlNoPad => f.write_str("base64url-nopad"),
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
/// **Construction compatibility.** This struct is not
/// `#[non_exhaustive]` and its fields are public, so a struct *literal* has to
/// name every field: adding a field (as `timestamp_unit` and `signed_headers`
/// did in 0.2.0) is a source break for that form. [`CustomScheme::new`] plus
/// the `with_*` builders
/// keep compiling across field additions because they fill in each new field's
/// `Default`, so prefer them in code you cannot edit in lockstep with a
/// release. Migrating a literal is one line — add
/// `timestamp_unit: TimestampUnit::Seconds` and `signed_headers: &[]` to keep
/// the pre-0.2.0 behavior.
/// Whether such a break may ship is bounded by this crate's version line: a
/// pre-1.0 release may break in a *minor* bump, and `cargo semver-checks` (CI
/// job `semver-checks`) enforces exactly that for
/// `constructible_struct_adds_field`.
///
/// **Ambiguity-check caveat.** Framework adapters (`tower`, `actix`) reject
/// duplicate headers whose values differ — but only for the headers the
/// crate's adapter ambiguity check scans, which for `Custom` is
/// [`signature_header`](Self::signature_header),
/// [`timestamp_header`](Self::timestamp_header), and every name declared in
/// [`signed_headers`](Self::signed_headers). If `signed_string` reads a header
/// the scheme did **not** declare there (e.g. a nonce, a URL, or a second
/// timestamp), duplicate values in it are **not** detected.
/// An attacker who can inject a conflicting value for such a header can cause
/// the proxy and verifier to disagree on the signed input — the exact
/// scenario `spec.md` §4.4 exists to prevent. When designing a custom scheme,
/// declare every header `signed_string` folds into the signed bytes in
/// `signed_headers`; a name left undeclared is a name the adapter cannot
/// guard against proxy disagreement on.
///
/// The second way the scan can reject a delivery the scheme would otherwise
/// accept is a declared name (in any of those three places) that is not a valid
/// HTTP field name: unlike every
/// built-in provider, these names are caller-typed and nothing validates
/// them, so a space or a stray control byte makes the scan report the header as
/// ambiguous for *every* request while `verify()` on a pair table still reads
/// it. See [`signature_header`](Self::signature_header).
///
/// [`PartialEq`] compares the declarative configuration only; `signed_string`
/// is excluded — function pointers have no meaningful or reliable equality.
#[must_use]
#[derive(Debug, Clone, Copy)]
pub struct CustomScheme {
    /// HMAC hash algorithm the sender uses.
    pub hash: HashAlg,
    /// Name of the header carrying the encoded signature.
    ///
    /// Must be a valid HTTP field name — `field-name = token`, RFC 9110 §5.1.
    /// Every built-in provider's header names are in-crate constants guarded
    /// by `providers::tests::signature_header_names_are_valid_http_field_names`,
    /// but this one is typed by the caller and nothing can check it before use.
    ///
    /// A name that is **not** a valid field name (a space, a stray control
    /// byte, a non-ASCII character) makes the `spec.md` §4.4 ambiguity scan
    /// report this header as ambiguous on *every* request — it cannot look up a
    /// name it cannot represent, and failing closed is the only safe answer,
    /// since a name no header map can hold can never be verified against
    /// either. The symptom is a `400` with an empty body from the `tower`/
    /// `actix` adapters, or a "reject this request" verdict for a caller
    /// running
    /// [`ambiguous_signature_header_in`](crate::ambiguous_signature_header_in)
    /// — including for a table with no duplicate in it at all. `verify()` on a
    /// pair table still *reads* the same name (the crate's `HeaderMap` impls
    /// compare names as plain case-insensitive strings), so a scheme with a
    /// malformed name is one where the ambiguity check rejects what `verify()`
    /// would have accepted. `Provider::Custom` is deliberately absent from the
    /// guard test (it is not name-constructible), so nothing but this note
    /// stands between a typo and a total, undiagnosable outage; the fail-closed
    /// direction is pinned by
    /// `tests::an_unparseable_declared_header_name_is_always_ambiguous`.
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
    ///
    /// Subject to the same "must be a valid HTTP field name" requirement as
    /// [`signature_header`](Self::signature_header), with the same
    /// reject-everything consequence when it is not.
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
    /// Additional headers [`signed_string`](Self::signed_string) reads, listed
    /// so the `spec.md` §4.4 duplicate-ambiguity scan covers them (issue #395).
    ///
    /// The adapters (and the public
    /// [`ambiguous_signature_header_in`](crate::ambiguous_signature_header_in))
    /// scan [`signature_header`](Self::signature_header) and
    /// [`timestamp_header`](Self::timestamp_header) regardless; this field is
    /// how a scheme says which *other* headers its closure folds into the
    /// signed bytes — a nonce, a request URL, `content-type`, a second
    /// timestamp. A conflicting duplicate of a declared name is rejected
    /// before any signature work, exactly as for a built-in provider's own
    /// signing headers. De-duplicated against the two declared names
    /// (ASCII-case-insensitively, the way header names compare) and in list
    /// order, so naming `signature_header` here again scans it once and
    /// reports it under its `signature_header` spelling.
    ///
    /// **Only what is declared is scanned.** A header the closure reads but
    /// this list does not name still gets first-match lookup with no duplicate
    /// detection — see the struct-level ambiguity caveat. The declaration is
    /// the caller's, because nothing outside the closure can enumerate it:
    /// `signed_string` is a plain `fn`, so no request field and no crate API
    /// can say what it reads.
    ///
    /// Each entry must be a valid HTTP field name (`field-name = token`, RFC
    /// 9110 §5.1) for the same reason
    /// [`signature_header`](Self::signature_header) must: an unparseable name
    /// cannot be looked up, so the scan fails closed and reports it ambiguous
    /// on **every** request (a `400` from the adapters). Nothing validates the
    /// entries before use, so this note plus
    /// `tests::an_unparseable_declared_signed_header_name_is_always_ambiguous`
    /// are what stand between a typo and an outage.
    pub signed_headers: &'static [&'static str],
    /// Builds the exact byte string the sender HMACs, from the request
    /// headers and the **raw** body bytes. Read any additional signed inputs
    /// (timestamps, URL context) out of `headers`; never re-serialize or
    /// normalize `raw_body`.
    ///
    /// **Note:** Every header this function reads beyond
    /// [`signature_header`](Self::signature_header) and
    /// [`timestamp_header`](Self::timestamp_header) must also be listed in
    /// [`signed_headers`](Self::signed_headers), or the framework adapters'
    /// duplicate-header ambiguity check will **not** cover it — see the
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
            && self.signed_headers == other.signed_headers
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
        self.signed_headers.hash(state);
    }
}

impl CustomScheme {
    /// Creates a scheme from the required fields, leaving the optional
    /// `timestamp_header` and `prefix` unset (`None`), `signed_headers`
    /// empty, and `timestamp_unit` at its default of [`TimestampUnit::Seconds`].
    ///
    /// Configure the optional fields with
    /// [`CustomScheme::with_timestamp_header`],
    /// [`CustomScheme::with_timestamp_unit`],
    /// [`CustomScheme::with_prefix`], and
    /// [`CustomScheme::with_signed_headers`] when the sender's scheme uses
    /// them.
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
            signed_headers: &[],
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

    /// Declares the extra headers `signed_string` reads, so the `spec.md`
    /// §4.4 duplicate-ambiguity scan covers them (issue #395).
    ///
    /// The scan already covers [`signature_header`](Self::signature_header)
    /// and [`timestamp_header`](Self::timestamp_header); this is how a scheme
    /// says which *other* headers its closure folds into the signed bytes — a
    /// nonce, `content-type`, a request URL. Without the declaration the
    /// adapters see only first-match lookup for those names, so an
    /// intermediary can prepend a second value and have the verifier
    /// sign-check one value while an upstream validator saw the other.
    ///
    /// Declare **every** header the closure reads; a name omitted here is
    /// exactly the residual carve-out
    /// [`spec.md`](https://github.com/SlopMaster2/webhook-verify/blob/master/spec.md)
    /// §4.4 leaves behind. Each entry must be a valid HTTP field name (RFC
    /// 9110 §5.1) or the scan fails closed and reports it ambiguous on every
    /// request — see [`signature_header`](Self::signature_header).
    ///
    /// # Example
    ///
    /// A scheme whose signed bytes fold in `x-request-id` alongside the body:
    ///
    /// ```
    /// use webhook_verify::{CustomScheme, Encoding, HashAlg};
    ///
    /// let scheme = CustomScheme::new(
    ///     HashAlg::Sha256,
    ///     "X-Webhook-Sig",
    ///     Encoding::Hex,
    ///     |headers, raw_body| {
    ///         let id = headers.get("X-Request-Id").unwrap_or_default();
    ///         let mut signed = Vec::with_capacity(id.len() + 1 + raw_body.len());
    ///         signed.extend_from_slice(id.as_bytes());
    ///         signed.push(b':');
    ///         signed.extend_from_slice(raw_body);
    ///         signed
    ///     },
    /// )
    /// .with_signed_headers(&["X-Request-Id"]);
    ///
    /// assert_eq!(scheme.signed_headers, ["X-Request-Id"].as_slice());
    /// ```
    pub fn with_signed_headers(mut self, signed_headers: &'static [&'static str]) -> Self {
        self.signed_headers = signed_headers;
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
    // built-in timestamped schemes report. Its value is parsed below, still
    // *before* the signature comparison: every built-in timestamped provider
    // does the same (all header parsing up front, `check_replay` only after a
    // signature verifies, `spec.md` §3), so an unparseable timestamp is
    // reported as a malformed header rather than as a forged signature. Only
    // the tolerance check is deferred. Pinned by
    // `tests::malformed_timestamp_outranks_a_well_formed_forged_signature`.
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

    // Each base64 arm below decodes with exactly the one engine its variant
    // names. The variants must not be loosened into "try every engine": a
    // scheme is the caller's declaration of the sender's wire format, and the
    // digest-length check that follows is the only thing standing between an
    // over-permissive decoder and a signature that verifies under a
    // configuration nobody asked for. `Base64`'s reason string is left as it
    // shipped — it is pre-1.0 message text callers may match on — while the
    // variants added here name the vocabulary they expect, so a caller who
    // configures the wrong one learns which wire shape actually arrived
    // instead of only that it was "not valid base64" (issue #329).
    let bytes = match scheme.encoding {
        Encoding::Hex => hex::decode(encoded).map_err(|_| VerifyError::BadEncoding {
            reason: "signature is not valid hexadecimal",
        })?,
        Encoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid base64",
            })?,
        Encoding::Base64Url => base64::engine::general_purpose::URL_SAFE
            .decode(encoded)
            .map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid padded URL-safe base64",
            })?,
        Encoding::Base64NoPad => base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid unpadded standard base64",
            })?,
        Encoding::Base64UrlNoPad => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| VerifyError::BadEncoding {
                reason: "signature is not valid unpadded URL-safe base64",
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
    use base64::Engine as _;
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
            signed_headers: &[],
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
            signed_headers: &[],
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
            signed_headers: &[],
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
            signed_headers: &[],
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
            signed_headers: &[],
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

    /// The timestamp is *parsed* before the signature is compared, even
    /// though the replay *window* is checked after — the same split every
    /// built-in timestamped provider uses (§3), where all header parsing
    /// happens up front so a request that cannot be parsed is reported as
    /// such rather than as a forgery.
    ///
    /// The forged signature here is well-formed (right prefix, right hex
    /// length) so that only its *value* is wrong: it is what
    /// `SignatureMismatch` reports on its own, which is what makes the two
    /// assertions below distinguish the two possible orders.
    #[test]
    fn malformed_timestamp_outranks_a_well_formed_forged_signature() {
        let forged = format!("sha256={}", "0".repeat(64));

        // Only the signature is wrong: the forged digest is reported.
        let mismatched = verify_custom(
            &ts_scheme_config(),
            &[
                (ts_scheme::HEADER.to_string(), forged.clone()),
                (
                    ts_scheme::TS_HEADER.to_string(),
                    ts_scheme::TIMESTAMP.to_string(),
                ),
            ],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(mismatched, Err(VerifyError::SignatureMismatch));

        // Same forged signature, now alongside an unparseable timestamp: the
        // timestamp parse still runs first, so the request is reported as
        // malformed rather than as a mismatch.
        let malformed = verify_custom(
            &ts_scheme_config(),
            &[
                (ts_scheme::HEADER.to_string(), forged),
                (ts_scheme::TS_HEADER.to_string(), "not-a-number".to_string()),
            ],
            ts_scheme::PING_BODY,
            ts_scheme::SECRET,
            clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
        );
        assert_eq!(
            malformed,
            Err(VerifyError::MalformedHeader {
                header: ts_scheme::TS_HEADER,
                reason: "timestamp is not a valid unix timestamp",
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

    // --- Base64 encoding variants (issues #329, #366) ------------------------
    //
    // `Encoding::Base64Url`, `Encoding::Base64NoPad` and
    // `Encoding::Base64UrlNoPad` close the three cells of
    // the alphabet × padding matrix `Encoding::Base64` alone could not express.
    // The vectors are RFC 4231 test case 2 / RFC 2202 test case 2 (the same
    // key/data as `rfc_vectors_across_hash_and_encoding_combinations` above),
    // re-encoded with Python's `base64` and independently cross-checked against
    // `openssl dgst -<alg> -mac HMAC -macopt key:Jefe -binary | base64`.
    //
    // RFC_KEY/RFC_DATA from this module's own test constants.

    /// The base64-family `Encoding` variants, so a battery that must run for
    /// each of them names one list rather than repeating it.
    const BASE64_VARIANTS: [Encoding; 3] = [
        Encoding::Base64Url,
        Encoding::Base64NoPad,
        Encoding::Base64UrlNoPad,
    ];

    /// RFC 2202 test case 2's SHA-1 digest, hex — the value whose base64
    /// spellings carry both a `/` and the URL-safe `_` that make the two
    /// alphabets distinguishable, so the tests that re-encode it per variant
    /// are testing the decoder rather than an accidental match.
    const SHA1_DIGEST: &str = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";

    /// A raw-body scheme over the RFC key/data, in one given encoding.
    fn raw_body_scheme(hash: HashAlg, encoding: Encoding) -> CustomScheme {
        CustomScheme {
            hash,
            signature_header: "X-Raw-Sig",
            timestamp_header: None,
            timestamp_unit: TimestampUnit::Seconds,
            encoding,
            prefix: None,
            signed_headers: &[],
            signed_string: |_headers, raw_body| raw_body.to_vec(),
        }
    }

    fn verify_raw(hash: HashAlg, encoding: Encoding, signature: &str) -> Result<(), VerifyError> {
        verify_custom(
            &raw_body_scheme(hash, encoding),
            &[("X-Raw-Sig", signature)],
            RFC_DATA,
            RFC_KEY,
            Default::default(),
        )
    }

    // 1. Official / reference vectors.
    //
    // SHA-256's URL-safe value is *identical* to its standard value — that
    // digest's base64 happens to contain none of `+`/`/` — and it is pinned
    // here on purpose, so the `Base64Url` row is not read as "the two
    // alphabets are the same thing". SHA-1 and SHA-512 both do carry the
    // characters that differ.

    #[test]
    fn base64_variants_verify_the_rfc_vectors() {
        // (hash, encoding, expected signature header value)
        let cases: &[(HashAlg, Encoding, &str)] = &[
            // URL-safe alphabet, padding kept. Differs from the `Base64` row
            // above only by `-`/`_` in place of `+`/`/`.
            (
                HashAlg::Sha1,
                Encoding::Base64Url,
                "7_zfauXrL6LSdBbV8YTfnCWafHk=",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64Url,
                "Fkt6e_z4GeLjlfvnO1bgo4e9ZCIugx_WECcM1-olBVSXWL91wFqZSm0DT2X48Ob9yuqxo01Ka0tjbgcKOLznNw==",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64Url,
                "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM=",
            ),
            // Standard alphabet, padding omitted.
            (
                HashAlg::Sha256,
                Encoding::Base64NoPad,
                "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM",
            ),
            (
                HashAlg::Sha1,
                Encoding::Base64NoPad,
                "7/zfauXrL6LSdBbV8YTfnCWafHk",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64NoPad,
                "Fkt6e/z4GeLjlfvnO1bgo4e9ZCIugx/WECcM1+olBVSXWL91wFqZSm0DT2X48Ob9yuqxo01Ka0tjbgcKOLznNw",
            ),
            // URL-safe alphabet *and* padding omitted — the cell no other
            // variant names (issue #366). SHA-1 and SHA-512 carry `-`/`_` where
            // the standard spelling carries `+`/`/`; SHA-256's URL-safe value is
            // identical to its standard one, pinned for the same reason as the
            // `Base64Url` row above.
            (
                HashAlg::Sha1,
                Encoding::Base64UrlNoPad,
                "7_zfauXrL6LSdBbV8YTfnCWafHk",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64UrlNoPad,
                "Fkt6e_z4GeLjlfvnO1bgo4e9ZCIugx_WECcM1-olBVSXWL91wFqZSm0DT2X48Ob9yuqxo01Ka0tjbgcKOLznNw",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64UrlNoPad,
                "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM",
            ),
        ];

        for &(hash, encoding, signature) in cases {
            let result = verify_custom(
                &raw_body_scheme(hash, encoding),
                &[("X-Raw-Sig", signature)],
                RFC_DATA,
                RFC_KEY,
                Default::default(),
            );
            assert_eq!(result, Ok(()), "{hash:?} + {encoding:?}");
        }
    }

    // 2. Negative: a wrong key still fails, and it fails as a mismatch rather
    //    than by decoding to something the comparison accepts.

    #[test]
    fn base64_variants_reject_the_wrong_secret() {
        for encoding in BASE64_VARIANTS {
            let result = verify_custom(
                &raw_body_scheme(HashAlg::Sha1, encoding),
                &[("X-Raw-Sig", reencode(SHA1_DIGEST, encoding).as_str())],
                RFC_DATA,
                "not the RFC key",
                Default::default(),
            );
            assert_eq!(
                result,
                Err(VerifyError::SignatureMismatch),
                "{encoding:?} + wrong secret"
            );
        }
    }

    // 3. Tamper: one flipped byte of the body breaks the signature.

    #[test]
    fn base64_variants_reject_a_tampered_body() {
        let mut tampered = RFC_DATA.to_vec();
        tampered[0] ^= 0x01;
        for encoding in BASE64_VARIANTS {
            let result = verify_custom(
                &raw_body_scheme(HashAlg::Sha1, encoding),
                &[("X-Raw-Sig", reencode(SHA1_DIGEST, encoding).as_str())],
                &tampered,
                RFC_KEY,
                Default::default(),
            );
            assert_eq!(
                result,
                Err(VerifyError::SignatureMismatch),
                "{encoding:?} + tampered body"
            );
        }
    }

    // 4. Replay: the window runs for a new encoding exactly as for `Hex` and
    //    `Base64`, so the variant only changes the decoder and nothing else.

    /// Re-encode an already-pinned hex digest in one of the base64-family
    /// variants, so one vector drives all of them. Cross-checked against
    /// Python's `base64.b64encode`/`urlsafe_b64encode` and
    /// `openssl ... | base64`.
    fn reencode(hex_digest: &str, encoding: Encoding) -> String {
        let Ok(bytes) = hex::decode(hex_digest) else {
            panic!("test vector {hex_digest:?} is not valid hex");
        };
        let engine = match encoding {
            Encoding::Base64Url => base64::engine::general_purpose::URL_SAFE,
            Encoding::Base64NoPad => base64::engine::general_purpose::STANDARD_NO_PAD,
            Encoding::Base64UrlNoPad => base64::engine::general_purpose::URL_SAFE_NO_PAD,
            other => panic!("{other:?} is not re-encoded here"),
        };
        engine.encode(bytes)
    }

    #[test]
    fn base64_variants_run_the_shared_replay_window() {
        for encoding in BASE64_VARIANTS {
            let scheme = CustomScheme {
                encoding,
                prefix: None,
                ..ts_scheme_config()
            };
            let headers = [
                (
                    ts_scheme::HEADER.to_string(),
                    reencode(ts_scheme::PING_SIG, encoding),
                ),
                (
                    ts_scheme::TS_HEADER.to_string(),
                    ts_scheme::TIMESTAMP.to_string(),
                ),
            ];

            // In-window: the authentic delivery verifies.
            assert_eq!(
                verify_custom(
                    &scheme,
                    &headers,
                    ts_scheme::PING_BODY,
                    ts_scheme::SECRET,
                    clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300))),
                ),
                Ok(()),
                "{encoding:?} in window"
            );

            // Same signature, one second past the window: the authenticated
            // delivery is now refused. `BadEncoding` instead would mean the
            // decoder, not the window, rejected it.
            assert_eq!(
                verify_custom(
                    &scheme,
                    &headers,
                    ts_scheme::PING_BODY,
                    ts_scheme::SECRET,
                    clocked_at(ts_scheme::TIMESTAMP + 301, Some(Duration::from_secs(300))),
                ),
                Err(VerifyError::TimestampOutOfTolerance {
                    skew: Duration::from_secs(301),
                    max_age: Duration::from_secs(300),
                }),
                "{encoding:?} out of window"
            );
        }
    }

    // 5. Malformed header: each variant rejects the wire shapes it does not
    //    name, so the new ones cannot drift into "any base64". This is the
    //    battery that fails if someone relaxes a variant to try several
    //    engines.

    #[test]
    fn base64_variants_reject_the_wire_shapes_they_do_not_name() {
        // Each value below is an *authentic* signature from the vector test
        // above, re-spelled into a shape the variant under test must not
        // accept. Each row pairs the value with the hash whose digest length
        // it really has, so a row fails only on the vocabulary it is about and
        // never incidentally on length — that is what makes the SHA-512
        // spellings a real alphabet test: they differ in `+`/`/` vs
        // `-`/`_`, whereas the SHA-256 vector's base64 happens to contain
        // neither and would pass under either alphabet.
        const PADDED_STANDARD_SHA1: &str = "7/zfauXrL6LSdBbV8YTfnCWafHk=";
        const PADDED_URL_SHA1: &str = "7_zfauXrL6LSdBbV8YTfnCWafHk=";
        const UNPADDED_STANDARD_SHA1: &str = "7/zfauXrL6LSdBbV8YTfnCWafHk";
        const PADDED_STANDARD_SHA512: &str = "Fkt6e/z4GeLjlfvnO1bgo4e9ZCIugx/WECcM1+olBVSXWL91wFqZSm0DT2X48Ob9yuqxo01Ka0tjbgcKOLznNw==";
        const PADDED_URL_SHA512: &str = "Fkt6e_z4GeLjlfvnO1bgo4e9ZCIugx_WECcM1-olBVSXWL91wFqZSm0DT2X48Ob9yuqxo01Ka0tjbgcKOLznNw==";
        const UNPADDED_STANDARD_SHA512: &str = "Fkt6e/z4GeLjlfvnO1bgo4e9ZCIugx/WECcM1+olBVSXWL91wFqZSm0DT2X48Ob9yuqxo01Ka0tjbgcKOLznNw";

        let cases: Vec<(HashAlg, Encoding, &str, &str)> = vec![
            // `Base64` keeps its old, narrow vocabulary: no URL-safe value,
            // no unpadded value.
            (
                HashAlg::Sha1,
                Encoding::Base64,
                PADDED_URL_SHA1,
                "URL-safe under Base64",
            ),
            (
                HashAlg::Sha1,
                Encoding::Base64,
                UNPADDED_STANDARD_SHA1,
                "unpadded under Base64",
            ),
            // `Base64Url` is not "base64": the standard alphabet's `+`/`/` are
            // not URL-safe characters.
            (
                HashAlg::Sha1,
                Encoding::Base64Url,
                PADDED_STANDARD_SHA1,
                "standard under Base64Url",
            ),
            // ... and it still requires padding.
            (
                HashAlg::Sha1,
                Encoding::Base64Url,
                UNPADDED_STANDARD_SHA1,
                "unpadded under Base64Url",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64Url,
                UNPADDED_STANDARD_SHA512,
                "unpadded + standard under Base64Url",
            ),
            // `Base64NoPad` is neither "base64, padding optional" nor
            // "base64url, padding optional".
            (
                HashAlg::Sha1,
                Encoding::Base64NoPad,
                PADDED_STANDARD_SHA1,
                "padded under Base64NoPad",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64NoPad,
                PADDED_URL_SHA512,
                "padded + URL-safe under Base64NoPad",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64NoPad,
                PADDED_STANDARD_SHA512,
                "padded + standard under Base64NoPad",
            ),
            // `Base64UrlNoPad` is "base64url, padding omitted" and nothing
            // else: the padded URL-safe spelling and the whole standard
            // alphabet are both out, in each of the two digest sizes that
            // actually spell the two alphabets differently.
            (
                HashAlg::Sha1,
                Encoding::Base64UrlNoPad,
                PADDED_URL_SHA1,
                "padded under Base64UrlNoPad",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64UrlNoPad,
                PADDED_URL_SHA512,
                "padded + URL-safe under Base64UrlNoPad",
            ),
            (
                HashAlg::Sha1,
                Encoding::Base64UrlNoPad,
                UNPADDED_STANDARD_SHA1,
                "unpadded + standard under Base64UrlNoPad",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64UrlNoPad,
                UNPADDED_STANDARD_SHA512,
                "unpadded + standard (sha-512) under Base64UrlNoPad",
            ),
            (
                HashAlg::Sha512,
                Encoding::Base64UrlNoPad,
                PADDED_STANDARD_SHA512,
                "padded + standard under Base64UrlNoPad",
            ),
            // Garbage, and the empty value, still fail on every variant.
            (
                HashAlg::Sha256,
                Encoding::Base64Url,
                "!!!!",
                "garbage under Base64Url",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64NoPad,
                "!!!!",
                "garbage under Base64NoPad",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64Url,
                "",
                "empty under Base64Url",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64NoPad,
                "",
                "empty under Base64NoPad",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64UrlNoPad,
                "!!!!",
                "garbage under Base64UrlNoPad",
            ),
            (
                HashAlg::Sha256,
                Encoding::Base64UrlNoPad,
                "",
                "empty under Base64UrlNoPad",
            ),
        ];

        for (hash, encoding, signature, label) in cases {
            let result = verify_raw(hash, encoding, signature);
            match result {
                Err(VerifyError::BadEncoding { .. }) | Err(VerifyError::MalformedHeader { .. }) => {
                }
                other => panic!("expected a decode failure for {label}, got {other:?}"),
            }
        }
    }

    /// The digest-length check still applies on the base64 variants: base64's
    /// trailing-bit slack means a value can decode cleanly at the wrong length,
    /// and that must still be `BadEncoding` rather than a comparison against a
    /// differently sized buffer.
    #[test]
    fn base64_variants_still_enforce_the_digest_length() {
        // A 20-byte (SHA-1) digest under a SHA-256 scheme: decodes fine in
        // the right alphabet and padding, wrong length for the hash. Each
        // value is the SHA-1 RFC vector in that variant's own spelling —
        // `reencode` rather than a literal, so a row cannot pass on the
        // vocabulary it is here to pin.
        for encoding in BASE64_VARIANTS {
            let result = verify_raw(HashAlg::Sha256, encoding, &reencode(SHA1_DIGEST, encoding));
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {encoding:?}, got {other:?}"),
            }
        }
    }

    /// Each variant renders a distinct, stable label, so an operator
    /// reading a `Display`ed scheme configuration can tell which wire shape
    /// was configured.
    #[test]
    fn base64_variants_have_distinct_display_labels() {
        let mut labels: Vec<String> = [
            Encoding::Hex,
            Encoding::Base64,
            Encoding::Base64Url,
            Encoding::Base64NoPad,
            Encoding::Base64UrlNoPad,
        ]
        .iter()
        .map(|encoding| encoding.to_string())
        .collect();
        labels.sort();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "encoding labels collide: {labels:?}");
    }

    /// The two no-pad variants' docs both claim that dropping the padding
    /// changes a digest's spelling on *every* input — "a 32-byte digest is 44
    /// characters padded and 43 unpadded" — because padding is not
    /// data-dependent. That claim is what makes a wrong no-pad variant fail
    /// loudly rather than slipping through on a digest whose two spellings
    /// happen to coincide, so the figures the prose states are asserted here
    /// against what the encoders actually produce, over several digest
    /// contents so nothing about the *input* can move them.
    #[test]
    fn base64_padding_is_never_data_dependent() {
        // (unpadded length, padded length) per digest, and the 3-byte digest
        // size whose first byte is varied below to show nothing about the
        // input reaches the two lengths.
        for (hash, unpadded, padded) in [
            (HashAlg::Sha1, 27, 28),
            (HashAlg::Sha256, 43, 44),
            (HashAlg::Sha512, 86, 88),
        ] {
            for (no_pad, with_pad) in [
                (
                    base64::engine::general_purpose::STANDARD_NO_PAD,
                    base64::engine::general_purpose::STANDARD,
                ),
                (
                    base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    base64::engine::general_purpose::URL_SAFE,
                ),
            ] {
                for first in [0x00u8, 0x55, 0xaa, 0xff] {
                    let mut bytes = vec![first; hash.digest_len()];
                    // Vary a trailing byte too, so the check is not satisfied by
                    // a fixed-length table that only ever saw one input.
                    bytes[hash.digest_len() - 1] = first.rotate_left(3);
                    assert_eq!(
                        no_pad.encode(&bytes).len(),
                        unpadded,
                        "{hash:?} unpadded length must not depend on the bytes"
                    );
                    assert_eq!(
                        with_pad.encode(&bytes).len(),
                        padded,
                        "{hash:?} padded length must not depend on the bytes"
                    );
                }
            }
        }
    }

    /// `Encoding::Base64Url`'s docs tell a caller how often the standard and
    /// URL-safe spellings of the *same* digest coincide, because that rate is
    /// what decides whether configuring the wrong variant is caught by the
    /// first authentic delivery or slips through. Those figures are a derived
    /// quantity — `(62/64)^groups`, where `groups` is the count of full 6-bit
    /// groups in the digest's base64 form — so a hand-written number in prose
    /// can be wrong with nothing failing, which is exactly what happened:
    /// the docs claimed "roughly seven digests in ten", while the real rates
    /// are 44% (SHA-1), 26% (SHA-256) and 7% (SHA-512).
    ///
    /// So the figures are derived here from the code — `digest_len()`, not a
    /// hand-written list — and required to appear in the variant's own doc
    /// comment. The formula is checked two ways: against the closed form, and
    /// against an exhaustive count over the first group's worth of values,
    /// which pins the exponent's per-group probability of *not* colliding.
    #[test]
    fn base64url_docs_state_the_derived_alphabet_collision_rate() {
        /// Probability that a digest with `groups` full 6-bit groups is
        /// spelled identically under the standard and URL-safe alphabets:
        /// each group is `+`/`/` with probability 2/64, and the alphabets
        /// agree on every other value.
        fn collision_rate(groups: u32) -> f64 {
            (62.0f64 / 64.0).powi(i32::try_from(groups).unwrap_or(i32::MAX))
        }

        // The per-group probability, counted rather than assumed: of the 64
        // possible 6-bit values, exactly `+` (62) and `/` (63) differ between
        // the two alphabets, so 62 values agree.
        let differing_values = (0u8..64)
            .filter(|group| {
                // A 3-byte input is exactly four 6-bit groups with no
                // padding, and `group << 2` places `group` in the leading one
                // with the rest zero — encoding a single byte instead would
                // only ever reach the low 6 bits of it.
                let bytes = [group << 2, 0, 0];
                base64::engine::general_purpose::STANDARD.encode(bytes)
                    != base64::engine::general_purpose::URL_SAFE.encode(bytes)
            })
            .count();
        assert_eq!(
            differing_values, 2,
            "expected exactly two 6-bit values (`+` and `/`) to differ between the standard \
             and URL-safe alphabets, found {differing_values} differing"
        );

        let source = include_str!("custom.rs");
        let docs = source
            .lines()
            .skip_while(|line| !line.contains("/// URL-safe base64 alphabet"))
            .take_while(|line| line.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !docs.is_empty(),
            "could not locate `Encoding::Base64Url`'s doc comment in `custom.rs`; this guard \
             is matching the first `/// URL-safe base64 alphabet` line, so update it if the \
             variant's docs were reworded"
        );

        for hash in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha512] {
            // `base64` encodes `8 * bits / 6` groups, of which the last one is
            // partial whenever the digest is not a whole number of 3-byte
            // quanta; only full groups can carry a `+`/`/` at all, since the
            // trailing partial group is zero-padded on the right.
            let groups = u32::try_from(hash.digest_len() * 8 / 6).unwrap_or(u32::MAX);
            let rate = collision_rate(groups);
            let percent = (rate * 100.0).round() as u32;
            assert!(
                docs.contains(&format!("**{percent}%**")),
                "`Encoding::Base64Url`'s docs must state **{percent}%** as the rate at which \
                 the two alphabets spell a {hash:?} digest identically \
                 (`(62/64)^{groups}` = {rate:.4}); it currently says:\n{docs}"
            );
        }
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
        assert!(
            scheme.signed_headers.is_empty(),
            "no extra signed headers are declared by default (issue #395)"
        );
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

    /// A caller-typed header name that is not a valid HTTP field name must
    /// read as *ambiguous on every request*, not as "nothing to scan"
    /// (issue #286).
    ///
    /// `signature_header_names` returns `CustomScheme`'s declared names —
    /// `signature_header`, `timestamp_header`, and the `signed_headers` list —
    /// verbatim, and unlike every built-in provider's in-crate constants no
    /// guard can check them before use — `Provider::Custom` is deliberately
    /// absent from `provider_list()`. The scan's answer for a name it cannot
    /// represent has to stay "ambiguous": a name no header map can hold can
    /// never be proven unambiguous, and returning `false` would be the
    /// tempting-but-wrong "fix" that turns a typo into a silently disabled
    /// §4.4 check.
    ///
    /// Pinned in both directions, and against the strongest form of the wrong
    /// behavior: the verdict holds for a completely **empty** header table,
    /// where there is provably no duplicate of anything. The last assertion is
    /// the operator-visible tell — `verify()` on a pair table still *reads* the
    /// malformed name and reaches the signature comparison, so the scan is the
    /// stricter of the two paths. That divergence is documented on
    /// [`CustomScheme::signature_header`]; this test keeps it from being
    /// "fixed" out from under that note.
    #[test]
    fn an_unparseable_declared_header_name_is_always_ambiguous() {
        use crate::ambiguous_signature_header_in;
        use crate::core::headers::is_valid_field_name;

        // A space is not a `tchar`, so this is not a `field-name = token`
        // (RFC 9110 §5.1) and no header map can hold it.
        const MALFORMED: &str = "X-Bad Name";
        assert!(!is_valid_field_name(MALFORMED));

        let scheme = CustomScheme::new(
            HashAlg::Sha256,
            MALFORMED,
            Encoding::Hex,
            |_headers, raw_body| raw_body.to_vec(),
        );

        // Even with nothing in the table at all: there is no duplicate here, and
        // the answer is still "ambiguous", because "cannot look the name up" is
        // not evidence of "no duplicate".
        let empty: Vec<(&str, &str)> = vec![];
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &empty),
            Some(MALFORMED)
        );

        // And the same scheme over a single-valued table naming the header
        // once — still ambiguous, not a pass.
        let single: Vec<(&str, &str)> = vec![(MALFORMED, "abcd")];
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &single),
            Some(MALFORMED)
        );

        // The control: the identical scheme with a *valid* name over the
        // identical single-valued table is unambiguous, so the assertions above
        // are about the name and not about the table or the scheme shape.
        let valid = CustomScheme {
            signature_header: "X-Bad-Name",
            ..scheme
        };
        assert!(is_valid_field_name("X-Bad-Name"));
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(valid), &single),
            None
        );

        // The `verify()` side of the documented divergence: a pair-table
        // `HeaderMap` compares names as plain case-insensitive strings, so it
        // finds the malformed name and gets as far as the signature check. The
        // `BadEncoding` here is the two-byte `abcd` failing the 32-byte digest
        // length — proof the lookup happened, not a rejection of the name.
        assert_eq!(
            verify_custom(
                &scheme,
                &single,
                b"payload",
                "shared-secret",
                Default::default()
            ),
            Err(VerifyError::BadEncoding {
                reason: "signature length does not match the hash algorithm's digest size"
            }),
            "`verify()` reads the malformed name; only the ambiguity scan refuses to"
        );
    }

    /// A malformed `timestamp_header` is scanned on the same terms as a
    /// malformed `signature_header` (issue #286).
    ///
    /// The two declared names reach the scan through the same
    /// `signature_header_names` arm, and the scan reports the *first* ambiguous
    /// entry in list order, so a mistyped timestamp name has to be reported on
    /// its own terms — not masked by, and not masking, a well-formed signature
    /// name.
    #[test]
    fn an_unparseable_timestamp_header_name_is_also_always_ambiguous() {
        use crate::ambiguous_signature_header_in;

        // A tab is not a `tchar` (RFC 9110 §5.1), so this cannot be a
        // `field-name`. The signature name is deliberately well-formed and
        // single-valued, so the malformed timestamp name is the only thing the
        // scan can report.
        let scheme = CustomScheme {
            timestamp_header: Some("X-Ts\t"),
            ..CustomScheme::new(
                HashAlg::Sha256,
                "X-Webhook-Sig",
                Encoding::Hex,
                |_headers, raw_body| raw_body.to_vec(),
            )
        };

        let single: Vec<(&str, &str)> = vec![("X-Webhook-Sig", "abcd")];
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &single),
            Some("X-Ts\t")
        );

        // And with nothing in the table at all, still the timestamp name.
        let empty: Vec<(&str, &str)> = vec![];
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &empty),
            Some("X-Ts\t")
        );

        // The control: the same scheme with a valid timestamp name over the same
        // single-valued table is unambiguous, so the two assertions above are
        // about the name and not about the table or the scheme shape.
        let valid = CustomScheme {
            timestamp_header: Some("X-Ts"),
            ..scheme
        };
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(valid), &single),
            None
        );
    }

    // --- signed_headers (issue #395) -----------------------------------------

    /// The declaration closes the §4.4 hole the issue is about, and the
    /// undeclared header is the carve-out that remains: a duplicate in a
    /// header the scheme listed in `signed_headers` is reported through the
    /// pair-table entry point (and through both adapters, pinned in
    /// `tower.rs`/`actix.rs`), while a duplicate the scheme never declared
    /// stays invisible to the scan — the honest "cannot tell" the struct docs
    /// promise.
    ///
    /// Both halves are pinned against `verify()` on the *same* table, so the
    /// scan's verdict cannot be confused with a signature or replay failure:
    /// the duplicated-but-unscanned tables verify, which is precisely why the
    /// declaration is the only thing that closes the door.
    #[test]
    fn a_declared_extra_signed_header_is_scanned_and_an_undeclared_one_is_not() {
        use crate::ambiguous_signature_header_in;

        let scheme = CustomScheme {
            signed_headers: &["X-Example-Nonce"],
            ..ts_scheme_config()
        };
        // The signed bytes are `{ts}.{body}` (see `ts_signed_string`), so a
        // nonce header neither helps nor breaks the signature: the only thing
        // that changes between the tables below is what the *scan* sees.
        let table = |extra: &[(&str, &str)]| {
            let mut headers: Vec<(String, String)> = vec![
                (
                    ts_scheme::HEADER.to_string(),
                    format!("sha256={}", ts_scheme::PING_SIG),
                ),
                (
                    ts_scheme::TS_HEADER.to_string(),
                    ts_scheme::TIMESTAMP.to_string(),
                ),
            ];
            headers.extend(
                extra
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.to_string())),
            );
            headers
        };
        let options = clocked_at(ts_scheme::TIMESTAMP, Some(Duration::from_secs(300)));

        // Declared, duplicated with differing values: the scan reports it —
        // and the very same table verifies, so the scan is what rejects.
        let declared_duplicate = table(&[("X-Example-Nonce", "one"), ("x-example-nonce", "two")]);
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &declared_duplicate),
            Some("X-Example-Nonce"),
        );
        assert_eq!(
            verify_custom(
                &scheme,
                &declared_duplicate,
                ts_scheme::PING_BODY,
                ts_scheme::SECRET,
                options.clone()
            ),
            Ok(()),
            "`verify()` sees one value; only the ambiguity scan refuses the duplicate"
        );

        // Declared, single-valued: unambiguous and verified.
        let declared_once = table(&[("X-Example-Nonce", "one")]);
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &declared_once),
            None,
        );
        assert_eq!(
            verify_custom(
                &scheme,
                &declared_once,
                ts_scheme::PING_BODY,
                ts_scheme::SECRET,
                options.clone()
            ),
            Ok(())
        );

        // Undeclared, duplicated: the documented residual. The scan does not
        // know the closure reads it (here it does not even), so it says
        // nothing — and the delivery verifies on first-match lookup.
        let undeclared_duplicate = table(&[("X-Unrelated", "one"), ("x-unrelated", "two")]);
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &undeclared_duplicate),
            None,
            "an undeclared header is the documented residual carve-out"
        );
        assert_eq!(
            verify_custom(
                &scheme,
                &undeclared_duplicate,
                ts_scheme::PING_BODY,
                ts_scheme::SECRET,
                options
            ),
            Ok(())
        );
    }

    /// A `signed_headers` entry that is not a valid HTTP field name fails
    /// closed as ambiguous on **every** request, on the same terms as a
    /// malformed `signature_header`/`timestamp_header` (issue #395): the scan
    /// cannot look up a name it cannot represent, and "nothing to scan" would
    /// read as "no duplicate".
    #[test]
    fn an_unparseable_declared_signed_header_name_is_always_ambiguous() {
        use crate::ambiguous_signature_header_in;
        use crate::core::headers::is_valid_field_name;

        // A space is not a `tchar`, so this is not a `field-name = token`
        // (RFC 9110 §5.1) and no header map can hold it.
        const MALFORMED: &str = "X-Bad Nonce";
        assert!(!is_valid_field_name(MALFORMED));

        let scheme = CustomScheme::new(
            HashAlg::Sha256,
            "X-Webhook-Sig",
            Encoding::Hex,
            |_headers, raw_body| raw_body.to_vec(),
        )
        .with_signed_headers(&["X-Good-Nonce", MALFORMED]);

        // Even with nothing in the table at all: there is no duplicate here,
        // and the answer is still "ambiguous".
        let empty: Vec<(&str, &str)> = vec![];
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &empty),
            Some(MALFORMED)
        );

        // And over a table that *does* carry a single value for it — the name
        // is reported, not skipped over in favour of a "found it, no duplicate"
        // reading.
        let single: Vec<(&str, &str)> = vec![("X-Webhook-Sig", "abcd"), (MALFORMED, "1")];
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(scheme), &single),
            Some(MALFORMED)
        );

        // The control: the same scheme shape with a valid declared name over
        // the identical single-valued table is unambiguous, so the assertions
        // above are about the name and not about the table or the scheme.
        let valid = CustomScheme {
            signed_headers: &["X-Good-Nonce"],
            ..scheme
        };
        assert!(is_valid_field_name("X-Good-Nonce"));
        assert_eq!(
            ambiguous_signature_header_in(Provider::Custom(valid), &single),
            None
        );
    }

    /// A name that `signed_headers` repeats — or repeats one of the other two
    /// declared headers, in any letter case — is scanned **once**, under the
    /// first spelling in list order. The scan is a linear pass over
    /// `signature_header_names`, so a duplicate entry would be looked up
    /// twice, and HTTP field names compare ASCII-case-insensitively, so
    /// `x-sig` and `X-Sig` are one header rather than two.
    #[test]
    fn signed_header_names_are_deduplicated_case_insensitively_in_list_order() {
        let scheme = CustomScheme::new(
            HashAlg::Sha256,
            "X-Example-Signature",
            Encoding::Hex,
            |_headers, raw_body| raw_body.to_vec(),
        )
        .with_timestamp_header("X-Example-Timestamp")
        .with_signed_headers(&[
            // Repeats the signature header in another case...
            "x-example-signature",
            // ...names a genuinely new one twice, in two cases...
            "X-Request-Id",
            "x-request-id",
            // ...and repeats the timestamp header.
            "x-example-timestamp",
        ]);

        assert_eq!(
            crate::providers::signature_header_names(&Provider::Custom(scheme)),
            ["X-Example-Signature", "X-Example-Timestamp", "X-Request-Id",],
        );
    }

    /// `signed_headers` changes what the scan does, so it is part of the
    /// scheme's declarative identity and must participate in `PartialEq` and
    /// `Hash` alongside the other declarative fields — a caller keying a map
    /// by scheme must not collapse two schemes that scan different headers.
    #[test]
    fn signed_headers_participates_in_equality_and_hash() {
        use crate::test_helpers::hash_of;

        let bare = CustomScheme::new(
            HashAlg::Sha256,
            "X-Webhook-Sig",
            Encoding::Hex,
            |_headers, raw_body| raw_body.to_vec(),
        );
        let declared = bare.with_signed_headers(&["X-Request-Id"]);
        let declared_other = bare.with_signed_headers(&["X-Other-Id"]);

        assert_ne!(bare, declared, "signed_headers participates in equality");
        assert_ne!(
            declared, declared_other,
            "signed_headers participates in equality"
        );
        assert_ne!(
            hash_of(&bare),
            hash_of(&declared),
            "signed_headers participates in Hash"
        );
        assert_ne!(
            hash_of(&declared),
            hash_of(&declared_other),
            "signed_headers participates in Hash"
        );

        // And the builder sets exactly what it says, leaving the other fields
        // (including `signed_string`) alone.
        assert_eq!(declared.signed_headers, ["X-Request-Id"].as_slice());
        assert_eq!(
            declared.signature_header,
            CustomScheme::new(
                HashAlg::Sha256,
                "X-Webhook-Sig",
                Encoding::Hex,
                |_headers, raw_body| raw_body.to_vec(),
            )
            .signature_header
        );
    }
}
