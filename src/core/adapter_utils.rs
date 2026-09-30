//! The `spec.md` §4.4 ambiguity check, and the utilities the framework
//! adapters (tower, actix) share so they cannot drift as new [`VerifyError`]
//! variants are added — or, with cross-secret rotation, as the list of keys an
//! adapter tries gains entries.
//!
//! Three kinds of item live here:
//!
//! * the ambiguity scan itself, unconditional: it is public API twice over —
//!   [`ambiguous_signature_header`] for a caller holding an `http::HeaderMap`
//!   (the `http` feature) and [`ambiguous_signature_header_in`] for a caller
//!   holding a name/value pair table (no features at all) — as well as the
//!   adapters' internal step, so one implementation serves all three;
//! * adapter-only glue ([`KeyRing`], `rejection_status`,
//!   `declared_content_length`), which carries a narrower `cfg` so nothing is
//!   dead code when no adapter is enabled.

#[cfg(any(feature = "tower", feature = "actix"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(any(feature = "tower", feature = "actix"))]
use core::fmt;

#[cfg(any(feature = "tower", feature = "actix"))]
use super::VerifyError;
use crate::core::headers::is_valid_field_name;
use crate::providers::{
    CONTENTFUL_SIGNED_HEADERS_HEADER, CONTENTFUL_SIGNED_HEADERS_SEPARATOR, Provider,
    provider_sent_duplicate_headers, signature_header_names,
};
#[cfg(any(feature = "tower", feature = "actix"))]
use crate::{Secret, VerifyOptions};

/// Raw, multi-value header access for the framework adapters.
///
/// The crate's [`HeaderMap`](crate::HeaderMap) trait intentionally exposes
/// only first-value lookup — `spec.md` §4.4 leaves duplicate detection to the
/// adapter layer. Adapters still need every value of a header to reject
/// conflicting duplicates, and they run on two different `http` versions
/// (tower/axum on `http` 1.x, actix-web 4 on `http` 0.2), so this private
/// trait unifies the multi-value iteration [`has_conflicting_duplicates`]
/// needs across both. Keeping the implementations here — rather than one
/// copy of the scan per adapter — is what guarantees a hardening applied to
/// one framework's ambiguity check cannot be skipped for the other.
pub(crate) trait MultiValueHeaders {
    /// Iterates over every value stored under `name`, in order, as the raw
    /// (unvalidated) bytes each header line carried.
    ///
    /// Returns `None` when `name` cannot be parsed into a valid header name.
    /// Callers must treat that as a fail-closed condition: an unparseable
    /// name can never be verified against, so reporting it as ambiguous is
    /// the only safe answer.
    fn get_all_bytes(&self, name: &str) -> Option<impl Iterator<Item = &[u8]>>;

    /// The first value stored under `name`, decoded as a string — but only
    /// when every byte is *visible ASCII*, per each framework's
    /// `HeaderValue::to_str` semantics.
    ///
    /// [`declared_content_length`] relies on this precise behavior: a value
    /// with non-visible-ASCII bytes must read as "no declared length", exactly
    /// as each adapter's historical helper read it, rather than as a string
    /// that happens to parse after trimming. Returns `None` for an unparseable
    /// header name, an absent header, or a non-visible-ASCII value — all
    /// fail-closed.
    fn get_first_str(&self, name: &str) -> Option<&str>;
}

#[cfg(feature = "http")]
impl MultiValueHeaders for ::http::HeaderMap {
    fn get_all_bytes(&self, name: &str) -> Option<impl Iterator<Item = &[u8]>> {
        // `HeaderName::from_bytes` normalizes to lowercase and rejects names
        // with invalid bytes, so an unparseable name is a `None` the shared
        // scan treats as fail-closed.
        let key = ::http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
        Some(self.get_all(&key).iter().map(::http::HeaderValue::as_bytes))
    }

    fn get_first_str(&self, name: &str) -> Option<&str> {
        let key = ::http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
        self.get(&key).and_then(|value| value.to_str().ok())
    }
}

#[cfg(feature = "actix")]
impl MultiValueHeaders for actix_web::http::header::HeaderMap {
    fn get_all_bytes(&self, name: &str) -> Option<impl Iterator<Item = &[u8]>> {
        let key = actix_web::http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
        Some(
            self.get_all(&key)
                .map(actix_web::http::header::HeaderValue::as_bytes),
        )
    }

    fn get_first_str(&self, name: &str) -> Option<&str> {
        let key = actix_web::http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
        self.get(&key).and_then(|value| value.to_str().ok())
    }
}

/// A header table held as a sequence of name/value pairs, viewed through
/// [`MultiValueHeaders`] so the one scan implementation serves it too.
///
/// Unlike the two framework maps, a pair table keeps *every* header line it was
/// handed — repeated names included — so a caller who built one holds the
/// second value the ambiguity check needs. The `HeaderMap` impls for
/// `Vec`/array/slice-of-pairs can therefore not see a duplicate, but the
/// caller's own table can; this view is what bridges that (issue #282).
///
/// Names are compared ASCII-case-insensitively, exactly as
/// [`HeaderMap`](crate::HeaderMap) does for the same types, so the scan
/// reaches the pairs a framework map would have reached. A name that is not a
/// valid field name reports `None` from both methods, which
/// [`has_conflicting_duplicates`] turns into *ambiguous* — the same fail-closed
/// answer the framework maps give for a name they cannot parse.
struct PairHeaders<'a, K, V>(&'a [(K, V)]);

impl<K, V> MultiValueHeaders for PairHeaders<'_, K, V>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn get_all_bytes(&self, name: &str) -> Option<impl Iterator<Item = &[u8]>> {
        if !is_valid_field_name(name) {
            return None;
        }
        Some(
            self.0
                .iter()
                .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_ref().as_bytes()),
        )
    }

    fn get_first_str(&self, name: &str) -> Option<&str> {
        if !is_valid_field_name(name) {
            return None;
        }
        self.0
            .iter()
            .find(|(k, _)| k.as_ref().eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_ref())
    }
}

/// Returns true when `name` occurs in `headers` more than once with *differing*
/// values — the ambiguity `spec.md` §4.4 requires rejecting — or false when it
/// occurs at most once (or not at all).
///
/// Values are compared as raw bytes: the scan must reject two lines carrying
/// different bytes, and opaque-byte values that could never parse as a
/// signature are still ambiguous when duplicated with differing bytes.
///
/// An unparseable name means the scan cannot see *any* value for it, so it
/// fails closed (reported as ambiguous) rather than skipping the name — a name
/// no header map can represent can never be verified against either, and
/// "nothing to scan" would read as "no duplicate". The arm is reachable from
/// two directions, and only one of them is a bug in this crate:
///
/// - names a *request* supplies (Contentful's signed-header list): attacker-
///   reachable, so failing closed is the only safe answer, and it is what
///   `unparseable_scan_name_reads_as_ambiguous` pins;
/// - names a *caller* supplies to a [`CustomScheme`](crate::CustomScheme),
///   which `signature_header_names` returns verbatim: a typo, a space, or a
///   stray control byte in a `signature_header` / `timestamp_header` therefore
///   makes the scan report that header ambiguous for **every** request, while
///   `verify()` on a pair table still reads the same name (the crate's own
///   `HeaderMap` impls compare names as plain case-insensitive strings). That
///   is fail-closed and deliberate — `verify()` must not be the weaker of the
///   two paths — but it is an operator footgun, so it is documented on
///   `CustomScheme` and pinned by
///   `custom::tests::an_unparseable_declared_header_name_is_always_ambiguous`.
///
/// For every *built-in* provider the names are in-crate constants, so the arm
/// is statically unreachable. What keeps it that way is
/// `providers::tests::signature_header_names_are_valid_http_field_names`, which
/// cannot cover `Provider::Custom` (not name-constructible, so absent from
/// `provider_list()`) — hence the documentation rather than a guard for that
/// one.
///
/// `pub(crate)` so each adapter's tests can pin the behavior of *its own*
/// `MultiValueHeaders` impl (the two `http` versions) against this predicate,
/// rather than only through a provider's static header list.
pub(crate) fn has_conflicting_duplicates<H: MultiValueHeaders + ?Sized>(
    headers: &H,
    name: &str,
) -> bool {
    let Some(mut values) = headers.get_all_bytes(name) else {
        return true;
    };
    let Some(first) = values.next() else {
        return false;
    };
    values.any(|value| *value != *first)
}

/// Returns the name of the signature header of `provider` that is ambiguous in
/// `headers`, or `None` when none is.
///
/// This is the single entry point the framework adapters use, so the
/// `spec.md` §4.4 ambiguity contract cannot be applied to one adapter and
/// skipped for the other. It has two halves:
///
/// 1. the **static** scan over [`signature_header_names`], which covers every
///    header a provider's scheme declares for all built-in providers, minus any
///    header the provider itself sends duplicated
///    ([`provider_sent_duplicate_headers`] — today Mollie's rotation window);
/// 2. a **dynamic** scan for [`Provider::Contentful`], whose
///    `x-contentful-signed-headers` value is self-describing — the headers it
///    names are folded into the canonical string, so a conflicting duplicate of
///    any of them is just as ambiguous as a duplicate of the signature header
///    itself. The list is in the request, so the adapter can enumerate it
///    instead of giving up on those headers (which is the remaining carve-out,
///    for [`Provider::Custom`], whose `signed_string` closure reads headers
///    nothing outside the closure can enumerate).
///
/// A rejection of the dynamic half is reported against
/// `x-contentful-signed-headers` — the request-controlled header that *named*
/// the ambiguous value, and the only name available as the `&'static str` the
/// [`VerifyError::MalformedHeader`] payload requires.
pub(crate) fn find_ambiguous_signature_header<H: MultiValueHeaders + ?Sized>(
    headers: &H,
    provider: &Provider,
) -> Option<&'static str> {
    // The provider-sent exemptions are intersected with the provider's own
    // header list rather than trusted as-is, so an entry naming a header the
    // scheme no longer reads cannot silently disable a scan that is still
    // needed.
    let sent_by_provider = provider_sent_duplicate_headers(provider);
    signature_header_names(provider)
        .iter()
        .copied()
        .filter(|name| !sent_by_provider.contains(name))
        .find(|name| has_conflicting_duplicates(headers, name))
        .or_else(|| dynamically_named_ambiguity(headers, provider))
}

/// The `spec.md` §4.4 ambiguity check for callers driving
/// [`verify()`](crate::verify()) against an
/// [`http::HeaderMap`](::http::HeaderMap) themselves.
///
/// Returns `Some(header)` when `provider`'s signature headers — or, for
/// [`Provider::Contentful`], any header its self-describing
/// `x-contentful-signed-headers` list names — arrive more than once with
/// *differing* values, and `None` otherwise. Identical repeats are not
/// ambiguous and return `None`.
///
/// [`HeaderMap`](crate::HeaderMap)'s lookup is first-match-only, so it
/// structurally cannot see a duplicate: a proxy that sees a different value
/// for the signature header than the verifier does is exactly the case
/// `spec.md` §4.4 requires rejecting, and a caller calling
/// [`verify()`](crate::verify()) directly has to perform that check itself.
/// The `tower` and `actix` adapters do it for you; this function is the same
/// code path, exported so a manual-extraction caller (the ordinary axum handler
/// shape, with no adapter in the path) can honor the same contract instead of
/// silently accepting an ambiguous request.
///
/// Reject with
/// [`VerifyError::MalformedHeader`](crate::VerifyError::MalformedHeader)
/// carrying the returned `header` and a `reason` of your choosing — the
/// adapters use [`VerifyError::AMBIGUOUS_HEADER_REASON`], which is the
/// exported spelling of that one string. Call it
/// *before* [`verify()`](crate::verify()):
///
/// ```
/// # #[cfg(feature = "http")] {
/// use webhook_verify::{
///     Provider, Secret, VerifyError, VerifyOptions, ambiguous_signature_header, verify,
/// };
///
/// let mut headers = ::http::HeaderMap::new();
/// headers.append(
///     "X-Hub-Signature-256",
///     ::http::HeaderValue::from_static("sha256=forged"),
/// );
/// headers.append(
///     "X-Hub-Signature-256",
///     ::http::HeaderValue::from_static("sha256=other"),
/// );
///
/// // Reject the ambiguous request instead of verifying whichever value the
/// // first-match lookup happens to return.
/// if let Some(header) = ambiguous_signature_header(Provider::GitHub, &headers) {
///     let error = VerifyError::MalformedHeader {
///         header,
///         reason: VerifyError::AMBIGUOUS_HEADER_REASON,
///     };
///     assert_eq!(
///         error.to_string(),
///         "malformed header `X-Hub-Signature-256`: \
///          header present multiple times with different values",
///     );
/// } else {
///     unreachable!("the two values differ, so the header is ambiguous");
/// }
///
/// // A single-valued request is unambiguous and proceeds to verification.
/// let mut clean = ::http::HeaderMap::new();
/// clean.insert(
///     "X-Hub-Signature-256",
///     ::http::HeaderValue::from_static(
///         "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
///     ),
/// );
/// assert_eq!(ambiguous_signature_header(Provider::GitHub, &clean), None);
/// assert_eq!(
///     verify(
///         Provider::GitHub,
///         &clean,
///         b"Hello, World!",
///         &Secret::new("It's a Secret to Everybody"),
///         VerifyOptions::default(),
///     ),
///     Ok(()),
/// );
/// # }
/// ```
///
/// The `Custom` carve-out documented on
/// [`CustomScheme`](crate::CustomScheme) is unchanged: for
/// [`Provider::Custom`] the scan covers only `signature_header` and
/// `timestamp_header`, and duplicates in any additional header a
/// `signed_string` closure reads are not detected. Note the second consequence
/// of those two names being caller-typed rather than in-crate constants: a name
/// that is not a valid HTTP field name (RFC 9110 §5.1) cannot be looked up, so
/// it is reported as ambiguous on *every* request — see
/// [`CustomScheme::signature_header`](crate::CustomScheme::signature_header).
///
/// One header is exempt for the opposite reason — the **provider** sends it
/// twice on purpose: [`Provider::Mollie`]'s `X-Mollie-Signature` arrives as two
/// header lines with different values for the 24 hours after a signing-secret
/// rotation (<https://docs.mollie.com/reference/webhooks-new>). Rejecting the
/// provider's own documented shape would make Mollie's rotation window unusable
/// through this check, so it is not reported as ambiguous. `verify()` still
/// reads the first value and verifies it, unchanged.
#[cfg(feature = "http")]
#[must_use]
pub fn ambiguous_signature_header(
    provider: Provider,
    headers: &::http::HeaderMap,
) -> Option<&'static str> {
    find_ambiguous_signature_header(headers, &provider)
}

/// The `spec.md` §4.4 ambiguity check for callers holding their headers as a
/// sequence of name/value pairs — `Vec<(String, String)>`,
/// `Vec<(&str, &str)>`, or any slice/array of pairs (`&table[..]`), the same
/// shapes [`HeaderMap`](crate::HeaderMap) is implemented for.
///
/// This is the entry point for the configurations
/// `ambiguous_signature_header` cannot serve: it needs neither the `http`
/// feature nor `std`, and it covers the header representation the crate's own
/// documentation uses. It exists because `spec.md` §4.4 obliges every caller of
/// [`verify()`](crate::verify()) to run the check, and `HeaderMap`'s
/// first-match-only lookup structurally cannot do it (issue #282).
///
/// Both entry points run the *same* scan, so a hardening here applies to the
/// `tower` and `actix` adapters and to `http::HeaderMap` callers too.
///
/// Returns `Some(header)` when `provider`'s signature headers — or, for
/// [`Provider::Contentful`], any header its self-describing
/// `x-contentful-signed-headers` list names — appear more than once in the
/// table with *differing* values, and `None` otherwise. Identical repeats are
/// not ambiguous. Names are matched ASCII-case-insensitively, the same way
/// [`HeaderMap`](crate::HeaderMap)` matches them for these types.
///
/// Reject with
/// [`VerifyError::MalformedHeader`](crate::VerifyError::MalformedHeader)
/// carrying the returned `header`, exactly as `ambiguous_signature_header`
/// documents (plain text rather than a link: that item is behind the `http`
/// feature and this one is not):
///
/// ```
/// use webhook_verify::{
///     Provider, Secret, VerifyError, ambiguous_signature_header_in, verify,
/// };
///
/// let headers: Vec<(String, String)> = vec![
///     ("x-hub-signature-256".to_string(), "sha256=one".to_string()),
///     // A proxy that appended its own value: two lines, one name, differing
///     // bytes — exactly what §4.4 requires rejecting.
///     ("x-hub-signature-256".to_string(), "sha256=two".to_string()),
/// ];
///
/// if let Some(header) = ambiguous_signature_header_in(Provider::GitHub, &headers) {
///     let error = VerifyError::MalformedHeader {
///         header,
///         reason: VerifyError::AMBIGUOUS_HEADER_REASON,
///     };
///     assert_eq!(
///         error.to_string(),
///         "malformed header `X-Hub-Signature-256`: \
///          header present multiple times with different values",
///     );
/// } else {
///     unreachable!("the two values differ, so the header is ambiguous");
/// }
///
/// // One line for the name, plus an unrelated header: unambiguous, and this is
/// // the table `verify()` reads.
/// let clean: Vec<(&str, &str)> = vec![
///     ("content-type", "application/json"),
///     (
///         "x-hub-signature-256",
///         "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
///     ),
/// ];
/// assert_eq!(ambiguous_signature_header_in(Provider::GitHub, &clean), None);
/// assert_eq!(
///     verify(
///         Provider::GitHub,
///         &clean,
///         b"Hello, World!",
///         &Secret::new("It's a Secret to Everybody"),
///         Default::default(),
///     ),
///     Ok(()),
/// );
/// ```
///
/// A table that keeps one value per name — `BTreeMap`, `HashMap`, anything with
/// one value per key — cannot use this: there is no second value to compare the
/// first against, which is a property of the `HeaderMap` impl rather than of
/// this check. The [`HeaderMap`](crate::HeaderMap) docs say the same. Route such
/// a request through the `tower`/`actix` adapter, or compare the values you hold
/// yourself.
///
/// The `Custom` carve-out and Mollie's rotation-window exemption documented on
/// `ambiguous_signature_header` apply here unchanged — it is the same scan
/// (plain text rather than a link: that item is behind the `http` feature and
/// this one is not).
#[must_use]
pub fn ambiguous_signature_header_in<K, V>(
    provider: Provider,
    headers: &[(K, V)],
) -> Option<&'static str>
where
    K: AsRef<str>,
    V: AsRef<str>,
{
    find_ambiguous_signature_header(&PairHeaders(headers), &provider)
}

/// The dynamic half of the ambiguity scan: headers the provider's scheme
/// reads that are enumerated by the request itself.
///
/// Today only Contentful has any, and it has exactly one source — the
/// self-describing `x-contentful-signed-headers` list. A list that is absent or
/// not decodable as visible ASCII contributes nothing here: `verify()` then
/// reports it missing or malformed on its own, so this scan never has to guess
/// at a shape it cannot read.
///
/// The list is split on [`CONTENTFUL_SIGNED_HEADERS_SEPARATOR`], the same
/// delimiter `contentful::verify` signs over, so the names enumerated here are
/// exactly the names that go into the canonical string. A second literal here
/// would degrade the whole half to a silent no-op: every element it looked up
/// would be a whole-element string no request carries, every duplicate check
/// would come back clean, and Contentful's dynamic ambiguity protection would
/// be gone with the test suite still green.
fn dynamically_named_ambiguity<H: MultiValueHeaders + ?Sized>(
    headers: &H,
    provider: &Provider,
) -> Option<&'static str> {
    if !matches!(provider, Provider::Contentful) {
        return None;
    }
    let list = headers.get_first_str(CONTENTFUL_SIGNED_HEADERS_HEADER)?;
    // Empty names are skipped rather than reported here: `verify()` rejects a
    // list containing one as `MalformedHeader` on the list header itself, and
    // an empty name can never match a real header anyway.
    let ambiguous = list
        .split(CONTENTFUL_SIGNED_HEADERS_SEPARATOR)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .any(|name| has_conflicting_duplicates(headers, name));
    ambiguous.then_some(CONTENTFUL_SIGNED_HEADERS_HEADER)
}

/// The request's declared `Content-Length`, when present and decodable.
///
/// Surrounding optional whitespace is stripped first, so an OWS-padded value
/// is the same declared length as its bare form. That is deliberate and is the
/// one respect in which this parse differs from `parse_unsigned_decimal` in
/// `replay.rs`, which rejects whitespace outright: RFC 9110 §5.5 defines a
/// field value as running from its first to its last non-OWS octet, and OWS is
/// `SP`/`HTAB` only, so a padded `Content-Length` is a correctly-spelled
/// header rather than a malformed one.
///
/// After that, the digits must be exactly the canonical `1*DIGIT` grammar HTTP
/// requires — no leading `+`/`-`, no radix prefix, no separator. Any other
/// value is treated as "no declared length": the request then falls through to
/// the post-buffer size check, which still bounds the verification work, and
/// the framing layer (`hyper`/`axum` on tower, actix-http on actix) has
/// already rejected inconsistent `Content-Length` fields. A non-visible-ASCII
/// value cannot reach here at all — [`MultiValueHeaders::get_first_str`] only
/// decodes visible ASCII, so it reads as "no declared length" one step
/// earlier. Shared between the adapters so the pre-buffer 413 guard cannot
/// drift.
#[cfg(any(feature = "tower", feature = "actix"))]
#[must_use]
pub(crate) fn declared_content_length<H: MultiValueHeaders + ?Sized>(headers: &H) -> Option<usize> {
    let value = headers.get_first_str("content-length")?.trim();
    // HTTP's Content-Length grammar is `1*DIGIT` (RFC 9110 §8.6) — no sign, no
    // radix prefix, no separator. Parse strictly, which is the same digit rule
    // `parse_unsigned_decimal` in `replay.rs` applies (Rust's `usize::from_str`
    // would otherwise silently accept a leading `+`, e.g. `+100`, which is not
    // a valid Content-Length). Any non-canonical value is treated as "no
    // declared length" and falls through to the post-buffer size check, which
    // still bounds the signature-verification work.
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// The ordered set of signing keys one adapter request may be verified
/// against (issue #259).
///
/// A provider may sign with the old or the new key for the length of its
/// rotation window, and the caller has to be able to accept both. The adapters
/// used to hold exactly one `Arc<Secret>`, which made that impossible: a
/// delivery signed by the not-yet-retired key was rejected as a forgery, and
/// the only way out was to abandon the adapter and hand-roll the request
/// lifecycle — while `verify_any()` and the crate's own "prefer the layer"
/// advice said otherwise.
///
/// Keys are tried in the order given — index 0 is the primary secret from
/// `VerifyLayer::new` / `WebhookConfig::new`, and the rest are the fallbacks
/// added by `with_fallback_secrets` — and verification delegates to the same
/// `verify_ref` / `verify_any_ref` pair, with the same `spec.md` §2.1 error
/// aggregation, that `verify()` / `verify_any()` use. Sharing the type is what
/// keeps the two adapters from drifting: an aggregation rule or a
/// secret-shape rule added for one framework is then already the other's.
///
/// The slice is behind an `Arc` so cloning a layer (or the middleware built
/// from it, as tower runners routinely do) never copies key material, and
/// verification borrows it in place — no per-request `Vec` or `Secret` clone.
#[cfg(any(feature = "tower", feature = "actix"))]
#[derive(Clone)]
pub(crate) struct KeyRing {
    /// Index 0 is the primary key; the remainder are fallbacks, in order.
    keys: Arc<[Secret]>,
}

#[cfg(any(feature = "tower", feature = "actix"))]
impl KeyRing {
    /// A ring holding exactly one key — the configuration every adapter had
    /// before `with_fallback_secrets` existed.
    pub(crate) fn new(secret: Secret) -> Self {
        Self {
            keys: Arc::from(Vec::from([secret])),
        }
    }

    /// Appends keys to try *after* the primary one, returning the new ring.
    ///
    /// Configuration-time only: this reallocates the ring, which is why the
    /// adapters take it by value in a builder method rather than mutating a
    /// ring a running server already cloned.
    pub(crate) fn with_fallbacks(self, fallbacks: impl IntoIterator<Item = Secret>) -> Self {
        let mut keys = Vec::from(&*self.keys);
        keys.extend(fallbacks);
        Self {
            keys: Arc::from(keys),
        }
    }

    /// Verifies one request against the ring, returning `Ok(())` if any key
    /// matches.
    ///
    /// A single-key ring takes `verify_ref` directly: that is provably what a
    /// one-element `verify_any` loop does (the loop's final report is
    /// `SignatureMismatch` when a usable key mismatched and the first
    /// `InvalidSecret` when the only key was unusable, which is exactly what
    /// that key's own `verify_ref` returned), and keeping the direct call means
    /// the default single-secret deployment runs the same code it always did,
    /// with no aggregation state on the hot path.
    pub(crate) fn verify(
        &self,
        provider: Provider,
        headers: &dyn crate::HeaderMap,
        raw_body: &[u8],
        options: &VerifyOptions,
    ) -> Result<(), VerifyError> {
        match &*self.keys {
            [only] => crate::providers::verify_ref(provider, headers, raw_body, only, options),
            keys => crate::providers::verify_any_ref(provider, headers, raw_body, keys, options),
        }
    }
}

#[cfg(any(feature = "tower", feature = "actix"))]
impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Secret`'s own `Debug` is redacted, so this reports only *how many*
        // keys are configured — useful when a rotation window is open, and
        // useless to an attacker.
        f.debug_list().entries(self.keys.iter()).finish()
    }
}

/// Maps a verification outcome to its rejection HTTP status code.
///
/// Returns the raw numeric status (400/401/500) rather than a framework's
/// `StatusCode` type because the tower adapter uses `http` 1.x while
/// actix-web 4 uses `http` 0.2 — two distinct types. Each adapter converts the
/// number to its own `StatusCode`, so the classification logic (and its
/// exhaustive match over the in-crate enum) lives in exactly one place.
///
/// | Class | Status | Rationale |
/// |---|---|---|
/// | `MissingHeader`, `MalformedHeader`, `BadEncoding` | `400` | Malformed request |
/// | `SignatureMismatch`, `TimestampOutOfTolerance` | `401` | Auth signal |
/// | `UnsupportedProvider`, `InvalidSecret`, `MissingContext` | `500` | Operator misconfiguration |
///
/// Adding a `VerifyError` variant will surface here at compile time so its
/// status class is chosen deliberately.
#[cfg(any(feature = "tower", feature = "actix"))]
#[must_use]
pub(crate) fn rejection_status(error: &VerifyError) -> u16 {
    match error {
        // Malformed request: missing/unparseable signature headers.
        VerifyError::MissingHeader { .. }
        | VerifyError::MalformedHeader { .. }
        | VerifyError::BadEncoding { .. } => 400,

        // Authentication signals: wrong signature or stale timestamp.
        VerifyError::SignatureMismatch | VerifyError::TimestampOutOfTolerance { .. } => 401,

        // Operator misconfiguration: unsupported/broken configuration, never
        // the requester's fault. Still rejected — fail closed.
        VerifyError::UnsupportedProvider
        | VerifyError::InvalidSecret { .. }
        | VerifyError::MissingContext { .. } => 500,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "tower", feature = "actix"))]
    use super::{KeyRing, rejection_status};
    // The helper itself is available to either adapter, but its tests here
    // build an `http` 1.x `HeaderMap`, so they are `http`-gated as well. The
    // `actix` feature does not enable `http` (actix carries its own 0.2 header
    // types), which is why this import needs the narrower gate than its
    // siblings above: with `--features actix` it was unused, and nothing in CI
    // built that combination (issue #335).
    #[cfg(all(feature = "http", any(feature = "tower", feature = "actix")))]
    use super::declared_content_length;
    #[cfg(any(feature = "tower", feature = "actix"))]
    use crate::VerifyError;
    #[cfg(all(not(feature = "std"), any(feature = "tower", feature = "actix")))]
    use crate::test_helpers::*;
    // The README doc-drift guards below build strings and slices of blocks, so
    // they need the same prelude the other test modules restore under `no_std`.
    #[cfg(all(not(feature = "std"), feature = "http"))]
    use crate::test_helpers::*;

    /// The shared key-ring logic (issue #259), pinned once so the tower and
    /// actix adapters — which differ only in their header map and status
    /// types — cannot drift on rotation semantics. Each adapter's own tests
    /// then cover the same cases as HTTP statuses.
    ///
    /// The `Vec<(String, String)>` `HeaderMap` impl is used rather than
    /// `::http::HeaderMap` so this module compiles (and tests) under the
    /// `actix`-only build, where the `http` feature is not enabled.
    #[cfg(any(feature = "tower", feature = "actix"))]
    mod key_ring {
        use super::KeyRing;
        use crate::{Provider, Secret, VerifyError, VerifyOptions, verify};

        /// GitHub's published `Hello, World!` vector
        /// (<https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>).
        const GENUINE: &str =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        const BODY: &[u8] = b"Hello, World!";
        const LIVE: &str = "It's a Secret to Everybody";
        const PREVIOUS: &str = "the previous signing secret";
        const UNRELATED: &str = "some other secret entirely";

        fn headers() -> Vec<(&'static str, &'static str)> {
            vec![("x-hub-signature-256", GENUINE)]
        }

        fn ring(secrets: &[&str]) -> KeyRing {
            match secrets {
                // A ring always has a primary key; the empty case cannot arise
                // from the fixtures below and falls back to a usable one.
                [] => KeyRing::new(Secret::new(LIVE)),
                [first, rest @ ..] => KeyRing::new(Secret::new(*first))
                    .with_fallbacks(rest.iter().map(|secret| Secret::new(*secret))),
            }
        }

        #[test]
        fn a_single_key_ring_matches_the_public_verify() {
            // The pre-rotation configuration: one key, one call, and exactly
            // the result `verify()` would have produced. Pinned because the
            // ring short-circuits to `verify_ref` for the single-key case, and
            // that shortcut has to stay equivalent to the whole-`verify_any`
            // path it stands in for.
            let keys = ring(&[LIVE]);
            for outcome in [
                verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &Secret::new(LIVE),
                    VerifyOptions::default(),
                ),
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
            ] {
                assert_eq!(outcome, Ok(()));
            }

            let keys = ring(&[UNRELATED]);
            assert_eq!(
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
                verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &Secret::new(UNRELATED),
                    VerifyOptions::default(),
                ),
                "a mismatching single key reports what `verify()` reports"
            );
        }

        #[test]
        fn a_delivery_signed_by_either_side_of_the_window_verifies() {
            // The rotation window: a delivery signed by the key that is *not*
            // the primary one must still be accepted, and adding a fallback
            // must not shadow the primary.
            let keys = ring(&[LIVE, PREVIOUS]);
            assert_eq!(
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
                Ok(()),
                "the primary key is what signed this delivery",
            );

            let keys = ring(&[PREVIOUS, LIVE]);
            assert_eq!(
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
                Ok(()),
                "and it verifies whichever side of the window it was signed with",
            );
        }

        #[test]
        fn a_ring_with_no_matching_key_is_a_signature_mismatch() {
            let keys = ring(&[UNRELATED, PREVIOUS]);
            assert_eq!(
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
                Err(VerifyError::SignatureMismatch),
            );
        }

        #[test]
        fn an_unusable_key_is_skipped_rather_than_aborting_the_search() {
            // `spec.md` §2.1: an unusable key is unusable *for this request*
            // only. A rotation list that picked up an empty/whitespace/NUL
            // entry still verifies against the healthy one.
            for unusable in ["", "  ", "\0\0"] {
                let keys = ring(&[unusable, LIVE]);
                assert_eq!(
                    keys.verify(
                        Provider::GitHub,
                        &headers(),
                        BODY,
                        &VerifyOptions::default(),
                    ),
                    Ok(()),
                    "{unusable:?} must be skipped, not reported",
                );
            }

            // An unusable key *after* the live one is equally harmless.
            let keys = ring(&[LIVE, ""]);
            assert_eq!(
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
                Ok(())
            );
        }

        #[test]
        fn a_mismatch_outranks_an_unusable_key() {
            // Well-formed-but-wrong is the definitive rejection signal, so an
            // unusable entry must not turn a forgery into an operator error.
            let keys = ring(&["", UNRELATED]);
            assert_eq!(
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
                Err(VerifyError::SignatureMismatch),
            );
        }

        #[test]
        fn an_all_unusable_ring_is_reported_as_operator_misconfiguration() {
            // Nothing usable at all: `InvalidSecret` (which both adapters
            // answer with 500), not `SignatureMismatch`.
            let keys = ring(&["", " \t "]);
            assert_eq!(
                keys.verify(
                    Provider::GitHub,
                    &headers(),
                    BODY,
                    &VerifyOptions::default(),
                ),
                Err(VerifyError::InvalidSecret {
                    reason: "secret is empty"
                }),
            );
        }

        #[test]
        fn a_structural_error_short_circuits_the_whole_ring() {
            // Header-shaped errors do not depend on the key, so they are
            // reported immediately rather than after exhausting the list.
            let keys = ring(&[UNRELATED, PREVIOUS]);
            let empty: Vec<(&str, &str)> = Vec::new();
            assert_eq!(
                keys.verify(Provider::GitHub, &empty, BODY, &VerifyOptions::default()),
                Err(VerifyError::MissingHeader {
                    header: "X-Hub-Signature-256"
                }),
            );
        }

        #[test]
        fn debug_lists_the_keys_without_revealing_them() {
            let keys = ring(&[LIVE, PREVIOUS]);
            let debug = format!("{keys:?}");
            assert!(
                !debug.contains(LIVE) && !debug.contains(PREVIOUS),
                "Debug must not render key material: {debug}"
            );
            // The count is the useful part in a log line: it says whether a
            // rotation window is open.
            assert_eq!(debug.matches("redacted").count(), 2, "{debug}");
        }
    }

    #[cfg(any(feature = "tower", feature = "actix"))]
    fn status_of(error: VerifyError) -> u16 {
        rejection_status(&error)
    }

    #[cfg(any(feature = "tower", feature = "actix"))]
    #[test]
    fn malformed_request_class_maps_to_400() {
        assert_eq!(
            status_of(VerifyError::MissingHeader {
                header: "X-Signature"
            }),
            400
        );
        assert_eq!(
            status_of(VerifyError::MalformedHeader {
                header: "X-Signature",
                reason: "boom"
            }),
            400
        );
        assert_eq!(status_of(VerifyError::BadEncoding { reason: "boom" }), 400);
    }

    #[cfg(any(feature = "tower", feature = "actix"))]
    #[test]
    fn auth_signal_class_maps_to_401() {
        assert_eq!(status_of(VerifyError::SignatureMismatch), 401);
        assert_eq!(
            status_of(VerifyError::TimestampOutOfTolerance {
                skew: std::time::Duration::from_secs(1000),
                max_age: std::time::Duration::from_secs(300),
            }),
            401
        );
    }

    #[cfg(any(feature = "tower", feature = "actix"))]
    #[test]
    fn operator_misconfiguration_class_maps_to_500() {
        // UnsupportedProvider keeps its 500 class even once a feature (e.g.
        // `paypal`) implements the provider — the mapping is about the error
        // class, not the current build's provider set.
        assert_eq!(status_of(VerifyError::UnsupportedProvider), 500);
        assert_eq!(
            status_of(VerifyError::InvalidSecret { reason: "boom" }),
            500
        );
        assert_eq!(
            status_of(VerifyError::MissingContext { reason: "boom" }),
            500
        );
    }

    /// Contentful's self-describing signed-header list: the ambiguity scan must
    /// follow it into the request, not stop at the three fixed headers.
    ///
    /// Mirrors the `http` 1.x header map; `src/actix.rs` pins the actix
    /// (`http` 0.2) side of the same helper end-to-end.
    #[cfg(feature = "http")]
    mod contentful_dynamic_scan {
        use super::super::find_ambiguous_signature_header;
        use crate::Provider;
        // The provider's own constant, not a re-spelling of it: these fixtures
        // exercise the scan against the header `contentful::verify` actually
        // reads, so they cannot quietly keep testing a name the provider no
        // longer uses.
        use crate::providers::CONTENTFUL_SIGNED_HEADERS_HEADER as LIST;

        fn headers_with(pairs: &[(&str, &str)]) -> ::http::HeaderMap {
            let mut headers = ::http::HeaderMap::new();
            for (name, value) in pairs {
                headers.append(
                    ::http::header::HeaderName::from_bytes(name.as_bytes())
                        .unwrap_or_else(|_| panic!("{name:?} must be a valid field name")),
                    ::http::HeaderValue::from_bytes(value.as_bytes())
                        .unwrap_or_else(|_| panic!("{value:?} must be a valid header value")),
                );
            }
            headers
        }

        /// A well-formed Contentful delivery: the list names `content-type` and
        /// `x-contentful-topic`, each present exactly once.
        fn clean() -> ::http::HeaderMap {
            headers_with(&[
                ("x-contentful-signature", "ab"),
                (
                    LIST,
                    "content-type,x-contentful-timestamp,x-contentful-topic",
                ),
                ("x-contentful-timestamp", "1704391525000"),
                ("content-type", "application/json"),
                ("x-contentful-topic", "ContentManagement.Entry.publish"),
            ])
        }

        #[test]
        fn clean_delivery_is_not_ambiguous() {
            assert_eq!(
                find_ambiguous_signature_header(&clean(), &Provider::Contentful),
                None
            );
        }

        #[test]
        fn conflicting_duplicate_of_a_listed_header_is_rejected() {
            // The whole point of the dynamic half: `content-type` is folded into
            // the canonical string, so two differing copies of it are exactly as
            // ambiguous as two copies of the signature header. Reported against
            // the list header, the only name the error payload can carry.
            let mut headers = clean();
            headers.append(
                "content-type",
                ::http::HeaderValue::from_static("text/plain"),
            );
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                Some(LIST)
            );

            // Any position in the list is covered, not just the first name.
            let mut last = clean();
            last.append(
                "x-contentful-topic",
                ::http::HeaderValue::from_static("ContentManagement.Entry.unpublish"),
            );
            assert_eq!(
                find_ambiguous_signature_header(&last, &Provider::Contentful),
                Some(LIST)
            );
        }

        #[test]
        fn identical_duplicate_of_a_listed_header_is_not_ambiguous() {
            // Nothing is being smuggled: two identical values resolve to the
            // same header everywhere, so the delivery still verifies.
            let mut headers = clean();
            headers.append(
                "content-type",
                ::http::HeaderValue::from_static("application/json"),
            );
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                None
            );
        }

        #[test]
        fn duplicate_of_an_unlisted_header_is_not_rejected() {
            // Only headers the delivery *declares* as signed are scanned. An
            // unlisted header is not signing material, so ambiguity there is
            // out of this check's scope.
            let mut headers = clean();
            headers.append("x-unrelated", ::http::HeaderValue::from_static("a"));
            headers.append("x-unrelated", ::http::HeaderValue::from_static("b"));
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                None
            );
        }

        #[test]
        fn a_conflicting_duplicate_of_the_list_header_itself_is_rejected() {
            // The one ambiguity the dynamic half structurally *cannot* see: it
            // reads the list header's first value only, so a differing second
            // copy names headers this scan never learns about. Only the static
            // half catches it, which is why the list header has to stay in
            // `signature_header_names(Contentful)` — pinned here so dropping it
            // cannot silently reopen this from the other direction.
            let mut headers = clean();
            headers.append(LIST, ::http::HeaderValue::from_static("content-type"));
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                Some(LIST),
                "a differing second copy of the signed-headers list is ambiguous \
                 and only the static half can see it"
            );
        }

        #[test]
        fn a_list_naming_an_absent_header_does_not_reject() {
            // `verify()` reports a list referencing a header the request does
            // not carry as `MalformedHeader`; the ambiguity scan must not
            // pre-empt that with a different diagnosis for the same request.
            let headers = headers_with(&[
                ("x-contentful-signature", "ab"),
                (LIST, "content-type,x-contentful-absent"),
                ("content-type", "application/json"),
            ]);
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                None
            );
        }

        #[test]
        fn empty_names_in_the_list_are_skipped_not_scanned() {
            // An empty name can never match a real header, and `verify()`
            // rejects the list shape itself; scanning it would report an
            // ambiguity the request does not have.
            let headers = headers_with(&[
                (LIST, "content-type,,x-contentful-topic"),
                ("content-type", "application/json"),
            ]);
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                None
            );
        }

        #[test]
        fn missing_or_undecodable_list_contributes_nothing() {
            // No list at all: `verify()` reports `MissingHeader` on its own.
            assert_eq!(
                find_ambiguous_signature_header(
                    &headers_with(&[("x-contentful-signature", "ab")]),
                    &Provider::Contentful
                ),
                None
            );
            // A non-visible-ASCII list value is unreadable to both this scan and
            // `verify()`, which reports it as a malformed/missing header. The
            // scan must not guess at the names it cannot read.
            let mut headers = clean();
            headers.insert(
                LIST,
                ::http::HeaderValue::from_bytes(b"content-type,\xff")
                    .unwrap_or_else(|_| panic!("0xFF is a permitted header-value byte")),
            );
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                None
            );
        }

        #[test]
        fn static_scan_still_applies_to_contentful_and_the_dynamic_half_is_contentful_only() {
            // The static half is unchanged: a conflicting duplicate of any of
            // the three fixed headers is still caught, and reported against
            // that header rather than the list.
            let mut headers = clean();
            headers.append(
                "x-contentful-timestamp",
                ::http::HeaderValue::from_static("1704391525001"),
            );
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Contentful),
                Some("x-contentful-timestamp")
            );

            // Another provider's delivery carrying a Contentful-shaped list must
            // not be scanned through it — the list is not signing material for
            // any other scheme.
            let mut github = headers_with(&[("x-hub-signature-256", "sha256=ab")]);
            github.insert(LIST, ::http::HeaderValue::from_static("content-type"));
            github.append(
                "content-type",
                ::http::HeaderValue::from_static("application/json"),
            );
            github.append(
                "content-type",
                ::http::HeaderValue::from_static("text/plain"),
            );
            assert_eq!(
                find_ambiguous_signature_header(&github, &Provider::GitHub),
                None
            );
        }
    }

    /// Mollie is the one provider that sends its own signature header twice
    /// (issue #245), so the scan must not read the provider's documented
    /// rotation shape as a smuggled duplicate — while every other provider
    /// stays fully scanned.
    #[cfg(feature = "http")]
    mod provider_sent_duplicates {
        use super::super::find_ambiguous_signature_header;
        #[cfg(not(feature = "std"))]
        use crate::test_helpers::*;
        use crate::{Provider, Secret, ambiguous_signature_header, verify};

        /// Spelled as on the wire, like every other request fixture in this
        /// module: a rename of the provider's own constant is then a test
        /// failure rather than a scan that quietly follows a name no request
        /// carries.
        const MOLLIE_SIGNATURE_HEADER: &str = "X-Mollie-Signature";
        /// Box's primary signature header, spelled as on the wire (see above).
        const BOX_PRIMARY_SIGNATURE_HEADER: &str = "BOX-SIGNATURE-PRIMARY";
        const FORGED: &str =
            "sha256=0000000000000000000000000000000000000000000000000000000000000000";
        const BODY: &[u8] = b"{\"resource\":\"event\",\"id\":\"event_GvJ8WHrp5isUdRub9CJyH\"}";
        const LIVE_SECRET: &str = "current-signing-secret";
        const PREVIOUS_SECRET: &str = "previous-signing-secret";

        /// Mollie's documented signing construction (`spec.md` §3): the
        /// `sha256=`-prefixed hex HMAC-SHA256 of the raw body. Computed here
        /// rather than hardcoded so the fixture and the assertion about which
        /// value `verify()` reads cannot drift apart.
        fn mollie_signature(secret: &str, body: &[u8]) -> String {
            use hmac::{Hmac, KeyInit, Mac};
            use sha2::Sha256;

            let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
                Ok(mac) => mac,
                // Unreachable for a constant test secret (HMAC accepts
                // arbitrary-length keys); kept panic-free to honor the
                // crate-wide clippy deny on unwrap/expect.
                Err(_) => panic!("HMAC-SHA256 with a constant test secret cannot fail"),
            };
            mac.update(body);
            format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
        }

        /// The two header values Mollie sends for 24 hours after a secret roll,
        /// verbatim in shape from
        /// <https://docs.mollie.com/reference/webhooks-new> ("Updating a live
        /// signing secret"): two `X-Mollie-Signature` lines, one per active
        /// secret, with different values.
        fn rotation_window() -> (String, String) {
            (
                mollie_signature(LIVE_SECRET, BODY),
                mollie_signature(PREVIOUS_SECRET, BODY),
            )
        }

        /// A single-valued Mollie delivery.
        fn single_valued(value: &str) -> ::http::HeaderMap {
            let mut headers = ::http::HeaderMap::new();
            headers.insert(
                MOLLIE_SIGNATURE_HEADER,
                ::http::HeaderValue::from_str(value)
                    .unwrap_or_else(|_| panic!("a computed signature is a valid header value")),
            );
            headers
        }

        /// Mollie's rotation window as an `http::HeaderMap`, in the order the
        /// provider sends it.
        fn rotation_window_headers() -> ::http::HeaderMap {
            let (live, previous) = rotation_window();
            let mut headers = ::http::HeaderMap::new();
            for value in [live, previous] {
                headers.append(
                    MOLLIE_SIGNATURE_HEADER,
                    ::http::HeaderValue::from_str(&value)
                        .unwrap_or_else(|_| panic!("a computed signature is a valid header value")),
                );
            }
            headers
        }

        #[test]
        fn mollies_rotation_window_is_not_ambiguous() {
            // The reported bug: this request is exactly what Mollie emits for
            // 24 hours after a secret roll, and the scan used to report
            // `Some("X-Mollie-Signature")`, so both adapters answered a
            // body-less 400 and a `http`-feature caller was told to reject —
            // making the rotation workflow `mollie::verify`'s docs promise
            // unreachable through any of them.
            let headers = rotation_window_headers();
            assert_eq!(
                find_ambiguous_signature_header(&headers, &Provider::Mollie),
                None
            );
            assert_eq!(ambiguous_signature_header(Provider::Mollie, &headers), None);
        }

        #[test]
        fn mollies_rotation_window_reaches_verify_and_the_first_value_is_the_one_checked() {
            // The exemption only restores the documented *flow*; it does not
            // loosen what `verify()` accepts. `mollie::verify` reads the first
            // header value, so the documented workflow is "keep the previous
            // secret until the window closes and verify against each":
            //
            // * the first value is `TEST_SECRET`'s genuine signature, so it
            //   verifies against that secret;
            // * the second value is a different secret's signature, so it does
            //   *not* verify against it — the second header is never silently
            //   accepted as if it were the first.
            let headers = rotation_window_headers();
            assert_eq!(
                verify(
                    Provider::Mollie,
                    &headers,
                    BODY,
                    &Secret::new(LIVE_SECRET),
                    Default::default(),
                ),
                Ok(()),
                "the first rotation signature is the caller's key and must verify",
            );
            assert_eq!(
                verify(
                    Provider::Mollie,
                    &headers,
                    BODY,
                    &Secret::new(PREVIOUS_SECRET),
                    Default::default(),
                ),
                Err(crate::VerifyError::SignatureMismatch),
                "the second rotation signature must not verify against the first \
                 secret; `verify()` still reads only the first value"
            );
        }

        #[test]
        fn a_forged_value_appended_to_mollie_changes_nothing() {
            // The scan cannot tell Mollie's own second signature from an
            // appended one, so the exemption does not stop a third line. What
            // matters is that nothing is *accepted* on account of it: `verify()`
            // reads the first value regardless, so an appended forgery changes
            // the response only when the genuine first value is absent.
            let (live, _) = rotation_window();
            let mut headers = single_valued(&live);
            headers.append(
                MOLLIE_SIGNATURE_HEADER,
                ::http::HeaderValue::from_static(FORGED),
            );
            assert_eq!(ambiguous_signature_header(Provider::Mollie, &headers), None);
            assert_eq!(
                verify(
                    Provider::Mollie,
                    &headers,
                    BODY,
                    &Secret::new(LIVE_SECRET),
                    Default::default(),
                ),
                Ok(()),
            );

            // Prepending a forgery is a denial, never a bypass: the verifier
            // reads the forged first value and rejects the delivery.
            let mut prepended = ::http::HeaderMap::new();
            prepended.append(
                MOLLIE_SIGNATURE_HEADER,
                ::http::HeaderValue::from_static(FORGED),
            );
            prepended.append(
                MOLLIE_SIGNATURE_HEADER,
                ::http::HeaderValue::from_str(&live)
                    .unwrap_or_else(|_| panic!("a computed signature is a valid header value")),
            );
            assert_eq!(
                verify(
                    Provider::Mollie,
                    &prepended,
                    BODY,
                    &Secret::new(LIVE_SECRET),
                    Default::default(),
                ),
                Err(crate::VerifyError::SignatureMismatch),
            );
        }

        #[test]
        fn the_exemption_is_scoped_to_mollie_and_does_not_leak_to_other_providers() {
            // A different provider carrying the very same duplicate shape is
            // still rejected — the exemption is a per-provider fact about what
            // Mollie itself sends, not a general "duplicates are fine" rule.
            let mut github = ::http::HeaderMap::new();
            github.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(
                    "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                ),
            );
            github.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(FORGED),
            );
            assert_eq!(
                find_ambiguous_signature_header(&github, &Provider::GitHub),
                Some("X-Hub-Signature-256")
            );
            assert_eq!(
                ambiguous_signature_header(Provider::GitHub, &github),
                Some("X-Hub-Signature-256"),
            );

            // Nor does it leak across providers *within* Mollie's own header
            // name: a Box delivery is scanned in full.
            let mut box_headers = ::http::HeaderMap::new();
            box_headers.append(
                BOX_PRIMARY_SIGNATURE_HEADER,
                ::http::HeaderValue::from_static("sha256=4a4c6f3ed4d15fee87ad44e07a7fa9b8"),
            );
            box_headers.append(
                BOX_PRIMARY_SIGNATURE_HEADER,
                ::http::HeaderValue::from_static(FORGED),
            );
            assert_eq!(
                find_ambiguous_signature_header(&box_headers, &Provider::Box),
                Some(BOX_PRIMARY_SIGNATURE_HEADER)
            );
        }
    }

    /// The public `http`-feature entry point
    /// ([`crate::ambiguous_signature_header`]), exercised through the crate
    /// root the way a caller reaches it. The modules above pin the internal
    /// generic; this one pins the exported wrapper's signature, feature gate,
    /// and — most importantly — that a delivery which *verifies* against the
    /// first-match lookup is still reported as ambiguous, which is the whole
    /// reason the check exists as a separate caller step.
    #[cfg(feature = "http")]
    mod public_http_entry_point {
        use crate::{
            CustomScheme, Encoding, HashAlg, Provider, Secret, VerifyError, VerifyOptions,
            ambiguous_signature_header, verify,
        };

        /// GitHub's published `Hello, World!` vector
        /// (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).
        const GENUINE: &str =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        const BODY: &[u8] = b"Hello, World!";
        const SECRET: &str = "It's a Secret to Everybody";
        const FORGED: &str =
            "sha256=0000000000000000000000000000000000000000000000000000000000000000";

        fn github_secret() -> Secret {
            Secret::new(SECRET)
        }

        fn clean_github() -> ::http::HeaderMap {
            let mut headers = ::http::HeaderMap::new();
            headers.insert(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(GENUINE),
            );
            headers
        }

        #[test]
        fn a_single_valued_delivery_is_unambiguous_and_verifies() {
            let headers = clean_github();
            assert_eq!(ambiguous_signature_header(Provider::GitHub, &headers), None);
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    BODY,
                    &github_secret(),
                    VerifyOptions::default(),
                ),
                Ok(()),
            );
        }

        #[test]
        fn a_delivery_that_verifies_is_still_reported_ambiguous_when_duplicated() {
            // The case this whole entry point exists for. A proxy rewrites the
            // signature header, appending its own value; `HeaderMap` lookup is
            // first-match-only, so `verify()` sees the genuine value and
            // happily returns `Ok(())` — while whatever the proxy validated
            // upstream saw a different one. The check cannot be folded into
            // `verify()` (it would have to change the `HeaderMap` contract),
            // which is why it is a separate caller step, and why it has to
            // catch a request that verifies.
            let mut headers = ::http::HeaderMap::new();
            headers.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(GENUINE),
            );
            headers.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(FORGED),
            );

            // The naive path accepts it. Pinned so the check cannot be
            // dismissed as redundant with verification.
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    BODY,
                    &github_secret(),
                    VerifyOptions::default(),
                ),
                Ok(()),
            );

            // The check is what rejects it, and it names the header the caller
            // puts in `MalformedHeader` — as the provider spells it, not as
            // this request did, so the name is a `&'static str` that does not
            // borrow the request.
            assert_eq!(
                ambiguous_signature_header(Provider::GitHub, &headers),
                Some("X-Hub-Signature-256"),
            );
        }

        #[test]
        fn an_identical_duplicate_is_not_ambiguous() {
            // Repeating the same value smuggles nothing: every reader of the
            // header agrees on what it is. Rejecting this would break
            // well-behaved proxies that re-emit headers verbatim.
            let mut headers = ::http::HeaderMap::new();
            headers.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(GENUINE),
            );
            headers.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(GENUINE),
            );
            assert_eq!(ambiguous_signature_header(Provider::GitHub, &headers), None);
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    BODY,
                    &github_secret(),
                    VerifyOptions::default(),
                ),
                Ok(()),
            );
        }

        #[test]
        fn every_declared_header_of_a_multi_header_provider_is_scanned() {
            // GitHub has one; Box and Contentful have several. A provider whose
            // list silently lost a header would leave the other half of its
            // scheme unprotected, so the scan is per-provider rather than
            // hard-coded to a "the signature header".
            let mut headers = clean_github();
            headers.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(FORGED),
            );
            assert_eq!(
                ambiguous_signature_header(Provider::GitHub, &headers),
                Some("X-Hub-Signature-256"),
            );

            let mut contentful = ::http::HeaderMap::new();
            contentful.append(
                "x-contentful-signature",
                ::http::HeaderValue::from_static("ab"),
            );
            // The timestamp, not the signature: still a conflict, and reported
            // against the timestamp, which is the header that actually moved.
            contentful.append(
                "x-contentful-timestamp",
                ::http::HeaderValue::from_static("1704391525001"),
            );
            contentful.append(
                "x-contentful-timestamp",
                ::http::HeaderValue::from_static("1704391525002"),
            );
            assert_eq!(
                ambiguous_signature_header(Provider::Contentful, &contentful),
                Some("x-contentful-timestamp"),
            );
        }

        #[test]
        fn contentfuls_dynamic_half_reaches_the_public_entry_point() {
            // The exported wrapper must not silently degrade to the static scan
            // only: Contentful folds the headers named by
            // `x-contentful-signed-headers` into the signed string, so a
            // conflicting duplicate of one of *those* is as ambiguous as a
            // duplicate of the signature header.
            let mut headers = ::http::HeaderMap::new();
            headers.insert(
                "x-contentful-signature",
                ::http::HeaderValue::from_static("ab"),
            );
            headers.insert(
                "x-contentful-signed-headers",
                ::http::HeaderValue::from_static("content-type,x-contentful-timestamp"),
            );
            headers.append(
                "content-type",
                ::http::HeaderValue::from_static("application/json"),
            );
            headers.append(
                "content-type",
                ::http::HeaderValue::from_static("text/plain"),
            );

            // Reported against the list header: the request-controlled header
            // that named the ambiguous value, and the only name available as
            // the `&'static str` `MalformedHeader` carries.
            assert_eq!(
                ambiguous_signature_header(Provider::Contentful, &headers),
                Some("x-contentful-signed-headers"),
            );
        }

        #[test]
        fn a_custom_scheme_scans_exactly_its_two_declared_headers() {
            // The documented `spec.md` §4.4 carve-out, pinned so the carve-out
            // stays a deliberate boundary rather than drifting into "custom
            // providers get no check at all".
            fn body_only(_headers: &dyn crate::HeaderMap, raw_body: &[u8]) -> alloc::vec::Vec<u8> {
                raw_body.to_vec()
            }
            let scheme =
                CustomScheme::new(HashAlg::Sha256, "x-webhook-sig", Encoding::Hex, body_only)
                    .with_timestamp_header("x-webhook-ts");
            let custom = Provider::Custom(scheme);

            for conflicting in ["x-webhook-sig", "x-webhook-ts"] {
                let mut headers = ::http::HeaderMap::new();
                headers.insert("x-webhook-sig", ::http::HeaderValue::from_static("ab"));
                headers.insert("x-webhook-ts", ::http::HeaderValue::from_static("1"));
                headers.append(conflicting, ::http::HeaderValue::from_static("2"));
                assert_eq!(
                    ambiguous_signature_header(custom, &headers),
                    Some(conflicting),
                    "{conflicting} is a declared header and must be scanned",
                );
            }

            // A third header the closure never reads is irrelevant either way,
            // and the honest answer is "cannot tell" — the scan cannot know
            // which headers a `signed_string` closure reads, so it does not
            // pretend to.
            let mut headers = ::http::HeaderMap::new();
            headers.insert("x-webhook-sig", ::http::HeaderValue::from_static("ab"));
            headers.append("x-unrelated", ::http::HeaderValue::from_static("1"));
            headers.append("x-unrelated", ::http::HeaderValue::from_static("2"));
            assert_eq!(ambiguous_signature_header(custom, &headers), None);
        }

        #[test]
        fn the_reported_name_is_usable_as_a_malformed_header_error() {
            // The value is only useful to a caller if it is exactly what
            // `VerifyError::MalformedHeader` wants: a `&'static str`, with no
            // borrow of the request left over — which is what lets the caller
            // hand it straight to the error after `headers` goes out of scope.
            let mut headers = clean_github();
            headers.append(
                "x-hub-signature-256",
                ::http::HeaderValue::from_static(FORGED),
            );
            match ambiguous_signature_header(Provider::GitHub, &headers) {
                Some(header) => {
                    assert_eq!(header, "X-Hub-Signature-256");
                    // `header` outlives the borrow of `headers` here, so the
                    // error can be built after the request is gone.
                    let error = VerifyError::MalformedHeader {
                        header,
                        reason: VerifyError::AMBIGUOUS_HEADER_REASON,
                    };
                    assert_eq!(
                        error,
                        VerifyError::MalformedHeader {
                            header: "X-Hub-Signature-256",
                            reason: VerifyError::AMBIGUOUS_HEADER_REASON,
                        },
                    );
                }
                // The two signature values differ, so the header is ambiguous;
                // `None` here would mean the scan silently did nothing.
                None => panic!("the two signature values differ, so the header is ambiguous"),
            }
        }
    }

    /// The pair-table entry point (issue #282).
    ///
    /// `spec.md` §4.4 makes this check the caller's job for *every* `verify()`
    /// call, but the only public entry point until now took an
    /// `http::HeaderMap`. A caller whose headers are a `Vec<(String, String)>`
    /// — the representation the crate's own documentation uses — could not run
    /// it at all, and not because it was told to: the `HeaderMap` impl for a
    /// pair table keeps the first match, so the second value was already gone
    /// by the time any check could look. These pin that the new entry point
    /// catches the same cases the `http` one does, and that it cannot degrade
    /// into a silent no-op — the failure mode that would leave §4.4
    /// unenforced for pair-table callers with the suite still green.
    mod pair_table_entry_point {
        use crate::ambiguous_signature_header_in;
        // These tests are unconditional, so they are also compiled without
        // `std`, where the standard prelude is not injected.
        #[cfg(not(feature = "std"))]
        use crate::test_helpers::*;
        use crate::{CustomScheme, Encoding, HashAlg, Provider, Secret, verify};

        /// GitHub's published `Hello, World!` vector
        /// (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries).
        const GENUINE: &str =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        const FORGED: &str =
            "sha256=0000000000000000000000000000000000000000000000000000000000000000";
        const BODY: &[u8] = b"Hello, World!";
        const LIVE: &str = "It's a Secret to Everybody";

        /// The `Vec<(String, String)>` shape the crate documents for
        /// non-`http` callers, so the tests exercise the exact type a caller
        /// would build rather than a convenient one.
        fn owned() -> Vec<(String, String)> {
            vec![("x-hub-signature-256".to_string(), GENUINE.to_string())]
        }

        #[test]
        fn a_single_valued_delivery_is_unambiguous_and_verifies() {
            let headers = owned();
            assert_eq!(
                ambiguous_signature_header_in(Provider::GitHub, &headers),
                None
            );
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    BODY,
                    &Secret::new(LIVE),
                    Default::default(),
                ),
                Ok(()),
            );
        }

        #[test]
        fn a_delivery_that_verifies_is_still_reported_ambiguous_when_duplicated() {
            // The case the entry point exists for, and the one a pair table can
            // represent: both values are right there, in order, with nothing
            // dropped in between. A proxy appended its own signature to the
            // genuine one; `verify()` reads the first value and returns
            // `Ok(())` while whatever the proxy validated upstream saw a
            // different one. If this test ever returns `None`, the check has
            // silently stopped working.
            let headers = vec![
                ("x-hub-signature-256".to_string(), GENUINE.to_string()),
                ("x-hub-signature-256".to_string(), FORGED.to_string()),
            ];

            // Pinned so the check cannot be dismissed as redundant with
            // verification: verification accepts this request.
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    BODY,
                    &Secret::new(LIVE),
                    Default::default(),
                ),
                Ok(()),
            );

            assert_eq!(
                ambiguous_signature_header_in(Provider::GitHub, &headers),
                Some("X-Hub-Signature-256"),
            );
        }

        #[test]
        fn an_identical_duplicate_is_not_ambiguous() {
            // Repeating the same value smuggles nothing: every reader agrees on
            // what it is, and rejecting it would break well-behaved proxies that
            // re-emit headers verbatim.
            let headers = vec![
                ("x-hub-signature-256".to_string(), GENUINE.to_string()),
                ("x-hub-signature-256".to_string(), GENUINE.to_string()),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::GitHub, &headers),
                None
            );
            assert_eq!(
                verify(
                    Provider::GitHub,
                    &headers,
                    BODY,
                    &Secret::new(LIVE),
                    Default::default(),
                ),
                Ok(()),
            );
        }

        #[test]
        fn names_are_matched_case_insensitively() {
            // Header names are case-insensitive, so a table that spells one
            // differently in each of two lines carries a single header with two
            // values. Comparing the raw names instead would answer `None` and
            // hand an attacker a case-flip past §4.4, which is why this is
            // pinned separately from the duplicate tests above.
            let headers = vec![
                ("X-Hub-Signature-256", GENUINE),
                ("x-hub-signature-256", FORGED),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::GitHub, &headers),
                Some("X-Hub-Signature-256"),
            );
        }

        #[test]
        fn an_empty_table_has_nothing_to_be_ambiguous_about() {
            let headers: Vec<(&str, &str)> = Vec::new();
            assert_eq!(
                ambiguous_signature_header_in(Provider::GitHub, &headers),
                None
            );
        }

        #[test]
        fn every_declared_header_of_a_multi_header_provider_is_scanned() {
            // The scan is per-provider, not hard-coded to "the signature
            // header", so a provider's list cannot silently lose one.
            let headers = vec![
                ("x-contentful-signature", "ab"),
                ("x-contentful-timestamp", "1704391525001"),
                ("x-contentful-timestamp", "1704391525002"),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::Contentful, &headers),
                Some("x-contentful-timestamp"),
            );
        }

        #[test]
        fn contentfuls_dynamic_half_reaches_the_pair_table_entry_point() {
            // Contentful folds the headers named by
            // `x-contentful-signed-headers` into the signed string, so a
            // conflicting duplicate of one of *those* is as ambiguous as a
            // duplicate of the signature header. Reported against the list
            // header: the request-controlled header that named the value, and
            // the only name available as the `&'static str` `MalformedHeader`
            // carries.
            let headers = vec![
                ("x-contentful-signature", "ab"),
                (
                    "x-contentful-signed-headers",
                    "content-type,x-contentful-timestamp",
                ),
                ("content-type", "application/json"),
                ("content-type", "text/plain"),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::Contentful, &headers),
                Some("x-contentful-signed-headers"),
            );
        }

        #[test]
        fn a_listed_name_the_request_cannot_spell_fails_closed() {
            // The dynamic scan cannot enumerate the values of a name it is not
            // allowed to spell, so "cannot tell" has to read as ambiguous
            // rather than clean. A list element containing a space is not a
            // valid field name (RFC 9110: `field-name = token`), and no
            // request can carry such a header — so the honest answer is
            // "ambiguous", exactly as it is for the two framework maps.
            let headers = vec![
                ("x-contentful-signature", "ab"),
                ("x-contentful-signed-headers", "x contentful topic"),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::Contentful, &headers),
                Some("x-contentful-signed-headers"),
            );
        }

        #[test]
        fn mollies_rotation_window_exemption_applies_here_too() {
            // One scan, so one exemption: Mollie documents two `X-Mollie-Signature`
            // lines with different values during a signing-secret rotation, and
            // rejecting the provider's own shape would make that window unusable
            // for pair-table callers too.
            let headers = vec![
                ("x-mollie-signature", "first"),
                ("x-mollie-signature", "second"),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::Mollie, &headers),
                None
            );

            // Scoped to Mollie: the same shape is still ambiguous for a provider
            // that never sends it.
            assert_eq!(
                ambiguous_signature_header_in(Provider::GitHub, &headers),
                None,
            );
            let other: Vec<(&str, &str)> = vec![
                ("x-slack-signature", "first"),
                ("x-slack-signature", "second"),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::Slack, &other),
                Some("X-Slack-Signature"),
            );
        }

        #[test]
        fn a_custom_scheme_scans_exactly_its_two_declared_headers() {
            fn body_only(_headers: &dyn crate::HeaderMap, raw_body: &[u8]) -> alloc::vec::Vec<u8> {
                raw_body.to_vec()
            }
            let scheme =
                CustomScheme::new(HashAlg::Sha256, "x-webhook-sig", Encoding::Hex, body_only)
                    .with_timestamp_header("x-webhook-ts");
            let custom = Provider::Custom(scheme);

            for conflicting in ["x-webhook-sig", "x-webhook-ts"] {
                let headers = vec![
                    ("x-webhook-sig", "ab"),
                    ("x-webhook-ts", "1"),
                    (conflicting, "2"),
                ];
                assert_eq!(
                    ambiguous_signature_header_in(custom, &headers),
                    Some(conflicting),
                    "{conflicting} is a declared header and must be scanned",
                );
            }

            // A third header the closure never reads is irrelevant, and the
            // honest answer is "cannot tell" — the scan cannot know which
            // headers a `signed_string` closure reads, so it does not pretend to.
            let headers = vec![
                ("x-webhook-sig", "ab"),
                ("x-unrelated", "1"),
                ("x-unrelated", "2"),
            ];
            assert_eq!(ambiguous_signature_header_in(custom, &headers), None);
        }

        #[cfg(not(feature = "paypal"))]
        #[test]
        fn a_provider_disabled_by_a_feature_flag_has_no_headers_to_scan() {
            // A feature-gated provider's headers are unknown to this build, so
            // there is nothing to enumerate and nothing to reject here;
            // `verify()` fails the request closed with `UnsupportedProvider`
            // instead. Pinned so turning a provider's feature *on* is what makes
            // its headers scannable — and so a future change cannot start
            // rejecting requests for a provider this build cannot verify at all.
            let headers = vec![
                ("paypal-transmission-id", "one"),
                ("paypal-transmission-id", "two"),
            ];
            assert_eq!(
                ambiguous_signature_header_in(Provider::PayPal, &headers),
                None
            );
        }

        /// The two entry points must not be able to disagree: same request,
        /// same provider, same answer. A pair table and an `http::HeaderMap`
        /// can both carry the duplicate, and a hardening that reached only one
        /// of them would be a silent hole for the other.
        #[cfg(feature = "http")]
        #[test]
        fn it_agrees_with_the_http_entry_point_on_the_same_request() {
            use crate::ambiguous_signature_header;

            let cases: &[(&[(&str, &str)], bool)] = &[
                (&[("x-hub-signature-256", GENUINE)], false),
                (
                    &[
                        ("x-hub-signature-256", GENUINE),
                        ("x-hub-signature-256", FORGED),
                    ],
                    true,
                ),
                (
                    &[
                        ("x-hub-signature-256", GENUINE),
                        ("x-hub-signature-256", GENUINE),
                    ],
                    false,
                ),
                (
                    &[
                        ("X-Hub-Signature-256", GENUINE),
                        ("x-hub-signature-256", FORGED),
                    ],
                    true,
                ),
                (&[], false),
            ];

            for (pairs, expected_ambiguous) in cases {
                // `from_bytes`, not `from_static`: one case deliberately carries
                // an upper-case name, and `from_static` panics on anything but a
                // lower-case name. A bare `panic!` rather than `expect` because
                // the crate denies `unwrap`/`expect` outright.
                let mut map = ::http::HeaderMap::new();
                for (name, value) in *pairs {
                    let parsed = match ::http::HeaderName::from_bytes(name.as_bytes()) {
                        Ok(name) => name,
                        Err(_) => panic!("fixture header name is not valid: {name}"),
                    };
                    map.append(parsed, ::http::HeaderValue::from_static(value));
                }
                let expected = if *expected_ambiguous {
                    Some("X-Hub-Signature-256")
                } else {
                    None
                };
                assert_eq!(
                    ambiguous_signature_header_in(Provider::GitHub, pairs),
                    expected,
                    "pair table {pairs:?} disagreed with the http entry point",
                );
                assert_eq!(
                    ambiguous_signature_header(Provider::GitHub, &map),
                    expected,
                    "http entry point disagreed with the pair table for {pairs:?}",
                );
            }
        }
    }

    /// The dynamic scan must not carry its own copy of Contentful's list
    /// separator (issue #267).
    ///
    /// #235 stopped this scan from re-spelling Contentful's list *header name*
    /// as a second literal. The delimiter was still spelled twice: once in
    /// `contentful::parse_signed_header_names` and once here, both as a bare
    /// `','`. Nothing tied the two together, and the failure mode is worse than
    /// a duplicate-name bug, because it is invisible:
    ///
    /// * every existing fixture uses a comma list, so both spellings agree on
    ///   all of them and the suite stays green;
    /// * a separator change that reached only `contentful::verify` (a provider
    ///   switch, a new delimiter) would leave this scan splitting the old way,
    ///   so every element it looked up would be a *whole* element such as
    ///   `"content-type;x-contentful-topic"`, which no request carries;
    /// * `has_conflicting_duplicates` on a name no request has finds no values
    ///   and returns `false`, so `contentful_dynamic_scan`'s duplicate tests
    ///   would still pass while the production path stopped rejecting ambiguous
    ///   Contentful deliveries entirely — a silent loss of `spec.md` §4.4
    ///   coverage for the one provider whose signed-header set is
    ///   request-declared.
    ///
    /// The fix is to read the provider's own constant
    /// (`CONTENTFUL_SIGNED_HEADERS_SEPARATOR`); this pins that it stays read,
    /// so the re-spelling cannot come back. Structural rather than behavioral
    /// because both spellings are behaviorally identical today — only a
    /// *disagreement* would be observable, and by then the coverage is already
    /// gone. Same idiom as the sibling guard in `providers::tests` that keeps
    /// one candidate comparison per signed string.
    #[test]
    fn the_dynamic_scan_splits_contentfuls_list_on_the_providers_separator() {
        use std::fs;
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/core/adapter_utils.rs");
        // This module is shipped in the crates.io tarball, so a read failure is
        // only a guard against a packaging surprise, not a test failure.
        let Ok(source) = fs::read_to_string(&path) else {
            return;
        };
        // Only the implementation is scanned. Without this bound the slice runs
        // to end-of-file and picks up the literals in *this* test's own
        // assertion messages, which is exactly what the second assertion looks
        // for.
        let implementation = match source.find("#[cfg(test)]") {
            Some(at) => &source[..at],
            None => source.as_str(),
        };
        let body = implementation
            .split_once("fn dynamically_named_ambiguity")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.split_once('{').map(|(_, body)| body))
            .unwrap_or_else(|| panic!("{} must still define the dynamic scan", path.display()));

        assert!(
            body.contains("CONTENTFUL_SIGNED_HEADERS_SEPARATOR"),
            "{} splits Contentful's signed-header list on something other than the \
             provider's own `SIGNED_HEADERS_SEPARATOR`. Re-spelling the delimiter here \
             silently disables `spec.md` §4.4's dynamic half for Contentful: a mismatch \
             yields element strings no request carries, so no duplicate is ever found \
             and the test suite stays green. Import and use \
             `CONTENTFUL_SIGNED_HEADERS_SEPARATOR` instead.",
            path.display(),
        );
        // Belt and braces: name the literal shape explicitly, so a `split(',')`
        // regression is reported as itself rather than only as the missing
        // reference above.
        assert!(
            !body.contains(".split(',')") && !body.contains(".split(\",\")"),
            "{} splits Contentful's signed-header list on a literal delimiter; it must use \
             the provider's `SIGNED_HEADERS_SEPARATOR` (see \
             `CONTENTFUL_SIGNED_HEADERS_SEPARATOR`)",
            path.display(),
        );
    }

    #[cfg(feature = "http")]
    #[cfg(any(feature = "tower", feature = "actix"))]
    #[test]
    fn declared_content_length_parses_and_ignores_garbage() {
        // The shared helper over the http 1.x header map, mirroring the
        // actix-side unit test in `src/actix.rs` so both impls of the
        // underlying `MultiValueHeaders::get_first_str` are pinned.
        let mut headers = ::http::HeaderMap::new();
        assert_eq!(declared_content_length(&headers), None);
        headers.insert(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("131072"),
        );
        assert_eq!(declared_content_length(&headers), Some(131072));
        headers.insert(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static("oops"),
        );
        assert_eq!(declared_content_length(&headers), None);
        // Non-canonical spellings of a length must be rejected, not rounded
        // down to a number: HTTP's Content-Length grammar is `1*DIGIT`, and
        // `usize::from_str` would otherwise silently accept a leading `+`
        // (e.g. `+131072`), which is not a valid Content-Length (mirrors the
        // crate's strict timestamp parsing, `replay.rs`).
        for value in ["+131072", "+0", "-131072", "0x20000"] {
            headers.insert(
                ::http::header::CONTENT_LENGTH,
                ::http::HeaderValue::from_static(value),
            );
            assert_eq!(
                declared_content_length(&headers),
                None,
                "non-canonical Content-Length {value:?} must be treated as undeclared"
            );
        }
        // Surrounding OWS is stripped, so the padded spelling is the same
        // declared length (RFC 9110 §5.5: a field value runs from its first to
        // its last non-OWS octet, and OWS is `SP`/`HTAB`). This is the one
        // respect in which this parse is *not* identical to
        // `parse_unsigned_decimal`, which rejects whitespace outright.
        for padded in [" 131072 ", "\t131072\t", " \t131072\t "] {
            headers.insert(
                ::http::header::CONTENT_LENGTH,
                ::http::HeaderValue::from_static(padded),
            );
            assert_eq!(
                declared_content_length(&headers),
                Some(131072),
                "OWS-padded Content-Length {padded:?} is the same declared length"
            );
        }
        // Whitespace-only is still undeclared rather than a length of 0.
        for value in [" ", "\t", " \t "] {
            headers.insert(
                ::http::header::CONTENT_LENGTH,
                ::http::HeaderValue::from_static(value),
            );
            assert_eq!(
                declared_content_length(&headers),
                None,
                "whitespace-only Content-Length {value:?} must be treated as undeclared"
            );
        }
    }

    /// Pins the "non-visible-ASCII value" half of `declared_content_length`'s
    /// contract, which `from_str`/`from_static` cannot express: those two
    /// constructors reject such a value outright, so the only way to build one
    /// is `from_bytes` (obs-text). The `MultiValueHeaders::get_first_str`
    /// decode then fails and the length reads as undeclared, so the pre-buffer
    /// guard falls through to the post-buffer size check.
    #[cfg(feature = "http")]
    #[cfg(any(feature = "tower", feature = "actix"))]
    #[test]
    fn declared_content_length_rejects_non_visible_ascii_values() {
        let mut headers = ::http::HeaderMap::new();
        // `from_bytes` permits obs-text (128-255) but rejects DEL and the
        // control bytes, so those are the only shapes constructible here — and
        // exactly the ones `to_str` then refuses to decode.
        for bytes in [
            &b"\xa0131072"[..], // leading NBSP (U+00A0)
            &b"131072\xa0"[..], // trailing NBSP
            &b"\xc2\xa0131072"[..],
            &b"131072\xe3\x80\x80"[..], // trailing IDEOGRAPHIC SPACE (U+3000)
            &b"\xff"[..],               // bare non-ASCII
        ] {
            headers.insert(
                ::http::header::CONTENT_LENGTH,
                ::http::HeaderValue::from_bytes(bytes)
                    .unwrap_or_else(|_| unreachable!("obs-text is valid for from_bytes")),
            );
            assert_eq!(
                declared_content_length(&headers),
                None,
                "non-visible-ASCII Content-Length {bytes:?} must be treated as undeclared"
            );
        }
    }

    /// Index of the README block that introduces the ambiguity check: the
    /// paragraph a reader reads to learn what the check takes and what it
    /// cannot take. Both README guards below anchor on it, and both previously
    /// searched for the first block naming `ambiguous_signature_header`
    /// anywhere in the file.
    ///
    /// The anchor has to exclude fenced code, because a fence can no longer
    /// claim it: `README.md`'s first code block — the front-door example — now
    /// names `ambiguous_signature_header_in` inside a fence of its own (issue
    /// #284), and a search that accepted a fence would silently retarget both
    /// guards onto the headline example and compare the wrong text. Fences are
    /// line-based and a blank line inside one splits it into several blocks, so
    /// "inside a fence" is tracked per block: an odd number of fence-marker
    /// lines in a block means it opened one (the opener is the block's first
    /// line) or closed one (the closer is its last), and nothing in between
    /// changes the state — so the front-door snippet's own comment paragraph is
    /// skipped along with the rest of its fence.
    ///
    /// Fence parity is a property of the file's structure rather than of any
    /// wording, so this anchor survives rewording, reheading, or reordering the
    /// prose it finds.
    #[cfg(feature = "http")]
    fn readme_ambiguity_prose_block(readme: &str, blocks: &[&str]) -> usize {
        let mut offset = 0;
        let mut inside_fence = false;
        let mut found = None;
        for (at, block) in blocks.iter().enumerate() {
            let markers = readme[offset..offset + block.len()]
                .lines()
                .filter(|line| line.starts_with("```"))
                .count();
            // An odd marker count means this block either opens a fence (the
            // opener is its first line) or closes one (the closer is its
            // last), so it is inside a fence either way.
            let fenced = inside_fence || markers % 2 == 1;
            if !fenced && block.contains("ambiguous_signature_header") {
                found = Some(at);
                break;
            }
            if markers % 2 == 1 {
                inside_fence = !inside_fence;
            }
            // `split("\n\n")` eats the separator, so the next block starts two
            // bytes past this one's end.
            offset += block.len() + 2;
        }
        found
            .unwrap_or_else(|| panic!("README.md must still document `ambiguous_signature_header`"))
    }

    /// The README's `ambiguous_signature_header` section, pinned to the two
    /// qualifiers that function's signature carries (issue #269).
    ///
    /// A `rust` fence in `README.md` is documentation, not a doctest — nothing
    /// compiles it, and the crate is built without the README entirely — so the
    /// section shipped a snippet passing a `Vec<(String, String)>` (the
    /// map the README's own first example defines) to a function that takes
    /// `&::http::HeaderMap`, while never naming the `http` feature that gates
    /// it. A reader following the README top-to-bottom got a type error, or
    /// concluded the check did not exist and dropped the §4.4 duplicate-header
    /// defense. `src/core/headers.rs` and the helper's own doctest had both
    /// qualifiers right, which is why only the README was wrong.
    ///
    /// The qualifiers are checked *inside the section that makes the claim*,
    /// not anywhere in the file: a passing mention of the `http` feature two
    /// paragraphs earlier (which the README has, for the `HeaderMap` impl) is
    /// exactly the shape of prose that let the gap through, so anchoring only
    /// the file would not catch its return.
    ///
    /// "The section that makes the claim" is located by
    /// [`readme_ambiguity_prose_block`], which the front-door example's fence
    /// cannot capture.
    #[cfg(feature = "http")]
    #[test]
    fn readme_states_the_ambiguity_checks_requirements() {
        const README: &str = include_str!("../../README.md");

        let blocks: Vec<&str> = README.split("\n\n").collect();
        let at = readme_ambiguity_prose_block(README, &blocks);
        // The prose paragraph that introduces the helper, plus the whole code
        // fence after it (a fence is several blank-line-separated blocks, so
        // it is reassembled rather than taken one block at a time).
        let mut section = String::new();
        for block in &blocks[at..] {
            section.push_str(block);
            section.push_str("\n\n");
            if section.matches("```").count() >= 2 {
                break;
            }
        }
        let lower = section.to_lowercase();
        assert!(
            lower.contains("http` feature"),
            "README.md's `ambiguous_signature_header` section must name the \
             `http` feature, which is what exports the helper at all; found: {section}"
        );
        assert!(
            section.contains("http::HeaderMap"),
            "README.md's `ambiguous_signature_header` section must name the \
             argument type it takes, `&http::HeaderMap`; found: {section}"
        );

        // The type error the shipped snippet had: the map has to exist, and
        // has to be an `http::HeaderMap`, before the call that borrows it.
        let fence = section.find("```rust").unwrap_or_else(|| {
            panic!("the section must carry a runnable snippet; found: {section}")
        });
        let snippet = &section[fence..];
        let built = snippet.find("http::HeaderMap::new()").unwrap_or_else(|| {
            panic!(
                "the snippet must build an `http::HeaderMap` to pass to \
                     `ambiguous_signature_header`; found: {snippet}"
            )
        });
        let called = snippet
            .find("ambiguous_signature_header(")
            .unwrap_or_else(|| {
                panic!("the snippet must call `ambiguous_signature_header`; found: {snippet}")
            });
        assert!(
            built < called,
            "the snippet must build the `http::HeaderMap` before passing it to \
             `ambiguous_signature_header`; found: {snippet}"
        );
    }

    /// The honest limit the same section owes a caller holding a container
    /// that keeps one value per name.
    ///
    /// `HeaderMap` is first-match-only by design (`spec.md` §4.4), so no
    /// *single-value* container *can* support the scan: a map holding one value
    /// per name has no second value to compare against. That is still a real
    /// limit and the README has to keep saying it — but it is narrower than
    /// "no other `HeaderMap` impl", which stopped being true when
    /// `ambiguous_signature_header_in` gave pair tables a way in (#282). A pair
    /// table keeps repeated names, so it can answer the question; only the
    /// one-value container cannot. This guard finds the paragraph by that
    /// narrower subject rather than by the first "first-match" string after the
    /// intro, which is no longer unique: the pair-table snippet legitimately
    /// mentions first-match lookup to explain why the table is not the same as
    /// what `verify()` saw.
    #[cfg(feature = "http")]
    #[test]
    fn readme_states_why_a_single_value_map_cannot_use_the_ambiguity_check() {
        const README: &str = include_str!("../../README.md");

        let blocks: Vec<&str> = README.split("\n\n").collect();
        let at = readme_ambiguity_prose_block(README, &blocks);
        let limit = blocks[at + 1..]
            .iter()
            .find(|block| block.contains("first-match") && block.contains("one value per name"))
            .unwrap_or_else(|| {
                panic!(
                    "README.md must explain that a container keeping one value per name \
                     cannot support the ambiguity check, because the `HeaderMap` trait's \
                     first-match-only lookup leaves no second value to compare"
                )
            });
        assert!(
            limit.contains("compare the values you hold"),
            "that explanation must say what a caller with such a map does instead — \
             compare the values it holds for the same name — found: {limit}"
        );
        assert!(
            limit.contains("ambiguous_signature_header_in"),
            "the same paragraph must point a pair-table caller at the entry point that \
             does work for them, so the limit is not read as \"nobody can do this\"; \
             found: {limit}"
        );
    }

    /// Offset of the first `verify` in `doc` that is a *call* rather than a
    /// mention.
    ///
    /// Both front-door examples explain the check in a comment that names
    /// `` `verify()` `` before running it — which is exactly the ordering the
    /// guard below wants to distinguish a mention from the verification it
    /// precedes, so a plain `find("verify(")` reads the comment as the call and
    /// reports an example that already puts its check first. A mention has `)`
    /// straight after the paren; a call has an argument.
    fn first_verify_call(doc: &str) -> Option<usize> {
        doc.match_indices("verify(")
            .find_map(|(at, matched)| (!doc[at + matched.len()..].starts_with(')')).then_some(at))
    }

    /// Both front-door examples — `README.md`'s first code block and the crate
    /// docs' headline doctest — pinned to the §4.4 obligation they each carry
    /// (issue #284).
    ///
    /// They are the two snippets a new reader copies before knowing anything
    /// else about the crate, and both hold their headers in a
    /// `Vec<(String, String)>` pair table: exactly the shape §4.4 obliges a
    /// caller to run `ambiguous_signature_header_in` on. `verify()` is a
    /// first-match lookup by contract, so an example that omits the check
    /// teaches a deployment that accepts a delivery carrying a real signature
    /// header with a forged value appended behind it — the shape §4.4 exists
    /// for, and one neither example's assertions can detect.
    ///
    /// The obligation was already stated everywhere *below* the fold (the
    /// `HeaderMap` trait docs, the function's own rustdoc, the README's
    /// duplicate-header section), so this is not a hole in the documentation —
    /// it is the one place a reader meets before any of that. Nothing pinned it
    /// there: a future edit that trims the check for brevity shipped silently,
    /// which is how the crate docs' example came to import `HeaderMap` for an
    /// ambiguity check it never ran (its own doctest now denies unused imports,
    /// so that residue is a compile error rather than a warning).
    ///
    /// Each example is located by the first fence in its file — the front door
    /// by construction, since nothing else precedes it — and the check is
    /// required *between* the header table and the `verify()` call, not merely
    /// present: a check moved above the table it scans, or below the
    /// verification it guards, teaches the same acceptance.
    #[test]
    fn front_door_examples_run_the_ambiguity_check_before_verify() {
        for (label, doc) in [
            ("README.md", include_str!("../../README.md")),
            ("crate docs", include_str!("../lib.rs")),
        ] {
            // The first fence in each file, `rust` tag or not: the crate docs'
            // headline block is a bare ```` ``` ```` doctest, and both files put
            // nothing before it.
            let fence = doc
                .find("```")
                .unwrap_or_else(|| panic!("`{label}` must open with a runnable example"));
            let fenced = &doc[fence..];
            let end = fenced[3..].find("```").map_or(fenced.len(), |at| at + 3);
            let snippet = &fenced[..end];

            let table = snippet.find("let headers").unwrap_or_else(|| {
                panic!(
                    "`{label}`'s front-door example must build the header table it \
                     passes to `verify()`, or there is no pair table for the §4.4 \
                     check to scan; found: {snippet}"
                )
            });
            let checked = snippet
                .find("ambiguous_signature_header_in(")
                .unwrap_or_else(|| {
                    panic!(
                        "`{label}`'s front-door example must run \
                         `ambiguous_signature_header_in` before trusting \
                         `verify()`: spec §4.4 obliges every `verify()` caller to \
                         reject a signature header that arrived more than once with \
                         differing values, and `verify()`'s first-match lookup \
                         cannot see the second value; found: {snippet}"
                    )
                });
            let verified = first_verify_call(snippet).unwrap_or_else(|| {
                panic!("`{label}`'s front-door example must call `verify()`; found: {snippet}")
            });
            assert!(
                table < checked,
                "`{label}`'s front-door example must build the header table before \
                 the ambiguity check scans it; found: {snippet}"
            );
            assert!(
                checked < verified,
                "`{label}`'s front-door example must run the ambiguity check before \
                 `verify()`, since a forged value appended behind a real one is \
                 accepted by `verify()` alone; found: {snippet}"
            );
        }
    }

    /// The count of code (non-comment) lines in the fuzz target that call
    /// `ambiguous_signature_header_in`. Whole-line `//` comments and trailing
    /// `// …` comments are dropped first, for the reason the fuzz target's own
    /// prose makes unavoidable: every comment describing this scan names the
    /// function it is describing, so a raw line count would be satisfied by
    /// prose alone. A `//` inside a string literal would be mis-trimmed; the
    /// fuzz target has none, and this is a floor check over a repo-internal
    /// file, not a parser. Test-only helper over the target's source text.
    fn fuzz_ambiguity_scan_call_hits(target: &str) -> usize {
        target
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                !line.starts_with("//")
                    && match line.find("//") {
                        Some(at) => &line[..at],
                        None => line,
                    }
                    .contains("ambiguous_signature_header_in(")
            })
            .count()
    }

    /// The §4.4 ambiguity scan is driven from the shared fuzz target
    /// (issue #296).
    ///
    /// `spec.md` §5.6 asks for a "no panic, no timeout" guarantee on each
    /// provider's header-parsing path, and `src/providers/mod.rs` guards pin
    /// the target's `IMPLEMENTED` pool to all 58 providers. This scan was the
    /// one public entry point the pool's reachability did not imply: it is not
    /// on the `verify()` path at all, so every `attempt`/`attempt_any` call
    /// walked past it, and nothing in the target's source mentioned it.
    ///
    /// It matters more than its size suggests. `dynamically_named_ambiguity`
    /// splits and trims `x-contentful-signed-headers` — a header the *request*
    /// controls — and then duplicate-checks each name, which is the only
    /// place in the crate where attacker-supplied text steers the choice of
    /// headers to look up. Every unit test for it is a hand-written table of
    /// well-formed names, so the arbitrary-input case was untested. And
    /// `spec.md` §4.4 obliges every caller of `verify()` to run this check,
    /// with the hand-extraction path the crate's own front-door example uses
    /// as the recommended integration — a panic in it would be a remote DoS on
    /// a documented deployment, not on an internal one.
    ///
    /// The pair-table overload is the one required: it is the representation
    /// the target already builds, it needs no features, and the `http`-
    /// feature overload funnels into the same
    /// `find_ambiguous_signature_header`. A floor of one rather than an exact
    /// count — what matters is that the scan is driven, and a second call site
    /// (say, per slice shape like `attempt_any`'s three) is a gain, not drift.
    ///
    /// `fuzz/` is excluded from the crates.io tarball (`Cargo.toml`
    /// `exclude`), so in a packaged checkout the file does not exist and the
    /// guard is skipped — it is a repo-internal test, not part of the shipped
    /// crate's contract.
    #[test]
    fn fuzz_target_drives_the_ambiguity_scan() {
        use std::fs;
        use std::path::Path;

        let target = {
            let path =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets/parse_and_verify.rs");
            match fs::read_to_string(path) {
                Ok(src) => src,
                // `fuzz/` not present (e.g. the publish tarball): nothing to
                // guard against here, and the crate's own tests must not fail
                // on a file it does not ship.
                Err(_) => return,
            }
        };

        let hits = fuzz_ambiguity_scan_call_hits(&target);
        assert!(
            hits > 0,
            "fuzz target must call `ambiguous_signature_header_in` — the spec.md §4.4 \
             ambiguity scan is a public entry point that parses the request-controlled \
             `x-contentful-signed-headers` list, it is not on the `verify()` path the \
             rest of the target drives, and spec.md §5.6 asks for a no-panic/no-timeout \
             guarantee over exactly that kind of input"
        );
    }

    /// The positive side of [`fuzz_ambiguity_scan_call_hits`]: a real call
    /// counts, a whole-line comment does not, a trailing comment does not, and
    /// the count is a floor rather than an exact total.
    ///
    /// Written as string literals rather than `format!` so it builds under
    /// `--no-default-features`, where this module is `no_std` and the
    /// `format!` macro is not in scope.
    #[test]
    fn fuzz_ambiguity_scan_call_hits_ignores_prose() {
        let real = "    let _ = ambiguous_signature_header_in(provider, &headers);";
        let whole_line_comment = "    // fuzz target must call ambiguous_signature_header_in( here";
        let trailing_comment = "    attempt(provider); // calls ambiguous_signature_header_in(";
        let two_calls = "\
    let _ = ambiguous_signature_header_in(provider, &headers);
    let _ = ambiguous_signature_header_in(provider, &headers);";
        assert_eq!(fuzz_ambiguity_scan_call_hits(real), 1);
        assert_eq!(fuzz_ambiguity_scan_call_hits(whole_line_comment), 0);
        assert_eq!(fuzz_ambiguity_scan_call_hits(trailing_comment), 0);
        assert_eq!(fuzz_ambiguity_scan_call_hits(two_calls), 2);
    }

    /// `spec.md` §5.8 describes the fail-closed adapter path by naming the
    /// functions that implement it, and it had drifted: it named
    /// `conflicting_signature_header`, a per-adapter helper removed when the
    /// duplicate scan was unified into this module, so the normative contract
    /// pointed readers at a symbol that does not exist. The live path is
    /// `has_conflicting_duplicates` returning `true` for an unparseable name
    /// and `find_ambiguous_signature_header` reporting it. This pins the
    /// §5.8 prose to those symbols so the paragraph that explains *why* a
    /// typo'd header constant fails closed keeps naming the code that does it.
    ///
    /// `spec.md` and the code must not drift (`AGENTS.md` §6); every other
    /// hand-maintained surface here has a guard, and §5.8's own implementation
    /// note already pins the two provider tests that exercise the behavior.
    #[test]
    fn spec_five_eight_names_the_live_ambiguity_scan() {
        let spec = include_str!("../../spec.md");
        let Some(start) = spec.find("**Adapter-visible header names are valid HTTP field names**")
        else {
            panic!("spec.md §5.8 must keep its heading");
        };
        let Some(end) = spec[start..].find("\n---") else {
            panic!("spec.md §5.8 must be followed by a horizontal rule");
        };
        let item = &spec[start..start + end];
        assert!(
            item.contains("find_ambiguous_signature_header"),
            "spec.md §5.8 must name `find_ambiguous_signature_header`, the live \
             ambiguity-scan entry point"
        );
        assert!(
            item.contains("has_conflicting_duplicates"),
            "spec.md §5.8 must name `has_conflicting_duplicates`, the predicate \
             that treats an unparseable scan name as a duplicate"
        );
        assert!(
            !item.contains("conflicting_signature_header"),
            "spec.md §5.8 must not name `conflicting_signature_header`; it was \
             removed when the scan was unified into `core::adapter_utils`"
        );
    }
}
