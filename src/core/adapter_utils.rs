//! The `spec.md` §4.4 ambiguity check, and the utilities the framework
//! adapters (tower, actix) share so they cannot drift as new [`VerifyError`]
//! variants are added.
//!
//! Two kinds of item live here:
//!
//! * the ambiguity scan itself, compiled under the `http` feature *and* both
//!   adapter features, because it is public API for `http`-feature callers
//!   (see [`ambiguous_signature_header`]) as well as the adapters' internal
//!   step; and
//! * adapter-only glue (`rejection_status`, `declared_content_length`),
//!   which carries a narrower `cfg` so nothing is dead code in the
//!   `http`-only configuration.

#[cfg(any(feature = "tower", feature = "actix"))]
use super::VerifyError;
use crate::providers::{Provider, signature_header_names};

/// Contentful's self-describing signed-header list: the header whose *value*
/// names the other headers folded into the canonical string
/// (`spec.md` §3, Contentful row).
///
/// Unlike every other provider's header set, these cannot live in
/// `signature_header_names`: they are only known once the request is in hand.
const CONTENTFUL_SIGNED_HEADERS_HEADER: &str = "x-contentful-signed-headers";

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

/// Returns true when `name` occurs in `headers` more than once with *differing*
/// values — the ambiguity `spec.md` §4.4 requires rejecting — or false when it
/// occurs at most once (or not at all).
///
/// Values are compared as raw bytes: the scan must reject two lines carrying
/// different bytes, and opaque-byte values that could never parse as a
/// signature are still ambiguous when duplicated with differing bytes.
///
/// Static header-name constants always parse, so the unparseable-name arm is
/// unreachable for the names `signature_header_names` returns and simply fails
/// closed (reported as ambiguous). It *is* reachable for the names a request
/// supplies (Contentful's signed-header list), and failing closed there is
/// still the only safe answer: such a name can never be verified against.
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
///    header a provider's scheme declares for all built-in providers; and
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
    signature_header_names(provider)
        .iter()
        .copied()
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
/// adapters use "header present multiple times with different values". Call it
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
///         reason: "header present multiple times with different values",
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
/// `signed_string` closure reads are not detected.
#[cfg(feature = "http")]
#[must_use]
pub fn ambiguous_signature_header(
    provider: Provider,
    headers: &::http::HeaderMap,
) -> Option<&'static str> {
    find_ambiguous_signature_header(headers, &provider)
}

/// The dynamic half of the ambiguity scan: headers the provider's scheme
/// reads that are enumerated by the request itself.
///
/// Today only Contentful has any, and it has exactly one source — the
/// self-describing `x-contentful-signed-headers` list. A list that is absent or
/// not decodable as visible ASCII contributes nothing here: `verify()` then
/// reports it missing or malformed on its own, so this scan never has to guess
/// at a shape it cannot read.
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
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .any(|name| has_conflicting_duplicates(headers, name));
    ambiguous.then_some(CONTENTFUL_SIGNED_HEADERS_HEADER)
}

/// The request's declared `Content-Length`, when present and decodable.
///
/// Parse failure — a non-visible-ASCII value, a value that is not the
/// canonical `1*DIGIT` spelling HTTP requires (a leading `+`/`-`, a radix
/// prefix, empty), or an unparseable header name — is treated as "no declared
/// length": the request then falls through to the post-buffer size check,
/// which still bounds the verification work, and the framing layer
/// (`hyper`/`axum` on tower, actix-http on actix) has already rejected
/// inconsistent `Content-Length` fields. Shared between the adapters so the
/// pre-buffer 413 guard cannot drift.
#[cfg(any(feature = "tower", feature = "actix"))]
#[must_use]
pub(crate) fn declared_content_length<H: MultiValueHeaders + ?Sized>(headers: &H) -> Option<usize> {
    let value = headers.get_first_str("content-length")?.trim();
    // HTTP's Content-Length grammar is `1*DIGIT` (RFC 9110 §8.6) — no sign, no
    // radix prefix, no separator. Parse strictly, mirroring `parse_unsigned_decimal`
    // in `replay.rs`: Rust's `usize::from_str` would otherwise silently accept a
    // leading `+` (e.g. `+100`), which is not a valid Content-Length. Any
    // non-canonical value is treated as "no declared length" and falls through to
    // the post-buffer size check, which still bounds the signature-verification work.
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
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
    use super::{declared_content_length, rejection_status};
    #[cfg(any(feature = "tower", feature = "actix"))]
    use crate::VerifyError;
    #[cfg(all(not(feature = "std"), any(feature = "tower", feature = "actix")))]
    use crate::test_helpers::*;

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

        const LIST: &str = "x-contentful-signed-headers";

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
                        reason: "header present multiple times with different values",
                    };
                    assert_eq!(
                        error,
                        VerifyError::MalformedHeader {
                            header: "X-Hub-Signature-256",
                            reason: "header present multiple times with different values",
                        },
                    );
                }
                // The two signature values differ, so the header is ambiguous;
                // `None` here would mean the scan silently did nothing.
                None => panic!("the two signature values differ, so the header is ambiguous"),
            }
        }
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
        // Legacy tolerance: surrounding whitespace was historically trimmed
        // before parsing, so keep accepting the padded spelling.
        headers.insert(
            ::http::header::CONTENT_LENGTH,
            ::http::HeaderValue::from_static(" 131072 "),
        );
        assert_eq!(declared_content_length(&headers), Some(131072));
    }
}
