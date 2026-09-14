//! Shared utilities for framework adapters (tower, actix).
//!
//! This module is only compiled when an adapter feature is enabled. It holds
//! logic that the adapters share so it cannot drift as new [`VerifyError`]
//! variants are added.

use super::VerifyError;

/// Raw, multi-value header access for the framework adapters.
///
/// The crate's [`HeaderMap`](crate::HeaderMap) trait intentionally exposes
/// only first-value lookup — `spec.md` §4.4 leaves duplicate detection to the
/// adapter layer. Adapters still need every value of a header to reject
/// conflicting duplicates, and they run on two different `http` versions
/// (tower/axum on `http` 1.x, actix-web 4 on `http` 0.2), so this private
/// trait unifies the multi-value iteration [`conflicting_signature_header`]
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

/// Returns the name of the first header in `names` that occurs in `headers`
/// more than once with *differing* values — the ambiguity `spec.md` §4.4
/// requires rejecting — or `None` when none is ambiguous.
///
/// Values are compared as raw bytes: the scan must reject two lines carrying
/// different bytes, and opaque-byte values that could never parse as a
/// signature are still ambiguous when duplicated with differing bytes.
///
/// Static header-name constants always parse, so the unparseable-name arm is
/// unreachable in practice and simply fails closed (reported as ambiguous).
pub(crate) fn conflicting_signature_header<H: MultiValueHeaders + ?Sized>(
    headers: &H,
    names: &[&'static str],
) -> Option<&'static str> {
    names.iter().copied().find(|name| {
        let Some(mut values) = headers.get_all_bytes(name) else {
            return true;
        };
        let Some(first) = values.next() else {
            return false;
        };
        values.any(|value| *value != *first)
    })
}

/// The request's declared `Content-Length`, when present and decodable.
///
/// A parsing failure — a non-visible-ASCII or non-numeric value, or an
/// unparseable header name — is treated as "no declared length": the request
/// then falls through to the post-buffer size check, which still bounds the
/// verification work, and the framing layer (`hyper`/`axum` on tower,
/// actix-http on actix) has already rejected inconsistent `Content-Length`
/// fields. Shared between the adapters so the pre-buffer 413 guard cannot
/// drift.
#[must_use]
pub(crate) fn declared_content_length<H: MultiValueHeaders + ?Sized>(headers: &H) -> Option<usize> {
    headers.get_first_str("content-length")?.trim().parse().ok()
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
    use super::{declared_content_length, rejection_status};
    use crate::VerifyError;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;

    fn status_of(error: VerifyError) -> u16 {
        rejection_status(&error)
    }

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

    #[cfg(feature = "http")]
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
    }
}
