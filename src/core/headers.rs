//! The [`HeaderMap`] abstraction: lets `verify()` work against any framework's
//! header representation.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::HashMap;

/// Case-insensitive, read-only header lookup.
///
/// Returns the value of the *first* header matching `name` (ASCII
/// case-insensitively), or `None` if absent. For ordered collections
/// (`Vec`, arrays, slices) "first" means insertion order. For `BTreeMap`
/// the winner among case-variant keys (e.g. `X-Sig` vs `x-sig`) is the
/// lexicographically smallest; for `HashMap` it is hash-seed-dependent
/// and nondeterministic across Rust versions. **Callers must not supply
/// case-variant keys** when using map-backed `HeaderMap` impls — the
/// value returned in that scenario is unspecified for those types.
///
/// # Ambiguity contract
///
/// Per `spec.md` §4.4, a request whose signature header appears multiple times
/// with *different* values is ambiguous and must be rejected — but detection of
/// duplicates belongs to the caller/adapter layer, since this trait exposes
/// only first-match lookup. Framework adapters are expected to reject
/// duplicated signature headers before calling [`crate::verify()`].
///
/// # `HashMap` caveat
///
/// For `HashMap` the inherent exact-case `get` shadows this trait method in
/// method-call position. Pass the map to `HeaderMap::get(&map, name)` to get
/// the case-insensitive lookup this crate relies on. If the map contains
/// case-variant keys (e.g. `X-Sig` and `x-sig`), which value is returned
/// is unspecified — it depends on hash-seed-dependent iteration order.
///
/// # `BTreeMap` caveat
///
/// For [`BTreeMap`] the inherent exact-case `get` shadows this trait method in
/// method-call position. Pass the map to `HeaderMap::get(&map, name)` to get
/// the case-insensitive lookup this crate relies on. If the map contains
/// case-variant keys, the returned value is that of the key that is
/// lexicographically smallest (by ASCII byte value).
///
/// # Slice caveat
///
/// A [`slice`] also has an inherent `get` (indexing by `usize`) that shadows
/// this trait method in method-call position. The slices the impls below cover
/// (`[(&str, &str)]` and `[(String, String)]`) are usually passed as a `&[T]`
/// to [`crate::verify()`], where unsized coercion selects the trait impl —
/// there is no ambiguity in that position. Method-call syntax on the slice
/// itself behaves like the maps above: use `HeaderMap::get(&slice, name)`.
///
/// # `http::HeaderMap` support
///
/// Behind the `http` feature this trait is implemented for
/// `http::HeaderMap`, so requests from any framework built on the `http`
/// crate (axum, tower, hyper) verify without copying headers. Lookup uses
/// that type's own first-value-wins, case-insensitive semantics; a value
/// that is not visible ASCII (which `http` permits but this crate cannot
/// treat as a signature) is reported as absent, failing closed downstream
/// as a missing header.
pub trait HeaderMap {
    /// Case-insensitive lookup of a single header value.
    fn get(&self, name: &str) -> Option<&str>;
}

impl HeaderMap for Vec<(String, String)> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl<const N: usize> HeaderMap for [(String, String); N] {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl<const N: usize> HeaderMap for [(&str, &str); N] {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

impl HeaderMap for Vec<(&str, &str)> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

/// Borrowed slice of str tuples — covers subsections of a header table
/// (`&vec[..]`, `&array[1..]`, a function parameter that hands you `&[..]`)
/// without an owning allocation alongside the array impl.
impl HeaderMap for [(&str, &str)] {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

/// Borrowed slice of owned strings, the unsized counterpart of the
/// `[(String, String); N]` array impl.
impl HeaderMap for [(String, String)] {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl HeaderMap for BTreeMap<String, String> {
    fn get(&self, name: &str) -> Option<&str> {
        // Keys may differ in case from the canonical names providers document,
        // so exact-key lookup is not enough.
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(feature = "std")]
impl HeaderMap for HashMap<String, String> {
    fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(feature = "http")]
impl HeaderMap for ::http::HeaderMap {
    fn get(&self, name: &str) -> Option<&str> {
        // `HeaderName::from_bytes` normalizes to lowercase and rejects names
        // with invalid bytes, so an unparseable lookup name is simply a miss.
        // The inherent `get` (reached via UFCS with the typed key) is
        // case-insensitive per HTTP semantics and returns the first value
        // when several are present. Duplicate *detection* stays the
        // adapter's job — see the trait's ambiguity contract.
        let key = ::http::header::HeaderName::from_bytes(name.as_bytes()).ok()?;
        let value = ::http::HeaderMap::get(self, &key)?;
        value.to_str().ok()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use std::collections::BTreeMap;
    #[cfg(feature = "std")]
    use std::collections::HashMap;

    use super::HeaderMap;

    #[test]
    fn lookup_is_ascii_case_insensitive() {
        let headers = vec![("X-Hub-Signature-256".to_string(), "sha256=ab".to_string())];
        assert_eq!(headers.get("x-hub-signature-256"), Some("sha256=ab"));
        assert_eq!(headers.get("X-HUB-SIGNATURE-256"), Some("sha256=ab"));
        assert_eq!(headers.get("x-hub-signature-1"), None);
    }

    #[test]
    fn first_match_wins() {
        let headers = [
            ("a".to_string(), "first".to_string()),
            ("A".to_string(), "second".to_string()),
        ];
        assert_eq!(headers.get("A"), Some("first"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn hash_map_is_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("Webhook-Signature".to_string(), "v1,aa".to_string());
        assert_eq!(HeaderMap::get(&headers, "webhook-signature"), Some("v1,aa"));
        assert_eq!(HeaderMap::get(&headers, "WEBHOOK-SIGNATURE"), Some("v1,aa"));
        assert_eq!(HeaderMap::get(&headers, "missing"), None);
    }

    #[test]
    fn btree_map_is_case_insensitive() {
        let mut headers = BTreeMap::new();
        headers.insert("Webhook-Signature".to_string(), "v1,aa".to_string());
        // Note: `headers.get(..)` would resolve to BTreeMap's *inherent* exact-key
        // lookup, which shadows the trait method in method-call position; go
        // through the trait explicitly.
        assert_eq!(HeaderMap::get(&headers, "webhook-signature"), Some("v1,aa"));
    }

    #[test]
    fn str_tuple_arrays_work() {
        let headers = [("X-Slack-Signature", "v0=ff")];
        assert_eq!(headers.get("x-slack-signature"), Some("v0=ff"));
    }

    #[test]
    fn str_tuple_vecs_work() {
        // Dynamically-built header lists of static strings — the `Vec`
        // counterpart of the fixed array form (spec.md §2).
        let mut headers: Vec<(&str, &str)> = vec![("X-Slack-Signature", "v0=ff")];
        headers.push(("Host", "example.com"));
        assert_eq!(
            headers.get("x-slack-signature"),
            Some("v0=ff"),
            "case-insensitive lookup on the str-tuple Vec"
        );
        assert_eq!(headers.get("MISSING"), None);
    }

    // --- borrowed slices ([(&str, &str)] and [(String, String)]) ------------

    #[test]
    fn str_tuple_slices_work() {
        // A bare `&[(&str, &str)]` — the type a read-only header table, a
        // subslice (`&vec[..]` / `&array[1..]`), or an argument slice yields.
        // Method-call `get` would hit the slice's inherent usize-index; go
        // through the trait explicitly (documented caveat).
        let table: &[(&str, &str)] = &[("Host", "example.com"), ("X-Slack-Signature", "v0=ff")];
        assert_eq!(HeaderMap::get(table, "x-slack-signature"), Some("v0=ff"));
        assert_eq!(HeaderMap::get(table, "X-SLACK-SIGNATURE"), Some("v0=ff"));
        assert_eq!(HeaderMap::get(table, "MISSING"), None);
    }

    #[test]
    fn string_tuple_slices_work() {
        let table: &[(String, String)] = &[
            ("X-Hub-Signature-256".to_string(), "sha256=ab".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        assert_eq!(
            HeaderMap::get(table, "x-hub-signature-256"),
            Some("sha256=ab")
        );
        assert_eq!(
            HeaderMap::get(table, "Content-Type"),
            Some("application/json")
        );
        assert_eq!(HeaderMap::get(table, "MISSING"), None);
    }

    #[test]
    fn subslices_of_header_tables_work() {
        // `&vec[..]` coerces to a `[(&str, &str)]` slice; a mid-table window
        // must look the same as the raw table would.
        let vec_headers = vec![
            ("Host", "example.com"),
            ("X-Slack-Signature", "v0=ff"),
            ("x-slack-request-timestamp", "1531420618"),
        ];
        let whole: &[(&str, &str)] = &vec_headers;
        assert_eq!(HeaderMap::get(whole, "x-slack-signature"), Some("v0=ff"));

        let window: &[(&str, &str)] = &vec_headers[1..];
        assert_eq!(HeaderMap::get(window, "x-slack-signature"), Some("v0=ff"));
        assert_eq!(HeaderMap::get(window, "Host"), None);
        assert_eq!(
            HeaderMap::get(window, "x-slack-request-timestamp"),
            Some("1531420618")
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn slices_verify_end_to_end() {
        // The same GitHub vector passed as a plain slice reaches the same
        // result as through the Vec/array forms.
        use crate::{Provider, Secret, verify};

        let result = verify(
            Provider::GitHub,
            &[(
                "X-Hub-Signature-256",
                "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
            )],
            b"Hello, World!",
            &Secret::new("It's a Secret to Everybody"),
            Default::default(),
        );
        assert_eq!(result, Ok(()));
    }

    // --- `http::HeaderMap` (feature = "http") ---------------------------------

    #[cfg(feature = "http")]
    mod http_header_map {
        use super::HeaderMap;
        use crate::{Provider, Secret, verify};

        /// GitHub's documented example vector
        /// (<https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries>),
        /// same one used in the crate-level docs.
        fn github_headers() -> ::http::HeaderMap {
            let mut headers = ::http::HeaderMap::new();
            headers.insert(
                "X-Hub-Signature-256",
                ::http::HeaderValue::from_static(
                    "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17",
                ),
            );
            headers
        }

        #[test]
        fn lookup_is_ascii_case_insensitive() {
            let headers = github_headers();
            assert_eq!(
                HeaderMap::get(&headers, "x-hub-signature-256"),
                Some("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
            );
            assert_eq!(
                HeaderMap::get(&headers, "X-HUB-SIGNATURE-256"),
                Some("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
            );
            assert_eq!(headers.get("x-hub-signature-1"), None);
        }

        #[test]
        fn first_value_wins_for_multivalued_headers() {
            let mut headers = ::http::HeaderMap::new();
            headers.append(
                "X-Slack-Signature",
                ::http::HeaderValue::from_static("v0=first"),
            );
            headers.append(
                "X-Slack-Signature",
                ::http::HeaderValue::from_static("v0=second"),
            );
            assert_eq!(
                HeaderMap::get(&headers, "X-Slack-Signature"),
                Some("v0=first")
            );
        }

        #[test]
        fn unparseable_lookup_name_is_a_miss_not_a_panic() {
            let headers = github_headers();
            // Invalid header-name bytes must yield `None`, never panic.
            assert_eq!(HeaderMap::get(&headers, "bad name\n"), None);
            assert_eq!(HeaderMap::get(&headers, ""), None);
        }

        #[test]
        fn non_visible_ascii_value_is_reported_absent() {
            let mut headers = ::http::HeaderMap::new();
            // The `http` crate permits opaque bytes >= 0x80 in header values,
            // so such values are reachable in practice (e.g. hand-built
            // maps); `to_str` rejects them, and we surface that as absent
            // rather than panicking or silently matching.
            let Ok(value) = ::http::HeaderValue::from_bytes(&[0xFF]) else {
                panic!("0xFF is a permitted header-value byte");
            };
            headers.insert("X-Webhook-Sig", value);
            assert_eq!(HeaderMap::get(&headers, "X-Webhook-Sig"), None);
        }

        /// End-to-end: a real provider verifies straight against an
        /// `http::HeaderMap` with no header copying.
        #[test]
        fn verifies_github_delivery_end_to_end() {
            let result = verify(
                Provider::GitHub,
                &github_headers(),
                b"Hello, World!",
                &Secret::new("It's a Secret to Everybody"),
                Default::default(),
            );
            assert_eq!(result, Ok(()));

            // And a tampered body fails closed through the same path.
            let result = verify(
                Provider::GitHub,
                &github_headers(),
                b"Hello, World?",
                &Secret::new("It's a Secret to Everybody"),
                Default::default(),
            );
            assert_eq!(result, Err(crate::VerifyError::SignatureMismatch));
        }

        #[test]
        fn missing_header_surfaces_as_missing_header_error() {
            let result = verify(
                Provider::GitHub,
                &::http::HeaderMap::new(),
                b"Hello, World!",
                &Secret::new("It's a Secret to Everybody"),
                Default::default(),
            );
            assert_eq!(
                result,
                Err(crate::VerifyError::MissingHeader {
                    header: "X-Hub-Signature-256"
                })
            );
        }
    }
}
