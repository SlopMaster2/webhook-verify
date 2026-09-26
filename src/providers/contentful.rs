//! Contentful webhook signature verification.
//!
//! Scheme, per Contentful's official documentation
//! (<https://www.contentful.com/developers/docs/webhooks/request-verification/>),
//! the canonicalizing helpers in their official reference SDK
//! (`@contentful/node-apps-toolkit`, `src/requests/sign-request.ts` and
//! `verify-request.ts`), and their official
//! [request-verification-examples](https://github.com/contentful-labs/request-verification-examples)
//! repository (a Rust/Warp reference that reconstructs the same canonical
//! string):
//!
//! - Headers: `x-contentful-signature` (`<hex(HMAC-SHA256(...))>`),
//!   `x-contentful-signed-headers` (a comma-separated list of the header
//!   names included in the signature), and `x-contentful-timestamp` (epoch
//!   **milliseconds**). All three are present on every request once a webhook
//!   signing secret is configured for the space.
//! - Canonical string, per the documentation's pseudo-code:
//!   `[method, requestPath, headers, requestBody].join('\n')`, where
//!   `headers` is, for each name in `x-contentful-signed-headers` (in list
//!   order), `{lowercase_name}:{value}`, joined by `;`, and `requestPath` is
//!   the delivery's URL-encoded request path (see below).
//! - Path encoding: the documentation's pseudo-code url-encodes only the
//!   *query* portion (`query = urlEncode(query)`), with the pathname passed
//!   through as its UTF-8 bytes. This crate implements exactly that: the
//!   pathname is used verbatim and the search portion is percent-encoded with
//!   JavaScript's `encodeURIComponent` unescaped set (`A-Z a-z 0-9 - _ . ! ~
//!   * ' ( )`), each other byte as `%XX` uppercase. `request_url` is passed
//!   through the same scheme→authority→path/value split as the SDK's
//!   `getNormalizedEncodedURI`; a caller may alternatively supply the bare
//!   path form (`/webhooks/...`), which is used verbatim.
//! - Path/query encoding divergence: the two sources above do **not** agree
//!   here, and no wire capture settles which one Contentful's signer follows
//!   (`spec.md` §7). The SDK runs `querystring.escape` on the query and then a
//!   second `encodeURI`, which re-escapes every `%` the first pass produced, so
//!   its `requestPath` differs from the documentation's for *any* URL with a
//!   query string (`/hook?a=b` → the SDK's `/hook?a%253Db`, the documentation's
//!   `/hook?a%3Db`) and for any path containing `%` (`/hooks/%E2%9C%93` →
//!   `/hooks/%25E2%259C%2593`). This crate implements the documentation's form,
//!   the normative source. The failure direction is safe: a mismatch here
//!   *rejects* a legitimate delivery rather than accepting a forged one. If a
//!   delivery to a query-bearing webhook URL is ever rejected as
//!   [`VerifyError::SignatureMismatch`], this divergence is the first suspect.
//!   Both forms are pinned by
//!   `path_encoding_diverges_from_the_reference_sdk_on_any_query`.
//! - Algorithm: HMAC-SHA256, hex-encoded (lowercase). Key: the space's
//!   64-character webhook signing secret, used as its UTF-8 bytes verbatim.
//!
//! # Caller-supplied context
//!
//! Like HubSpot, verification cannot proceed from headers + body + secret
//! alone: the canonical string includes both the HTTP method and the request
//! path. Callers pass them via [`VerifyOptions::request_method`] and
//! [`VerifyOptions::request_url`]. Omitting or emptying either fails closed
//! with [`VerifyError::MissingContext`] rather than degrading into a weaker
//! check.
//!
//! # Signed-header fidelity
//!
//! The list of signed headers is **self-describing**: whatever
//! `x-contentful-signed-headers` names is what was signed, in the order it
//! lists them. This crate reads the list from the request and reconstructs
//! the signed header segment exactly. Contentful's own signer emits the
//! sorted, lowercase names (e.g. `content-type,x-contentful-timestamp,
//! x-contentful-topic`), and this crate preserves any casing/order it is
//! given — the sender and receiver agree as long as each side uses the value
//! of the header. Every header named in the list must be present in the
//! request; a list referencing an absent header fails closed
//! (`MalformedHeader` on `x-contentful-signed-headers`).
//!
//! # Ambiguity scan
//!
//! Because the signed-header list is self-describing, the framework adapters'
//! duplicate-ambiguity scan (`spec.md` §4.4) can enumerate it: besides the
//! three fixed headers [`SIGNATURE_HEADER`], [`SIGNED_HEADERS_HEADER`], and
//! [`TIMESTAMP_HEADER`], they scan every header the request's list names
//! (Contentful's own signer emits `content-type` and `x-contentful-topic`).
//! A conflicting duplicate of a named header is ambiguous in exactly the same
//! way a conflicting duplicate of the signature header is, so it is rejected
//! with `MalformedHeader` on `x-contentful-signed-headers` — the only name
//! available for the error payload's `&'static str`. Identical repeats are not
//! ambiguous and verify normally, and headers the list does not name are not
//! signing material and are not scanned.
//!
//! This is what makes the scheme fully covered: the remaining carve-out in
//! `spec.md` §4.4 is for a [`crate::CustomScheme`]'s `signed_string` closure,
//! whose headers no request-declared list enumerates.
//!
//! # Replay protection
//!
//! Like HubSpot, Contentful delivers the signing timestamp in **epoch
//! milliseconds** (its docs call `x-contentful-timestamp` "timestamp of when
//! the request was signed. Can be used to ensure a TTL"). The recency check
//! converts to whole seconds (`millis / 1000`) and applies the shared
//! symmetric default window ([`VerifyOptions::max_age`], injectable clock);
//! Contentful's `node-apps-toolkit` defaults `verifyRequest` to a 30s TTL, so
//! tighten `max_age` beyond the crate default if your delivery requires it.
//!
//! Note that Contentful's signer always includes `x-contentful-timestamp` in
//! the signed-headers list (matching its published SDK), in which case the
//! timestamp is HMAC-covered and the replay window is cryptographic: editing
//! the header to "now" breaks the signature instead of extending the window.
//!
//! If a delivery ever arrives whose list does **not** name the timestamp
//! header, the window provides **no protection at all** for that shape, and
//! the reason is worth stating precisely. `x-contentful-signed-headers` is
//! itself *not* part of the canonical string — only the headers it *lists*
//! are — so with the timestamp unlisted the header falls entirely outside the
//! HMAC. An attacker holding one captured delivery of that shape replays it
//! forever by rewriting that single header to the current millisecond value;
//! the signature, method, path, and body are replayed byte for byte. No
//! signature forgery and no knowledge of the signing secret is involved, so
//! unlike the `CustomScheme` caveat — where an uncovered timestamp can at
//! least only be moved within the tolerance of a signature the attacker
//! already holds — the recency check here is bypassable outright rather than
//! merely weak.
//!
//! This crate does not hard-fail that shape (the list is self-describing, so
//! Contentful could legitimately deliver a subset of headers): it preserves
//! the best-effort recency check and documents the residual risk, which
//! `an_uncovered_timestamp_lets_a_captured_delivery_be_replayed_forever`
//! pins in both directions. Deployments that cannot rule the shape out should
//! not rely on `max_age` alone for Contentful.
//!
//! # Test-vector provenance
//!
//! Contentful publishes no frozen numeric signature example; its docs,
//! SDK, and reference examples describe the recipe above without hardcoded
//! vectors. The signature constants pinned in the tests below were therefore
//! produced by an **independent** implementation of the same documented
//! algorithm (a Python script mirroring the docs' pseudo-code and the
//! SDK's canonicalization, using Python's `hmac`/`hashlib`), after verifying
//! the recipe reproduces the canonical-string shapes shown in Contentful's
//! own example code. They are local vectors over Contentful's documented
//! construction, not wire-captured packets.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::verify_hmac_sha256;
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::replay::{check_replay, parse_millis};
use crate::core::secret::Secret;

/// The header carrying the HMAC-SHA256 signature (lowercase hex).
pub(crate) const SIGNATURE_HEADER: &str = "x-contentful-signature";

/// The header listing (comma-separated) which headers the signature covers.
pub(crate) const SIGNED_HEADERS_HEADER: &str = "x-contentful-signed-headers";

/// The header carrying the signing timestamp (unix epoch **milliseconds**).
pub(crate) const TIMESTAMP_HEADER: &str = "x-contentful-timestamp";

/// HMAC-SHA256 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 32;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let signature_value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;
    let signed_headers_value =
        headers
            .get(SIGNED_HEADERS_HEADER)
            .ok_or(VerifyError::MissingHeader {
                header: SIGNED_HEADERS_HEADER,
            })?;
    let timestamp_raw = headers
        .get(TIMESTAMP_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: TIMESTAMP_HEADER,
        })?;

    // Fail closed on missing caller context *before* touching the signature:
    // without the method and URL there is nothing to verify against, and
    // falling through would turn a configuration error into an attack-shaped
    // `SignatureMismatch`.
    let request_method = options
        .request_method
        .as_deref()
        .filter(|m| !m.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "Contentful signs the request method; set VerifyOptions::request_method",
        })?;
    let request_url = options
        .request_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "Contentful signs the request URL; set VerifyOptions::request_url",
        })?;

    let provided = parse_signature(signature_value)?;
    let key = signing_key(secret.as_bytes())?;
    let signed_header_names: Vec<String> =
        parse_signed_header_names(headers, signed_headers_value)?;

    // The timestamp must parse as epoch milliseconds before anything else is
    // compared: a malformed value is a malformed header, not a signature
    // mismatch (spec.md §2.1). The canonical string below still uses the raw
    // header bytes verbatim, exactly as signed.
    let timestamp = parse_millis(TIMESTAMP_HEADER, timestamp_raw)?;

    let request_path = normalized_request_path(request_url);
    let mut canonical = Vec::with_capacity(
        request_method.len() + request_path.len() + signed_headers_value.len() + raw_body.len() + 2,
    );
    canonical.extend_from_slice(request_method.as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(request_path.as_bytes());
    canonical.push(b'\n');
    append_signed_headers_segment(&mut canonical, headers, &signed_header_names)?;
    canonical.push(b'\n');
    // The raw request body is appended untouched (spec.md §4).
    canonical.extend_from_slice(raw_body);

    if !verify_hmac_sha256(key, &canonical, &provided) {
        return Err(VerifyError::SignatureMismatch);
    }

    // The timestamp arrives in epoch milliseconds; drop the sub-second
    // remainder (mirroring HubSpot's ms → s division) before the shared
    // recency check. Contentful's signer includes the timestamp in the
    // signed-headers list, which is what makes the window cryptographic. When
    // a delivery's list does not, the timestamp header is outside the HMAC
    // entirely and this check is bypassable by editing that one header — see
    // the module docs' replay caveat, which pins the behavior in both
    // directions.
    check_replay(timestamp / 1000, options)
}

/// Returns the HMAC key bytes: the webhook signing secret as configured, used
/// as its UTF-8 bytes verbatim. Only an empty secret is rejected, failing
/// closed with [`VerifyError::InvalidSecret`].
fn signing_key(secret: &[u8]) -> Result<&[u8], VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "signature key is empty",
        });
    }
    Ok(secret)
}

/// Parses `x-contentful-signature` into its 32 decoded signature bytes.
///
/// The value is bare lowercase hex with no prefix. Every failure mode maps to
/// a distinct error variant so callers can tell malformed-request noise from
/// signature-mismatch signals (`spec.md` §2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
            reason: "header is empty",
        });
    }

    let bytes = hex::decode(value).map_err(|_| VerifyError::BadEncoding {
        reason: "signature is not valid hex",
    })?;

    if bytes.len() != SIGNATURE_LEN_BYTES {
        return Err(VerifyError::BadEncoding {
            reason: "signature does not decode to 32 bytes",
        });
    }

    Ok(bytes)
}

/// Parses the comma-separated `x-contentful-signed-headers` list into the
/// ordered header names the signature covers, validating that the request
/// actually carries every name it lists.
///
/// The list is self-describing (`spec.md` §3, Contentful row): a delivery
/// whose list names a header the request does not carry cannot be the string
/// Contentful signed, so it fails closed. Name lookup is case-insensitive
/// (Contentful lowercases the names it emits; HTTP header names are
/// case-insensitive). The names themselves are trimmed of surrounding
/// whitespace, matching the reference implementations; a list containing an
/// empty name is malformed.
fn parse_signed_header_names(
    headers: &dyn HeaderMap,
    value: &str,
) -> Result<Vec<String>, VerifyError> {
    let malformed = || VerifyError::MalformedHeader {
        header: SIGNED_HEADERS_HEADER,
        reason: "lists a header that is not present in the request",
    };

    if value.trim().is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNED_HEADERS_HEADER,
            reason: "header is empty",
        });
    }

    let mut names = Vec::new();
    for name in value.split(',') {
        let name = name.trim();
        if name.is_empty() {
            return Err(VerifyError::MalformedHeader {
                header: SIGNED_HEADERS_HEADER,
                reason: "lists an empty header name",
            });
        }
        // Every name in the list must be present in the request.
        if headers.get(name).is_none() {
            return Err(malformed());
        }
        names.push(name.to_string());
    }
    Ok(names)
}

/// Appends the signed-header segment (`name:value` pairs joined by `;`, in
/// list order, names lowercased) to `canonical`.
fn append_signed_headers_segment(
    canonical: &mut Vec<u8>,
    headers: &dyn HeaderMap,
    signed_header_names: &[String],
) -> Result<(), VerifyError> {
    for (i, name) in signed_header_names.iter().enumerate() {
        if i > 0 {
            canonical.push(b';');
        }
        let lower = name.to_ascii_lowercase();
        canonical.extend_from_slice(lower.as_bytes());
        canonical.push(b':');
        // Presence of every listed name was already validated.
        match headers.get(name) {
            Some(value) => canonical.extend_from_slice(value.as_bytes()),
            None => {
                return Err(VerifyError::MalformedHeader {
                    header: SIGNED_HEADERS_HEADER,
                    reason: "lists a header that is not present in the request",
                });
            }
        }
    }
    Ok(())
}

/// Reduces the signing URL to the (percent-encoded) request path Contentful's
/// canonical string uses.
///
/// Mirrors the documentation's pseudo-code and the SDK's path handling:
///
/// - a full URL's `scheme://authority` is stripped (they never enter the
///   signed string). The authority ends at the first `/`, `?`, or `#`
///   (RFC 3986 §3.2), *not* at the first `/` anywhere in the remainder — a
///   `/` inside a query or fragment belongs to neither and must not be
///   mistaken for the path start;
/// - when that delimiter is `?` or `#` the path is empty, so the root `/` is
///   synthesized ahead of the query (an empty path and the root path are the
///   same request target, and Contentful signs what the SDK's `new URL(...).pathname`
///   reports, i.e. `/`);
/// - any `#fragment` is dropped;
/// - a bare path (`/webhooks/...`) is used verbatim;
/// - if a `?query` is present, only the query portion is percent-encoded
///   (JavaScript `encodeURIComponent` set), with the pathname passed through
///   as UTF-8 bytes; with no query, nothing is re-encoded.
///
/// The scheme/authority/fragment handling above mirrors both sources; the
/// query encoding deliberately follows the documentation's single pass rather
/// than the SDK's `querystring.escape` + `encodeURI` double pass (see the
/// module docs' path/query divergence note and `spec.md` §7).
fn normalized_request_path(url: &str) -> String {
    let path_and_query = if url.starts_with('/') {
        Cow::Borrowed(url)
    } else {
        match url.split_once("://") {
            // One scan for the authority's end: a `/` starts the path, while
            // a `?`/`#` means the path is empty and only the query/fragment
            // follow. Searching for `/` alone would mis-read a `/` inside
            // either of those as the path start, dropping the query or signing
            // part of the fragment.
            Some((_, rest)) => match rest.find(['/', '?', '#']) {
                Some(i) if rest.as_bytes()[i] == b'/' => Cow::Borrowed(&rest[i..]),
                Some(i) => {
                    let mut rooted = String::with_capacity(rest.len() - i + 1);
                    rooted.push('/');
                    rooted.push_str(&rest[i..]);
                    Cow::Owned(rooted)
                }
                None => Cow::Borrowed("/"),
            },
            None => Cow::Borrowed(url),
        }
    };
    let path_and_query: &str = match path_and_query.split_once('#') {
        Some((path, _)) => &path_and_query[..path.len()],
        None => &path_and_query,
    };

    match path_and_query.split_once('?') {
        Some((pathname, query)) => {
            let mut out = String::new();
            out.push_str(pathname);
            out.push('?');
            percent_encode_query(query, &mut out);
            out
        }
        None => path_and_query.to_string(),
    }
}

/// Appends `src` to `out`, percent-encoding every byte outside JavaScript's
/// `encodeURIComponent` unescaped set as `%XX` (uppercase hex).
///
/// The unescaped set matches the SDK/doc pseudo-code exactly: unreserved
/// letters/digits plus `- _ . ! ~ * ' ( )`. Everything else — including
/// space, `&`, `=`, `%`, `/`, and any non-ASCII UTF-8 byte — is encoded.
fn percent_encode_query(src: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in src.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SIGNATURE_HEADER, SIGNED_HEADERS_HEADER, TIMESTAMP_HEADER};
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    use crate::test_helpers::clocked_at;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;
    use std::time::Duration;

    /// A 64-character webhook signing secret (the documented secret shape).
    const SECRET: &str = "bF1dG2hJ4kL6mN8pQ0rS2tU4vW6bF1dG2hJ4kL6mN8pQ0rS2tU4vW6abcdefghij";
    const METHOD: &str = "POST";
    const URL: &str = "https://www.example.com/webhooks/content-management";
    /// A Contentful `ContentManagement.Entry.publish` event, minified as
    /// Contentful delivers it.
    const BODY: &[u8] = br#"{"sys":{"id":"2PTzng4EfC2gU2qkqc2kUY","type":"Entry","contentType":{"sys":{"type":"Link","linkType":"ContentType","id":"landingPage"}}},"fields":{"title":{"en-US":"Q3 launch"}},"metadata":{"tags":[]}}"#;
    /// Epoch **milliseconds**; the signing timestamp for the vectors below.
    const TIMESTAMP_MS: &str = "1753660800000";
    /// `TIMESTAMP_MS / 1000` — the whole-second clock the recency check
    /// compares against.
    const TIMESTAMP_SECS: u64 = 1_753_660_800;

    /// The topic/type headers Contentful sends on a signed delivery.
    fn delivery_headers(signature: &str) -> Vec<(String, String)> {
        vec![
            (SIGNATURE_HEADER.to_string(), signature.to_string()),
            (
                SIGNED_HEADERS_HEADER.to_string(),
                "content-type,x-contentful-timestamp,x-contentful-topic".to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP_MS.to_string()),
            (
                "X-Contentful-Topic".to_string(),
                "ContentManagement.Entry.publish".to_string(),
            ),
            (
                "Content-Type".to_string(),
                "application/vnd.contentful.management.v1+json".to_string(),
            ),
        ]
    }

    /// Runs `verify()` with the supplied context and `options`, delivering the
    /// three signed-headers-listed headers plus the signature.
    fn verify_with(
        body: &[u8],
        signature: &str,
        options: VerifyOptions,
        method: &str,
        url: &str,
    ) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Contentful,
            &delivery_headers(signature),
            body,
            &Secret::new(SECRET),
            options.with_request_method(method).with_request_url(url),
        )
    }

    /// A valid delivery at `now_secs` under the default 300s window.
    fn verify_pinned(signature: &str, now_secs: u64) -> Result<(), VerifyError> {
        verify_with(
            BODY,
            signature,
            clocked_at(now_secs, Some(Duration::from_secs(300))),
            METHOD,
            URL,
        )
    }

    #[test]
    fn official_recipe_vector_verifies() {
        // Signs over `POST\n/webhooks/content-management\ncontent-type:
        // application/vnd.contentful.management.v1+json;x-contentful-timestamp:
        // 1753660800000;x-contentful-topic:ContentManagement.Entry.publish\n`
        // plus the raw body. See module docs' test-vector provenance.
        assert_eq!(
            verify_pinned(
                "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
                TIMESTAMP_SECS,
            ),
            Ok(())
        );
    }

    #[test]
    fn query_string_vector_verifies() {
        // The request URL carries a query string; only the query portion is
        // percent-encoded (`source=webhook&v=2` → `source%3Dwebhook%26v%3D2`),
        // per the documentation's `urlEncode(query)` pseudo-code.
        let url = "https://www.example.com/webhooks/cms?source=webhook&v=2";
        let result = verify_with(
            BODY,
            "a11566b930094b9b458f1437f0448c728e21f21c759085725016af1bc608abaa",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
            METHOD,
            url,
        );
        assert_eq!(result, Ok(()));

        // The encoder runs: a query the signer did not cover ("...&v=2" vs
        // "...&v=2b") must not verify...
        assert_eq!(
            verify_with(
                BODY,
                "a11566b930094b9b458f1437f0448c728e21f21c759085725016af1bc608abaa",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                "https://www.example.com/webhooks/cms?source=webhook&v=2b",
            ),
            Err(VerifyError::SignatureMismatch)
        );
        // ...and passing an already percent-encoded query does not verify
        // either: the query is encoded exactly once, per the documentation's
        // `urlEncode(query)` pseudo-code. (The reference SDK would encode it
        // twice; the two cited sources genuinely disagree here and this crate
        // follows the documentation — see
        // `path_encoding_diverges_from_the_reference_sdk_on_any_query` and
        // `spec.md` §7.)
        assert_eq!(
            verify_with(
                BODY,
                "a11566b930094b9b458f1437f0448c728e21f21c759085725016af1bc608abaa",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                "https://www.example.com/webhooks/cms?source%3Dwebhook%26v%3D2",
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    // --- issue #231: the two cited sources disagree on query encoding --------
    //
    // The documentation's pseudo-code encodes the query once, while the
    // reference SDK's `getNormalizedEncodedURI` applies `querystring.escape`
    // and then a second `encodeURI`, which re-escapes every `%` the first pass
    // produced. The divergence fires on plain, unencoded input (`/hook?a=b`),
    // so it is not a caller-side pre-encoding mistake. Contentful publishes no
    // frozen signature for a query-bearing URL and no vector here is
    // wire-captured, so the crate cannot tell which form its signer emits; it
    // pins the documentation's form (implemented) against the SDK's (rejected)
    // for every divergent shape, so neither side drifts silently. The `per_sdk`
    // column was produced by running the SDK's function in Node.
    #[test]
    fn path_encoding_diverges_from_the_reference_sdk_on_any_query() {
        for (url, per_docs, per_sdk) in [
            ("/hook?a=b", "/hook?a%3Db", "/hook?a%253Db"),
            (
                "/hook?next=/x",
                "/hook?next%3D%2Fx",
                "/hook?next%253D%252Fx",
            ),
            (
                "/hooks/%E2%9C%93",
                "/hooks/%E2%9C%93",
                "/hooks/%25E2%259C%2593",
            ),
            (
                "/hook?a=b%23c",
                "/hook?a%3Db%2523c",
                "/hook?a%253Db%252523c",
            ),
        ] {
            assert_eq!(
                super::normalized_request_path(url),
                per_docs,
                "request_url {url:?} must normalize per the documentation's pseudo-code"
            );
            assert_ne!(
                super::normalized_request_path(url),
                per_sdk,
                "request_url {url:?} no longer diverges from the reference SDK. If a wire \
                 capture shows Contentful's signer emits the SDK's form, that is a behavior \
                 change to make deliberately — with spec.md §3 and §7 updated in the same \
                 commit — not a table to edit."
            );
        }
    }

    #[test]
    fn root_url_with_query_vector_verifies() {
        let result = verify_with(
            BODY,
            "72b6344cbfeaa72a18ffc9bfb490ea3e8bb5953d365b86c0194341bac7e0664d",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
            METHOD,
            "https://www.example.com?source=webhook&v=2",
        );
        assert_eq!(result, Ok(()));
    }

    // --- issue #216: the authority ends at the first `/`, `?`, or `#` ---------
    //
    // The authority scan used to look for the first `/` anywhere in the
    // remainder, so a `/` inside a query or fragment was mistaken for the path
    // start: the query was dropped outright and part of the fragment was
    // signed. Both silently produced a canonical string Contentful never
    // signed, so every delivery mismatched.

    #[test]
    fn root_url_query_containing_slash_is_not_mistaken_for_the_path() {
        let url = "https://www.example.com?a=/b";
        // Path is empty (so the root `/`), and the query is encoded whole:
        // `encodeURIComponent("a=/b")` is `a%3D%2Fb`.
        assert_eq!(super::normalized_request_path(url), "/?a%3D%2Fb");
        assert_eq!(
            verify_with(
                BODY,
                "7d0cdbd97937d5ed8c5781a4e1c8512cc861d6fbba914d7c86960468bcec53d0",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                url,
            ),
            Ok(())
        );
        // The pre-fix canonical path (`/b`, query dropped) must not verify.
        assert_eq!(
            verify_with(
                BODY,
                "0c3c4a6fea9b788ffcb905806c02b5595691d8318f6b483f6f4cf85b18a0a12c",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                url,
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn root_url_fragment_containing_slash_is_dropped_entirely() {
        let url = "https://www.example.com#frag/x";
        // The whole fragment is dropped, including the `/` inside it.
        assert_eq!(super::normalized_request_path(url), "/");
        assert_eq!(
            verify_with(
                BODY,
                "b995aa6eb1331f4f2d3264eda4fe18802d662e4dd05288e78cda104c4617b697",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                url,
            ),
            Ok(())
        );
        // The pre-fix canonical path (`/x`, fragment content signed) must not.
        assert_eq!(
            verify_with(
                BODY,
                "040115334cad413e31e73b2b23158e4949f348a10a139b7eb96e7fc17318d03c",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                url,
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn non_root_path_query_containing_slash_keeps_the_whole_path() {
        let url = "https://www.example.com/webhooks/cms?next=/hook";
        assert_eq!(
            super::normalized_request_path(url),
            "/webhooks/cms?next%3D%2Fhook"
        );
        assert_eq!(
            verify_with(
                BODY,
                "1ecb8f9c2a5b20f61f21ffffa63f58591060f3bea20f7152dd241ad88f849884",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                url,
            ),
            Ok(())
        );
        // The pre-fix canonical path (`/hook`, path and query both lost) must
        // not verify.
        assert_eq!(
            verify_with(
                BODY,
                "09e14d23ab40c98d542df2c20dece72b0589287534d6a947035dcdaadfbf1e22",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                url,
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn non_root_path_fragment_containing_slash_is_dropped() {
        let url = "https://www.example.com/webhooks/cms#frag/x";
        assert_eq!(super::normalized_request_path(url), "/webhooks/cms");
        assert_eq!(
            verify_with(
                BODY,
                "add119a59b03ca2d5dc6af2376b2cb53a11f96beb0f0762f8a4e5ed8e25aa645",
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
                METHOD,
                url,
            ),
            Ok(())
        );
    }

    #[test]
    fn authority_ends_at_the_first_slash_question_mark_or_hash() {
        // The path-start rule itself, table-pinned so a future refactor cannot
        // reintroduce a `/`-only scan. `urlsplit`-equivalent shapes: the
        // authority is everything up to the first `/`, `?`, or `#`.
        for (url, expected) in [
            // Ordinary path: first delimiter is `/`.
            ("https://example.com/webhooks/x", "/webhooks/x"),
            ("https://user:pw@example.com/hook", "/hook"),
            ("https://example.com//double", "//double"),
            // Empty path, query present: root + encoded query.
            ("https://example.com?a=b", "/?a%3Db"),
            ("https://example.com?a=/b", "/?a%3D%2Fb"),
            ("https://example.com:8443?a=/b", "/?a%3D%2Fb"),
            // Empty path, fragment only: root, fragment dropped.
            ("https://example.com#f", "/"),
            ("https://example.com#frag/x", "/"),
            // Query *and* fragment: the fragment goes, the query is encoded.
            ("https://example.com?a=/b#frag/x", "/?a%3D%2Fb"),
            ("https://example.com/hook?a=/b#f/x", "/hook?a%3D%2Fb"),
            // No path, no query, no fragment.
            ("https://example.com", "/"),
            // Bare paths are used verbatim and never authority-stripped.
            ("/webhooks/x?a=/b", "/webhooks/x?a%3D%2Fb"),
            (
                "/redirect/https://example.com/hook",
                "/redirect/https://example.com/hook",
            ),
            // A `#` inside a query is a literal, not a fragment delimiter.
            ("/hook?a=b%23c", "/hook?a%3Db%2523c"),
        ] {
            assert_eq!(
                super::normalized_request_path(url),
                expected,
                "request_url {url:?}"
            );
        }
    }

    #[test]
    fn unicode_query_vector_verifies() {
        // A query mixing non-ASCII UTF-8, a space, and a reserved byte `~`
        // (which `encodeURIComponent` leaves unescaped).
        let url = "https://www.example.com/webhooks/cms?q=h\u{00e9}llo w\u{00f6}rld&x=1+2~";
        let result = verify_with(
            BODY,
            "c780294e6675c75c69a9039dbd8cf97715830b48720a7820b79a080b25d0154a",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
            METHOD,
            url,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn bare_path_request_url_verifies() {
        // A caller may pass just the path (no scheme/authority); it is used
        // verbatim and the canonical path is identical to the full-URL case.
        let result = verify_with(
            BODY,
            "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
            METHOD,
            "/webhooks/content-management",
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn bare_path_containing_scheme_delimiter_is_not_truncated() {
        let result = verify_with(
            BODY,
            "feebede21c3f5baaf07d2dcd4c6afb620a259599ecdcd03c1d668463032e6ba2",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
            METHOD,
            "/redirect/https://example.com/hook",
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let result = verify(
            crate::Provider::Contentful,
            &[
                (
                    "X-CONTENTFUL-SIGNATURE",
                    "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
                ),
                (
                    "X-CONTENTFUL-SIGNED-HEADERS",
                    "Content-Type,X-Contentful-Timestamp,X-Contentful-Topic",
                ),
                ("X-Contentful-Timestamp", TIMESTAMP_MS),
                ("x-contentful-topic", "ContentManagement.Entry.publish"),
                (
                    "content-type",
                    "application/vnd.contentful.management.v1+json",
                ),
            ],
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn tampered_body_fails() {
        // The signature was computed over `BODY`; a one-character body change
        // must break verification.
        let tampered: &[u8] = br#"{"sys":{"id":"2PTzng4EfC2gU2qkqc2kUY","type":"Entry","contentType":{"sys":{"type":"Link","linkType":"ContentType","id":"landingPage"}}},"fields":{"title":{"en-US":"Q3 launch!"}},"metadata":{"tags":[]}}"#;
        assert_ne!(tampered, BODY);
        let result = verify(
            crate::Provider::Contentful,
            &delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129"),
            tampered,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn tampered_signature_fails() {
        // Flip one hex character: a wrong-but-well-formed signature.
        const GOOD: &str = "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129";
        let flipped = format!("1d{}", &GOOD[2..]);
        assert_ne!(flipped, GOOD);
        assert_eq!(
            verify_pinned(&flipped, TIMESTAMP_SECS),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let result = verify(
            crate::Provider::Contentful,
            &delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129"),
            BODY,
            &Secret::new("a-different-secret-not-matching-anything"),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_method_fails() {
        // The canonical string leads with the HTTP method; a different method
        // changes it.
        let result = verify_with(
            BODY,
            "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
            "GET",
            URL,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn wrong_request_url_fails() {
        let result = verify_with(
            BODY,
            "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300))),
            METHOD,
            "https://www.example.com/webhooks/other",
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn replay_old_timestamp_out_of_tolerance() {
        let result = verify_with(
            BODY,
            "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
            clocked_at(TIMESTAMP_SECS + 301, Some(Duration::from_secs(300))),
            METHOD,
            URL,
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
        let result = verify_with(
            BODY,
            "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
            clocked_at(TIMESTAMP_SECS - 301, Some(Duration::from_secs(300))),
            METHOD,
            URL,
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
    fn milliseconds_within_tolerance_verify_at_window_edges() {
        for now in [TIMESTAMP_SECS - 300, TIMESTAMP_SECS + 300] {
            let result = verify_with(
                BODY,
                "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
                clocked_at(now, Some(Duration::from_secs(300))),
                METHOD,
                URL,
            );
            assert_eq!(result, Ok(()), "now = {now}");
        }
    }

    #[test]
    fn disabled_max_age_accepts_stale_signatures() {
        let result = verify_with(
            BODY,
            "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
            clocked_at(TIMESTAMP_SECS + 86_400 * 365, None),
            METHOD,
            URL,
        );
        assert_eq!(result, Ok(()));
    }

    /// The headers of a delivery whose signed-headers list **omits** the
    /// timestamp header, so the canonical string covers only `content-type`
    /// and `x-contentful-topic`. Signature is over that reduced canonical
    /// string; see the module docs' replay caveat for what that shape does and
    /// does not protect.
    fn timestamp_uncovered_headers(signature: &str) -> Vec<(String, String)> {
        vec![
            (SIGNATURE_HEADER.to_string(), signature.to_string()),
            (
                SIGNED_HEADERS_HEADER.to_string(),
                "content-type,x-contentful-topic".to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP_MS.to_string()),
            (
                "X-Contentful-Topic".to_string(),
                "ContentManagement.Entry.publish".to_string(),
            ),
            (
                "Content-Type".to_string(),
                "application/vnd.contentful.management.v1+json".to_string(),
            ),
        ]
    }

    /// Replaces the value of `target` in `headers`, matched case-insensitively.
    fn set_header(headers: &mut [(String, String)], target: &str, value: &str) {
        for (name, existing) in headers.iter_mut() {
            if name.eq_ignore_ascii_case(target) {
                *existing = value.to_string();
            }
        }
    }

    #[test]
    fn timestamp_not_in_signed_list_still_replay_checked() {
        // A delivery whose signed-headers list omits the timestamp header: the
        // canonical string covers only `content-type` and `x-contentful-topic`
        // (see module docs' replay caveat). Within the window it verifies...
        let headers = timestamp_uncovered_headers(
            "0c58947137df900004500129c3707868a9ebfd35ccd7288e8097a8a0fe04d0e2",
        );
        let within = verify(
            crate::Provider::Contentful,
            &headers,
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(within, Ok(()));

        // ...but an *unmodified* replay of it outside the window fails closed.
        // This is weaker evidence than it looks: the next test shows the same
        // shape replays indefinitely once one header is rewritten.
        let stale = verify(
            crate::Provider::Contentful,
            &headers,
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP_SECS + 301, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(
            stale,
            Err(VerifyError::TimestampOutOfTolerance {
                skew: Duration::from_secs(301),
                max_age: Duration::from_secs(300),
            })
        );
    }

    #[test]
    fn an_uncovered_timestamp_lets_a_captured_delivery_be_replayed_forever() {
        // The residual risk the module docs' replay caveat describes, pinned
        // so the caveat cannot drift back into an understatement.
        //
        // `x-contentful-signed-headers` is itself *not* part of the canonical
        // string — only the headers it *lists* are. So for a delivery whose
        // list omits `x-contentful-timestamp`, the timestamp header is
        // entirely outside the HMAC, and rewriting that one header to the
        // current instant is enough to defeat the window. No signature forgery
        // and no knowledge of the signing secret is involved: the signature,
        // method, path, and body are all replayed byte-for-byte.
        let mut replayed = timestamp_uncovered_headers(
            "0c58947137df900004500129c3707868a9ebfd35ccd7288e8097a8a0fe04d0e2",
        );

        // A week later, the attacker rewrites only the uncovered timestamp
        // header to "now" and replays the capture verbatim otherwise.
        let replay_secs = TIMESTAMP_SECS + 7 * 24 * 60 * 60;
        set_header(
            &mut replayed,
            TIMESTAMP_HEADER,
            &(replay_secs * 1000).to_string(),
        );

        // The signature is untouched, so it still matches — and the recency
        // check passes too. This is the whole point: for this shape the replay
        // window is not merely "weaker", it provides no protection at all.
        //
        // The `Ok(())` here *documents the current residual risk*, it does not
        // endorse it. If a future change hard-fails a list that omits the
        // timestamp (strictly better, and a legitimate call to make — see
        // AGENTS.md §5), invert this assertion deliberately rather than
        // deleting the test, so the tradeoff stays visible.
        assert_eq!(
            verify(
                crate::Provider::Contentful,
                &replayed,
                BODY,
                &Secret::new(SECRET),
                clocked_at(replay_secs, Some(Duration::from_secs(300)))
                    .with_request_method(METHOD)
                    .with_request_url(URL),
            ),
            Ok(())
        );

        // Contrast: when the list *does* name the timestamp, the same rewrite
        // breaks the signature, because the header is inside the HMAC. This is
        // the shape Contentful's own signer emits, and the reason the caveat
        // above is scoped to the self-describing list rather than to the
        // provider as a whole.
        let mut covered =
            delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129");
        set_header(
            &mut covered,
            TIMESTAMP_HEADER,
            &(replay_secs * 1000).to_string(),
        );
        assert_eq!(
            verify(
                crate::Provider::Contentful,
                &covered,
                BODY,
                &Secret::new(SECRET),
                clocked_at(replay_secs, Some(Duration::from_secs(300)))
                    .with_request_method(METHOD)
                    .with_request_url(URL),
            ),
            Err(VerifyError::SignatureMismatch),
            "with the timestamp inside the HMAC, rewriting it breaks the signature"
        );
    }

    #[test]
    fn missing_request_method_fails_closed() {
        let result = verify(
            crate::Provider::Contentful,
            &delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129"),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default().with_request_url(URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Contentful signs the request method; set VerifyOptions::request_method",
            })
        );

        // An explicitly-empty method is treated the same as absent.
        let result = verify(
            crate::Provider::Contentful,
            &delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129"),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default()
                .with_request_method("")
                .with_request_url(URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Contentful signs the request method; set VerifyOptions::request_method",
            })
        );
    }

    #[test]
    fn missing_request_url_fails_closed() {
        let result = verify(
            crate::Provider::Contentful,
            &delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129"),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default().with_request_method(METHOD),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Contentful signs the request URL; set VerifyOptions::request_url",
            })
        );

        let result = verify(
            crate::Provider::Contentful,
            &delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129"),
            BODY,
            &Secret::new(SECRET),
            VerifyOptions::default()
                .with_request_method(METHOD)
                .with_request_url(""),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Contentful signs the request URL; set VerifyOptions::request_url",
            })
        );
    }

    #[test]
    fn missing_headers_error_distinctly() {
        // Helper: build the delivery with one of the three signing headers
        // dropped.
        fn delivery_without(sig: &str, dropped: &str) -> Vec<(String, String)> {
            let mut headers = delivery_headers(sig);
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case(dropped));
            headers
        }

        let options = VerifyOptions::default()
            .with_request_method(METHOD)
            .with_request_url(URL);

        let missing_signature = verify(
            crate::Provider::Contentful,
            &delivery_without(
                "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
                SIGNATURE_HEADER,
            ),
            BODY,
            &Secret::new(SECRET),
            options.clone(),
        );
        assert_eq!(
            missing_signature,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );

        let missing_list = verify(
            crate::Provider::Contentful,
            &delivery_without(
                "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
                SIGNED_HEADERS_HEADER,
            ),
            BODY,
            &Secret::new(SECRET),
            options.clone(),
        );
        assert_eq!(
            missing_list,
            Err(VerifyError::MissingHeader {
                header: SIGNED_HEADERS_HEADER
            })
        );

        let missing_timestamp = verify(
            crate::Provider::Contentful,
            &delivery_without(
                "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
                TIMESTAMP_HEADER,
            ),
            BODY,
            &Secret::new(SECRET),
            options,
        );
        assert_eq!(
            missing_timestamp,
            Err(VerifyError::MissingHeader {
                header: TIMESTAMP_HEADER
            })
        );
    }

    #[test]
    fn signed_headers_list_referencing_absent_header_fails_closed() {
        // The list is self-describing; a list that names a header the request
        // does not carry cannot be the canonical string Contentful signed.
        let headers = vec![
            (
                SIGNATURE_HEADER.to_string(),
                "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129".to_string(),
            ),
            (
                SIGNED_HEADERS_HEADER.to_string(),
                "content-type,x-contentful-timestamp,x-contentful-topic,host".to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP_MS.to_string()),
            (
                "X-Contentful-Topic".to_string(),
                "ContentManagement.Entry.publish".to_string(),
            ),
            (
                "Content-Type".to_string(),
                "application/vnd.contentful.management.v1+json".to_string(),
            ),
        ];
        let result = verify(
            crate::Provider::Contentful,
            &headers,
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::MalformedHeader {
                header: SIGNED_HEADERS_HEADER,
                reason: "lists a header that is not present in the request",
            })
        );
    }

    #[test]
    fn malformed_header_shapes_error_distinctly() {
        // Empty/garbage/non-hex signature.
        let empty_sig = verify_pinned("", TIMESTAMP_SECS);
        assert_eq!(
            empty_sig,
            Err(VerifyError::MalformedHeader {
                header: SIGNATURE_HEADER,
                reason: "header is empty",
            })
        );

        let non_hex = verify_pinned("not hex at all", TIMESTAMP_SECS);
        assert_eq!(
            non_hex,
            Err(VerifyError::BadEncoding {
                reason: "signature is not valid hex",
            })
        );

        // Valid hex but wrong length (31 bytes → 62 hex chars).
        let short = "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e1";
        let wrong_len = verify_pinned(short, TIMESTAMP_SECS);
        assert_eq!(
            wrong_len,
            Err(VerifyError::BadEncoding {
                reason: "signature does not decode to 32 bytes",
            })
        );

        // Uppercase hex decodes to the same bytes (the `hex` crate accepts
        // both cases); it must still verify.
        let upper = verify_pinned(
            "1C2D6EB95DAE2E5398C42493621E6813A2EB1A2FD33238B8E6A4ED1D4C33E129",
            TIMESTAMP_SECS,
        );
        assert_eq!(upper, Ok(()));

        // Empty signed-headers list.
        let empty_list = verify_with_headers(&[(SIGNED_HEADERS_HEADER, String::new())]);
        assert_eq!(
            empty_list,
            Err(VerifyError::MalformedHeader {
                header: SIGNED_HEADERS_HEADER,
                reason: "header is empty",
            })
        );

        // List containing an empty name (`.., ,..`).
        let empty_name = verify_with_headers(&[(
            SIGNED_HEADERS_HEADER,
            "content-type,,x-contentful-topic".to_string(),
        )]);
        assert_eq!(
            empty_name,
            Err(VerifyError::MalformedHeader {
                header: SIGNED_HEADERS_HEADER,
                reason: "lists an empty header name",
            })
        );

        // One-off: a list with a signed name that IS present verifies.
        let minimal = verify_with_headers(&[(
            SIGNED_HEADERS_HEADER,
            "content-type,x-contentful-topic".to_string(),
        )]);
        assert_eq!(minimal, Ok(()));
    }

    /// Verifies the primary delivery but with `overrides` inspected *instead
    /// of* the standard signed-headers value. Header ordering: signature,
    /// then override entries, then the base content headers.
    fn verify_with_headers(overrides: &[(&str, String)]) -> Result<(), VerifyError> {
        let mut headers: Vec<(String, String)> = vec![
            (
                SIGNATURE_HEADER.to_string(),
                "0c58947137df900004500129c3707868a9ebfd35ccd7288e8097a8a0fe04d0e2".to_string(),
            ),
            (
                SIGNED_HEADERS_HEADER.to_string(),
                "content-type,x-contentful-topic".to_string(),
            ),
            (TIMESTAMP_HEADER.to_string(), TIMESTAMP_MS.to_string()),
            (
                "X-Contentful-Topic".to_string(),
                "ContentManagement.Entry.publish".to_string(),
            ),
            (
                "Content-Type".to_string(),
                "application/vnd.contentful.management.v1+json".to_string(),
            ),
        ];
        for (k, v) in overrides {
            if let Some(pair) = headers.iter_mut().find(|(name, _)| name == k) {
                pair.1 = v.clone();
            } else {
                headers.push((k.to_string(), v.clone()));
            }
        }
        verify(
            crate::Provider::Contentful,
            &headers,
            BODY,
            &Secret::new(SECRET),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        )
    }

    #[test]
    fn malformed_timestamp_errors_distinctly() {
        for (value, reason) in [
            ("", "header is empty"),
            ("not-a-number", "timestamp is not valid epoch milliseconds"),
            (
                "-1753660800000",
                "timestamp is not valid epoch milliseconds",
            ),
            (
                "99999999999999999999999",
                "timestamp overflows epoch milliseconds",
            ),
        ] {
            let mut headers = delivery_headers(
                "1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129",
            );
            for (name, val) in headers.iter_mut() {
                if name.eq_ignore_ascii_case(TIMESTAMP_HEADER) {
                    *val = value.to_string();
                }
            }
            let result = verify(
                crate::Provider::Contentful,
                &headers,
                BODY,
                &Secret::new(SECRET),
                clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                    .with_request_method(METHOD)
                    .with_request_url(URL),
            );
            assert_eq!(
                result,
                Err(VerifyError::MalformedHeader {
                    header: TIMESTAMP_HEADER,
                    reason,
                }),
                "value: {value:?}"
            );
        }
    }

    #[test]
    fn empty_secret_fails_distinctly() {
        let result = verify(
            crate::Provider::Contentful,
            &delivery_headers("1c2d6eb95dae2e5398c42493621e6813a2eb1a2fd33238b8e6a4ed1d4c33e129"),
            BODY,
            &Secret::new(""),
            clocked_at(TIMESTAMP_SECS, Some(Duration::from_secs(300)))
                .with_request_method(METHOD)
                .with_request_url(URL),
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "secret is empty",
            })
        );
    }
}
