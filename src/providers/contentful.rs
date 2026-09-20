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
//! timestamp is HMAC-covered and the replay window is cryptographic. If a
//! delivery ever arrives whose list does **not** include the timestamp
//! header, the timestamp is still recency-checked but is not itself
//! HMAC-covered, so an attacker who can forge a fresh signature could extend
//! the window — the same documented caveat as [`crate::CustomScheme`]. This
//! crate does not hard-fail that shape (Contentful could list a subset of
//! headers on a delivery); it preserves the best-effort replay check and
//! documents the residual risk.
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
    // signed-headers list (making the window cryptographic); when a delivery
    // does not, the check is best-effort rather than HMAC-covered — see the
    // module docs' replay caveat.
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
///   signed string), leaving everything from the first `/` onwards;
/// - any `#fragment` is dropped;
/// - a bare path (`/webhooks/...`) is used verbatim;
/// - if a `?query` is present, only the query portion is percent-encoded
///   (JavaScript `encodeURIComponent` set), with the pathname passed through
///   as UTF-8 bytes; with no query, nothing is re-encoded.
fn normalized_request_path(url: &str) -> String {
    let path_and_query: &str = match url.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        },
        None => url,
    };
    let path_and_query: &str = match path_and_query.split_once('#') {
        Some((path, _)) => &path_and_query[..path.len()],
        None => path_and_query,
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
        // ...and a caller passing an already percent-encoded query must supply
        // the raw form instead: the query is encoded exactly once, per the
        // docs' `urlEncode(query)` pseudo-code (this deliberately does not
        // reproduce the reference SDK's double-encode corner).
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

    #[test]
    fn timestamp_not_in_signed_list_still_replay_checked() {
        // A delivery whose signed-headers list omits the timestamp header: the
        // canonical string covers only `content-type` and `x-contentful-topic`
        // (see module docs' replay caveat). Within the window it verifies...
        let headers = vec![
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

        // ...but the timestamp is still recency-checked, so a replay of the
        // same signature outside the window fails closed.
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
                reason: "signature key is empty",
            })
        );
    }
}
