//! Twilio webhook signature verification.
//!
//! Scheme, per Twilio's official security documentation ("Validating requests
//! are coming from Twilio",
//! <https://www.twilio.com/docs/usage/security#validating-requests>) and the
//! reference implementations in Twilio's official SDKs (e.g.
//! `twilio-python`'s `twilio/request_validator.py`, `twilio-go`'s
//! `client.NewRequestValidator`):
//!
//! - Header: `X-Twilio-Signature: <base64(HMAC-SHA1(auth_token, signed_string))>`
//! - Signed string: the full request URL (protocol through query string,
//!   exactly as configured with Twilio), followed by the `POST` form fields —
//!   sorted alphabetically by name in Unix-style byte order, each field's name
//!   and value concatenated directly to the string with no delimiter.
//! - Algorithm: HMAC-SHA1, base64-encoded (standard alphabet, padded). The
//!   docs note that HMAC construction is not affected by SHA-1's collision
//!   attacks given a secret key, which is why the scheme remains SHA-1.
//! - Key: the account's Auth Token, used as its UTF-8 bytes verbatim. An empty
//!   token fails closed with [`VerifyError::InvalidSecret`].
//!
//! # Not a raw-body scheme
//!
//! Twilio and Mailchimp Transactional ([`crate::Provider::Mandrill`]) are
//! the two shipped schemes that do **not** hash the raw body: the signature
//! covers the parsed form fields instead. With [`VerifyOptions::form_params`]
//! unset — the normal case — those fields are decoded from the `raw_body`
//! argument: `application/x-www-form-urlencoded`, one field per `&`-separated
//! element, `+` read as a space and `%XX` as the byte it names. Sorting is part
//! of the signing scheme and is applied here; fields arrive in any order. Under
//! a repeated field name the values are sorted and de-duplicated too, matching
//! `twilio-python`'s `for value in sorted(set(values))` — its `get_values`
//! helper reads duplicates from Flask `MultiDict`s and Django `QueryDict`s, so
//! the reference implementation does represent them. Two deliveries carrying
//! the same multiset of fields therefore sign identically regardless of the
//! order they arrived in.
//!
//! Deriving the fields from the body is what makes this provider verifiable
//! through a framework adapter, which holds one `VerifyOptions` for every
//! delivery: a field list configured on a layer could only ever describe one
//! delivery's body, and would reject the rest (issue #363). A caller whose own
//! framework parser is authoritative can still pass every received field
//! through [`VerifyOptions::form_params`] — Twilio's docs warn against
//! verifying against a hardcoded subset, since new parameters may be added
//! without notice — and it overrides the derivation when set.
//!
//! # The JSON-body variant
//!
//! Twilio's JSON-body variant signs the **URL alone**: the body is not form
//! fields, so there is nothing for the signature to cover, and decoding it as
//! form fields would produce a *different* signed string. Ask for the explicit
//! empty parameter list for that shape ([`VerifyOptions::with_form_params`]
//! with no items), and the body is authenticated by the `bodySHA256` query
//! parameter Twilio appends to the URL — the SHA-256 hex digest of the body it
//! sent.
//!
//! Whenever the configured [`VerifyOptions::request_url`] carries a
//! `bodySHA256` parameter, this provider checks `raw_body` against it in
//! addition to the signature, and fails closed on mismatch. Without that
//! second check the signature would authenticate the URL alone, so an
//! attacker who observes one legitimate JSON delivery could replay the same URL
//! and signature with a fully attacker-chosen body. A malformed
//! `bodySHA256` parameter is a comparison failure, never a skipped check —
//! including the key with no `=` at all (`?bodySHA256`), which commits to no
//! digest and is therefore **stricter** than upstream, whose `parse_qs` drops
//! such a pair and skips the check. A URL with no `bodySHA256` parameter is
//! unchanged, which is the form-encoded case where the signed form fields
//! already cover the body.
//!
//! # Caller-supplied context
//!
//! Verification needs [`VerifyOptions::request_url`] (the full URL,
//! including any query string); omitting it fails closed with
//! [`VerifyError::MissingContext`] rather than degrading into a weaker check.
//! The form fields are derived from `raw_body` unless
//! [`VerifyOptions::form_params`] overrides them (see above). The body is also
//! consulted through the `bodySHA256` parameter above — pass the received bytes
//! as `raw_body` either way.
//!
//! # The port in the signed URL
//!
//! Twilio's signing backend is known to be inconsistent about whether the port
//! appears in the URL it signs, and the official SDKs absorb that by signing
//! **twice**: `twilio-python`'s `RequestValidator.validate` computes the
//! signature over both `remove_port(uri)` and `add_port(uri)` — the latter
//! defaulting to `443` for `https` and `80` otherwise — and accepts a match
//! against either, commented *"since sig generation on back end is
//! inconsistent"* (`twilio/request_validator.py`).
//!
//! This crate signs **one** string: [`VerifyOptions::request_url`] verbatim,
//! with no alternate-URL retry. That is the same verbatim-URL contract every
//! URL-scoped provider here follows, and it keeps the signed string one
//! auditable construction — accepting either form would mean verifying against
//! two candidate signed strings, one of which the caller never configured.
//!
//! The consequence worth knowing how to diagnose: if Twilio signed
//! `https://example.com:443/webhook` and `request_url` is
//! `https://example.com/webhook` (or the reverse), **every** delivery fails
//! with [`VerifyError::SignatureMismatch`] — an error shaped like an active
//! attack for what is really a configuration mismatch. When a Twilio
//! integration rejects all traffic with that variant and nothing else looks
//! wrong, compare the port-qualified and port-stripped spellings against the
//! URL configured in the Twilio console and pass the matching one.
//! `port_is_not_tried_alternately` pins the single-string behavior so the
//! documented choice cannot change silently.
//!
//! # Replay protection
//!
//! Twilio signs no timestamp, so [`VerifyOptions::max_age`] and the injected
//! clock have **no effect** for this provider; that is documented behavior,
//! not an oversight (`spec.md` §3).

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::vec::Vec;

use crate::core::VerifyOptions;
use crate::core::crypto::{verify_hmac_sha1, verify_sha256_digest};
use crate::core::error::VerifyError;
use crate::core::headers::HeaderMap;
use crate::core::secret::Secret;
use base64::Engine;

use super::form;

/// The header carrying Twilio's signature.
pub(crate) const SIGNATURE_HEADER: &str = "X-Twilio-Signature";

/// Query parameter naming the SHA-256 hex digest of the body Twilio sent, and
/// the only thing authenticating the body in the JSON-body variant.
const BODY_HASH_PARAM: &str = "bodySHA256";

/// HMAC-SHA1 output length in bytes.
const SIGNATURE_LEN_BYTES: usize = 20;

pub(crate) fn verify(
    headers: &dyn HeaderMap,
    raw_body: &[u8],
    secret: &Secret,
    options: &VerifyOptions,
) -> Result<(), VerifyError> {
    let value = headers
        .get(SIGNATURE_HEADER)
        .ok_or(VerifyError::MissingHeader {
            header: SIGNATURE_HEADER,
        })?;

    // Fail closed on missing caller context *before* touching the signature:
    // without the URL and the parsed fields there is nothing to verify
    // against, and falling through would turn a configuration error into an
    // attack-shaped `SignatureMismatch`.
    let url = options
        .request_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .ok_or(VerifyError::MissingContext {
            reason: "Twilio signs the full request URL; set VerifyOptions::request_url",
        })?;
    // `form_params` is the per-delivery *body*, so it cannot come from a
    // `VerifyOptions` that a framework adapter fixed at construction time
    // (issue #363). When the caller supplied one it wins — that is the
    // JSON-body variant's only spelling, and it is also the escape hatch for a
    // framework whose own parser is authoritative. Otherwise the fields are
    // decoded from the `raw_body` already handed to this function, which is the
    // same bytes every raw-body scheme verifies and the adapter buffers
    // verbatim; nothing is re-serialized (`spec.md` §4.2).
    let derived;
    let params = match options.form_params.as_deref() {
        Some(supplied) => supplied,
        None => {
            derived = form::parse_form_urlencoded(raw_body)?;
            derived.as_slice()
        }
    };

    let provided = parse_signature(value)?;
    let key = auth_token_bytes(secret.as_bytes())?;

    // Signed string: URL bytes first, then every form field's name and value
    // concatenated in byte-wise-sorted-by-(name, value) order, no delimiters.
    // Sorting and de-duplicating *within* a repeated name mirrors
    // `twilio-python`'s `for value in sorted(set(values))`, so two deliveries
    // carrying the same multiset of fields sign identically no matter what
    // order the caller received them in.
    let mut ordered: Vec<(&str, &str)> = params
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    ordered.sort_by(|(name_a, value_a), (name_b, value_b)| {
        name_a.cmp(name_b).then_with(|| value_a.cmp(value_b))
    });
    ordered.dedup();

    let mut capacity = url.len();
    for (name, value) in &ordered {
        capacity += name.len() + value.len();
    }
    let mut signed_string = Vec::with_capacity(capacity);
    signed_string.extend_from_slice(url.as_bytes());
    for (name, value) in ordered {
        signed_string.extend_from_slice(name.as_bytes());
        signed_string.extend_from_slice(value.as_bytes());
    }

    if !verify_hmac_sha1(key, &signed_string, &provided) {
        return Err(VerifyError::SignatureMismatch);
    }

    // A `bodySHA256` query parameter on the signed URL is Twilio's commitment
    // to the body it sent, and it is the *only* one when the JSON-body variant
    // signs the URL alone: the form-field list is empty, so the signature above
    // never touches the bytes that carry the event. `twilio-python` ANDs the
    // body-hash comparison into its result for exactly this reason, and this
    // must run before returning `Ok(())` — the signature is a wire value, so a
    // replayed one would otherwise authenticate an attacker-chosen body.
    //
    // The comparison is constant-time like every other digest check here, and
    // a malformed parameter is a comparison failure rather than a skipped
    // check (`twilio-python` compares the two as opaque strings, so a
    // wrong-length or non-hex value simply does not match).
    match body_sha256_param(url) {
        Some(BodyHashParam::Value(provided)) => {
            // A parameter that is not a hex digest cannot equal a SHA-256
            // digest, so this fails the comparison below. Spelled as an early
            // return rather than `unwrap_or_default()` so the fail-closed path
            // is visible.
            let Ok(expected) = hex::decode(provided) else {
                return Err(VerifyError::SignatureMismatch);
            };
            if !verify_sha256_digest(raw_body, &expected) {
                return Err(VerifyError::SignatureMismatch);
            }
        }
        // A key with no `=` commits to no digest, so it can never equal
        // `sha256_hexdigest(raw_body)`. Treating it as a failed comparison rather
        // than as an absent parameter keeps the check un-skippable: reading it as
        // "no `bodySHA256`" would hand an attacker-chosen body a clean `Ok(())`.
        Some(BodyHashParam::Malformed) => return Err(VerifyError::SignatureMismatch),
        None => {}
    }

    Ok(())
}

/// The `bodySHA256` query parameter of the signed URL, as it appears there.
///
/// The distinction between [`Value`] and [`Malformed`] is load-bearing: both
/// mean the parameter is present, so both are checked, and only the first can
/// ever match a digest.
///
/// [`Value`]: BodyHashParam::Value
/// [`Malformed`]: BodyHashParam::Malformed
enum BodyHashParam<'a> {
    /// The parameter carries a digest, which may or may not be a well-formed
    /// SHA-256 hex string — both outcomes are comparison failures.
    Value(&'a str),
    /// The parameter is present as a bare key with no `=` (e.g. `?bodySHA256`).
    /// No shape Twilio sends, and a shape `parse_qs` drops upstream, but here it
    /// commits to nothing and must not be mistaken for an absent parameter.
    Malformed,
}

/// Returns the `bodySHA256` query parameter of `url`, if present.
///
/// The fragment is removed first and the query is what remains: RFC 3986 §3.5
/// begins the fragment at the *first* `#`, so a `?` after one is part of the
/// fragment rather than a query delimiter. Parameters are then matched on their
/// exact key, as `parse_qs` does upstream, and the first occurrence wins (again
/// matching upstream's `query["bodySHA256"][0]`) — valued or not, so a bare
/// `bodySHA256` ahead of a properly valued one is reported as
/// [`BodyHashParam::Malformed`] rather than searched past.
///
/// No percent-decoding is applied. The key `bodySHA256` consists entirely of
/// unreserved characters, so a conformant encoding leaves it intact, and the
/// value is a hex digest, whose characters are equally unaffected. This is not
/// a bypass surface: `url` is covered by the HMAC verified before this runs, so
/// an attacker cannot substitute a differently-spelled parameter without also
/// forging the signature over it.
fn body_sha256_param(url: &str) -> Option<BodyHashParam<'_>> {
    // Cut the fragment before looking for the `?`, not after: a URL whose only
    // `?` is inside the fragment has *no* query component, and looking for the
    // `?` first would read a parameter out of the fragment.
    let query = url.split('#').next()?.split_once('?')?.1;
    query
        .split('&')
        .find_map(|pair| match pair.split_once('=') {
            Some((name, value)) => (name == BODY_HASH_PARAM).then_some(BodyHashParam::Value(value)),
            None => (pair == BODY_HASH_PARAM).then_some(BodyHashParam::Malformed),
        })
}

/// Returns the HMAC key bytes: the Auth Token exactly as configured.
///
/// Twilio's scheme uses the token as UTF-8 bytes; only an empty token is
/// rejected, failing closed with [`VerifyError::InvalidSecret`].
fn auth_token_bytes(secret: &[u8]) -> Result<&[u8], VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::InvalidSecret {
            reason: "auth token is empty",
        });
    }
    Ok(secret)
}

/// Parses `X-Twilio-Signature` into its 20 decoded signature bytes.
///
/// Every failure mode maps to a distinct error variant so callers can tell
/// malformed-request noise from signature-mismatch signals (§2.1).
fn parse_signature(value: &str) -> Result<Vec<u8>, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header: SIGNATURE_HEADER,
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
            reason: "signature does not decode to 20 bytes",
        });
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::SIGNATURE_HEADER;
    use crate::core::error::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::core::secret::Secret;
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use crate::verify;

    /// Official vector from Twilio's own documentation ("Explore the
    /// algorithm yourself", <https://www.twilio.com/docs/usage/security>),
    /// reproduced end-to-end: AuthToken `12345`, URL
    /// `https://example.com/myapp.php?foo=1&bar=2`, five documented `POST`
    /// fields, expected signature `L/OH5YylLD5NRKLltdqwSvS0BnU=`.
    const OFFICIAL_TOKEN: &str = "12345";
    const OFFICIAL_URL: &str = "https://example.com/myapp.php?foo=1&bar=2";
    const OFFICIAL_PARAMS: [(&str, &str); 5] = [
        ("CallSid", "CA1234567890ABCDE"),
        ("To", "+18005551212"),
        ("From", "+14158675310"),
        ("Caller", "+14158675310"),
        ("Digits", "1234"),
    ];
    const OFFICIAL_SIGNATURE: &str = "L/OH5YylLD5NRKLltdqwSvS0BnU=";

    /// The same five fields as they arrive over the wire: the body Twilio
    /// POSTs for [`OFFICIAL_PARAMS`], in its own `application/x-www-form-urlencoded`
    /// spelling (`+` percent-escaped, since a bare `+` in a form body means a
    /// space). Verifying [`OFFICIAL_SIGNATURE`] against *this* body with
    /// nothing but `request_url` configured is what pins the derivation: it is
    /// the same published signature, reached through the decoded fields.
    const OFFICIAL_BODY: &str = "CallSid=CA1234567890ABCDE&To=%2B18005551212\
                              &From=%2B14158675310&Caller=%2B14158675310&Digits=1234";

    /// Locally constructed over the same recipe with an *empty* parameter
    /// list (boundary case; matches how Twilio's SDKs sign their JSON-body
    /// variant, where only the URL is covered):
    /// `printf '%s' 'https://example.com/myapp' |
    ///  openssl dgst -sha1 -hmac '12345' -binary | base64`
    const EMPTY_PARAMS_SIGNATURE: &str = "XqNa/0zb23Pa5OkAE2d03kJM920=";

    /// Locally constructed over `"héllo, 🦀 world!"` as a `Body` field value
    /// (unicode boundary case), same recipe as above.
    const UNICODE_VALUE_SIGNATURE: &str = "DLL/FecOOE0jpcpnmuiNzzZ+GUA=";

    /// Locally constructed with the field name `Body` sent twice (`a` then
    /// `b`; under a repeated name the values are sorted, so the signed string
    /// is `...BodyaBodyb` whichever order they arrived in), same recipe as
    /// above.
    const DUPLICATE_KEYS_SIGNATURE: &str = "Pb31hQflAm8COuKbY6mJvTRORg0=";

    /// Locally constructed with `Body` sent twice as the *same* value (`a`,
    /// `a`). `twilio-python` signs each distinct value under a repeated name
    /// once (`for value in sorted(set(values))`), so the signed string is
    /// `...Bodya` and not `...BodyaBodya`, same recipe as above.
    const DEDUPLICATED_VALUES_SIGNATURE: &str = "K3Jb1Qrq6WGUVNRaQJOceDfSXUI=";

    /// Locally constructed with a repeated `Tag` name arriving out of order and
    /// with one repeated value (`b`, `a`, `a`) alongside a `Body` field: the
    /// signed order is `Bodyx`, then `Taga`, then `Tagb` (values sorted and
    /// de-duplicated), same recipe as above.
    const MIXED_DUPLICATE_SIGNATURE: &str = "BTQiD7FaiaKg43vbe6eUNKX6+7U=";

    /// Locally constructed with mixed-case names pinned to byte-wise sorting
    /// (`Digits` < `api_version` < `StatusCallback`: digits sort before
    /// letters, uppercase before lowercase), same recipe as above.
    const BYTE_SORT_ORDER_SIGNATURE: &str = "Ww6eWkSu0j/9l8dG3e+uIq1kCUI=";

    /// Twilio's own JSON-body variant example, verbatim from "Explore the
    /// algorithm yourself" (<https://www.twilio.com/docs/usage/security>): the
    /// body below, its `bodySHA256` query parameter, and — constructed with the
    /// documented recipe over the URL *alone*, since the JSON variant signs no
    /// form fields — the expected signature
    /// `printf '%s' "$url" | openssl dgst -sha1 -hmac '12345' -binary | base64`.
    const JSON_BODY: &str = r#"{"property": "value", "boolean": true}"#;
    const JSON_BODY_SHA256: &str =
        "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620";
    const JSON_BODY_URL: &str = concat!(
        "https://example.com/myapp?bodySHA256=",
        "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
    );
    const JSON_BODY_SIGNATURE: &str = "Klp85180pYIxzIO5cuyxpfh1BKw=";

    fn twilio_headers(signature: &str) -> Vec<(String, String)> {
        vec![(SIGNATURE_HEADER.to_string(), signature.to_string())]
    }

    /// Verifies the JSON-body variant: an empty parameter list plus the raw
    /// body, which is authenticated by the URL's `bodySHA256` query parameter.
    fn verify_json_body(url: &str, body: &[u8], signature: &str) -> Result<(), VerifyError> {
        verify(
            crate::Provider::Twilio,
            &twilio_headers(signature),
            body,
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default()
                .with_request_url(url)
                .with_form_params(core::iter::empty::<(&str, &str)>()),
        )
    }

    fn verify_with(params: &[(&str, &str)], signature: &str) -> Result<(), VerifyError> {
        verify_with_url("https://example.com/myapp", params, signature)
    }

    fn verify_with_url(
        url: &str,
        params: &[(&str, &str)],
        signature: &str,
    ) -> Result<(), VerifyError> {
        let options = VerifyOptions::default()
            .with_request_url(url)
            .with_form_params(params.iter().copied());
        verify(
            crate::Provider::Twilio,
            &twilio_headers(signature),
            b"unused: not a raw-body scheme",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        )
    }

    #[test]
    fn official_vector_verifies() {
        assert_eq!(
            verify_with_url(OFFICIAL_URL, &OFFICIAL_PARAMS, OFFICIAL_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn official_vector_verifies_with_params_in_any_order() {
        // Sorting is the verifier's job: reversed input order must still pass.
        let reversed: Vec<(&str, &str)> = OFFICIAL_PARAMS.iter().rev().copied().collect();
        assert_eq!(
            verify_with_url(OFFICIAL_URL, &reversed, OFFICIAL_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn boundary_param_lists_verify() {
        assert_eq!(verify_with(&[], EMPTY_PARAMS_SIGNATURE), Ok(()));
        assert_eq!(
            verify_with(&[("Body", "héllo, 🦀 world!")], UNICODE_VALUE_SIGNATURE),
            Ok(())
        );
        assert_eq!(
            verify_with(&[("Body", "a"), ("Body", "b")], DUPLICATE_KEYS_SIGNATURE),
            Ok(())
        );
        assert_eq!(
            verify_with(
                &[
                    ("StatusCallback", "https://cb"),
                    ("api_version", "2010"),
                    ("Digits", "1234")
                ],
                BYTE_SORT_ORDER_SIGNATURE
            ),
            Ok(())
        );
    }

    #[test]
    fn official_vector_verifies_from_the_form_body_alone() {
        // The official vector again, with `form_params` left unset: the fields
        // come from the body the adapter already buffered, which is what makes
        // this provider usable through one (issue #363). No options are cloned
        // per delivery and no field list has to be threaded to the layer.
        assert_eq!(
            verify(
                crate::Provider::Twilio,
                &twilio_headers(OFFICIAL_SIGNATURE),
                OFFICIAL_BODY.as_bytes(),
                &Secret::new(OFFICIAL_TOKEN),
                VerifyOptions::default().with_request_url(OFFICIAL_URL),
            ),
            Ok(())
        );
        // …and it agrees with the caller-supplied path byte for byte, so a
        // deployment can move from one to the other without a signature ever
        // changing hands.
        assert_eq!(
            verify_with_url(OFFICIAL_URL, &OFFICIAL_PARAMS, OFFICIAL_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn derived_form_fields_follow_the_signing_scheme() {
        // Everything the explicit-list tests pin, reached through the body:
        // the empty list (the URL alone), a unicode value, a repeated name
        // sorted and de-duplicated, and byte-wise name ordering.
        let body = [
            ("", EMPTY_PARAMS_SIGNATURE),
            (
                // `héllo, 🦀 world!` percent-escaped, as a sender must spell it.
                "Body=h%C3%A9llo%2C%20%F0%9F%A6%80%20world%21",
                UNICODE_VALUE_SIGNATURE,
            ),
            ("Body=a&Body=b", DUPLICATE_KEYS_SIGNATURE),
            ("Body=a&Body=a", DEDUPLICATED_VALUES_SIGNATURE),
            (
                "StatusCallback=https%3A%2F%2Fcb&api_version=2010&Digits=1234",
                BYTE_SORT_ORDER_SIGNATURE,
            ),
            ("Tag=b&Tag=a&Tag=a&Body=x", MIXED_DUPLICATE_SIGNATURE),
        ];
        for (body, signature) in body {
            assert_eq!(
                verify(
                    crate::Provider::Twilio,
                    &twilio_headers(signature),
                    body.as_bytes(),
                    &Secret::new(OFFICIAL_TOKEN),
                    VerifyOptions::default().with_request_url("https://example.com/myapp"),
                ),
                Ok(()),
                "body {body:?} must produce the same signed string as its field list"
            );
        }
    }

    #[test]
    fn a_derived_field_set_still_rejects_a_tampered_body() {
        // Deriving the fields is not a way around the signature: a body whose
        // fields differ from the ones signed signs a different string, and one
        // that merely *adds* a field does too (every field's name and value go
        // into the string, so an extra field is not invisible).
        for body in [
            "CallSid=CA9999999999ABCDE&To=%2B18005551212&From=%2B14158675310\
             &Caller=%2B14158675310&Digits=1234",
            "CallSid=CA1234567890ABCDE&To=%2B18005551212&From=%2B14158675310\
             &Caller=%2B14158675310&Digits=1234&Extra=forged",
            // Same field multiset, one byte of the name changed.
            "CallSid=CA1234567890ABCDE&To=%2B18005551212&From=%2B14158675310\
             &Caller=%2B14158675310&Digit=1234",
            // A field deleted entirely.
            "To=%2B18005551212&From=%2B14158675310&Caller=%2B14158675310&Digits=1234",
        ] {
            assert_eq!(
                verify(
                    crate::Provider::Twilio,
                    &twilio_headers(OFFICIAL_SIGNATURE),
                    body.as_bytes(),
                    &Secret::new(OFFICIAL_TOKEN),
                    VerifyOptions::default().with_request_url(OFFICIAL_URL),
                ),
                Err(VerifyError::SignatureMismatch),
                "body {body:?} must not verify"
            );
        }
    }

    #[test]
    fn a_body_that_is_not_form_encoded_is_a_mismatch_not_a_context_error() {
        // The JSON-body variant without the explicit empty list: `form_params`
        // is derived, and a JSON document is not a form body, so the derived
        // field set is not the empty one and the signature over the URL alone
        // does not match. Reported as an auth signal (401) rather than as the
        // 500 `MissingContext` this path used to give — which is why
        // `verify_json_body` still passes the empty list explicitly.
        assert_eq!(
            verify(
                crate::Provider::Twilio,
                &twilio_headers(JSON_BODY_SIGNATURE),
                JSON_BODY.as_bytes(),
                &Secret::new(OFFICIAL_TOKEN),
                VerifyOptions::default().with_request_url(JSON_BODY_URL),
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn a_body_field_that_cannot_be_decoded_is_rejected_as_malformed() {
        // `%FF` is a well-formed escape whose byte is not UTF-8, so no field
        // pair can represent it. Rejected as a malformed request (400) rather
        // than decoded lossily, which would change the signed string.
        assert_eq!(
            verify(
                crate::Provider::Twilio,
                &twilio_headers(OFFICIAL_SIGNATURE),
                b"Body=%FF",
                &Secret::new(OFFICIAL_TOKEN),
                VerifyOptions::default().with_request_url(OFFICIAL_URL),
            ),
            Err(VerifyError::BadEncoding {
                reason: "request body is not decodable application/x-www-form-urlencoded (a \
                         percent-escaped field is not valid UTF-8)"
            })
        );
    }

    #[test]
    fn supplied_form_params_win_over_the_body() {
        // The option is an override, not a cross-check: a caller whose own
        // framework parser is authoritative can still say so, whatever the body
        // holds. This is the JSON-body variant, whose empty list is the only
        // way to express "the body is not fields" — the very request the
        // derived path rejects in
        // `a_body_that_is_not_form_encoded_is_a_mismatch_not_a_context_error`.
        assert_eq!(
            verify_json_body(JSON_BODY_URL, JSON_BODY.as_bytes(), JSON_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn raw_body_is_irrelevant_to_the_scheme() {
        // The signature covers the parsed fields, not the body bytes; pin that
        // passing arbitrary body bytes alongside valid context verifies fine.
        // (Only true while the signed URL carries no `bodySHA256`: see
        // `json_body_variant_*`. And only while `form_params` is supplied —
        // with it unset, the body *is* the field source; see
        // `official_vector_verifies_from_the_form_body_alone`.)
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"totally different bytes than what was posted",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn json_body_variant_verifies_and_authenticates_the_body() {
        // Twilio's own worked example: the URL alone is signed, and the body
        // is authenticated by the `bodySHA256` query parameter carrying its
        // SHA-256 hex digest. `sha256_hexdigest` is asserted against the
        // documented digest independently so a bug in this provider's wiring
        // cannot be masked by a bug in the shared helper.
        assert_eq!(
            crate::core::crypto::sha256_hexdigest(JSON_BODY.as_bytes()),
            JSON_BODY_SHA256
        );
        assert_eq!(
            verify_json_body(JSON_BODY_URL, JSON_BODY.as_bytes(), JSON_BODY_SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn json_body_variant_rejects_a_swapped_body() {
        // The bypass this closes: the signature and URL are unchanged, so only
        // the `bodySHA256` check stands between an attacker-chosen body and an
        // `Ok(())`.
        assert_eq!(
            verify_json_body(
                JSON_BODY_URL,
                br#"{"property": "attacker", "boolean": false}"#,
                JSON_BODY_SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn json_body_variant_rejects_an_altered_signed_body() {
        // A single flipped byte of the real body must not pass.
        let mut body = JSON_BODY.as_bytes().to_vec();
        let last = body.len() - 1;
        body[last] = b' ';
        assert_eq!(
            verify_json_body(JSON_BODY_URL, &body, JSON_BODY_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn malformed_body_sha256_fails_closed() {
        // `twilio-python` compares the digest as an opaque string, so a
        // malformed or wrong-length parameter is a plain comparison failure —
        // never a silently skipped check. Each signature is validly computed
        // over its own URL, so `SignatureMismatch` here can only come from the
        // body-hash check and not from the HMAC.
        let cases: &[(&str, &str)] = &[
            // Not hex.
            (
                "https://example.com/myapp?bodySHA256=not-a-hex-digest-at-all-but-long-enough-to-look-right!!",
                "Z8qKrg+/Q1Gp9IVtToZJ0VW82vQ=",
            ),
            // Valid hex, wrong length (SHA-1 size rather than SHA-256).
            (
                "https://example.com/myapp?bodySHA256=0a1ff7634d9ab3b95db5c9a2dfe9416e41502b28",
                "cB8+ZyW0TufQ1tGySQc9x2fmJ44=",
            ),
            // Empty value.
            (
                "https://example.com/myapp?bodySHA256=",
                "PZ2ZB8j1sTWZk/inD7lFpKm8iPA=",
            ),
            // Bare key, no `=` and so no digest at all.
            (
                "https://example.com/myapp?bodySHA256",
                "WQzTl5Duh9HVXAoU0tgUrW/YDX4=",
            ),
        ];
        for &(url, signature) in cases {
            assert_eq!(
                verify_json_body(url, JSON_BODY.as_bytes(), signature),
                Err(VerifyError::SignatureMismatch),
                "url: {url:?}"
            );
        }
    }

    #[test]
    fn body_sha256_without_a_value_is_not_an_absent_parameter() {
        // `?bodySHA256` with no `=` commits to no digest. `parse_qs` drops such a
        // pair, so upstream reads it as "no body hash"; here it must not, because
        // that would skip the only thing authenticating the body of a JSON-body
        // delivery. Signature validly computed over this exact URL with the
        // documented recipe, so `Ok(())` would mean the check was skipped.
        const URL: &str = "https://example.com/myapp?bodySHA256";
        const SIGNATURE: &str = "WQzTl5Duh9HVXAoU0tgUrW/YDX4=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
        assert_eq!(
            verify_json_body(URL, b"attacker-chosen", SIGNATURE),
            Err(VerifyError::SignatureMismatch),
            "an attacker-chosen body must not ride in on a digest-less parameter"
        );
    }

    #[test]
    fn the_first_body_sha256_occurrence_wins() {
        // A bare key ahead of a properly valued one is still the first
        // occurrence, so it is the malformed shape that decides the outcome —
        // not a search that walks past it to find the value that follows.
        const URL: &str = concat!(
            "https://example.com/myapp?bodySHA256&bodySHA256=",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
        );
        const SIGNATURE: &str = "Db6tT+UQQDFTF/JYaB4oO8eHEfI=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn body_sha256_is_compared_as_decoded_bytes() {
        // Twilio emits a lowercase digest; this pins that the comparison is on
        // the decoded 32 bytes rather than on the ASCII spelling, so a
        // case-folded spelling is accepted. Documented rather than relied upon:
        // hex encoding is canonical in practice, and this is the one input
        // shape where the crate is deliberately more permissive than upstream's
        // string comparison.
        const URL: &str = concat!(
            "https://example.com/myapp?bodySHA256=",
            "0A1FF7634D9AB3B95DB5C9A2DFE9416E41502B283A80C7CF19632632F96E6620"
        );
        const SIGNATURE: &str = "GScayKQw4JgUJBVFEY3VkzEkYnI=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn body_sha256_is_not_read_from_a_similar_named_parameter() {
        // Only the exact `bodySHA256` key names a body commitment. A lookalike
        // must not be mistaken for one — Twilio's SDKs match the key exactly
        // (`parse_qs`), so a `bodySHA256x` parameter commits to nothing and the
        // body check stays correctly skipped. The signature is valid over this
        // exact URL, so if the lookalike *were* read the swapped body would
        // fail; this pins that it is not read.
        const URL: &str = concat!(
            "https://example.com/myapp?bodySHA256x=",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
        );
        const SIGNATURE: &str = "xsTf5BeAjPX2Fn6DgoCix/OOr9Y=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(())
        );
        assert_eq!(verify_json_body(URL, b"attacker-chosen", SIGNATURE), Ok(()));
    }

    #[test]
    fn body_sha256_is_read_from_anywhere_in_the_query() {
        // `bodySHA256` is not required to be the first parameter, and other
        // parameters around it must not disturb the lookup. Signature
        // constructed over this exact URL with the documented recipe.
        const URL: &str = concat!(
            "https://example.com/myapp?a=1&bodySHA256=",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620&z=2"
        );
        const SIGNATURE: &str = "XfF5rbcC5Xzh39JhYVGh3vQlHAE=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(())
        );
    }

    #[test]
    fn fragment_is_not_part_of_the_query() {
        // A `#` ends the query string: a `bodySHA256` after it is not a query
        // parameter and must not be read as one. Signature constructed over this
        // exact URL with the documented recipe.
        const URL: &str = concat!(
            "https://example.com/myapp?a=1#",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
        );
        const SIGNATURE: &str = "RMmDEbpnZkTnoUdeRvUv5GFboJU=";
        assert_eq!(
            verify_json_body(URL, b"attacker-chosen", SIGNATURE),
            Ok(()),
            "a fragment-borne lookalike is not a query parameter"
        );
    }

    #[test]
    fn a_question_mark_inside_the_fragment_does_not_open_the_query() {
        // The other half of that rule, and the half that was not implemented:
        // the query is terminated by the *first* `#`, so a `?` after one belongs
        // to the fragment and cannot open a query. `body_sha256_param` split on
        // `?` before cutting the fragment, so a URL whose only `?` sits inside
        // the fragment still yielded a `bodySHA256` — and a delivery Twilio had
        // signed over exactly that URL was rejected on a body-hash comparison
        // its URL never commits to.
        //
        // Rejection is the fail-closed direction, not a bypass: `url` is covered
        // by the HMAC verified before this runs, so the parameter cannot be
        // substituted without also forging that signature. What it cost was
        // availability — a caller whose `request_url` legitimately carries a
        // fragment lost every delivery.
        //
        // The digest is well-formed and deliberately *wrong*, so reading it must
        // reject, and the signature is the documented recipe over this URL alone
        // (`printf '%s' "$url" | openssl dgst -sha1 -hmac '12345' -binary | base64`).
        const URL: &str = concat!(
            "https://example.com/myapp#frag?bodySHA256=",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        const SIGNATURE: &str = "yMFbdakBOwHePSngwRnMc2hij6I=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(()),
            "a `?` inside the fragment is not a query delimiter"
        );

        // Only the *reading* changes, not the body: the same URL carrying the
        // real digest for this body still verifies, which is what a fragment
        // that happens to name the digest must not come to depend on.
        const URL_CARRYING_THE_REAL_DIGEST: &str = concat!(
            "https://example.com/myapp#frag?bodySHA256=",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620"
        );
        const SIGNATURE_OVER_THE_REAL_DIGEST: &str = "QfSKuagGrV/A8oasxW/2T06veVQ=";
        assert_eq!(
            verify_json_body(
                URL_CARRYING_THE_REAL_DIGEST,
                JSON_BODY.as_bytes(),
                SIGNATURE_OVER_THE_REAL_DIGEST
            ),
            Ok(())
        );
    }

    #[test]
    fn a_genuine_query_is_unaffected_by_a_later_fragment() {
        // The fix is a reordering, so pin the direction it must not move: a
        // real `bodySHA256` ahead of a `#` is still the query's, and the
        // fragment after it cannot displace or shadow it.
        const URL: &str = concat!(
            "https://example.com/myapp?bodySHA256=",
            "0a1ff7634d9ab3b95db5c9a2dfe9416e41502b283a80c7cf19632632f96e6620",
            "#frag?bodySHA256=",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        const SIGNATURE: &str = "1qYIGWnpYzsyqvYC/8KGq+IV+hg=";
        assert_eq!(
            verify_json_body(URL, JSON_BODY.as_bytes(), SIGNATURE),
            Ok(()),
            "the query's own parameter is found ahead of the fragment"
        );
    }

    #[test]
    fn header_name_lookup_is_case_insensitive() {
        let result = verify(
            crate::Provider::Twilio,
            &[("x-twilio-signature", OFFICIAL_SIGNATURE)],
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default()
                .with_request_url(OFFICIAL_URL)
                .with_form_params(OFFICIAL_PARAMS),
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn negative_flipped_signature_byte_fails() {
        // Flip one character *within* the base64 alphabet so this exercises a
        // wrong-but-well-formed signature, not a decoding failure.
        let flipped = format!("{}O{}", &OFFICIAL_SIGNATURE[..1], &OFFICIAL_SIGNATURE[2..]);
        assert_ne!(flipped, OFFICIAL_SIGNATURE);
        assert_eq!(
            verify_with(&OFFICIAL_PARAMS, &flipped),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_field_value_fails() {
        let tampered: Vec<(&str, &str)> = OFFICIAL_PARAMS
            .iter()
            .map(|&(k, v)| if k == "Digits" { (k, "9999") } else { (k, v) })
            .collect();
        assert_eq!(
            verify_with(&tampered, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn omitted_field_fails() {
        // Twilio's docs warn against verifying against a hardcoded subset:
        // dropping any signed field must break verification.
        let subset = &OFFICIAL_PARAMS[1..];
        assert_eq!(
            verify_with(subset, OFFICIAL_SIGNATURE),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn tampered_url_fails() {
        // A delivery signed for any other endpoint — here differing by a
        // single trailing slash — must not verify.
        let options = VerifyOptions::default()
            .with_request_url("https://example.com/myapp.php/?foo=1&bar=2")
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn port_is_not_tried_alternately() {
        // Twilio's signing backend is known to be inconsistent about whether
        // the port appears in the signed URL, and the official SDKs absorb that
        // by signing both spellings and accepting either
        // (`twilio-python`: `valid_signature or valid_signature_with_port`,
        // commented "since sig generation on back end is inconsistent"). This
        // crate signs `request_url` verbatim and retries no alternate URL, so
        // the port-qualified and port-stripped spellings are *not*
        // interchangeable here. Pin both directions: a signature valid over one
        // must not be rescued by the other, and a genuinely signed delivery
        // must still verify. Without this, widening to two candidate signed
        // strings — one the caller never configured — would be a silent
        // behavior change rather than the documented choice.
        //
        // Signatures constructed with the documented recipe over an empty
        // parameter list. The port-stripped URL is `verify_with`'s default, so
        // that signature is the existing `EMPTY_PARAMS_SIGNATURE` rather than
        // a second spelling of the same value:
        //   printf '%s' "$url" | openssl dgst -sha1 -hmac '12345' -binary | base64
        const PORT_URL: &str = "https://example.com:443/myapp";
        const PORT_SIGNATURE: &str = "eR6XGaSSZgXExifpGrD4+fQoUwE=";

        assert_eq!(verify_with(&[], EMPTY_PARAMS_SIGNATURE), Ok(()));
        assert_eq!(verify_with_url(PORT_URL, &[], PORT_SIGNATURE), Ok(()));

        assert_eq!(
            verify_with_url(PORT_URL, &[], EMPTY_PARAMS_SIGNATURE),
            Err(VerifyError::SignatureMismatch),
            "a signature over the port-stripped URL is not retried with the port added"
        );
        assert_eq!(
            verify_with(&[], PORT_SIGNATURE),
            Err(VerifyError::SignatureMismatch),
            "a signature over the port-qualified URL is not retried with the port stripped"
        );
    }

    #[test]
    fn duplicate_field_names_are_sorted_and_deduplicated() {
        // `twilio-python` signs `for value in sorted(set(values))` under each
        // repeated name, so a multiset of same-named values signs identically
        // whatever order it arrived in, and a repeated value is signed once.
        // Each assertion feeds a permutation (or duplicate) of the values its
        // signature was built from.
        assert_eq!(
            verify_with(&[("Body", "a"), ("Body", "b")], DUPLICATE_KEYS_SIGNATURE),
            Ok(())
        );
        assert_eq!(
            verify_with(&[("Body", "b"), ("Body", "a")], DUPLICATE_KEYS_SIGNATURE),
            Ok(()),
            "received order must not matter"
        );
        assert_eq!(
            verify_with(
                &[("Body", "a"), ("Body", "a")],
                DEDUPLICATED_VALUES_SIGNATURE
            ),
            Ok(()),
            "the duplicate `a` is signed once"
        );
        assert_eq!(
            verify_with(
                &[("Tag", "b"), ("Tag", "a"), ("Body", "x"), ("Tag", "a")],
                MIXED_DUPLICATE_SIGNATURE
            ),
            Ok(()),
            "repeated out-of-order names with a repeated value"
        );
    }

    #[test]
    fn widening_a_duplicate_set_breaks_the_signature() {
        // The set semantics are on the signed string, not a tolerance: adding a
        // distinct third value under `Body` changes it and must fail.
        assert_eq!(
            verify_with(
                &[("Body", "a"), ("Body", "b"), ("Body", "c")],
                DUPLICATE_KEYS_SIGNATURE
            ),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new("secondary-auth-token-not-yet-primary"),
            options,
        );
        assert_eq!(result, Err(VerifyError::SignatureMismatch));
    }

    #[test]
    fn empty_secret_fails_closed_as_invalid_secret() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(""),
            options,
        );
        assert_eq!(
            result,
            Err(VerifyError::InvalidSecret {
                reason: "secret is empty"
            })
        );
    }

    #[test]
    fn max_age_has_no_effect_for_twilio() {
        // Twilio signs no timestamp: even a zero-second tolerance must not
        // reject a validly signed delivery. Pins the documented behavior.
        let options = crate::core::options::VerifyOptions {
            max_age: Some(std::time::Duration::ZERO),
            request_url: Some(OFFICIAL_URL.to_string()),
            form_params: Some(
                OFFICIAL_PARAMS
                    .iter()
                    .map(|&(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            ..crate::core::options::VerifyOptions::default()
        };
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn missing_request_context_fails_closed_as_missing_context() {
        // No URL at all.
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default().with_form_params(OFFICIAL_PARAMS),
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingContext {
                reason: "Twilio signs the full request URL; set VerifyOptions::request_url"
            })
        );

        // `form_params` is no longer required context (issue #363): absent, the fields
        // are decoded from `raw_body`, so the option that *is* still required
        // here is the URL. `derived_form_fields_*` pins the derived path.

        // An explicitly empty URL is equally unusable.
        let result = verify(
            crate::Provider::Twilio,
            &twilio_headers(OFFICIAL_SIGNATURE),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            VerifyOptions::default()
                .with_request_url("")
                .with_form_params(OFFICIAL_PARAMS),
        );
        assert!(matches!(result, Err(VerifyError::MissingContext { .. })));
    }

    #[test]
    fn missing_header_errors_distinctly() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let result = verify(
            crate::Provider::Twilio,
            &Vec::<(String, String)>::new(),
            b"",
            &Secret::new(OFFICIAL_TOKEN),
            options,
        );
        assert_eq!(
            result,
            Err(VerifyError::MissingHeader {
                header: SIGNATURE_HEADER
            })
        );
    }

    #[test]
    fn malformed_and_bad_encoding_errors_are_distinct() {
        let options = VerifyOptions::default()
            .with_request_url(OFFICIAL_URL)
            .with_form_params(OFFICIAL_PARAMS);
        let cases: &[(&str, VerifyError)] = &[
            (
                "",
                VerifyError::MalformedHeader {
                    header: SIGNATURE_HEADER,
                    reason: "header is empty",
                },
            ),
            // Valid base64 alphabet but wrong decoded length (SHA-256 size).
            (
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                VerifyError::BadEncoding {
                    reason: "signature does not decode to 20 bytes",
                },
            ),
        ];
        for &(value, expected) in cases {
            let result = verify(
                crate::Provider::Twilio,
                &[(SIGNATURE_HEADER, value)],
                b"",
                &Secret::new(OFFICIAL_TOKEN),
                options.clone(),
            );
            assert_eq!(result, Err(expected), "input: {value:?}");
        }

        for value in [
            "not base64!!",
            // Padded standard-base64 engine rejects unpadded input.
            OFFICIAL_SIGNATURE.trim_end_matches('='),
        ] {
            let result = verify(
                crate::Provider::Twilio,
                &[(SIGNATURE_HEADER, value)],
                b"",
                &Secret::new(OFFICIAL_TOKEN),
                options.clone(),
            );
            match result {
                Err(VerifyError::BadEncoding { .. }) => {}
                other => panic!("expected BadEncoding for {value:?}, got {other:?}"),
            }
        }
    }
}
