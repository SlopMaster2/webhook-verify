//! `application/x-www-form-urlencoded` decoding, for the two schemes whose
//! signature covers the *parsed* form fields rather than the body bytes
//! (Twilio and Mailchimp Transactional / Mandrill).
//!
//! Both schemes sign `{url}{name1}{value1}{name2}{value2}…` with the fields in
//! sorted order, so the field *names and values* are signing material and the
//! body bytes are not. This module is what lets `verify()` recover those fields
//! from the `raw_body` it is already handed, which is the difference between
//! those two providers being verifiable through a framework adapter and not
//! (issue #363): the adapters fix one `VerifyOptions` when the layer is built,
//! so a caller-supplied field list can only ever describe one delivery.
//!
//! # What it does and does not do
//!
//! It **decodes** — `+` becomes a space and `%XX` becomes the byte it names —
//! and it never re-encodes: the signed string is built from the decoded names
//! and values, so this module is not a re-serialization of the body in the
//! sense `spec.md` §4.2 forbids for the raw-body schemes. Nothing here is ever
//! compared against a signature, hashed, or logged; it is input to the signed
//! string, and a field that decodes to the wrong bytes produces the wrong
//! signed string, i.e. a `SignatureMismatch`.
//!
//! # Shape
//!
//! One pass over the body: split on `&`, split each element at its **first**
//! `=` (an element with none is a name with an empty value), drop empty
//! elements, and keep every field otherwise — order preserved, duplicates
//! preserved. Sorting and de-duplication are the signing scheme's business and
//! happen in the providers, not here.
//!
//! The rules mirror `urllib.parse.parse_qs` / `urllib.parse.unquote`, which is
//! what the reference verifiers read their fields from indirectly (Twilio's
//! official SDKs hand the validator whatever the host framework parsed, and
//! Python's `parse_qs` is the common case):
//!
//! - only `&` separates fields — a `;` is an ordinary value byte here, as it is
//!   to `parse_qs` and to every framework parser this replaces;
//! - a name and a value with nothing after `=` are kept as an empty value,
//!   which is what `keep_blank_values=True` parsers do and what
//!   `Body=hello&Body=` needs;
//! - a `%` not followed by two hex digits is a literal `%`, and the bytes after
//!   it are read as ordinary text, exactly as `unquote` does;
//! - a field that decodes to invalid UTF-8 cannot be a field either provider
//!   signed, so it fails closed with [`VerifyError::BadEncoding`] (a `400`,
//!   "malformed request") rather than being replaced by U+FFFD, which would
//!   change the signed string.

#![deny(clippy::unwrap_used, clippy::expect_used)]

use alloc::string::String;
use alloc::vec::Vec;

use crate::core::error::VerifyError;

/// The single decoding failure this module can report.
///
/// `BadEncoding` is the crate's existing "the request bytes are not in the
/// shape the scheme requires" variant, and the adapters already map it to `400`
/// (malformed request) rather than to an auth signal. The reason is a `&'static
/// str` like every other: it names the shape that failed, never the body.
const NOT_FORM_ENCODED: &str = "request body is not decodable application/x-www-form-urlencoded (a percent-escaped field is not valid UTF-8)";

/// Splits an `application/x-www-form-urlencoded` `body` into its
/// `(name, value)` pairs, in the order they appeared, duplicates preserved.
///
/// Returns [`VerifyError::BadEncoding`] when a field decodes to bytes that are
/// not valid UTF-8, since a `String` pair is what the signed string is built
/// from and a lossy substitution would authenticate a field the provider never
/// signed.
///
/// The pairs are *not* sorted or de-duplicated here: that is part of each
/// provider's signing scheme, and doing it in the providers keeps one
/// implementation of it for the two schemes that share the rule.
pub(crate) fn parse_form_urlencoded(body: &[u8]) -> Result<Vec<(String, String)>, VerifyError> {
    let mut fields = Vec::new();
    for element in body.split(|byte| *byte == b'&') {
        // An empty element is what a leading, doubled, or trailing `&` (and an
        // empty body) produce. `parse_qs` drops those, and a field whose name
        // and value are both empty would sign the empty string — i.e. nothing.
        if element.is_empty() {
            continue;
        }
        let (name, value): (&[u8], &[u8]) = match element.iter().position(|byte| *byte == b'=') {
            Some(at) => (&element[..at], &element[at + 1..]),
            None => (element, &[]),
        };
        fields.push((decode_field(name)?, decode_field(value)?));
    }
    Ok(fields)
}

/// Decodes one field's bytes: `+` to a space, `%XX` to the byte it names.
///
/// An invalid escape is a literal `%`, and the walk resumes at the byte right
/// after it — so the bytes that follow are still decoded in their own right,
/// which is what `unquote` does and what a `parse_qs` caller would have got.
/// Rejecting them instead would turn a signed-but-unusual field into a rejected
/// delivery for no security gain, and consuming them here would make `%+`
/// decode differently from `parse_qs`.
///
/// None of that helps an attacker: the decoded field only reaches the signed
/// string, which is compared against the signature. A field spelled `%41` and
/// one spelled `A` produce the same signed string *for the provider and for the
/// verifier alike*, which is the same equivalence the field multiset already
/// has.
fn decode_field(field: &[u8]) -> Result<String, VerifyError> {
    // One allocation per field, sized for the encoded form: a percent-escape
    // and a `+` only ever *shrink* a field, so this is the upper bound.
    let mut decoded = Vec::with_capacity(field.len());
    let mut at = 0;
    while at < field.len() {
        match field[at] {
            b'+' => {
                decoded.push(b' ');
                at += 1;
            }
            b'%' => {
                let escaped = field
                    .get(at + 1..at + 3)
                    .and_then(|pair| match pair {
                        [high, low] => Some((hex_digit(*high)?, hex_digit(*low)?)),
                        _ => None,
                    })
                    .map(|(high, low)| (high << 4) | low);
                match escaped {
                    Some(byte) => {
                        decoded.push(byte);
                        at += 3;
                    }
                    None => {
                        decoded.push(b'%');
                        at += 1;
                    }
                }
            }
            byte => {
                decoded.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| VerifyError::BadEncoding {
        reason: NOT_FORM_ENCODED,
    })
}

/// The value of a hexadecimal digit, or `None` for anything else.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use crate::test_helpers::*;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{NOT_FORM_ENCODED, parse_form_urlencoded};
    use crate::VerifyError;

    /// The parse, as the `(name, value)` pairs the signed string is built from.
    fn fields(body: &[u8]) -> Vec<(String, String)> {
        parse_form_urlencoded(body).unwrap_or_else(|error| panic!("{body:?} must parse: {error}"))
    }

    /// The five documented fields from Twilio's own worked example
    /// (<https://www.twilio.com/docs/usage/security>), in the exact
    /// `application/x-www-form-urlencoded` body its SDKs POST for them. The
    /// signature over these fields is Twilio's published `L/OH5YylLD5NRKLltdqwSvS0BnU=`
    /// (pinned end-to-end in `twilio.rs`'s own tests); here the point is the
    /// byte-level decode of the body that carries them.
    const TWILIO_BODY: &[u8] =
        b"CallSid=CA1234567890ABCDE&To=%2B18005551212&From=%2B14158675310&Caller=%2B14158675310&Digits=1234";
    const TWILIO_FIELDS: [(&str, &str); 5] = [
        ("CallSid", "CA1234567890ABCDE"),
        ("To", "+18005551212"),
        ("From", "+14158675310"),
        ("Caller", "+14158675310"),
        ("Digits", "1234"),
    ];

    /// [`TWILIO_FIELDS`] as the owned pairs the parser returns.
    fn twilio_fields() -> Vec<(String, String)> {
        TWILIO_FIELDS
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn parses_the_documented_twilio_form_body() {
        assert_eq!(fields(TWILIO_BODY), twilio_fields());
    }

    #[test]
    fn a_plus_is_a_space_and_a_percent_escape_is_its_byte() {
        assert_eq!(
            fields(b"Message=hello+world%21&Other=a%2Bb"),
            vec![
                ("Message".to_string(), "hello world!".to_string()),
                ("Other".to_string(), "a+b".to_string()),
            ]
        );
        // The two spellings of the same bytes decode identically, so they sign
        // identically — the same property as field order (see twilio.rs).
        assert_eq!(fields(b"f=%41"), fields(b"f=A"));
    }

    #[test]
    fn duplicate_names_are_all_kept_and_empty_elements_are_dropped() {
        // Nothing is de-duplicated here: the signing scheme's sort-then-dedup
        // is what collapses these, in the provider.
        assert_eq!(
            fields(b"&Body=a&Body=b&&Body=&Digits=1&"),
            vec![
                ("Body".to_string(), "a".to_string()),
                ("Body".to_string(), "b".to_string()),
                ("Body".to_string(), String::new()),
                ("Digits".to_string(), "1".to_string()),
            ]
        );
        // An empty body is zero fields, which is what the JSON-body variant
        // signs (the URL alone) once a bodySHA256 parameter is present.
        assert_eq!(fields(b""), Vec::new());
        assert_eq!(fields(b"&&"), Vec::new());
    }

    #[test]
    fn only_the_first_equals_sign_splits_and_a_missing_one_is_an_empty_value() {
        // A value may contain `=` when the sender percent-encoded it, and when
        // it did not: `parse_qs` splits at the first one too.
        assert_eq!(
            fields(b"Body=a=b"),
            vec![("Body".to_string(), "a=b".to_string())]
        );
        // A bare name is a name with an empty value (as `keep_blank_values`
        // parsers read it), and an empty name is kept rather than dropped.
        assert_eq!(
            fields(b"Body&=value"),
            vec![
                ("Body".to_string(), String::new()),
                (String::new(), "value".to_string()),
            ]
        );
    }

    #[test]
    fn a_semicolon_is_a_value_byte_not_a_separator() {
        // Every parser this replaces (Python's `parse_qs`, PHP, Django,
        // Werkzeug) splits on `&` alone, so splitting on `;` here would
        // disagree with the signer about what it sent.
        assert_eq!(
            fields(b"Body=a;b"),
            vec![("Body".to_string(), "a;b".to_string())]
        );
    }

    #[test]
    fn an_invalid_escape_is_left_verbatim() {
        // `unquote` behavior, kept rather than rejected: `parse_qs` produces
        // these strings, so a request carrying one has a field set the signer
        // can also have produced.
        for (body, expected) in [
            ("f=100%", "100%"),
            ("f=%zz", "%zz"),
            ("f=%2", "%2"),
            ("f=%", "%"),
            ("f=%2z", "%2z"),
            // `a%%41b`: the first `%` starts no escape (the next two bytes are
            // `%4`), so it is literal and the walk resumes at the second `%`,
            // which does start one — `a%Ab`, byte for byte what
            // `unquote_plus("f=a%%41b")` returns.
            ("f=a%%41b", "a%Ab"),
            // The walk resumes *at* the byte after a literal `%`, so an escape
            // candidate that is not one still gets its own decoding pass — the
            // same text `unquote_plus("f=%+")` produces.
            ("f=%+", "% "),
        ] {
            assert_eq!(
                fields(body.as_bytes()),
                vec![("f".to_string(), expected.to_string())],
                "{body:?}"
            );
        }
    }

    #[test]
    fn a_field_that_is_not_utf8_fails_closed() {
        // `%FF` is a permitted escape but decodes to a byte no `String` can
        // hold. Substituting U+FFFD would change the signed string, so this is
        // a malformed-request error instead — the variant the adapters answer
        // with 400, not an auth signal.
        for body in [b"f=%FF".as_slice(), b"Body=%C3".as_slice()] {
            assert_eq!(
                parse_form_urlencoded(body),
                Err(VerifyError::BadEncoding {
                    reason: NOT_FORM_ENCODED
                }),
                "{body:?}"
            );
        }
    }

    #[test]
    fn a_control_byte_in_a_field_is_data_not_a_parse_failure() {
        // A percent-escaped NUL is ordinary field content, and the providers
        // sort and sign whatever bytes they are given, so it must survive the
        // decode rather than being trimmed or rejected.
        assert_eq!(
            fields(b"Body=a%00b"),
            vec![("Body".to_string(), "a\0b".to_string())]
        );
    }
}
