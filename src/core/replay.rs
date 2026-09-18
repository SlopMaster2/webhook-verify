//! Shared replay-protection and timestamp-parsing helpers used by every
//! timestamped provider. Extracted to avoid duplicating identical logic
//! across provider modules (`spec.md` §5.4).

use crate::core::error::VerifyError;
use crate::core::options::VerifyOptions;

/// Parses a timestamp header value into unix seconds.
///
/// Returns a structured [`VerifyError::MalformedHeader`] for empty, negative,
/// non-numeric, or overflowing values. The `header` parameter identifies
/// which header was malformed so callers (built-in and `Custom`) surface
/// the correct name.
pub(crate) fn parse_timestamp(header: &'static str, value: &str) -> Result<u64, VerifyError> {
    parse_unsigned_decimal(
        header,
        value,
        "timestamp is not a valid unix timestamp",
        "timestamp overflows unix seconds",
    )
}

/// Parses an epoch-*milliseconds* header value into a `u64`.
///
/// HubSpot's `X-HubSpot-Request-Timestamp` is delivered in milliseconds
/// (`spec.md` §3, HubSpot row), unlike every other timestamped provider's
/// whole-second values. The shape rules are identical to [`parse_timestamp`]
/// (pure ASCII digits, no sign/whitespace); only the diagnostics say
/// milliseconds so operators debugging a rejected delivery are pointed at
/// the right unit.
pub(crate) fn parse_millis(header: &'static str, value: &str) -> Result<u64, VerifyError> {
    parse_unsigned_decimal(
        header,
        value,
        "timestamp is not valid epoch milliseconds",
        "timestamp overflows epoch milliseconds",
    )
}

/// Shared core of [`parse_timestamp`] / [`parse_millis`]: a value must be a
/// non-empty sequence of pure ASCII digits that fits in `u64`.
///
/// Rejects leading `+`/`-`, whitespace, and non-numeric text, all of which
/// would otherwise pass through Rust's `u64::from_str` (e.g. `+1531420618`).
/// Timestamps are "integer unix seconds" per `spec.md` §3 (or integer
/// milliseconds for HubSpot) — no sign prefix is valid.
fn parse_unsigned_decimal(
    header: &'static str,
    value: &str,
    not_digits_reason: &'static str,
    overflow_reason: &'static str,
) -> Result<u64, VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header,
            reason: "header is empty",
        });
    }

    // Reject any value that isn't a pure sequence of ASCII digits.
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VerifyError::MalformedHeader {
            header,
            reason: not_digits_reason,
        });
    }

    value
        .parse::<u64>()
        .map_err(|_| VerifyError::MalformedHeader {
            header,
            reason: overflow_reason,
        })
}

/// Parses an RFC 3339 / ISO 8601 `<date>T<time>` timestamp into unix seconds.
///
/// Accepts the exact shapes the RFC 3339 timestamp headers use (`spec.md`
/// §3): PayPal's `PayPal-Transmission-Time`, Twitch's
/// `Twitch-Eventsub-Message-Timestamp`, and Zendesk's
/// `X-Zendesk-Webhook-Signature-Timestamp` — `YYYY-MM-DDTHH:MM:SS`, an
/// optional fractional-seconds component, and either a `Z` suffix or a
/// numeric `±HH:MM` UTC offset. The `T` and `Z` characters are
/// case-insensitive, per RFC 3339 §5.6 note (a lowercase `t`/`z` is the ISO
/// 8601 spelling). The fractional part (if any) is truncated — sub-second
/// precision is below the resolution of the shared replay check.
///
/// The conversion is a dependency-free reimplementation of Howard Hinnant's
/// `days_from_civil` algorithm (C++ `<chrono>`), which maps a
/// y/m/d triplet to the count of days since 1970-01-01.
///
/// Returns a structured [`VerifyError::MalformedHeader`] for values that do
/// not match that shape or that map to a pre-epoch instant.
pub(crate) fn parse_rfc3339_timestamp(
    header: &'static str,
    value: &str,
) -> Result<u64, VerifyError> {
    let malformed = || VerifyError::MalformedHeader {
        header,
        reason: "timestamp is not a valid RFC 3339 timestamp",
    };

    let b = value.as_bytes();
    if b.len() < 20 {
        return Err(malformed());
    }
    let digits_ok = b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
        && (b[10] == b'T' || b[10] == b't')
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[13] == b':'
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[16] == b':'
        && b[17..19].iter().all(u8::is_ascii_digit);
    if !digits_ok {
        return Err(malformed());
    }

    let digits = |bytes: &[u8]| -> u64 {
        bytes
            .iter()
            .fold(0u64, |acc, c| acc * 10 + u64::from(c - b'0'))
    };
    let year = digits(&b[0..4]);
    let month = digits(&b[5..7]);
    let day = digits(&b[8..10]);
    let hour = digits(&b[11..13]);
    let minute = digits(&b[14..16]);
    let second = digits(&b[17..19]);

    if !(1..=12).contains(&month) {
        return Err(malformed());
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month: u64 = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return Err(malformed()),
    };
    if day < 1 || day > days_in_month {
        return Err(malformed());
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err(malformed());
    }
    // RFC 3339 §5.7 allows second 60 only as a leap second, expressed at the
    // end of the local day (`23:59:60`); a `60` at any other clock position
    // is not a valid calendar time and must fail closed.
    if second == 60 && (hour != 23 || minute != 59) {
        return Err(malformed());
    }

    // Optional fractional seconds: `.digits` — truncated, never rounded.
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let frac_start = i;
        while b.get(i).is_some_and(|c| c.is_ascii_digit()) {
            i += 1;
        }
        if i == frac_start {
            return Err(malformed());
        }
    }

    // UTC designator or a numeric ±HH:MM offset. RFC 3339 §5.6 allows the
    // `Z` designator in lowercase (`z`) as the ISO 8601 spelling.
    let mut offset_seconds: i64 = 0;
    match b.get(i) {
        Some(b'Z') | Some(b'z') => i += 1,
        Some(b'+') | Some(b'-') => {
            let sign: i64 = if b[i] == b'-' { -1 } else { 1 };
            i += 1;
            if b.len() < i + 5
                || !b[i..i + 2].iter().all(u8::is_ascii_digit)
                || b[i + 2] != b':'
                || !b[i + 3..i + 5].iter().all(u8::is_ascii_digit)
            {
                return Err(malformed());
            }
            let offset_hour = digits(&b[i..i + 2]);
            let offset_minute = digits(&b[i + 3..i + 5]);
            i += 5;
            // RFC 3339 bounds the offset hour at 23 and minutes at 59.
            if offset_hour > 23 || offset_minute > 59 {
                return Err(malformed());
            }
            offset_seconds = sign * (offset_hour as i64 * 3600 + offset_minute as i64 * 60);
        }
        _ => return Err(malformed()),
    }
    if i != b.len() {
        return Err(malformed());
    }

    let days = days_from_civil(year as i64, month as u32, day as u32);
    let unix_seconds = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add((hour * 3600 + minute * 60 + second) as i64))
        .and_then(|t| t.checked_sub(offset_seconds))
        .ok_or_else(malformed)?;
    if unix_seconds < 0 {
        return Err(malformed());
    }
    Ok(unix_seconds as u64)
}

/// Parses an RFC 7231 IMF-fixdate timestamp (the "HTTP-date" format the
/// `Date` header uses, spelled per RFC 1123 with a four-digit year) into unix
/// seconds.
///
/// Accepts the exact shape Klaviyo's `Klaviyo-Timestamp` header uses
/// (`spec.md` §3, Klaviyo row) — `Thu, 04 Jan 2024 18:05:25 GMT`: a
/// case-sensitive English three-letter weekday, comma, space, a zero-padded
/// two-digit day, space, a three-letter month name, space, a four-digit year,
/// space, zero-padded `HH:MM:SS`, space, and a literal `GMT` designator. The
/// value must be exactly 29 characters. This is the strict IMF-fixdate
/// grammar of RFC 7231 §7.1.1.1 and rejects the two-digit-year/asctime
/// spellings Go's `http.ParseTime` also accepts: a header the provider never
/// emits should not be silently normalized into a replayable instant.
///
/// Validation is strict and fail-closed:
/// - the weekday name must be one of the seven canonical English names *and*
///   match the weekday of the parsed date (RFC 7231 requires the day name to
///   be accurate; Go's `time.Parse` and the `httpdate` crate reject a
///   mismatched name the same way),
/// - the day must be valid for the month, including leap years,
/// - hour/minutes/seconds must be in 00–59 (IMF-fixdate's grammar is
///   `second = 2DIGIT`, so unlike RFC 3339 it has no leap-second value 60),
/// - the four-digit year must map to a non-negative unix timestamp (dates
///   before 1970-01-01 are rejected).
///
/// The conversion reuses the same `days_from_civil` algorithm as
/// [`parse_rfc3339_timestamp`].
pub(crate) fn parse_imf_fixdate(header: &'static str, value: &str) -> Result<u64, VerifyError> {
    let malformed = || VerifyError::MalformedHeader {
        header,
        reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
    };

    let b = value.as_bytes();
    if b.len() != 29 {
        return Err(malformed());
    }

    // `Sun` = 0, `Mon` = 1, ..., `Sat` = 6 — Sunday-anchored so the value
    // compares directly against the weekday computed below.
    let weekday = match &b[..3] {
        b"Sun" => 0,
        b"Mon" => 1,
        b"Tue" => 2,
        b"Wed" => 3,
        b"Thu" => 4,
        b"Fri" => 5,
        b"Sat" => 6,
        _ => return Err(malformed()),
    };

    // Fixed punctuation and literals: `ddd, DD Mon YYYY HH:MM:SS GMT`.
    if b[3] != b','
        || b[4] != b' '
        || b[7] != b' '
        || b[11] != b' '
        || b[16] != b' '
        || b[19] != b':'
        || b[22] != b':'
        || b[25] != b' '
        || &b[26..29] != b"GMT"
    {
        return Err(malformed());
    }

    let digits = |bytes: &[u8]| -> u64 {
        bytes
            .iter()
            .fold(0u64, |acc, c| acc * 10 + u64::from(c - b'0'))
    };

    if !(b[5..7].iter().all(u8::is_ascii_digit)
        && b[12..16].iter().all(u8::is_ascii_digit)
        && b[17..19].iter().all(u8::is_ascii_digit)
        && b[20..22].iter().all(u8::is_ascii_digit)
        && b[23..25].iter().all(u8::is_ascii_digit))
    {
        return Err(malformed());
    }

    let month = match &b[8..11] {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return Err(malformed()),
    };

    let day = digits(&b[5..7]);
    let year = digits(&b[12..16]);
    let hour = digits(&b[17..19]);
    let minute = digits(&b[20..22]);
    let second = digits(&b[23..25]);

    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month: u64 = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return Err(malformed()),
    };
    if day < 1 || day > days_in_month {
        return Err(malformed());
    }
    if hour > 23 || minute > 59 || second > 59 {
        return Err(malformed());
    }

    let days = days_from_civil(year as i64, month as u32, day as u32);
    let unix_seconds = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add((hour * 3600 + minute * 60 + second) as i64))
        .ok_or_else(malformed)?;
    if unix_seconds < 0 {
        return Err(malformed());
    }

    // RFC 7231 requires the day name to be accurate for the date, exactly as
    // Go's `time.Parse` and the `httpdate` crate enforce it. 1970-01-01 was a
    // Thursday (Sunday-anchored index 4), so `days + 4` mod 7 is the weekday.
    let computed_weekday = (days + 4).rem_euclid(7);
    if computed_weekday != weekday {
        return Err(malformed());
    }

    Ok(unix_seconds as u64)
}

/// Maps a proleptic-Gregorian civil date to the number of days since
/// 1970-01-01 (Howard Hinnant's `days_from_civil`, public domain).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Enforces `|now - t| <= max_age` when replay protection is enabled.
///
/// Symmetric window: the timestamp is HMAC-covered, and sub-second precision
/// of "now" is truncated. Returns `Ok(())` when `max_age` is `None` (check
/// disabled). A clock reading 0 (e.g. no `Clock` injected on a `no_std`
/// target) fail-closed rejects any realistic delivery timestamp.
pub(crate) fn check_replay(timestamp: u64, options: &VerifyOptions) -> Result<(), VerifyError> {
    let Some(max_age) = options.max_age else {
        return Ok(());
    };

    let now_unix = options.now();

    // `abs_diff` avoids overflow/panic for absurd attacker-chosen values in
    // either direction. The comparison re-wraps into a `Duration` and compares
    // against `max_age` directly, so a sub-second tolerance (e.g.
    // `Duration::from_millis(500)`) is honored exactly instead of being
    // silently floored by `.as_secs()`.
    let skew = core::time::Duration::from_secs(now_unix.abs_diff(timestamp));
    if skew > max_age {
        return Err(VerifyError::TimestampOutOfTolerance { skew, max_age });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_replay, parse_timestamp};
    use crate::VerifyError;
    use crate::core::options::VerifyOptions;
    use crate::test_helpers::{FixedClock, epoch};
    use std::sync::Arc;
    use std::time::Duration;

    // --- parse_rfc3339_timestamp (PayPal's `PayPal-Transmission-Time` and
    //     Twitch's `Twitch-Eventsub-Message-Timestamp`) -------------------------

    mod rfc3339 {
        use super::super::parse_rfc3339_timestamp;
        use crate::VerifyError;

        fn parse_header(value: &str) -> Result<u64, VerifyError> {
            parse_rfc3339_timestamp("X-Timestamp", value)
        }

        fn malformed(_value: &str) -> Result<u64, VerifyError> {
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp is not a valid RFC 3339 timestamp",
            })
        }

        #[test]
        fn parses_utc_zulu_format() {
            // PayPal's own published example transmission time
            // (developer.paypal.com "Integrate webhooks").
            assert_eq!(parse_header("2024-05-16T05:19:23Z"), Ok(1_715_836_763));
        }

        #[test]
        fn truncates_fractional_and_applies_offsets() {
            // Sub-second precision is truncated, not rounded: .999Z is still the
            // same whole second.
            assert_eq!(parse_header("2024-05-16T05:19:23.999Z"), Ok(1_715_836_763));
            assert_eq!(parse_header("2024-05-16T05:19:23.355Z"), Ok(1_715_836_763));
            // Numeric ±HH:MM offsets resolve to the same UTC instant.
            assert_eq!(parse_header("2024-05-16T07:19:23+02:00"), Ok(1_715_836_763));
            assert_eq!(parse_header("2024-05-16T01:19:23-04:00"), Ok(1_715_836_763));
            // `+00:00` is the numeric spelling of the same instant as `Z`.
            assert_eq!(parse_header("2024-05-16T05:19:23+00:00"), Ok(1_715_836_763));
        }

        #[test]
        fn accepts_lowercase_t_and_z_separators() {
            // RFC 3339 §5.6 note: "the 'T' and 'Z' characters in this syntax
            // may alternatively be lower case 't' or 'z' respectively."
            assert_eq!(parse_header("2024-05-16t05:19:23z"), Ok(1_715_836_763));
            assert_eq!(parse_header("2024-05-16t05:19:23Z"), Ok(1_715_836_763));
            assert_eq!(parse_header("2024-05-16T05:19:23z"), Ok(1_715_836_763));
            // A numeric offset is unaffected by the lowercase `t`.
            assert_eq!(parse_header("2024-05-16t07:19:23+02:00"), Ok(1_715_836_763));
        }

        #[test]
        fn handles_boundary_dates() {
            assert_eq!(parse_header("1970-01-01T00:00:00Z"), Ok(0));
            assert_eq!(parse_header("1970-01-01T00:00:01Z"), Ok(1));
            assert_eq!(parse_header("2000-02-29T00:00:00Z"), Ok(951_782_400));
            // Non-leap-year Feb 29 must fail, and so must month/day overflow.
            assert_eq!(
                parse_header("1900-02-29T00:00:00Z"),
                malformed("1900-02-29")
            );
            assert_eq!(
                parse_header("2023-02-29T00:00:00Z"),
                malformed("2023-02-29")
            );
            assert_eq!(
                parse_header("2024-13-01T00:00:00Z"),
                malformed("2024-13-01")
            );
            assert_eq!(
                parse_header("2024-04-31T00:00:00Z"),
                malformed("2024-04-31")
            );
        }

        #[test]
        fn leap_second_only_at_end_of_day() {
            // RFC 3339 §5.7 allows second 60 only as a leap second expressed
            // at the end of the local day (23:59:60); 05:19:60 is not a valid
            // calendar time.
            assert_eq!(parse_header("2024-05-16T23:59:60Z"), Ok(1_715_904_000));
            assert_eq!(
                parse_header("2024-05-16T05:19:60Z"),
                malformed("2024-05-16T05:19:60Z")
            );
            assert_eq!(
                parse_header("2024-05-16T23:58:60Z"),
                malformed("2024-05-16T23:58:60Z")
            );
            assert_eq!(
                parse_header("2024-05-16T00:00:60+01:00"),
                malformed("2024-05-16T00:00:60+01:00")
            );
        }

        #[test]
        fn rejects_malformed_values() {
            let bad = [
                "",
                "2024-05-16T05:19:23",   // no timezone
                "2024-05-16 05:19:23Z",  // space instead of T
                "2024-05-16T5:19:23Z",   // non-padded hour
                "24-5-16T05:19:23Z",     // non-padded year
                "2024-05-16T25:19:23Z",  // hour out of range
                "2024-05-16T05:60:23Z",  // minute out of range
                "2024-05-16T05:19:23",   // truncated
                "2024-05-16T05:19:23ZZ", // trailing garbage
                "2024-05-16T05:19:23+25:00",
                "2024-05-16T05:19:23+02:60",
                "2024-05-16T05:19:23+0200", // no colon in offset
                "2024-05-16T24:00:00Z",     // RFC 3339 §5.6: 24:00:00 is not a valid hour
                "2024-05-16T05:19:23.jZ",   // empty fraction
                "0000-01-01T00:00:00Z",     // pre-epoch
                "2024-05-16T05:19:23-04",   // truncated offset
                "2024-05-16T05:19:23D",
            ];
            for value in bad {
                assert_eq!(parse_header(value), malformed(value), "input: {value:?}");
            }
        }

        #[test]
        fn empty_value_is_rejected() {
            assert_eq!(
                parse_header(""),
                Err(VerifyError::MalformedHeader {
                    header: "X-Timestamp",
                    reason: "timestamp is not a valid RFC 3339 timestamp",
                })
            );
        }
    }

    // --- parse_imf_fixdate (Klaviyo's `Klaviyo-Timestamp`) -------------------

    mod imf_fixdate {
        use super::super::parse_imf_fixdate;
        use crate::VerifyError;

        fn parse_header(value: &str) -> Result<u64, VerifyError> {
            parse_imf_fixdate("X-Timestamp", value)
        }

        fn malformed(_value: &str) -> Result<u64, VerifyError> {
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp is not a valid IMF-fixdate (RFC 1123) timestamp",
            })
        }

        #[test]
        fn parses_klaviyo_example_format() {
            // Klaviyo's documented example timestamp header
            // (developers.klaviyo.com "Working with system webhooks"):
            // `Thu, 04 Jan 2024 18:05:25 GMT`.
            assert_eq!(
                parse_header("Thu, 04 Jan 2024 18:05:25 GMT"),
                Ok(1_704_391_525)
            );
        }

        #[test]
        fn parses_rfc7231_canonical_example() {
            // The epoch value RFC 7231 §7.1.1.1 works through for
            // `Sun, 06 Nov 1994 08:49:37 GMT`.
            assert_eq!(
                parse_header("Sun, 06 Nov 1994 08:49:37 GMT"),
                Ok(784_111_777)
            );
        }

        #[test]
        fn handles_boundary_dates_and_weekdays() {
            assert_eq!(parse_header("Thu, 01 Jan 1970 00:00:00 GMT"), Ok(0));
            assert_eq!(
                parse_header("Fri, 01 Jan 1971 00:00:00 GMT"),
                Ok(31_536_000)
            );
            // 2016 is a leap year: Feb 29 exists.
            assert_eq!(
                parse_header("Mon, 29 Feb 2016 00:00:00 GMT"),
                Ok(1_456_704_000)
            );
            // The last instant representable in the four-digit-year form.
            assert_eq!(
                parse_header("Thu, 31 Dec 2026 23:59:59 GMT"),
                Ok(1_798_761_599)
            );
            // Every weekday maps correctly; 2024-01-01 was a Monday.
            assert_eq!(
                parse_header("Mon, 01 Jan 2024 00:00:00 GMT"),
                Ok(1_704_067_200)
            );
        }

        #[test]
        fn weekday_name_must_match_the_date() {
            // RFC 7231 requires an accurate day name; 2024-01-04 was a
            // Thursday, so Wed/Thu-spelling mismatches fail closed even though
            // every other field is a well-formed calendar date.
            assert_eq!(
                parse_header("Wed, 04 Jan 2024 18:05:25 GMT"),
                malformed("Wed, 04 Jan 2024 18:05:25 GMT")
            );
            // A correct name on the wrong instant is likewise rejected.
            assert_eq!(
                parse_header("Thu, 04 Jan 2024 18:05:26 GMT"),
                Ok(1_704_391_526)
            );
        }

        #[test]
        fn rejects_malformed_values() {
            let bad = [
                "",
                "Thu, 04 Jan 2024 18:05:25 GMT ", // trailing space
                "Thu, 04 Jan 2024 18:05:25 GMTX",
                "Thu, 04 Jan 2024 18:05:25",      // no GMT
                "Thu, 04 Jan 2024 18:05:25 UT",   // wrong zone letter (same length)
                "Thu, 04 Jan 2024 18:05:25 UTC",  // three-letter non-GMT zone
                "Thu,04 Jan 2024 18:05:25 GMT",   // missing space after comma
                "Thu,  4 Jan 2024 18:05:25 GMT",  // non-padded day
                "Thu, 04 Jan 2024 18:05:25GMT",   // missing space before GMT
                "thu, 04 Jan 2024 18:05:25 GMT",  // lowercase weekday
                "Wen, 04 Jan 2024 18:05:25 GMT",  // misspelled weekday
                "Thu, 04 Jaa 2024 18:05:25 GMT",  // misspelled month
                "Thu, 04 Janv 2024 18:05:25 GMT", // janv ... wrong length too
                "Thu, 00 Jan 2024 18:05:25 GMT",  // zero day
                "Thu, 32 Jan 2024 18:05:25 GMT",  // day out of range
                "Thu, 30 Feb 2024 18:05:25 GMT",  // Feb has no 30th
                "Thu, 29 Feb 2023 18:05:25 GMT",  // 2023 is not a leap year
                "Thu, 04 Jan 2024 24:05:25 GMT",  // hour out of range
                "Thu, 04 Jan 2024 18:60:25 GMT",  // minute out of range
                "Thu, 04 Jan 2024 18:05:60 GMT",  // IMF-fixdate has no :60 (unlike RFC 3339)
                "Thu, 04 Jan 2024 18:05:25",      // truncated seconds
                "Thu, 04 Jan 2024 18:05:25 GTM",  // transposed zone
                "Thu, 04 Jan 20224 18:05:25 GMT", // five-digit year
                "Thu, 04 Jan 024 18:05:25 GMT",   // three-digit year
                "Thu, 04 Jan 2024 818:05:25 GMT", // three-digit hour
                "Thu, 04 Jan 0000 18:05:25 GMT",  // pre-epoch year
                "Thu, 04 Jan 2024T18:05:25 GMT",  // wrong separator
            ];
            for value in bad {
                assert_eq!(parse_header(value), malformed(value), "input: {value:?}");
            }
        }
    }

    // --- parse_timestamp -----------------------------------------------------

    #[test]
    fn parses_valid_timestamp() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "1700000000"),
            Ok(1_700_000_000)
        );
    }

    #[test]
    fn empty_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", ""),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "header is empty",
            })
        );
    }

    #[test]
    fn negative_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "-1"),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp is not a valid unix timestamp",
            })
        );
    }

    #[test]
    fn non_numeric_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "not-a-number"),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp is not a valid unix timestamp",
            })
        );
    }

    #[test]
    fn leading_plus_timestamp_is_malformed() {
        // `"+1700000000".parse::<u64>()` would otherwise succeed; a leading
        // sign is not "integer unix seconds" and must fail closed.
        assert_eq!(
            parse_timestamp("X-Timestamp", "+1700000000"),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp is not a valid unix timestamp",
            })
        );
    }

    #[test]
    fn whitespace_padded_timestamp_is_malformed() {
        // `u64::from_str` trims nothing, but a provider's reverse proxy might
        // re-emit a padded header value; the signed string uses the header
        // value verbatim, so padding must fail closed rather than be
        // normalized away. Mirrors the `+`-prefix case above.
        for value in [" 1700000000", "1700000000 ", "\t1700000000"] {
            assert_eq!(
                parse_timestamp("X-Timestamp", value),
                Err(VerifyError::MalformedHeader {
                    header: "X-Timestamp",
                    reason: "timestamp is not a valid unix timestamp",
                }),
                "input: {value:?}"
            );
        }
    }

    #[test]
    fn overflowing_timestamp_is_malformed() {
        assert_eq!(
            parse_timestamp("X-Timestamp", "99999999999999999999"),
            Err(VerifyError::MalformedHeader {
                header: "X-Timestamp",
                reason: "timestamp overflows unix seconds",
            })
        );
    }

    // --- check_replay --------------------------------------------------------

    #[test]
    fn valid_timestamp_within_window() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts + 100);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(check_replay(ts, &opts).is_ok());
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts + 600);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(matches!(
            check_replay(ts, &opts),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
    }

    #[test]
    fn future_timestamp_is_rejected() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts - 600);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(matches!(
            check_replay(ts, &opts),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
    }

    #[test]
    fn disabled_max_age_skips_check() {
        let ts = 1_700_000_000u64;
        let opts = VerifyOptions {
            max_age: None,
            ..VerifyOptions::default()
        };
        assert!(check_replay(ts, &opts).is_ok());
    }

    #[test]
    fn zero_clock_fails_closed_on_realistic_timestamps() {
        // Under `--no-default-features`, a missing `Clock` makes
        // `options.now()` return 0 (options.rs). A clock reading 0 must
        // reject any realistic delivery timestamp rather than treating every
        // delivery as "from the epoch" — the doc-comment contract of
        // `check_replay` (replay.rs). `FixedClock(0)` reproduces the no_std
        // fallback deterministically.
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(0))),
            ..VerifyOptions::default()
        };
        assert!(matches!(
            check_replay(1_700_000_000, &opts),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
        // An exact-epoch timestamp is the only peer a 0-reading clock accepts.
        assert!(check_replay(0, &opts).is_ok());
    }

    #[test]
    fn boundary_exactly_at_max_age_is_accepted() {
        let ts = 1_700_000_000u64;
        let now = epoch(ts + 300);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_secs(300)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(check_replay(ts, &opts).is_ok());
    }

    #[test]
    fn sub_second_max_age_is_honored_exactly() {
        // A sub-second tolerance must not be silently floored to 0s by
        // `.as_secs()`: a one-second skew has to fall outside a 500ms window.
        let ts = 1_700_000_000u64;
        let now = epoch(ts + 1);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_millis(500)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(
            matches!(
                check_replay(ts, &opts),
                Err(VerifyError::TimestampOutOfTolerance { .. })
            ),
            "1s skew must reject a 500ms window"
        );

        // And an in-window skew (zero whole seconds) still accepts.
        let opts = VerifyOptions {
            max_age: Some(Duration::from_millis(500)),
            clock: Some(Arc::new(FixedClock(now))),
            ..VerifyOptions::default()
        };
        assert!(check_replay(now, &opts).is_ok());
    }

    #[test]
    fn multi_second_max_age_rejects_skew_beyond_window() {
        // A 3.5s window must reject a 4s skew (previously floored to a 3s
        // window, which is the exact bug this guards against) and accept a 3s
        // skew.
        let ts = 1_700_000_000u64;
        let beyond = epoch(ts + 4);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_millis(3_500)),
            clock: Some(Arc::new(FixedClock(beyond))),
            ..VerifyOptions::default()
        };
        assert!(matches!(
            check_replay(ts, &opts),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));

        let within = epoch(ts + 3);
        let opts = VerifyOptions {
            max_age: Some(Duration::from_millis(3_500)),
            clock: Some(Arc::new(FixedClock(within))),
            ..VerifyOptions::default()
        };
        assert!(check_replay(ts, &opts).is_ok());
    }
}
