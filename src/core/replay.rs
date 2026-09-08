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
    if value.is_empty() {
        return Err(VerifyError::MalformedHeader {
            header,
            reason: "header is empty",
        });
    }

    // Reject any value that isn't a pure sequence of ASCII digits. This
    // refuses leading `+`/`-`, whitespace, and non-numeric text, all of which
    // would otherwise pass through Rust's `u64::from_str` (e.g. `+1531420618`).
    // Timestamps are "integer unix seconds" per `spec.md` §3 — no sign prefix
    // is valid.
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VerifyError::MalformedHeader {
            header,
            reason: "timestamp is not a valid unix timestamp",
        });
    }

    value
        .parse::<u64>()
        .map_err(|_| VerifyError::MalformedHeader {
            header,
            reason: "timestamp overflows unix seconds",
        })
}

/// Parses an RFC 3339 / ISO 8601 `<date>T<time>` timestamp into unix seconds.
///
/// Accepts the exact shape PayPal's `PayPal-Transmission-Time` header uses
/// (`spec.md` §3): `YYYY-MM-DDTHH:MM:SS`, an optional fractional-seconds
/// component, and either a `Z` suffix or a numeric `±HH:MM` UTC offset. The
/// fractional part (if any) is truncated — sub-second precision is below the
/// resolution of the shared replay check.
///
/// The conversion is a dependency-free reimplementation of Howard Hinnant's
/// `days_from_civil` algorithm (C++ `<chrono>`), which maps a
/// y/m/d triplet to the count of days since 1970-01-01.
///
/// Returns a structured [`VerifyError::MalformedHeader`] for values that do
/// not match that shape or that map to a pre-epoch instant.
#[cfg(feature = "paypal")]
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
        && b[10] == b'T'
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

    // UTC designator or a numeric ±HH:MM offset.
    let mut offset_seconds: i64 = 0;
    match b.get(i) {
        Some(b'Z') => i += 1,
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

/// Maps a proleptic-Gregorian civil date to the number of days since
/// 1970-01-01 (Howard Hinnant's `days_from_civil`, public domain).
#[cfg(feature = "paypal")]
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
    // either direction.
    let skew_secs = now_unix.abs_diff(timestamp);
    if skew_secs > max_age.as_secs() {
        return Err(VerifyError::TimestampOutOfTolerance {
            skew: core::time::Duration::from_secs(skew_secs),
            max_age,
        });
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

    // --- parse_rfc3339_timestamp (PayPal's `PayPal-Transmission-Time`) ---------
    //
    // Only compiled when the `paypal` feature is on; see the crate-wide
    // dead_code policy (feature-gated helpers stay feature-gated).

    #[cfg(feature = "paypal")]
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
}
