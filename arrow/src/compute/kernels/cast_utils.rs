// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use crate::error::{ArrowError, Result};
use chrono::format::Fixed::{Nanosecond, TimezoneOffsetColon};
use chrono::format::Item::{Fixed, Literal};
use chrono::format::{Item, Parsed};
use chrono::prelude::*;

/// Accepts a string in RFC3339 / ISO8601 standard format and some
/// variants and converts it to a nanosecond precision timestamp.
///
/// Implements the `to_timestamp` function to convert a string to a
/// timestamp, following the model of spark SQL’s to_`timestamp`.
///
/// In addition to RFC3339 / ISO8601 standard timestamps, it also
/// accepts strings that use a space ` ` to separate the date and time
/// as well as strings that have no explicit timezone offset.
///
/// Examples of accepted inputs:
/// * `1997-01-31T09:26:56.123Z`        # RCF3339
/// * `1997-01-31T09:26:56.123-05:00`   # RCF3339
/// * `1997-01-31 09:26:56.123-05:00`   # close to RCF3339 but with a space rather than T
/// * `1997-01-31T09:26:56.123`         # close to RCF3339 but no timezone offset specified
/// * `1997-01-31 09:26:56.123`         # close to RCF3339 but uses a space and no timezone offset
/// * `1997-01-31 09:26:56`             # close to RCF3339, no fractional seconds
//
/// Internally, this function uses the `chrono` library for the
/// datetime parsing
///
/// We hope to extend this function in the future with a second
/// parameter to specifying the format string.
///
/// ## Timestamp Precision
///
/// Function uses the maximum precision timestamps supported by
/// Arrow (nanoseconds stored as a 64-bit integer) timestamps. This
/// means the range of dates that timestamps can represent is ~1677 AD
/// to 2262 AM
///
///
/// ## Timezone / Offset Handling
///
/// Numerical values of timestamps are stored compared to offset UTC.
///
/// This function intertprets strings without an explicit time zone as
/// timestamps with offsets of the local time on the machine
///
/// For example, `1997-01-31 09:26:56.123Z` is interpreted as UTC, as
/// it has an explicit timezone specifier (“Z” for Zulu/UTC)
///
/// `1997-01-31T09:26:56.123` is interpreted as a local timestamp in
/// the timezone of the machine. For example, if
/// the system timezone is set to Americas/New_York (UTC-5) the
/// timestamp will be interpreted as though it were
/// `1997-01-31T09:26:56.123-05:00`
#[inline]
pub fn string_to_timestamp_nanos(s: &str) -> Result<i64> {
    // Fast path:  RFC3339 timestamp (with a T)
    // Example: 2020-09-08T13:42:29.190855Z
    if let Ok(ts) = DateTime::parse_from_rfc3339(s) {
        #[allow(deprecated)]
        return Ok(ts.timestamp_nanos());
    }

    // Implement quasi-RFC3339 support by trying to parse the
    // timestamp with various other format specifiers to to support
    // separating the date and time with a space ' ' rather than 'T' to be
    // (more) compatible with Apache Spark SQL

    // We parse the date and time prefix first to share work between all the different formats.
    let mut rest = s;
    let mut p;
    let separator_is_space;
    match try_parse_prefix(&mut rest) {
        Some(ParsedPrefix {
            result,
            separator_is_space: s,
        }) => {
            p = result;
            separator_is_space = s;
        }
        None => {
            return Err(ArrowError::CastError(format!(
                "Error parsing '{}' as timestamp",
                s
            )));
        }
    }

    if separator_is_space {
        // timezone offset, using ' ' as a separator
        // Example: 2020-09-08 13:42:29.190855-05:00
        // Full format string: "%Y-%m-%d %H:%M:%S%.f%:z".
        const FORMAT1: [Item; 2] = [Fixed(Nanosecond), Fixed(TimezoneOffsetColon)];
        if let Ok(ts) = chrono::format::parse(&mut p, rest, FORMAT1.iter())
            .and_then(|()| p.to_datetime())
        {
            #[allow(deprecated)]
            return Ok(ts.timestamp_nanos());
        }

        // with an explicit Z, using ' ' as a separator
        // Example: 2020-09-08 13:42:29Z
        // Full format string: "%Y-%m-%d %H:%M:%S%.fZ".
        const FORMAT2: [Item; 2] = [Fixed(Nanosecond), Literal("Z")];
        if let Ok(ts) = chrono::format::parse(&mut p, rest, FORMAT2.iter())
            .and_then(|()| p.to_datetime_with_timezone(&Utc))
        {
            #[allow(deprecated)]
            return Ok(ts.timestamp_nanos());
        }

        // without a timezone specifier as a local time, using ' ' as a separator
        // Example: 2020-09-08 13:42:29.190855
        const FORMAT5: [Item; 1] = [Fixed(Nanosecond)];
        // Full format string: "%Y-%m-%d %H:%M:%S%.f".
        if let Ok(ts) = chrono::format::parse(&mut p, rest, FORMAT5.iter())
            .and_then(|()| p.to_naive_datetime_with_offset(0))
        {
            return naive_datetime_to_timestamp(s, ts);
        }

        // without a timezone specifier as a local time, using ' ' as a
        // separator, no fractional seconds
        // Example: 2020-09-08 13:42:29
        // Full format string: "%Y-%m-%d %H:%M:%S".
        if rest.is_empty() {
            if let Ok(ts) = p.to_naive_datetime_with_offset(0) {
                return naive_datetime_to_timestamp(s, ts);
            }
        }
    }

    // Support timestamps without an explicit timezone offset, again
    // to be compatible with what Apache Spark SQL does.
    if !separator_is_space
    /* i.e. separator == b'T' */
    {
        // without a timezone specifier as a local time, using T as a separator
        // Example: 2020-09-08T13:42:29.190855
        // Full format string: "%Y-%m-%dT%H:%M:%S%.f".
        const FORMAT3: [Item; 1] = [Fixed(Nanosecond)];
        if let Ok(ts) = chrono::format::parse(&mut p, rest, FORMAT3.iter())
            .and_then(|()| p.to_naive_datetime_with_offset(0))
        {
            return naive_datetime_to_timestamp(s, ts);
        }

        // without a timezone specifier as a local time, using T as a
        // separator, no fractional seconds
        // Example: 2020-09-08T13:42:29
        // Full format string: "%Y-%m-%dT%H:%M:%S".
        if rest.is_empty() {
            if let Ok(ts) = p.to_naive_datetime_with_offset(0) {
                return naive_datetime_to_timestamp(s, ts);
            }
        }
    }

    // Note we don't pass along the error message from the underlying
    // chrono parsing because we tried several different format
    // strings and we don't know which the user was trying to
    // match. Ths any of the specific error messages is likely to be
    // be more confusing than helpful
    Err(ArrowError::CastError(format!(
        "Error parsing '{}' as timestamp",
        s
    )))
}

/// Parses YYYY-MM-DD(T| )HH:MM:SS.
fn try_parse_prefix(s: &mut &str) -> Option<ParsedPrefix> {
    let mut p = Parsed::new();

    let mut rest = s.as_bytes();
    let year = try_parse_num(&mut rest)?;
    try_consume(&mut rest, b'-')?;
    let month = try_parse_num(&mut rest)?;
    try_consume(&mut rest, b'-')?;
    let day = try_parse_num(&mut rest)?;
    if rest.is_empty() {
        return None;
    }

    let separator_is_space = match rest[0] {
        b' ' => true,
        b'T' => false,
        _ => return None,
    };

    rest = &rest[1..];
    let hour = try_parse_num(&mut rest)?;
    try_consume(&mut rest, b':')?;
    let minute = try_parse_num(&mut rest)?;
    try_consume(&mut rest, b':')?;
    let second = try_parse_num(&mut rest)?;

    p.set_year(year).ok()?;
    p.set_month(month).ok()?;
    p.set_day(day).ok()?;
    p.set_hour(hour).ok()?;
    p.set_minute(minute).ok()?;
    p.set_second(second).ok()?;

    *s = unsafe { std::str::from_utf8_unchecked(rest) };
    Some(ParsedPrefix {
        result: p,
        separator_is_space,
    })
}

#[must_use]
fn try_parse_num(s: &mut &[u8]) -> Option<i64> {
    if s.is_empty() {
        return None;
    }

    let mut i;
    if s[0] == b'-' {
        i = 1
    } else {
        i = 0;
    }

    while i < s.len() && b'0' <= s[i] && s[i] <= b'9' {
        i += 1
    }

    let res = unsafe { std::str::from_utf8_unchecked(&s[0..i]) }
        .parse()
        .ok();
    *s = &s[i..];
    res
}

#[must_use]
fn try_consume(s: &mut &[u8], c: u8) -> Option<()> {
    if s.is_empty() || s[0] != c {
        return None;
    }
    *s = &s[1..];
    Some(())
}

struct ParsedPrefix {
    result: Parsed,
    separator_is_space: bool, // When false, the separator is 'T'.
}

/// Converts the naive datetime (which has no specific timezone) to a
/// nanosecond epoch timestamp relative to UTC.
fn naive_datetime_to_timestamp(_s: &str, datetime: NaiveDateTime) -> Result<i64> {
    // CubeStore-specific: do not take timezones into account.
    #[allow(deprecated)]
    Ok(Utc.from_utc_datetime(&datetime).timestamp_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::LocalResult;

    #[test]
    fn string_to_timestamp_timezone() -> Result<()> {
        // Explicit timezone
        assert_eq!(
            1599572549190855000,
            parse_timestamp("2020-09-08T13:42:29.190855+00:00")?
        );
        assert_eq!(
            1599572549190855000,
            parse_timestamp("2020-09-08T13:42:29.190855Z")?
        );
        assert_eq!(
            1599572549000000000,
            parse_timestamp("2020-09-08T13:42:29Z")?
        ); // no fractional part
        assert_eq!(
            1599590549190855000,
            parse_timestamp("2020-09-08T13:42:29.190855-05:00")?
        );
        Ok(())
    }

    #[test]
    fn string_to_timestamp_timezone_space() -> Result<()> {
        // Ensure space rather than T between time and date is accepted
        assert_eq!(
            1599572549190855000,
            parse_timestamp("2020-09-08 13:42:29.190855+00:00")?
        );
        assert_eq!(
            1599572549190855000,
            parse_timestamp("2020-09-08 13:42:29.190855Z")?
        );
        assert_eq!(
            1599572549000000000,
            parse_timestamp("2020-09-08 13:42:29Z")?
        ); // no fractional part
        assert_eq!(
            1599590549190855000,
            parse_timestamp("2020-09-08 13:42:29.190855-05:00")?
        );
        Ok(())
    }

    /// Interprets a naive_datetime (with no explicit timzone offset)
    /// using the local timezone and returns the timestamp in UTC (0
    /// offset)
    #[allow(deprecated)]
    fn naive_datetime_to_timestamp(naive_datetime: &NaiveDateTime) -> i64 {
        // Note: Use chrono APIs that are different than
        // naive_datetime_to_timestamp to compute the utc offset to
        // try and double check the logic
        let utc_offset_secs = match Local.offset_from_local_datetime(naive_datetime) {
            LocalResult::Single(local_offset) => {
                local_offset.fix().local_minus_utc() as i64
            }
            _ => panic!("Unexpected failure converting to local datetime"),
        };
        let utc_offset_nanos = utc_offset_secs * 1_000_000_000;
        naive_datetime.timestamp_nanos() - utc_offset_nanos
    }

    #[test]
    #[ignore = "CubeStore always uses UTC"]
    #[cfg_attr(miri, ignore)] // unsupported operation: can't call foreign function: mktime
    fn string_to_timestamp_no_timezone() -> Result<()> {
        // This test is designed to succeed in regardless of the local
        // timezone the test machine is running. Thus it is still
        // somewhat suceptable to bugs in the use of chrono
        let naive_datetime = NaiveDateTime::new(
            #[allow(deprecated)]
            NaiveDate::from_ymd(2020, 9, 8),
            #[allow(deprecated)]
            NaiveTime::from_hms_nano(13, 42, 29, 190855),
        );

        // Ensure both T and ' ' variants work
        assert_eq!(
            naive_datetime_to_timestamp(&naive_datetime),
            parse_timestamp("2020-09-08T13:42:29.190855")?
        );

        assert_eq!(
            naive_datetime_to_timestamp(&naive_datetime),
            parse_timestamp("2020-09-08 13:42:29.190855")?
        );

        // Also ensure that parsing timestamps with no fractional
        // second part works as well
        let naive_datetime_whole_secs = NaiveDateTime::new(
            #[allow(deprecated)]
            NaiveDate::from_ymd(2020, 9, 8),
            #[allow(deprecated)]
            NaiveTime::from_hms(13, 42, 29),
        );

        // Ensure both T and ' ' variants work
        assert_eq!(
            naive_datetime_to_timestamp(&naive_datetime_whole_secs),
            parse_timestamp("2020-09-08T13:42:29")?
        );

        assert_eq!(
            naive_datetime_to_timestamp(&naive_datetime_whole_secs),
            parse_timestamp("2020-09-08 13:42:29")?
        );

        Ok(())
    }

    #[test]
    fn string_to_timestamp_invalid() {
        // Test parsing invalid formats

        // It would be nice to make these messages better
        expect_timestamp_parse_error("", "Error parsing '' as timestamp");
        expect_timestamp_parse_error("SS", "Error parsing 'SS' as timestamp");
        expect_timestamp_parse_error(
            "Wed, 18 Feb 2015 23:16:09 GMT",
            "Error parsing 'Wed, 18 Feb 2015 23:16:09 GMT' as timestamp",
        );
    }

    // Parse a timestamp to timestamp int with a useful human readable error message
    fn parse_timestamp(s: &str) -> Result<i64> {
        let result = string_to_timestamp_nanos(s);
        if let Err(e) = &result {
            eprintln!("Error parsing timestamp '{}': {:?}", s, e);
        }
        result
    }

    fn expect_timestamp_parse_error(s: &str, expected_err: &str) {
        match string_to_timestamp_nanos(s) {
            Ok(v) => panic!(
                "Expected error '{}' while parsing '{}', but parsed {} instead",
                expected_err, s, v
            ),
            Err(e) => {
                assert!(e.to_string().contains(expected_err),
                        "Can not find expected error '{}' while parsing '{}'. Actual error '{}'",
                        expected_err, s, e);
            }
        }
    }
}
