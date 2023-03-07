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

use std::str::FromStr;

use crate::datatypes::*;
use crate::error::{ArrowError, Result};
use chrono::{prelude::*, LocalResult};

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
/// This function interprets strings without an explicit time zone as
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
        return Ok(ts.timestamp_nanos());
    }

    // Implement quasi-RFC3339 support by trying to parse the
    // timestamp with various other format specifiers to to support
    // separating the date and time with a space ' ' rather than 'T' to be
    // (more) compatible with Apache Spark SQL

    // timezone offset, using ' ' as a separator
    // Example: 2020-09-08 13:42:29.190855-05:00
    if let Ok(ts) = DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f%:z") {
        return Ok(ts.timestamp_nanos());
    }

    // with an explicit Z, using ' ' as a separator
    // Example: 2020-09-08 13:42:29Z
    if let Ok(ts) = Utc.datetime_from_str(s, "%Y-%m-%d %H:%M:%S%.fZ") {
        return Ok(ts.timestamp_nanos());
    }

    // Support timestamps without an explicit timezone offset, again
    // to be compatible with what Apache Spark SQL does.

    // without a timezone specifier as a local time, using T as a separator
    // Example: 2020-09-08T13:42:29.190855
    if let Ok(ts) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return naive_datetime_to_timestamp(s, ts);
    }

    // without a timezone specifier as a local time, using T as a
    // separator, no fractional seconds
    // Example: 2020-09-08T13:42:29
    if let Ok(ts) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return naive_datetime_to_timestamp(s, ts);
    }

    // without a timezone specifier as a local time, using ' ' as a separator
    // Example: 2020-09-08 13:42:29.190855
    if let Ok(ts) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        return naive_datetime_to_timestamp(s, ts);
    }

    // without a timezone specifier as a local time, using ' ' as a
    // separator, no fractional seconds
    // Example: 2020-09-08 13:42:29
    if let Ok(ts) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return naive_datetime_to_timestamp(s, ts);
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

/// Converts the naive datetime (which has no specific timezone) to a
/// nanosecond epoch timestamp relative to UTC.
fn naive_datetime_to_timestamp(s: &str, datetime: NaiveDateTime) -> Result<i64> {
    let l = Local {};

    match l.from_local_datetime(&datetime) {
        LocalResult::None => Err(ArrowError::CastError(format!(
            "Error parsing '{}' as timestamp: local time representation is invalid",
            s
        ))),
        LocalResult::Single(local_datetime) => {
            Ok(local_datetime.with_timezone(&Utc).timestamp_nanos())
        }
        // Ambiguous times can happen if the timestamp is exactly when
        // a daylight savings time transition occurs, for example, and
        // so the datetime could validly be said to be in two
        // potential offsets. However, since we are about to convert
        // to UTC anyways, we can pick one arbitrarily
        LocalResult::Ambiguous(local_datetime, _) => {
            Ok(local_datetime.with_timezone(&Utc).timestamp_nanos())
        }
    }
}

pub fn parse_interval_year_month(
    value: &str,
) -> Result<<IntervalYearMonthType as ArrowPrimitiveType>::Native> {
    let (result_months, result_days, result_nanos) = parse_interval("years", value)?;
    if result_days != 0 || result_nanos != 0 {
        return Err(ArrowError::CastError(format!(
            "Cannot cast {value} to IntervalYearMonth. Only year and month fields are allowed."
        )));
    }
    Ok(IntervalYearMonthType::make_value(0, result_months))
}

pub fn parse_interval_day_time(
    value: &str,
) -> Result<<IntervalDayTimeType as ArrowPrimitiveType>::Native> {
    let (result_months, mut result_days, result_nanos) = parse_interval("days", value)?;
    if result_nanos % 1_000_000 != 0 {
        return Err(ArrowError::CastError(format!(
            "Cannot cast {value} to IntervalDayTime because the nanos part isn't multiple of milliseconds"
        )));
    }
    result_days += result_months * 30;
    Ok(IntervalDayTimeType::make_value(
        result_days,
        (result_nanos / 1_000_000) as i32,
    ))
}

pub fn parse_interval_month_day_nano(
    value: &str,
) -> Result<<IntervalMonthDayNanoType as ArrowPrimitiveType>::Native> {
    let (result_months, result_days, result_nanos) = parse_interval("months", value)?;
    Ok(IntervalMonthDayNanoType::make_value(
        result_months,
        result_days,
        result_nanos,
    ))
}

const SECONDS_PER_HOUR: f64 = 3_600_f64;
const NANOS_PER_MILLIS: f64 = 1_000_000_f64;
const NANOS_PER_SECOND: f64 = 1_000_f64 * NANOS_PER_MILLIS;
#[cfg(test)]
const NANOS_PER_MINUTE: f64 = 60_f64 * NANOS_PER_SECOND;
#[cfg(test)]
const NANOS_PER_HOUR: f64 = 60_f64 * NANOS_PER_MINUTE;
#[cfg(test)]
const NANOS_PER_DAY: f64 = 24_f64 * NANOS_PER_HOUR;

#[derive(Clone, Copy)]
#[repr(u16)]
enum IntervalType {
    Century = 0b_00_0000_0001,
    Decade = 0b_00_0000_0010,
    Year = 0b_00_0000_0100,
    Month = 0b_00_0000_1000,
    Week = 0b_00_0001_0000,
    Day = 0b_00_0010_0000,
    Hour = 0b_00_0100_0000,
    Minute = 0b_00_1000_0000,
    Second = 0b_01_0000_0000,
    Millisecond = 0b_10_0000_0000,
}

impl FromStr for IntervalType {
    type Err = ArrowError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "century" | "centuries" => Ok(Self::Century),
            "decade" | "decades" => Ok(Self::Decade),
            "year" | "years" => Ok(Self::Year),
            "month" | "months" => Ok(Self::Month),
            "week" | "weeks" => Ok(Self::Week),
            "day" | "days" => Ok(Self::Day),
            "hour" | "hours" => Ok(Self::Hour),
            "minute" | "minutes" => Ok(Self::Minute),
            "second" | "seconds" => Ok(Self::Second),
            "millisecond" | "milliseconds" => Ok(Self::Millisecond),
            _ => Err(ArrowError::NotYetImplemented(format!(
                "Unknown interval type: {s}"
            ))),
        }
    }
}

pub type MonthDayNano = (i32, i32, i64);

/// parse string value to a triple of aligned months, days, nanos.
/// leading field is the default unit. e.g. `INTERVAL 1` represents `INTERVAL 1 SECOND` when leading_filed = 'second'
fn parse_interval(leading_field: &str, value: &str) -> Result<MonthDayNano> {
    let mut used_interval_types = 0;

    let mut calculate_from_part = |interval_period_str: &str,
                                   interval_type: &str|
     -> Result<(i32, i32, i64)> {
        // TODO: Use fixed-point arithmetic to avoid truncation and rounding errors (#3809)
        let interval_period = match f64::from_str(interval_period_str) {
            Ok(n) => n,
            Err(_) => {
                return Err(ArrowError::NotYetImplemented(format!(
                    "Unsupported Interval Expression with value {value:?}"
                )));
            }
        };

        if interval_period > (i64::MAX as f64) {
            return Err(ArrowError::ParseError(format!(
                "Interval field value out of range: {value:?}"
            )));
        }

        let it = IntervalType::from_str(interval_type).map_err(|_| {
            ArrowError::ParseError(format!(
                "Invalid input syntax for type interval: {value:?}"
            ))
        })?;

        // Disallow duplicate interval types
        if used_interval_types & (it as u16) != 0 {
            return Err(ArrowError::ParseError(format!(
                "Invalid input syntax for type interval: {value:?}. Repeated type '{interval_type}'"
            )));
        } else {
            used_interval_types |= it as u16;
        }

        match it {
            IntervalType::Century => {
                align_interval_parts(interval_period * 1200_f64, 0.0, 0.0)
            }
            IntervalType::Decade => {
                align_interval_parts(interval_period * 120_f64, 0.0, 0.0)
            }
            IntervalType::Year => {
                align_interval_parts(interval_period * 12_f64, 0.0, 0.0)
            }
            IntervalType::Month => align_interval_parts(interval_period, 0.0, 0.0),
            IntervalType::Week => align_interval_parts(0.0, interval_period * 7_f64, 0.0),
            IntervalType::Day => align_interval_parts(0.0, interval_period, 0.0),
            IntervalType::Hour => Ok((
                0,
                0,
                (interval_period * SECONDS_PER_HOUR * NANOS_PER_SECOND) as i64,
            )),
            IntervalType::Minute => {
                Ok((0, 0, (interval_period * 60_f64 * NANOS_PER_SECOND) as i64))
            }
            IntervalType::Second => {
                Ok((0, 0, (interval_period * NANOS_PER_SECOND) as i64))
            }
            IntervalType::Millisecond => {
                Ok((0, 0, (interval_period * 1_000_000f64) as i64))
            }
        }
    };

    let mut result_month: i32 = 0;
    let mut result_days: i32 = 0;
    let mut result_nanos: i64 = 0;

    let mut parts = value.split_whitespace();

    while let Some(interval_period_str) = parts.next() {
        let unit = parts.next().unwrap_or(leading_field);

        let (diff_month, diff_days, diff_nanos) =
            calculate_from_part(interval_period_str, unit)?;

        result_month = result_month.checked_add(diff_month).ok_or_else(|| {
            ArrowError::ParseError(format!(
                "Interval field value out of range: {value:?}"
            ))
        })?;

        result_days = result_days.checked_add(diff_days).ok_or_else(|| {
            ArrowError::ParseError(format!(
                "Interval field value out of range: {value:?}"
            ))
        })?;

        result_nanos = result_nanos.checked_add(diff_nanos).ok_or_else(|| {
            ArrowError::ParseError(format!(
                "Interval field value out of range: {value:?}"
            ))
        })?;
    }

    Ok((result_month, result_days, result_nanos))
}

/// The fractional units must be spilled to smaller units.
/// [reference Postgresql doc](https://www.postgresql.org/docs/15/datatype-datetime.html#DATATYPE-INTERVAL-INPUT:~:text=Field%20values%20can,fractional%20on%20output.)
/// INTERVAL '0.5 MONTH' = 15 days, INTERVAL '1.5 MONTH' = 1 month 15 days
/// INTERVAL '0.5 DAY' = 12 hours, INTERVAL '1.5 DAY' = 1 day 12 hours
fn align_interval_parts(
    month_part: f64,
    mut day_part: f64,
    mut nanos_part: f64,
) -> Result<(i32, i32, i64)> {
    // Convert fractional month to days, It's not supported by Arrow types, but anyway
    day_part += (month_part - (month_part as i64) as f64) * 30_f64;

    // Convert fractional days to hours
    nanos_part += (day_part - ((day_part as i64) as f64))
        * 24_f64
        * SECONDS_PER_HOUR
        * NANOS_PER_SECOND;

    if month_part > i32::MAX as f64
        || month_part < i32::MIN as f64
        || day_part > i32::MAX as f64
        || day_part < i32::MIN as f64
        || nanos_part > i64::MAX as f64
        || nanos_part < i64::MIN as f64
    {
        return Err(ArrowError::ParseError(format!(
            "Parsed interval field value out of range: {month_part} months {day_part} days {nanos_part} nanos"
        )));
    }

    Ok((month_part as i32, day_part as i32, nanos_part as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Interprets a naive_datetime (with no explicit timezone offset)
    /// using the local timezone and returns the timestamp in UTC (0
    /// offset)
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
    #[cfg_attr(miri, ignore)] // unsupported operation: can't call foreign function: mktime
    fn string_to_timestamp_no_timezone() -> Result<()> {
        // This test is designed to succeed in regardless of the local
        // timezone the test machine is running. Thus it is still
        // somewhat susceptible to bugs in the use of chrono
        let naive_datetime = NaiveDateTime::new(
            NaiveDate::from_ymd(2020, 9, 8),
            NaiveTime::from_hms_nano(13, 42, 29, 190855000),
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
            NaiveDate::from_ymd(2020, 9, 8),
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

    #[test]
    fn test_parse_interval() {
        assert_eq!(
            (1i32, 0i32, 0i64),
            parse_interval("months", "1 month").unwrap(),
        );

        assert_eq!(
            (2i32, 0i32, 0i64),
            parse_interval("months", "2 month").unwrap(),
        );

        assert_eq!(
            (-1i32, -18i32, (-0.2 * NANOS_PER_DAY) as i64),
            parse_interval("months", "-1.5 months -3.2 days").unwrap(),
        );

        assert_eq!(
            (2i32, 10i32, (9.0 * NANOS_PER_HOUR) as i64),
            parse_interval("months", "2.1 months 7.25 days 3 hours").unwrap(),
        );

        assert_eq!(
            parse_interval("months", "1 centurys 1 month")
                .unwrap_err()
                .to_string(),
            r#"Parser error: Invalid input syntax for type interval: "1 centurys 1 month""#
        );

        assert_eq!(
            (37i32, 0i32, 0i64),
            parse_interval("months", "3 year 1 month").unwrap(),
        );

        assert_eq!(
            (35i32, 0i32, 0i64),
            parse_interval("months", "3 year -1 month").unwrap(),
        );

        assert_eq!(
            (-37i32, 0i32, 0i64),
            parse_interval("months", "-3 year -1 month").unwrap(),
        );

        assert_eq!(
            (-35i32, 0i32, 0i64),
            parse_interval("months", "-3 year 1 month").unwrap(),
        );

        assert_eq!(
            (0i32, 5i32, 0i64),
            parse_interval("months", "5 days").unwrap(),
        );

        assert_eq!(
            (0i32, 7i32, (3f64 * NANOS_PER_HOUR) as i64),
            parse_interval("months", "7 days 3 hours").unwrap(),
        );

        assert_eq!(
            (0i32, 7i32, (5f64 * NANOS_PER_MINUTE) as i64),
            parse_interval("months", "7 days 5 minutes").unwrap(),
        );

        assert_eq!(
            (0i32, 7i32, (-5f64 * NANOS_PER_MINUTE) as i64),
            parse_interval("months", "7 days -5 minutes").unwrap(),
        );

        assert_eq!(
            (0i32, -7i32, (5f64 * NANOS_PER_HOUR) as i64),
            parse_interval("months", "-7 days 5 hours").unwrap(),
        );

        assert_eq!(
            (
                0i32,
                -7i32,
                (-5f64 * NANOS_PER_HOUR
                    - 5f64 * NANOS_PER_MINUTE
                    - 5f64 * NANOS_PER_SECOND) as i64
            ),
            parse_interval("months", "-7 days -5 hours -5 minutes -5 seconds").unwrap(),
        );

        assert_eq!(
            (12i32, 0i32, (25f64 * NANOS_PER_MILLIS) as i64),
            parse_interval("months", "1 year 25 millisecond").unwrap(),
        );

        assert_eq!(
            (12i32, 1i32, (0.000000001 * NANOS_PER_SECOND) as i64),
            parse_interval("months", "1 year 1 day 0.000000001 seconds").unwrap(),
        );

        assert_eq!(
            (12i32, 1i32, (0.1 * NANOS_PER_MILLIS) as i64),
            parse_interval("months", "1 year 1 day 0.1 milliseconds").unwrap(),
        );

        assert_eq!(
            (1i32, 0i32, (-NANOS_PER_SECOND) as i64),
            parse_interval("months", "1 month -1 second").unwrap(),
        );

        assert_eq!(
            (-13i32, -8i32, (- NANOS_PER_HOUR - NANOS_PER_MINUTE - NANOS_PER_SECOND - 1.11 * NANOS_PER_MILLIS) as i64),
            parse_interval("months", "-1 year -1 month -1 week -1 day -1 hour -1 minute -1 second -1.11 millisecond").unwrap(),
        );
    }

    #[test]
    fn test_duplicate_interval_type() {
        let err = parse_interval("months", "1 month 1 second 1 second")
            .expect_err("parsing interval should have failed");
        assert_eq!(
            r#"ParseError("Invalid input syntax for type interval: \"1 month 1 second 1 second\". Repeated type 'second'")"#,
            format!("{err:?}")
        );
    }
}
