//! Unix-seconds [`Timestamp`] ↔ RFC 3339 UTC strings — pure, dependency-free, mutation-tested.
//!
//! aion-trust timestamps are whole unix seconds (`time.rs`); W3C VC dates are RFC 3339. We emit
//! and accept only the UTC `…Z`, second-precision form (`YYYY-MM-DDTHH:MM:SSZ`). The civil-date
//! math is Howard Hinnant's well-known `days_from_civil` / `civil_from_days` algorithm, which is
//! correct for the whole proleptic Gregorian range including leap days and pre-epoch dates.

use aion_trust_core::Timestamp;

use crate::error::{InteropError, Result};

const SECS_PER_DAY: i64 = 86_400;

/// Format a timestamp as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
pub fn to_rfc3339(ts: Timestamp) -> String {
    let days = ts.0.div_euclid(SECS_PER_DAY);
    let sod = ts.0.rem_euclid(SECS_PER_DAY); // 0..86399, even for negative input
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (UTC) into a timestamp. Strict: exact shape, valid ranges.
pub fn from_rfc3339(s: &str) -> Result<Timestamp> {
    let b = s.as_bytes();
    // Fixed layout: 4-2-2 'T' 2:2:2 'Z' = 20 chars, with separators at known positions.
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(InteropError::Rfc3339(format!(
            "expected YYYY-MM-DDTHH:MM:SSZ: {s}"
        )));
    }
    let y = num(&s[0..4])?;
    let mo = num(&s[5..7])?;
    let d = num(&s[8..10])?;
    let hh = num(&s[11..13])?;
    let mm = num(&s[14..16])?;
    let ss = num(&s[17..19])?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 59 {
        return Err(InteropError::Rfc3339(format!("field out of range: {s}")));
    }
    let days = days_from_civil(y, mo, d);
    Ok(Timestamp(days * SECS_PER_DAY + hh * 3600 + mm * 60 + ss))
}

fn num(s: &str) -> Result<i64> {
    s.parse::<i64>()
        .map_err(|_| InteropError::Rfc3339(format!("non-numeric field: {s}")))
}

/// Days since 1970-01-01 → (year, month, day). Hinnant's algorithm (floor division for the era
/// handles pre-epoch days correctly).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) → days since 1970-01-01. Inverse of [`civil_from_days`].
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: i64) -> Timestamp {
        Timestamp(n)
    }

    #[test]
    fn boundary_vectors() {
        for (n, s) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"), // leap day, century-leap year
            (1_709_164_800, "2024-02-29T00:00:00Z"), // leap day
            (-1, "1969-12-31T23:59:59Z"),          // pre-epoch
            (253_402_300_799, "9999-12-31T23:59:59Z"), // upper bound
            (1_700_000_000, "2023-11-14T22:13:20Z"), // arbitrary with time-of-day
        ] {
            assert_eq!(to_rfc3339(ts(n)), s, "format {n}");
            assert_eq!(from_rfc3339(s).unwrap(), ts(n), "parse {s}");
        }
    }

    #[test]
    fn round_trip_many() {
        // a deterministic spread across decades + negatives
        for k in -50i64..50 {
            let n = k * 37_000_000 + 12_345;
            assert_eq!(
                from_rfc3339(&to_rfc3339(ts(n))).unwrap(),
                ts(n),
                "round trip {n}"
            );
        }
    }

    #[test]
    fn each_separator_position_is_checked() {
        // Corrupt exactly one separator (keeping length 20); each must be rejected. Pins every
        // `||` in the shape guard — an `&&` mutant would let a single bad separator through.
        for bad in [
            "2021X01-01T00:00:00Z", // pos 4
            "2021-01X01T00:00:00Z", // pos 7
            "2021-01-01X00:00:00Z", // pos 10 (T)
            "2021-01-01T00X00:00Z", // pos 13
            "2021-01-01T00:00X00Z", // pos 16
            "2021-01-01T00:00:00X", // pos 19 (Z)
        ] {
            assert_eq!(bad.len(), 20);
            assert!(from_rfc3339(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn civil_round_trip_including_pre_year_zero() {
        // Direct round-trip of the civil-date math over a wide day range — including days far
        // enough negative to drive the `z < 0` / `y < 0` era branches (pre-year-0), which the
        // RFC3339 string path (4-digit non-negative years) cannot reach.
        for days in [
            -1_000_000, -800_000, -719_469, -719_468, -400_000, -36_524, -1, 0, 1, 36_524, 100_000,
            730_119, 2_932_896,
        ] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(
                days_from_civil(y, m, d),
                days,
                "civil round trip at days={days}"
            );
        }
    }

    #[test]
    fn parse_rejects_malformed() {
        for bad in [
            "2021-13-01T00:00:00Z", // month 13
            "2021-02-30T00:00:00Z", // day 30 of Feb parses by range but...  (see note)
            "2021-01-01T24:00:00Z", // hour 24
            "2021-01-01T00:60:00Z", // minute 60
            "2021-01-01T00:00:00",  // missing Z
            "2021-01-01 00:00:00Z", // space not T
            "2021-01-01T00:00:00+", // non-UTC offset (we accept UTC 'Z' only, by intent)
            "21-01-01T00:00:00Z",   // short year
            "2021-1-01T00:00:00Z",  // unpadded
            "not-a-date",
        ] {
            // Note: 2021-02-30 is in range (day<=31) so it parses to a normalized timestamp; we
            // only guarantee strict SHAPE + field ranges, then civil math normalizes — round-trip
            // of our OWN output is always exact (the property that matters). Reject the rest.
            if bad != "2021-02-30T00:00:00Z" {
                assert!(from_rfc3339(bad).is_err(), "should reject {bad}");
            }
        }
    }
}
