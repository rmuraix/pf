//! Text formatting for table cells and status lines.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

/// `1536` → `1.5 KiB`.
pub fn bytes(n: u64) -> String {
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Bytes per second.
pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", bytes(bytes_per_sec.max(0.0) as u64))
}

/// Compact counter: `999`, `12.3k`, `4.5M`.
pub fn count(n: u64) -> String {
    match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1_000.0),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

/// Time since the last activity: `now`, `5s`, `3m05s`, `2h03m`, `4d`.
pub fn age(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0 => "now".into(),
        1..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m{:02}s", secs / 60, secs % 60),
        3600..=86_399 => format!("{}h{:02}m", secs / 3600, secs % 3600 / 60),
        _ => format!("{}d", secs / 86_400),
    }
}

/// Length of a flow: `0.5s`, `12.3s`, `3m 02s`, `2h 03m`.
pub fn duration(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=59 => format!("{:.1}s", d.as_secs_f64()),
        60..=3599 => format!("{}m {:02}s", secs / 60, secs % 60),
        _ => format!("{}h {:02}m", secs / 3600, secs % 3600 / 60),
    }
}

/// UTC time of day with milliseconds: `13:05:09.042`.
pub fn clock(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since_epoch.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60,
        since_epoch.subsec_millis()
    )
}

/// Offset from the first packet: `+0.123s`.
pub fn offset(d: Duration) -> String {
    format!("+{:.3}s", d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_scale_by_1024() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1024), "1.0 KiB");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(bytes(u64::MAX), "16777216.0 TiB");
    }

    #[test]
    fn rate_is_bytes_per_second_and_never_negative() {
        assert_eq!(rate(2048.0), "2.0 KiB/s");
        assert_eq!(rate(0.4), "0 B/s");
        assert_eq!(rate(-5.0), "0 B/s");
    }

    #[test]
    fn counts_are_compact() {
        assert_eq!(count(9_999), "9999");
        assert_eq!(count(12_345), "12.3k");
        assert_eq!(count(4_500_000), "4.5M");
    }

    #[test]
    fn ages() {
        assert_eq!(age(Duration::from_millis(900)), "now");
        assert_eq!(age(Duration::from_secs(5)), "5s");
        assert_eq!(age(Duration::from_secs(185)), "3m05s");
        assert_eq!(age(Duration::from_secs(7380)), "2h03m");
        assert_eq!(age(Duration::from_secs(3 * 86_400)), "3d");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(Duration::from_millis(500)), "0.5s");
        assert_eq!(duration(Duration::from_secs(182)), "3m 02s");
        assert_eq!(duration(Duration::from_secs(7380)), "2h 03m");
    }

    #[test]
    fn clock_is_utc_time_of_day() {
        let t = UNIX_EPOCH
            + Duration::from_millis(86_400_000 * 3 + 13 * 3_600_000 + 5 * 60_000 + 9_042);
        assert_eq!(clock(t), "13:05:09.042");
    }

    #[test]
    fn offsets_have_millisecond_precision() {
        assert_eq!(offset(Duration::from_micros(123_456)), "+0.123s");
    }
}
