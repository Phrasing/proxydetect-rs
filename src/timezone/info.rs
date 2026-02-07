use chrono::{DateTime, Datelike, Local, Offset, TimeZone, Timelike};
use chrono_tz::Tz;
use serde::Deserialize;
use std::collections::HashMap;

/// Timezone-derived fields for client telemetry payload.
#[derive(Clone, Debug)]
pub struct Info {
    pub iana_name: String,
    pub windows_zone: String,
    pub offset_minutes: i32,
    pub resolved_epoch: i64,
    pub system_epoch: i64,
    pub date_string: String,
    pub time_string: String,
    pub timestamp_millis: i64,
}

#[derive(Deserialize)]
struct IpApiResponse {
    timezone: Option<String>,
}

/// Lookup IANA timezone from IP via ip-api.com.
pub async fn lookup_from_ip(ip: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("http://ip-api.com/json/{}?fields=timezone", ip);
    let body = wreq::get(&url).send().await?.text().await?;
    let resp: IpApiResponse = serde_json::from_str(&body)?;

    resp.timezone
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("empty timezone for IP {}", ip).into())
}

/// Resolve all timezone-derived values from an IANA timezone name.
pub fn resolve(iana_name: &str) -> Result<Info, Box<dyn std::error::Error + Send + Sync>> {
    let tz: Tz = iana_name.parse()?;
    let now = Local::now().with_timezone(&tz);
    let fixed = now.offset().fix();
    let offset_seconds = fixed.local_minus_utc();
    let offset_minutes = offset_seconds / 60;

    // JS Date.getTimezoneOffset() returns minutes WEST of UTC (positive for behind UTC)
    let js_offset = -offset_minutes;

    // resolvedOptionsEpoch: July 1, 1113 in the target timezone
    let epoch_1113 = tz
        .with_ymd_and_hms(1113, 7, 1, 0, 0, 0)
        .single()
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0);

    let windows_zone = iana_to_windows(iana_name);

    Ok(Info {
        iana_name: iana_name.to_string(),
        windows_zone: windows_zone.to_string(),
        offset_minutes: js_offset,
        resolved_epoch: epoch_1113,
        system_epoch: epoch_1113,
        date_string: format_js_date(&now, &fixed, windows_zone),
        time_string: format_js_time(&now),
        timestamp_millis: now.timestamp_millis(),
    })
}

/// Format date like JavaScript's Date.toString().
fn format_js_date<T: TimeZone>(
    now: &DateTime<T>,
    fixed: &chrono::FixedOffset,
    windows_zone: &str,
) -> String {
    let offset_seconds = fixed.local_minus_utc();
    let sign = if offset_seconds >= 0 { "+" } else { "-" };
    let abs_offset = offset_seconds.abs();
    let hours = abs_offset / 3600;
    let minutes = (abs_offset % 3600) / 60;

    let weekday = match now.weekday() {
        chrono::Weekday::Mon => "Mon",
        chrono::Weekday::Tue => "Tue",
        chrono::Weekday::Wed => "Wed",
        chrono::Weekday::Thu => "Thu",
        chrono::Weekday::Fri => "Fri",
        chrono::Weekday::Sat => "Sat",
        chrono::Weekday::Sun => "Sun",
    };

    let month = match now.month() {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    };

    format!(
        "{} {} {:02} {} {:02}:{:02}:{:02} GMT{}{:02}{:02} ({})",
        weekday,
        month,
        now.day(),
        now.year(),
        now.hour(),
        now.minute(),
        now.second(),
        sign,
        hours,
        minutes,
        windows_zone
    )
}

/// Format time like "12:56:04 PM".
fn format_js_time<T: TimeZone>(now: &DateTime<T>) -> String {
    let hour = now.hour();
    let period = if hour >= 12 { "PM" } else { "AM" };
    let display_hour = if hour > 12 {
        hour - 12
    } else if hour == 0 {
        12
    } else {
        hour
    };
    format!(
        "{}:{:02}:{:02} {}",
        display_hour,
        now.minute(),
        now.second(),
        period
    )
}

/// Map IANA timezone names to Windows display names.
fn iana_to_windows(iana: &str) -> &str {
    static IANA_WINDOWS_MAP: std::sync::LazyLock<HashMap<&'static str, &'static str>> =
        std::sync::LazyLock::new(|| {
            let mut m = HashMap::new();
            // North America
            m.insert("America/New_York", "Eastern Standard Time");
            m.insert("America/Chicago", "Central Standard Time");
            m.insert("America/Denver", "Mountain Standard Time");
            m.insert("America/Los_Angeles", "Pacific Standard Time");
            m.insert("America/Phoenix", "US Mountain Standard Time");
            m.insert("America/Anchorage", "Alaskan Standard Time");
            m.insert("Pacific/Honolulu", "Hawaiian Standard Time");
            m.insert("America/Halifax", "Atlantic Standard Time");
            m.insert("America/St_Johns", "Newfoundland Standard Time");
            m.insert("America/Regina", "Canada Central Standard Time");
            m.insert("America/Mexico_City", "Central Standard Time (Mexico)");
            m.insert("America/Bogota", "SA Pacific Standard Time");
            m.insert("America/Caracas", "Venezuela Standard Time");
            m.insert("America/Santiago", "Pacific SA Standard Time");
            m.insert("America/Argentina/Buenos_Aires", "Argentina Standard Time");
            m.insert("America/Sao_Paulo", "E. South America Standard Time");
            m.insert("America/Winnipeg", "Central Standard Time");
            m.insert("America/Edmonton", "Mountain Standard Time");
            m.insert("America/Vancouver", "Pacific Standard Time");
            m.insert("America/Toronto", "Eastern Standard Time");
            // Europe
            m.insert("Europe/London", "GMT Standard Time");
            m.insert("Europe/Paris", "Romance Standard Time");
            m.insert("Europe/Berlin", "W. Europe Standard Time");
            m.insert("Europe/Rome", "W. Europe Standard Time");
            m.insert("Europe/Madrid", "Romance Standard Time");
            m.insert("Europe/Amsterdam", "W. Europe Standard Time");
            m.insert("Europe/Brussels", "Romance Standard Time");
            m.insert("Europe/Vienna", "W. Europe Standard Time");
            m.insert("Europe/Zurich", "W. Europe Standard Time");
            m.insert("Europe/Stockholm", "W. Europe Standard Time");
            m.insert("Europe/Oslo", "W. Europe Standard Time");
            m.insert("Europe/Copenhagen", "Romance Standard Time");
            m.insert("Europe/Helsinki", "FLE Standard Time");
            m.insert("Europe/Warsaw", "Central European Standard Time");
            m.insert("Europe/Prague", "Central Europe Standard Time");
            m.insert("Europe/Budapest", "Central Europe Standard Time");
            m.insert("Europe/Bucharest", "GTB Standard Time");
            m.insert("Europe/Athens", "GTB Standard Time");
            m.insert("Europe/Istanbul", "Turkey Standard Time");
            m.insert("Europe/Moscow", "Russian Standard Time");
            m.insert("Europe/Kiev", "FLE Standard Time");
            m.insert("Europe/Kyiv", "FLE Standard Time");
            m.insert("Europe/Dublin", "GMT Standard Time");
            m.insert("Europe/Lisbon", "GMT Standard Time");
            // Asia
            m.insert("Asia/Tokyo", "Tokyo Standard Time");
            m.insert("Asia/Shanghai", "China Standard Time");
            m.insert("Asia/Hong_Kong", "China Standard Time");
            m.insert("Asia/Taipei", "Taipei Standard Time");
            m.insert("Asia/Seoul", "Korea Standard Time");
            m.insert("Asia/Singapore", "Singapore Standard Time");
            m.insert("Asia/Kolkata", "India Standard Time");
            m.insert("Asia/Calcutta", "India Standard Time");
            m.insert("Asia/Dubai", "Arabian Standard Time");
            m.insert("Asia/Riyadh", "Arab Standard Time");
            m.insert("Asia/Tehran", "Iran Standard Time");
            m.insert("Asia/Baghdad", "Arabic Standard Time");
            m.insert("Asia/Jerusalem", "Israel Standard Time");
            m.insert("Asia/Bangkok", "SE Asia Standard Time");
            m.insert("Asia/Jakarta", "SE Asia Standard Time");
            m.insert("Asia/Kuala_Lumpur", "Singapore Standard Time");
            m.insert("Asia/Manila", "Singapore Standard Time");
            m.insert("Asia/Karachi", "Pakistan Standard Time");
            m.insert("Asia/Dhaka", "Bangladesh Standard Time");
            m.insert("Asia/Almaty", "Central Asia Standard Time");
            m.insert("Asia/Vladivostok", "Vladivostok Standard Time");
            m.insert("Asia/Novosibirsk", "N. Central Asia Standard Time");
            // Oceania
            m.insert("Australia/Sydney", "AUS Eastern Standard Time");
            m.insert("Australia/Melbourne", "AUS Eastern Standard Time");
            m.insert("Australia/Brisbane", "E. Australia Standard Time");
            m.insert("Australia/Perth", "W. Australia Standard Time");
            m.insert("Australia/Adelaide", "Cen. Australia Standard Time");
            m.insert("Australia/Darwin", "AUS Central Standard Time");
            m.insert("Pacific/Auckland", "New Zealand Standard Time");
            m.insert("Pacific/Fiji", "Fiji Standard Time");
            // Africa
            m.insert("Africa/Cairo", "Egypt Standard Time");
            m.insert("Africa/Johannesburg", "South Africa Standard Time");
            m.insert("Africa/Lagos", "W. Central Africa Standard Time");
            m.insert("Africa/Nairobi", "E. Africa Standard Time");
            m.insert("Africa/Casablanca", "Morocco Standard Time");
            // UTC
            m.insert("UTC", "UTC");
            m.insert("Etc/UTC", "UTC");
            m.insert("Etc/GMT", "GMT Standard Time");
            m
        });

    IANA_WINDOWS_MAP.get(iana).copied().unwrap_or(iana)
}
