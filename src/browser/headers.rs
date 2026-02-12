use super::preset::Preset;
use wreq::header::{HeaderMap, HeaderValue};

const PAGE_ORIGIN: &str = "https://proxydetect.live";
const PAGE_REFERER: &str = "https://proxydetect.live/";

fn is_chrome(preset: &Preset) -> bool {
    preset.name == "chrome-143" || preset.name == "chrome-131"
}

fn is_firefox(preset: &Preset) -> bool {
    preset.name == "firefox-133"
}

fn is_safari(preset: &Preset) -> bool {
    preset.name == "safari-18"
}

fn chrome_sec_ch_ua(preset: &Preset) -> &'static str {
    if preset.name == "chrome-143" {
        r#""Chromium";v="143", "Not/A)Brand";v="24", "Google Chrome";v="143""#
    } else {
        r#""Chromium";v="131", "Not/A)Brand";v="24", "Google Chrome";v="131""#
    }
}

/// Headers for GET /pd-lib.js (script loading context).
pub fn script_headers(preset: &Preset) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if is_chrome(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert(
            "Sec-Ch-Ua",
            HeaderValue::from_static(chrome_sec_ch_ua(preset)),
        );
        headers.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "Sec-Ch-Ua-Platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("script"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_firefox(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.5"),
        );
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("script"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_safari(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("script"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    }

    headers
}

/// Headers for GET /images/small.png (image probe context).
pub fn image_headers(preset: &Preset) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if is_chrome(preset) {
        headers.insert(
            "Accept",
            HeaderValue::from_static(
                "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            ),
        );
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert(
            "Sec-Ch-Ua",
            HeaderValue::from_static(chrome_sec_ch_ua(preset)),
        );
        headers.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "Sec-Ch-Ua-Platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("image"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("no-cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_firefox(preset) {
        headers.insert(
            "Accept",
            HeaderValue::from_static(
                "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
            ),
        );
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.5"),
        );
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("image"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("no-cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_safari(preset) {
        headers.insert("Accept", HeaderValue::from_static("image/webp,image/avif,image/jxl,image/heic,image/heic-sequence,video/*;q=0.8,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("image"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("no-cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    }

    headers
}

/// Headers for POST /s (sendBeacon/fetch telemetry submission).
pub fn beacon_headers(preset: &Preset) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if is_chrome(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("text/plain;charset=UTF-8"),
        );
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert(
            "Sec-Ch-Ua",
            HeaderValue::from_static(chrome_sec_ch_ua(preset)),
        );
        headers.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "Sec-Ch-Ua-Platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("no-cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_firefox(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.5"),
        );
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("text/plain;charset=UTF-8"),
        );
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("no-cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_safari(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert(
            "Content-Type",
            HeaderValue::from_static("text/plain;charset=UTF-8"),
        );
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("no-cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    }

    headers
}

/// Headers for GET https://api.ipapi.is/ (ipapi.is frontend fetch context).
pub fn ipapi_headers(preset: &Preset) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if is_chrome(preset) {
        headers.insert(
            "Sec-Ch-Ua-Platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
        headers.insert(
            "Sec-Ch-Ua",
            HeaderValue::from_static(chrome_sec_ch_ua(preset)),
        );
        headers.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert("Origin", HeaderValue::from_static("https://ipapi.is"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Referer", HeaderValue::from_static("https://ipapi.is/"));
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("Priority", HeaderValue::from_static("u=1, i"));
    } else if is_firefox(preset) {
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert("Origin", HeaderValue::from_static("https://ipapi.is"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Referer", HeaderValue::from_static("https://ipapi.is/"));
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.5"),
        );
    } else if is_safari(preset) {
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert("Origin", HeaderValue::from_static("https://ipapi.is"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Referer", HeaderValue::from_static("https://ipapi.is/"));
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
    }

    headers
}

/// Headers for GET /i?&uuid= (polling context).
pub fn poll_headers(preset: &Preset) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if is_chrome(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("Cache-Control", HeaderValue::from_static("no-cache"));
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert(
            "Sec-Ch-Ua",
            HeaderValue::from_static(chrome_sec_ch_ua(preset)),
        );
        headers.insert("Sec-Ch-Ua-Mobile", HeaderValue::from_static("?0"));
        headers.insert(
            "Sec-Ch-Ua-Platform",
            HeaderValue::from_static("\"Windows\""),
        );
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_firefox(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.5"),
        );
        headers.insert("Cache-Control", HeaderValue::from_static("no-cache"));
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    } else if is_safari(preset) {
        headers.insert("Accept", HeaderValue::from_static("*/*"));
        headers.insert(
            "Accept-Encoding",
            HeaderValue::from_static("gzip, deflate, br"),
        );
        headers.insert(
            "Accept-Language",
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert("Cache-Control", HeaderValue::from_static("no-cache"));
        headers.insert("Origin", HeaderValue::from_static(PAGE_ORIGIN));
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));
        headers.insert("Referer", HeaderValue::from_static(PAGE_REFERER));
        headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
        headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
        headers.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
        headers.insert(
            "User-Agent",
            HeaderValue::from_str(preset.user_agent).unwrap(),
        );
    }

    headers
}
