use crate::detect::DetectionResult;
use crate::ipapi::IpInfo;
use serde_json::{Map, Value};
use std::io::Write;

/// Test display order.
const TEST_DISPLAY_ORDER: &[&str] = &[
    "latency_vs_ping",
    "http_headers",
    "datacenter_ip",
    "proxy_ip",
    "vpn_ip",
    "enumerated_vpn_ip",
    "tcpip_fp",
    "timezone",
    "net",
    "webrtc",
    "latency",
    "flow_pattern",
    "high_latencies",
    "proxy_ai",
    "vpn_ai",
    "tor_detection",
];

/// Output raw JSON with pretty formatting.
pub fn render_json(result: &DetectionResult) {
    let output = serde_json::to_string_pretty(&result.raw_json).unwrap_or_default();
    println!("{}", output);
}

/// Output formatted terminal table of detection results.
pub fn render_table(result: &DetectionResult, exit_ip: &str, verbose: bool) {
    let divider = "=".repeat(64);
    let thin_div = "-".repeat(64);

    println!();
    println!("{}", divider);
    println!("  Proxy Detection Results for {}", exit_ip);
    println!("{}", divider);

    if !result.finished {
        println!();
        println!("  WARNING: Results may be incomplete (polling timed out)");
    }

    // Aggregate verdicts
    render_aggregate(&result.tests, "proxy", "Proxy Score");
    render_aggregate(&result.tests, "vpn", "VPN Score");
    render_client_threat(&result.tests);
    render_meta(&result.tests);

    println!();
    println!("{}", thin_div);
    println!("  Individual Tests");
    println!("{}", thin_div);

    // Extract tests sub-object
    let tests_map = extract_tests_map(&result.tests);
    if tests_map.is_none() {
        println!("  No test data available");
        println!();
        return;
    }
    let tests_map = tests_map.unwrap();

    // Render each test in display order
    let mut rendered = std::collections::HashSet::new();
    for key in TEST_DISPLAY_ORDER {
        if let Some(raw) = tests_map.get(*key) {
            rendered.insert(*key);
            render_test(key, raw, verbose);
        }
    }

    // Render any tests not in our display order
    for (key, raw) in tests_map.iter() {
        if !rendered.contains(key.as_str()) {
            render_test(key, raw, verbose);
        }
    }

    println!();
    println!("{}", thin_div);
    println!(
        "  Bandwidth Used: {} bytes ({:.2} KB)",
        result.bandwidth_bytes,
        result.bandwidth_bytes as f64 / 1024.0
    );
    println!("{}", divider);
}

/// Output an IP intelligence section sourced from ipapi.is.
pub fn render_ip_intelligence(info: &IpInfo) {
    let thin_div = "-".repeat(64);
    println!();
    println!("{}", thin_div);
    println!("  IP Intelligence (ipapi.is)");
    println!("{}", thin_div);
    println!(
        "  [ ] {:<20} {}",
        "Exit IP",
        if info.ip.is_empty() {
            "unknown"
        } else {
            &info.ip
        }
    );
    println!(
        "  [ ] {:<20} proxy={} vpn={} datacenter={} tor={} abuser={}",
        "Threat Flags",
        bool_flag(info.is_proxy),
        bool_flag(info.is_vpn),
        bool_flag(info.is_datacenter),
        bool_flag(info.is_tor),
        bool_flag(info.is_abuser),
    );
    println!(
        "  [ ] {:<20} {:.4}{}",
        "Abuser Score",
        info.abuser_score,
        if info.abuser_label.is_empty() {
            "".to_string()
        } else {
            format!(" ({})", info.abuser_label)
        }
    );
    println!(
        "  [ ] {:<20} {} ({})",
        "Company",
        value_or_unknown(&info.company),
        value_or_unknown(&info.company_type),
    );
    println!(
        "  [ ] {:<20} {}",
        "ASN Org",
        value_or_unknown(&info.asn_org)
    );
    println!(
        "  [ ] {:<20} {}, {}",
        "Location",
        value_or_unknown(&info.city),
        value_or_unknown(&info.country),
    );
}

fn extract_tests_map(tests: &Map<String, Value>) -> Option<Map<String, Value>> {
    tests.get("tests").and_then(|v| v.as_object()).cloned()
}

fn render_test(key: &str, raw: &Value, verbose: bool) {
    let is_proxy = raw.get("is_proxy").and_then(|v| v.as_bool());
    let is_vpn = raw.get("is_vpn").and_then(|v| v.as_bool());
    let name = raw.get("name").and_then(|v| v.as_str()).unwrap_or(key);

    let (verdict, icon) = determine_verdict(is_proxy, is_vpn);
    println!("  {} {:<36} {}", icon, name, verdict);

    if verbose {
        if let Some(info) = raw.get("info") {
            render_verbose_info(key, info);
        }
    }
}

fn determine_verdict(is_proxy: Option<bool>, is_vpn: Option<bool>) -> (&'static str, &'static str) {
    let proxy_detected = is_proxy == Some(true);
    let vpn_detected = is_vpn == Some(true);

    match (proxy_detected, vpn_detected, is_proxy, is_vpn) {
        (true, true, _, _) => ("PROXY+VPN DETECTED", "[!!]"),
        (true, false, _, _) => ("PROXY DETECTED", "[!!]"),
        (false, true, _, _) => ("VPN DETECTED", "[!!]"),
        (false, false, None, None) => ("N/A", "[ ]"),
        (false, false, Some(false), _) | (false, false, _, Some(false)) => ("clean", "[ok]"),
        _ => ("inconclusive", "[? ]"),
    }
}

fn render_aggregate(tests: &Map<String, Value>, key: &str, label: &str) {
    if let Some(raw) = tests.get(key) {
        let is_proxy = raw
            .get("isProxy")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let is_vpn = raw.get("isVpn").and_then(|v| v.as_bool()).unwrap_or(false);
        let score = raw.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        let informal = raw.get("informal").and_then(|v| v.as_str()).unwrap_or("");

        let icon = if is_proxy || is_vpn || score > 0 {
            "[!!]"
        } else {
            "[ok]"
        };
        println!();
        println!("  {} {:<20} {}", icon, label, informal);
    }
}

fn render_client_threat(tests: &Map<String, Value>) {
    if let Some(raw) = tests.get("client") {
        let is_threat = raw
            .get("isClientThreat")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let informal = raw.get("informal").and_then(|v| v.as_str()).unwrap_or("");

        let icon = if is_threat { "[! ]" } else { "[ok]" };
        println!("  {} {:<20} {}", icon, "Client Threats", informal);
    }
}

fn render_meta(tests: &Map<String, Value>) {
    if let Some(raw) = tests.get("meta") {
        let region = raw.get("region").and_then(|v| v.as_str()).unwrap_or("");
        let version = raw.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let elapsed = raw
            .get("elapsedTime")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        println!(
            "  [ ] {:<20} region={}, version={}, elapsed={:.0}ms",
            "Server Meta", region, version, elapsed
        );
    }
}

// ── Bulk output ──────────────────────────────────────────────────────

/// Aggregate verdict for a single proxy scan.
pub enum BulkStatus {
    Clean,
    Detected,
}

/// Print a start line for a bulk scan task.
pub fn render_bulk_start_line(proxy_display: &str, index: usize, total: usize) {
    println!("[..] [{}/{}] testing {}", index, total, proxy_display);
}

/// Extracted verdict fields from a detection result.
struct Verdict {
    proxy_detected: bool,
    vpn_detected: bool,
    proxy_positive: i64,
    proxy_total: i64,
    vpn_positive: i64,
    vpn_total: i64,
}

fn extract_verdict(tests: &Map<String, Value>) -> Verdict {
    let proxy = tests.get("proxy");
    let vpn = tests.get("vpn");

    Verdict {
        proxy_detected: proxy
            .and_then(|v| v.get("isProxy"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        vpn_detected: vpn
            .and_then(|v| v.get("isVpn"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        proxy_positive: proxy
            .and_then(|v| v.get("numPositiveTests"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        proxy_total: proxy
            .and_then(|v| v.get("numTests"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        vpn_positive: vpn
            .and_then(|v| v.get("numPositiveTests"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
        vpn_total: vpn
            .and_then(|v| v.get("numTests"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0),
    }
}

fn format_verdict_field(label: &str, detected: bool, positive: i64, total: i64) -> String {
    if detected {
        format!("DETECTED({}/{})", positive, total)
    } else {
        label.to_string()
    }
}

/// Classify a detection result as Clean or Detected.
pub fn classify_result(result: &DetectionResult) -> BulkStatus {
    let verdict = extract_verdict(&result.tests);
    if verdict.proxy_detected || verdict.vpn_detected {
        BulkStatus::Detected
    } else {
        BulkStatus::Clean
    }
}

/// Print a compact one-liner for a completed bulk scan.
pub fn render_bulk_line(
    progress: &str,
    proxy_display: &str,
    result: &DetectionResult,
    elapsed_secs: f64,
    status: &BulkStatus,
    ip_info: Option<&IpInfo>,
) {
    let verdict = extract_verdict(&result.tests);

    let icon = match status {
        BulkStatus::Detected => "[!!]",
        BulkStatus::Clean => "[ok]",
    };

    if let Some(info) = ip_info {
        let proxy_tag = if info.is_proxy { "detected" } else { "clean" };
        let vpn_tag = if info.is_vpn { "detected" } else { "clean" };
        println!(
            "{} {} {:<30} exit={:<15} proxy={:<8} vpn={:<8} dc={} abuse={:<7.4} {:.1}s",
            progress,
            icon,
            proxy_display,
            result.exit_ip,
            proxy_tag,
            vpn_tag,
            bool_flag(info.is_datacenter),
            info.abuser_score,
            elapsed_secs,
        );
    } else {
        let proxy_tag = format_verdict_field(
            "clean",
            verdict.proxy_detected,
            verdict.proxy_positive,
            verdict.proxy_total,
        );
        let vpn_tag = format_verdict_field(
            "clean",
            verdict.vpn_detected,
            verdict.vpn_positive,
            verdict.vpn_total,
        );

        println!(
            "{} {} {:<30} exit={:<15} proxy={:<16} vpn={:<16} {:.1}s",
            progress, icon, proxy_display, result.exit_ip, proxy_tag, vpn_tag, elapsed_secs,
        );
    }
}

/// Print an error line for a failed bulk scan.
pub fn render_bulk_error(
    progress: &str,
    proxy_display: &str,
    err: &str,
    elapsed_secs: f64,
    ip_info: Option<&IpInfo>,
) {
    if let Some(info) = ip_info {
        println!(
            "{} [ER] {:<30} error: {:<28} abuse={:<7.4} {:.1}s",
            progress, proxy_display, err, info.abuser_score, elapsed_secs,
        );
    } else {
        println!(
            "{} [ER] {:<30} error: {:<39} {:.1}s",
            progress, proxy_display, err, elapsed_secs,
        );
    }
}

/// Print a single NDJSON line for a successful scan.
pub fn render_bulk_json_line(
    proxy_raw: &str,
    result: &DetectionResult,
    ip_info: Option<&IpInfo>,
    filtered: bool,
    filter_threshold: Option<f64>,
) {
    let line = serde_json::json!({
        "proxy": proxy_raw,
        "exit_ip": result.exit_ip,
        "result": result.raw_json,
        "ipapi": ip_info.map(ip_info_json),
        "filtered": filtered,
        "max_fraud_score": filter_threshold,
        "error": null,
    });
    println!("{}", serde_json::to_string(&line).unwrap_or_default());
}

/// Print a single NDJSON line for a failed scan.
pub fn render_bulk_json_error(
    proxy_raw: &str,
    err: &str,
    ip_info: Option<&IpInfo>,
    filtered: bool,
    filter_threshold: Option<f64>,
) {
    let line = serde_json::json!({
        "proxy": proxy_raw,
        "exit_ip": null,
        "result": null,
        "ipapi": ip_info.map(ip_info_json),
        "filtered": filtered,
        "max_fraud_score": filter_threshold,
        "error": err,
    });
    println!("{}", serde_json::to_string(&line).unwrap_or_default());
}

/// Print a filtered line for a proxy excluded by abuse threshold.
pub fn render_bulk_filtered_line(
    progress: &str,
    proxy_display: &str,
    exit_ip: &str,
    abuser_score: f64,
    threshold: f64,
    elapsed_secs: f64,
) {
    println!(
        "{} [--] {:<30} exit={:<15} FILTERED (abuse={:.4} > {:.4}) {:.1}s",
        progress, proxy_display, exit_ip, abuser_score, threshold, elapsed_secs,
    );
}

/// Print the final summary block to stderr.
pub fn render_bulk_summary(
    total: usize,
    clean: usize,
    detected: usize,
    filtered: usize,
    errors: usize,
    avg_abuser_score: Option<f64>,
    abuser_score_samples: usize,
) {
    let divider = "=".repeat(64);
    let mut out = std::io::stderr();
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", divider);
    let _ = writeln!(out, "  Bulk Scan Summary");
    let _ = writeln!(out, "{}", divider);
    let _ = writeln!(out, "  Total:    {}", total);
    let _ = writeln!(out, "  Clean:    {}", clean);
    let _ = writeln!(out, "  Detected: {}", detected);
    let _ = writeln!(out, "  Filtered: {}", filtered);
    let _ = writeln!(out, "  Errors:   {}", errors);
    if let Some(avg) = avg_abuser_score {
        let _ = writeln!(
            out,
            "  Avg Abuser Score: {:.4} ({} lookups)",
            avg, abuser_score_samples
        );
    } else {
        let _ = writeln!(out, "  Avg Abuser Score: n/a (0 lookups)");
    }
    let _ = writeln!(out, "{}", divider);
}

// ── CSV output ───────────────────────────────────────────────────────

/// CSV header row.
pub fn csv_header(include_ipapi: bool) -> String {
    let mut base = "proxy,exit_ip,status,proxy_detected,vpn_detected,proxy_score,vpn_score,proxy_positive_tests,proxy_total_tests,vpn_positive_tests,vpn_total_tests,error".to_string();
    if include_ipapi {
        base.push_str(",ipapi_proxy,ipapi_vpn,ipapi_datacenter,ipapi_abuser,abuser_score,company,company_type,asn_org,country,city");
    }
    base
}

/// Quote a CSV field (double any internal quotes, wrap in quotes).
fn csv_quote(field: &str) -> String {
    format!("\"{}\"", field.replace('"', "\"\""))
}

/// Format a successful result as a CSV row.
pub fn csv_row(
    proxy_display: &str,
    result: &DetectionResult,
    ip_info: Option<&IpInfo>,
    include_ipapi: bool,
) -> String {
    let verdict = extract_verdict(&result.tests);
    let status = if verdict.proxy_detected || verdict.vpn_detected {
        "detected"
    } else {
        "clean"
    };

    let proxy_score = result
        .tests
        .get("proxy")
        .and_then(|val| val.get("score"))
        .and_then(|val| val.as_i64())
        .unwrap_or(0);
    let vpn_score = result
        .tests
        .get("vpn")
        .and_then(|val| val.get("score"))
        .and_then(|val| val.as_i64())
        .unwrap_or(0);

    let mut row = format!(
        "{},{},{},{},{},{},{},{},{},{},{},",
        csv_quote(proxy_display),
        csv_quote(&result.exit_ip),
        status,
        verdict.proxy_detected,
        verdict.vpn_detected,
        proxy_score,
        vpn_score,
        verdict.proxy_positive,
        verdict.proxy_total,
        verdict.vpn_positive,
        verdict.vpn_total,
    );

    if include_ipapi {
        // Keep the "error" column explicitly empty before appending ipapi columns.
        row.push(',');
        row.push_str(&csv_ipapi_columns(ip_info));
    }

    row
}

/// Format an error as a CSV row.
pub fn csv_error_row(proxy_display: &str, err: &str, include_ipapi: bool) -> String {
    let mut row = format!(
        "{},,error,,,,,,,,,{}",
        csv_quote(proxy_display),
        csv_quote(err),
    );
    if include_ipapi {
        row.push(',');
        row.push_str(&csv_ipapi_columns(None));
    }
    row
}

fn csv_ipapi_columns(ip_info: Option<&IpInfo>) -> String {
    match ip_info {
        Some(info) => format!(
            "{},{},{},{},{:.4},{},{},{},{},{}",
            info.is_proxy,
            info.is_vpn,
            info.is_datacenter,
            info.is_abuser,
            info.abuser_score,
            csv_quote(&info.company),
            csv_quote(&info.company_type),
            csv_quote(&info.asn_org),
            csv_quote(&info.country),
            csv_quote(&info.city),
        ),
        None => [""; 10].join(","),
    }
}

fn ip_info_json(info: &IpInfo) -> Value {
    serde_json::json!({
        "ip": info.ip,
        "is_proxy": info.is_proxy,
        "is_vpn": info.is_vpn,
        "is_datacenter": info.is_datacenter,
        "is_tor": info.is_tor,
        "is_abuser": info.is_abuser,
        "abuser_score": info.abuser_score,
        "abuser_label": info.abuser_label,
        "company": info.company,
        "company_type": info.company_type,
        "asn_org": info.asn_org,
        "country": info.country,
        "city": info.city,
    })
}

fn bool_flag(value: bool) -> &'static str {
    if value {
        "Y"
    } else {
        "N"
    }
}

fn value_or_unknown(value: &str) -> &str {
    if value.is_empty() {
        "unknown"
    } else {
        value
    }
}

fn render_verbose_info(key: &str, info: &Value) {
    let obj = match info.as_object() {
        Some(o) => o,
        None => return,
    };

    match key {
        "tcpip_fp" => {
            if let Some(val) = obj.get("tcpIpHighestOs") {
                println!("       TCP/IP OS: {}", val);
            }
            if let Some(val) = obj.get("userAgentOs") {
                println!("       UA OS:     {}", val);
            }
        }
        "proxy_ai" => {
            if let Some(val) = obj.get("label") {
                println!("       AI label:  {}", val);
            }
            if let Some(val) = obj.get("score") {
                println!("       AI score:  {}", val);
            }
        }
        "timezone" => {
            if let Some(val) = obj.get("isProxyByTimezone") {
                println!("       TZ mismatch: {}", val);
            }
        }
        "latency_vs_ping" | "latency" => {
            if let Some(val) = obj.get("error") {
                println!("       Note: {}", val);
            }
        }
        "flow_pattern" => {
            if let Some(val) = obj.get("numFlows") {
                println!("       Flows analyzed: {}", val);
            }
        }
        _ => {
            if let Some(msg) = obj.get("message") {
                println!("       {}", msg);
            }
            if let Some(err) = obj.get("error") {
                println!("       Note: {}", err);
            }
        }
    }
}
