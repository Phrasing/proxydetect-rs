use crate::detect::DetectionResult;
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
    proxy_display: &str,
    result: &DetectionResult,
    elapsed_secs: f64,
    status: &BulkStatus,
) {
    let verdict = extract_verdict(&result.tests);
    let proxy_tag = format_verdict_field("clean", verdict.proxy_detected, verdict.proxy_positive, verdict.proxy_total);
    let vpn_tag = format_verdict_field("clean", verdict.vpn_detected, verdict.vpn_positive, verdict.vpn_total);

    let icon = match status {
        BulkStatus::Detected => "[!!]",
        BulkStatus::Clean => "[ok]",
    };

    println!(
        "{} {:<30} exit={:<15} proxy={:<16} vpn={:<16} {:.1}s",
        icon, proxy_display, result.exit_ip, proxy_tag, vpn_tag, elapsed_secs,
    );
}

/// Print an error line for a failed bulk scan.
pub fn render_bulk_error(proxy_display: &str, err: &str, elapsed_secs: f64) {
    println!(
        "[ER] {:<30} error: {:<39} {:.1}s",
        proxy_display, err, elapsed_secs,
    );
}

/// Print a single NDJSON line for a successful scan.
pub fn render_bulk_json_line(proxy_raw: &str, result: &DetectionResult) {
    let line = serde_json::json!({
        "proxy": proxy_raw,
        "exit_ip": result.exit_ip,
        "result": result.raw_json,
        "error": null,
    });
    println!("{}", serde_json::to_string(&line).unwrap_or_default());
}

/// Print a single NDJSON line for a failed scan.
pub fn render_bulk_json_error(proxy_raw: &str, err: &str) {
    let line = serde_json::json!({
        "proxy": proxy_raw,
        "exit_ip": null,
        "result": null,
        "error": err,
    });
    println!("{}", serde_json::to_string(&line).unwrap_or_default());
}

/// Print the final summary block to stderr.
pub fn render_bulk_summary(total: usize, clean: usize, detected: usize, errors: usize) {
    let divider = "=".repeat(64);
    let mut out = std::io::stderr();
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", divider);
    let _ = writeln!(out, "  Bulk Scan Summary");
    let _ = writeln!(out, "{}", divider);
    let _ = writeln!(out, "  Total:    {}", total);
    let _ = writeln!(out, "  Clean:    {}", clean);
    let _ = writeln!(out, "  Detected: {}", detected);
    let _ = writeln!(out, "  Errors:   {}", errors);
    let _ = writeln!(out, "{}", divider);
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
