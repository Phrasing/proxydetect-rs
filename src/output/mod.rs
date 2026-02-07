use crate::detect::DetectionResult;
use serde_json::{Map, Value};

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
