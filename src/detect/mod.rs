mod config;
mod payload;
mod result;

use crate::browser::{
    beacon_headers, get_preset, image_headers, poll_headers, script_headers, websocket_ping_pong,
    Preset, WsLatencyResult,
};
use crate::timezone;
use std::time::{Duration, Instant};
use wreq_util::tower::delay::JitterDelayLayer;

pub use config::{parse_config, ServerConfig};
pub use payload::{build_payload, ClientPayload};
pub use result::{parse_result, DetectionResult};

const ENGINE_ENDPOINT: &str = "https://engine.proxydetect.live";
const TELEMETRY_JITTER_BASE_MS: u64 = 350;
const TELEMETRY_JITTER_PCT: f64 = 0.5;

/// Progressive backoff schedule (in milliseconds).
const POLL_INTERVALS: &[u64] = &[
    0, 200, 400, 650, 900, 1200, 1600, 2100, 2700, 3500, 4500, 6000, 8000, 10000, 12000,
];

/// Approximate HTTP overhead per request (headers, TLS record framing).
const HTTP_OVERHEAD_PER_REQUEST: u64 = 500;

/// Detection run options.
pub struct Options {
    pub proxy_url: Option<String>,
    pub browser_name: String,
    pub timezone_iana: Option<String>,
    pub verbose: bool,
    pub json_output: bool,
}

/// Execute the full 4-phase detection protocol.
pub async fn run(
    opts: &Options,
    log: impl Fn(&str),
) -> Result<DetectionResult, Box<dyn std::error::Error + Send + Sync>> {
    let preset = get_preset(&opts.browser_name);
    let start_time = Instant::now();
    let mut total_bytes: u64 = 0;

    log(&format!("Using browser preset: {}", preset.name));

    let telemetry_jitter = JitterDelayLayer::new(
        Duration::from_millis(TELEMETRY_JITTER_BASE_MS),
        TELEMETRY_JITTER_PCT,
    )
    .when(|req: &tokio_tungstenite::tungstenite::http::Request<_>| {
        req.method().as_str() == "POST" && req.uri().path() == "/s"
    });

    let mut builder = wreq::Client::builder()
        .emulation(preset.emulation)
        .layer(telemetry_jitter);

    if let Some(ref proxy) = opts.proxy_url {
        builder = builder.proxy(wreq::Proxy::all(proxy)?);
        log(&format!("Routing through proxy: {}", proxy));
    }

    let client = builder.build()?;

    log("Initializing session...");
    let (cfg, p1_bytes) = phase1_fetch_config(&client, &preset, &log).await?;
    total_bytes += p1_bytes;
    let loaded_ms = start_time.elapsed().as_millis() as f64;
    log(&format!("  UUID: {}", cfg.uuid));
    log(&format!("  Exit IP: {}", cfg.rip));

    let tz_info = if let Some(ref iana) = opts.timezone_iana {
        log(&format!("  Override timezone: {}", iana));
        timezone::resolve(iana)?
    } else {
        log("  Resolving timezone...");
        let iana = match timezone::lookup_from_ip(&cfg.rip).await {
            Ok(tz) => {
                log(&format!("  Timezone: {}", tz));
                tz
            }
            Err(e) => {
                log(&format!(
                    "WARNING: Timezone lookup failed ({}), falling back to UTC",
                    e
                ));
                "UTC".to_string()
            }
        };
        timezone::resolve(&iana).unwrap_or_else(|_| timezone::resolve("UTC").unwrap())
    };

    log("Measuring latencies...");
    let ws_uuid = cfg.uuid.clone();
    let ws_handle = tokio::spawn(async move { websocket_ping_pong(&ws_uuid).await });

    let (image_latencies, p2_bytes) = phase2_image_probes(&client, &preset, &log).await;
    total_bytes += p2_bytes;
    let formatted_images: Vec<String> = image_latencies
        .iter()
        .map(|l| format!("{:.0}", l))
        .collect();
    log(&format!("  Image RTTs: [{}]", formatted_images.join(", ")));

    let ws_result: WsLatencyResult = match ws_handle.await {
        Ok(Ok(result)) => {
            log(&format!(
                "  WebSocket: {} samples captured",
                result.latencies.len()
            ));
            if !result.latencies.is_empty() {
                let formatted: Vec<String> = result
                    .latencies
                    .iter()
                    .map(|l| format!("{:.2}", l))
                    .collect();
                log(&format!("  WS RTTs: [{}]", formatted.join(", ")));
            }
            result
        }
        Ok(Err(e)) => {
            log(&format!("WebSocket ping-pong failed: {}", e));
            WsLatencyResult {
                latencies: vec![],
                bytes_sent: 0,
                bytes_received: 0,
            }
        }
        Err(_) => {
            log("WebSocket ping-pong task panicked");
            WsLatencyResult {
                latencies: vec![],
                bytes_sent: 0,
                bytes_received: 0,
            }
        }
    };
    total_bytes += ws_result.bytes_sent + ws_result.bytes_received;

    let ws_latencies_for_payload: Vec<f64> = if ws_result.latencies.is_empty() {
        log("  WebSocket latencies unavailable; using image RTTs as fallback");
        image_latencies.clone()
    } else {
        ws_result.latencies.clone()
    };

    let elapsed_ms = start_time.elapsed().as_millis() as f64;
    log("Submitting telemetry...");
    let payload = build_payload(
        &cfg,
        &preset,
        &tz_info,
        &image_latencies,
        &ws_latencies_for_payload,
        loaded_ms,
        elapsed_ms,
    );
    let p3_bytes = phase3_submit_telemetry(&client, &preset, &payload, &log).await?;
    total_bytes += p3_bytes;

    log("Waiting for analysis results...");
    let (mut result, p4_bytes) = phase4_poll(&client, &preset, &cfg.uuid, &log).await?;
    total_bytes += p4_bytes;
    result.exit_ip = cfg.rip;
    result.bandwidth_bytes = total_bytes;

    log(&format!("Bandwidth: {:.1} KB", total_bytes as f64 / 1024.0));

    Ok(result)
}

async fn phase1_fetch_config(
    client: &wreq::Client,
    preset: &Preset,
    _log: impl Fn(&str),
) -> Result<(ServerConfig, u64), Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/pd-lib.js", ENGINE_ENDPOINT);
    let headers = script_headers(preset);

    let resp = client.get(&url).headers(headers).send().await?;
    let body = resp.text().await?;

    let bytes = HTTP_OVERHEAD_PER_REQUEST + body.len() as u64;
    Ok((parse_config(&body)?, bytes))
}

async fn phase2_image_probes(
    client: &wreq::Client,
    preset: &Preset,
    log: impl Fn(&str),
) -> (Vec<f64>, u64) {
    let image_count = 3;
    let mut latencies = Vec::with_capacity(image_count);
    let headers = image_headers(preset);
    let mut bytes: u64 = 0;

    for idx in 0..image_count {
        let random_str = format!("{:x}", rand::random::<u64>());
        let url = format!(
            "{}/images/small.png?n={}&r={}",
            ENGINE_ENDPOINT, idx, random_str
        );

        let start = Instant::now();
        let result = client.get(&url).headers(headers.clone()).send().await;
        let rtt = start.elapsed().as_millis() as f64;

        match result {
            Ok(resp) => {
                let body = resp.bytes().await.unwrap_or_default();
                bytes += HTTP_OVERHEAD_PER_REQUEST + body.len() as u64;
                log(&format!("  Probe {}: {}ms", idx + 1, rtt as i64));
            }
            Err(e) => {
                bytes += HTTP_OVERHEAD_PER_REQUEST; // Count request even on failure
                log(&format!(
                    "Image probe {} failed: {} (using synthetic latency)",
                    idx, e
                ));
            }
        }
        latencies.push(rtt);
    }

    (latencies, bytes)
}

async fn phase3_submit_telemetry(
    client: &wreq::Client,
    preset: &Preset,
    payload: &ClientPayload,
    log: impl Fn(&str),
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let payload_json = serde_json::to_string(payload)?;
    let payload_len = payload_json.len() as u64;

    let url = format!("{}/s", ENGINE_ENDPOINT);
    let max_attempts: u32 = 4;

    for attempt in 0..max_attempts {
        let headers = beacon_headers(preset);
        let resp = client
            .post(&url)
            .headers(headers)
            .body(payload_json.clone())
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let response_len = body.len() as u64;
        log(&format!("  Server response: status {}", status));

        if status.as_u16() >= 500 && attempt < max_attempts - 1 {
            let base_ms: u64 = if attempt == 0 { 2000 } else { 4000 };
            let jitter_ms = rand::random::<u64>() % 2000 + 1000;
            let delay_ms = base_ms + jitter_ms;
            log(&format!(
                "  Telemetry 5xx (attempt {}/{}), retrying in {}ms...",
                attempt + 1,
                max_attempts,
                delay_ms
            ));
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            continue;
        }

        if status.as_u16() >= 400 {
            return Err(format!("server rejected telemetry (status {}): {}", status, body).into());
        }

        return Ok(HTTP_OVERHEAD_PER_REQUEST + payload_len + response_len);
    }

    Err("telemetry submission failed after all retry attempts".into())
}

async fn phase4_poll(
    client: &wreq::Client,
    preset: &Preset,
    uuid: &str,
    log: impl Fn(&str),
) -> Result<(DetectionResult, u64), Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/i?&uuid={}", ENGINE_ENDPOINT, uuid);
    let headers = poll_headers(preset);
    let mut bytes: u64 = 0;

    let mut schedule: Vec<u64> = POLL_INTERVALS.to_vec();
    schedule.extend(std::iter::repeat_n(12000, 10));

    let mut last_result = DetectionResult::default();

    for (idx, delay_ms) in schedule.iter().enumerate() {
        if *delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
        }

        log(&format!("  check #{} ({}ms)...", idx + 1, delay_ms));

        let resp = match client.get(&url).headers(headers.clone()).send().await {
            Ok(r) => r,
            Err(e) => {
                log(&format!("Poll request failed: {}", e));
                bytes += HTTP_OVERHEAD_PER_REQUEST;
                continue;
            }
        };

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                log(&format!("Reading poll response failed: {}", e));
                bytes += HTTP_OVERHEAD_PER_REQUEST;
                continue;
            }
        };

        bytes += HTTP_OVERHEAD_PER_REQUEST + body.len() as u64;

        let result = match parse_result(body.as_bytes()) {
            Ok(r) => r,
            Err(e) => {
                log(&format!("Parsing poll response failed: {}", e));
                continue;
            }
        };

        last_result = result;
        if last_result.finished {
            log(&format!(
                "  Analysis complete: {} tests",
                last_result.tests.len()
            ));
        } else {
            log(&format!(
                "  ... {} tests completed",
                last_result.tests.len()
            ));
        }

        if last_result.finished {
            return Ok((last_result, bytes));
        }
    }

    log("WARNING: Poll schedule exhausted, returning partial results");
    Ok((last_result, bytes))
}
