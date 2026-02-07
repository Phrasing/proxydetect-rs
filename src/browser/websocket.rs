use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const WS_ENDPOINT: &str = "wss://engine.proxydetect.live:7630";
const WS_ROUNDS: usize = 5;
const WS_TIMEOUT: Duration = Duration::from_secs(10);

/// WebSocket latency result.
#[derive(Clone, Debug)]
pub struct WsLatencyResult {
    pub latencies: Vec<f64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// WebSocket ping-pong for latency measurement.
/// Opens a WebSocket connection and exchanges UUID messages, measuring round-trip times.
pub async fn websocket_ping_pong(
    uuid: &str,
) -> Result<WsLatencyResult, Box<dyn std::error::Error + Send + Sync>> {
    let uuid_json = format!(r#"{{"uuid":"{}"}}"#, uuid);
    let msg_len = uuid_json.len() as u64;

    let connect_result = tokio::time::timeout(WS_TIMEOUT, connect_async(WS_ENDPOINT)).await;

    let (ws_stream, _response) = match connect_result {
        Ok(Ok((stream, resp))) => (stream, resp),
        Ok(Err(e)) => {
            return Err(format!("WebSocket connection failed: {}", e).into());
        }
        Err(_) => {
            return Err("WebSocket connection timed out".into());
        }
    };

    let (mut tx, mut rx) = ws_stream.split();

    let mut latencies = Vec::with_capacity(WS_ROUNDS);
    let mut bytes_sent: u64 = 0;
    let mut bytes_received: u64 = 0;

    // WebSocket frame overhead: ~6 bytes for client-to-server (masked), ~2 bytes for server-to-client
    const WS_FRAME_OVERHEAD_SEND: u64 = 6;
    const WS_FRAME_OVERHEAD_RECV: u64 = 2;

    for _round in 0..WS_ROUNDS {
        let start = Instant::now();

        tx.send(Message::Text(uuid_json.clone())).await?;
        bytes_sent += msg_len + WS_FRAME_OVERHEAD_SEND;

        let recv_result = tokio::time::timeout(Duration::from_secs(5), rx.next()).await;

        match recv_result {
            Ok(Some(Ok(msg))) => {
                let rtt = start.elapsed().as_secs_f64() * 1000.0; // Convert to ms
                latencies.push(rtt);
                let recv_len = match &msg {
                    Message::Text(s) => s.len() as u64,
                    Message::Binary(b) => b.len() as u64,
                    _ => 0,
                };
                bytes_received += recv_len + WS_FRAME_OVERHEAD_RECV;
            }
            Ok(Some(Err(_e))) => {
                return Ok(WsLatencyResult {
                    latencies,
                    bytes_sent,
                    bytes_received,
                });
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    // Send close frame (~4 bytes)
    let _ = tx.send(Message::Close(None)).await;
    bytes_sent += 4;

    Ok(WsLatencyResult {
        latencies,
        bytes_sent,
        bytes_received,
    })
}
