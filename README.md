# Proxy Detector (Rust)

A high-performance, asynchronous CLI tool designed to detect proxy and VPN usage through advanced network fingerprinting and behavioral analysis.

## Features

- **TLS Fingerprinting**: Emulates modern browser TLS handshakes (Chrome, Firefox, Safari) using `wreq` to evade basic anti-bot detection.
- **Latency Analysis**: Measures WebSocket and TCP/IP latencies to identify proxy routing anomalies.
- **Browser Emulation**: Mimics browser header orders and values for specific versions (e.g., Chrome 143, Safari 18).
- **Bandwidth Tracking**: detailed tracking of bandwidth usage during detection scans.
- **4-Phase Detection Protocol**:
  1.  **Configuration**: Fetches session configuration and exit IP.
  2.  **Latency Probing**: Concurrent WebSocket and image load latency measurements.
  3.  **Telemetry**: Submits encrypted client environment data (timezones, screen, etc.).
  4.  **Analysis**: Polls the analysis engine for the final verdict.

## Usage

```bash
cargo run -- --help
```

### Basic Scan
```bash
cargo run
```

### Scan with Proxy
```bash
cargo run -- --proxy http://user:pass@1.2.3.4:8080
```

### JSON Output
```bash
cargo run -- --json
```

## Build

```bash
cargo build --release
```

## License

MIT
