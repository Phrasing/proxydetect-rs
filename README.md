# proxydetect-rs

A CLI tool designed to detect proxy and VPN usage through advanced network fingerprinting using proxydetect.live private API.

## Features
- HTTP Headers Test
- IP belongs to Hosting Provider
- IP on Proxy List
- IP on VPN List
- VPN Exit Node Enumeration
- Passive AI-based Proxy Detection
- TCP/IP Fingerprint Test
- Network Behavior Test
- Network Flow Pattern Test
- Latency Test

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

### Bulk scan
```bash
cargo run -- --file proxies.txt
```