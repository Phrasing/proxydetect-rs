# proxydetect-rs

A CLI tool designed to detect proxy and VPN usage through advanced network fingerprinting using proxydetect.live private API.

## Features
- HTTP Headers Test
- IP belongs to Hosting Provider
- IP on Proxy List
- IP on VPN List
- VPN Exit Node Enumeration
- TOR Detection Test
- Passive AI-based Proxy Detection
- TCP/IP Fingerprint Test
- Timezone Test
- Network Behavior Test
- WebRTC IP Leak Test
- Network Flow Pattern Test
- Latency Test
- High Latency Test 

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
