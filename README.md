# DPI Engine

A high-performance **Deep Packet Inspection** engine written in Go. Reads raw PCAP captures, classifies traffic by application, extracts domains via TLS SNI / HTTP Host / DNS queries, applies configurable blocking rules, and produces a detailed forensic report — all through a multi-threaded, lock-free pipeline.

```
╔══════════════════════════════════════════════════════════════╗
║                  DPI Engine (Go)                            ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Architecture

```
                          ┌────────────────────┐
                          │    Input  .pcap     │
                          └─────────┬──────────┘
                                    │
                          ┌─────────▼──────────┐
                          │      Reader         │
                          │  (pcap parser +     │
                          │   packet decoder)   │
                          └──┬──┬──┬──┬────────┘
                  hash-based │  │  │  │  routing
              ┌──────────────┘  │  │  └──────────────┐
              ▼                 ▼  ▼                  ▼
       ┌────────────┐   ┌────────────┐        ┌────────────┐
       │  Worker 0   │   │  Worker 1   │  ...   │  Worker N   │
       │ ┌──────────┐│   │ ┌──────────┐│        │ ┌──────────┐│
       │ │ ConnTrack ││   │ │ ConnTrack ││        │ │ ConnTrack ││
       │ │   DPI     ││   │ │   DPI     ││        │ │   DPI     ││
       │ │  Rules    ││   │ │  Rules    ││        │ │  Rules    ││
       │ └──────────┘│   │ └──────────┘│        │ └──────────┘│
       └──────┬──────┘   └──────┬──────┘        └──────┬──────┘
              │                 │                       │
              └────────────┬────┴───────────────────────┘
                           ▼
                  ┌─────────────────┐
                  │     Writer       │
                  │ (pcap output)    │
                  └────────┬────────┘
                           ▼
                  ┌─────────────────┐     ┌─────────────────────┐
                  │  Output .pcap   │     │   Forensic Report   │
                  └─────────────────┘     └─────────────────────┘
```

Packets are hashed by their **5-tuple** (src/dst IP, src/dst port, protocol) and routed to a consistent worker. Each worker maintains its own connection table — zero lock contention on the fast path.

---

## What It Does

| Capability | Details |
|---|---|
| **Protocol Parsing** | IPv4, TCP, UDP, ICMP |
| **TLS SNI Extraction** | Parses ClientHello to identify HTTPS targets |
| **HTTP Host Extraction** | Pulls `Host:` header from cleartext HTTP |
| **DNS Query Extraction** | Decodes DNS QNAME from query packets |
| **App Classification** | Maps domains to 22 app types (YouTube, Netflix, Discord, etc.) |
| **Traffic Filtering** | Block by IP, port, app type, or domain (wildcards supported) |
| **Suspicious Activity Detection** | High volume, port scanning, unusual ports, reserved IP ranges |
| **Threat Propagation** | Flags all destinations connected from a suspicious source |
| **PCAP Output** | Writes filtered packets to a valid .pcap file |

---

## Supported Applications

The engine identifies and classifies traffic for:

| Category | Apps |
|---|---|
| **Streaming** | YouTube, Netflix, Spotify, TikTok |
| **Social** | Facebook, Instagram, Twitter/X, WhatsApp, Telegram |
| **Productivity** | Google, Microsoft, Apple, Zoom |
| **Developer** | GitHub, Discord, Cloudflare |
| **Protocols** | HTTP, HTTPS, DNS, TLS, QUIC |

Classification works via **domain suffix matching** — e.g. `*.googlevideo.com` and `*.ytimg.com` both resolve to YouTube.

---

## Quick Start

### Build

```bash
go build -o dpi_engine .
```

### Basic Analysis (pass-through)

```bash
./dpi_engine capture.pcap output.pcap
```

### Block YouTube + TikTok

```bash
./dpi_engine capture.pcap filtered.pcap \
  --block-app YouTube \
  --block-domain "*.tiktok.com"
```

### Block by IP, Port, and Domain

```bash
./dpi_engine capture.pcap filtered.pcap \
  --block-ip 192.168.1.100 \
  --block-port 6881 \
  --block-domain "*.facebook.com" \
  --workers 8 \
  --verbose
```

### Load Rules from File

```bash
./dpi_engine capture.pcap filtered.pcap --rules rules.txt
```

**Rules file format:**

```ini
[BLOCKED_IPS]
10.0.0.50
192.168.1.100

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.facebook.com
ads.example.com

[BLOCKED_PORTS]
6881
8888
```

---

## CLI Reference

```
Usage: dpi_engine <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>         Block all packets from this source IP
  --block-app <app>       Block by app name (e.g. YouTube, Netflix)
  --block-domain <domain> Block domain, supports wildcards (*.tiktok.com)
  --block-port <port>     Block destination port
  --rules <file>          Load rules from a file
  --workers <n>           Number of worker goroutines (default: 4)
  --verbose               Verbose output
```

---

## Sample Report

```
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║  Overall Packet Statistics                                  ║
╠══════════════════════════════════════════════════════════════╣
║  Total packets:      7461                                    ║
║  Total bytes:        7554202                                 ║
║  TCP packets:        127                                     ║
║  UDP packets:        26                                      ║
╠══════════════════════════════════════════════════════════════╣
║  Application Classification Breakdown                       ║
╠══════════════════════════════════════════════════════════════╣
║  TLS                 4 ( 40.0%) ████████████████████
║  HTTPS               3 ( 30.0%) ███████████████
║  GitHub              2 ( 20.0%) ██████████
║  Netflix             1 ( 10.0%) █████
╠══════════════════════════════════════════════════════════════╣
║  Top 20 Domains                                             ║
╠══════════════════════════════════════════════════════════════╣
║  1   az764295.vo.msecnd.net                          4     ║
║  2   github.com                                      1     ║
║  3   netflix.com                                     1     ║
╠══════════════════════════════════════════════════════════════╣
║  !! Suspicious IP Activity                                  ║
╠══════════════════════════════════════════════════════════════╣
║  !! 13.127.247.216   [HIGH VOLUME: 147 connections          ] ║
║  !! 192.168.1.3      [PORT SCAN: 16 unique ports contacted  ] ║
║     Visited domains:
║       -> github.com
║       -> netflix.com
║     Connected to IPs:
║       -> 13.127.247.216
║       -> 140.82.112.21 (copilot-telemetry.githubusercontent.com)
╚══════════════════════════════════════════════════════════════╝
```

---

## How the DPI Pipeline Works

Each packet flows through a **7-step pipeline** inside a worker:

```
Packet arrives
     │
     ▼
 [1] Connection Lookup ──── 5-tuple match (forward + reverse)
     │
     ▼
 [2] TCP State Machine ──── SYN → SYN-ACK → EST → FIN → CLOSED
     │
     ▼
 [3] Block Check ────────── Drop if connection already blocked
     │
     ▼
 [4] Payload Inspection ─── TLS SNI / HTTP Host / DNS Query
     │
     ▼
 [5] Rule Evaluation ────── IP → Port → App → Domain (priority order)
     │
     ▼
 [6] IP Tracking ────────── Record src/dst for forensic analysis
     │
     ▼
 [7] Forward / Drop
```

---

## Suspicious Activity Detection

The engine flags IPs based on these heuristics:

| Rule | Trigger |
|---|---|
| **HIGH VOLUME** | > 100 connections from/to a single IP |
| **RESERVED RANGE** | Private/bogon IP appearing as destination (10.x, 172.16-31.x, 192.168.x, multicast) |
| **PORT SCAN** | > 10 unique destination ports from one IP |
| **UNUSUAL PORT** | Non-standard port below 1024 |
| **ASSOCIATED** | Destination connected from an already-flagged source IP |

The **propagation** step ensures that when your machine is flagged (e.g. as a private IP), every website and server it talked to is also surfaced in the suspicious activity report — giving you a complete picture of the network footprint.

---

## Project Structure

```
.
├── main.go                    # Entry point
├── cmd/
│   └── root.go                # CLI parser & orchestrator
├── engine/
│   ├── engine.go              # Pipeline coordinator
│   ├── reader.go              # PCAP reader (TCP/UDP/ICMP)
│   ├── worker.go              # Fast-path packet processor
│   ├── writer.go              # PCAP output writer
│   └── stats.go               # Statistics, IP tracking, reporting
├── dpi/
│   ├── sni.go                 # TLS ClientHello SNI extractor
│   ├── http.go                # HTTP Host header extractor
│   └── dns.go                 # DNS QNAME extractor
├── tracker/
│   └── connection.go          # Per-worker connection state machine
├── rules/
│   └── manager.go             # Thread-safe rule engine
├── types/
│   └── types.go               # Core types, 5-tuple, app classification
└── testdata/
    └── gen_pcap.go            # Test PCAP generator
```

---

## Performance Design

- **Lock-free fast path** — each worker owns its connection table; no mutexes on the hot path
- **Atomic counters** — global stats use `sync/atomic` instead of mutexes
- **Hash-based routing** — Boost-style hash combining ensures consistent flow-to-worker mapping
- **Buffered channels** — 10,000-entry buffers absorb burst traffic between pipeline stages
- **Lazy decoding** — gopacket decodes only the layers we inspect
- **LRU eviction** — connection tables bounded at 65,536 entries per worker
- **Defensive copies** — packet data is decoupled from gopacket internals to prevent data races

---

## Testing

```bash
go test ./...
```

Test coverage includes:
- TLS ClientHello parsing with real hex payloads
- HTTP header extraction across methods (GET, POST, HEAD, etc.)
- DNS query decoding with multi-label domains
- Rule matching (IP, port, app, domain wildcards)
- 5-tuple hashing distribution and routing invariants
- End-to-end pipeline with synthetic PCAPs

---

## Dependencies

| Package | Purpose |
|---|---|
| [google/gopacket](https://github.com/google/gopacket) | Packet decoding and PCAP reading |
| golang.org/x/sys | System call support (gopacket dependency) |

That's it. Two dependencies. The DPI extractors, connection tracker, rule engine, and report generator are all built from scratch.

---

## License

MIT
