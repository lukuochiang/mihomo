# mihomo smart

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-blue?style=for-the-badge" alt="Platform">
</p>

---

## Overview

**mihomo smart** is an intelligent proxy kernel based on [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) (Clash.Meta), featuring a built-in AI-powered Smart policy engine for automatic optimal node selection.

## Features

### 🌟 Smart Policy Engine

- **Multi-dimensional Scoring**: Automatically scores nodes based on latency, jitter, stability, bandwidth, and region
- **Intelligent Mode Selection**: `auto`, `fast`, `stable`, `balanced`, `learning`
- **Smart Region Matching**: Automatically selects optimal nodes for Netflix, YouTube, GitHub, and other services
- **Machine Learning**: Learns from historical data to predict optimal nodes

### 📦 Protocol Support

| Category | Protocols |
|----------|-----------|
| **Proxy** | VMess, VLESS, Trojan, Shadowsocks, ShadowsocksR, Snell, TUIC, Hysteria, SSH, WireGuard |
| **Inbound** | HTTP, HTTPS, SOCKS5, Mixed, Redirect, TProxy, Tunnel, Shadowsocks Server, VMess/VLESS/Trojan Server, TUIC/Hysteria2 Server |
| **Transport** | WebSocket, gRPC, HTTP/2, mKCP, Reality, TLS |

### 🔧 Rule Engine

- Domain-based: `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`
- Geo-based: `GEOIP`, `GEOSITE`
- IP-based: `IP-CIDR`, `IP-CIDR6`
- Process-based: `PROCESS`, `PROCESS-PATH`
- Advanced: `RULE-SET`, `SUB-RULE`, `INBOUND-TAG`

### 📊 Proxy Groups

| Type | Description |
|------|-------------|
| `selector` | Manual node selection |
| `url-test` | Auto select by latency test |
| `fallback` | Failover to next node |
| `load-balance` | Load balancing (round-robin, least-connections, consistent-hash) |
| `relay` | Proxy chain |
| `interface` | Select by network interface |
| **`smart`** | AI-powered intelligent selection |

### 🚀 Additional Features

- **DNS Optimization**: DoH, DoT, DoQ, FakeIP, Enhanced Mode
- **TUN Mode**: Full-stack TUN device with gVisor
- **Hot Reload**: Configuration hot reload via file watch or API
- **Dashboard**: Built-in Web UI
- **RESTful API**: Full control via HTTP API
- **Metrics**: Prometheus-compatible metrics export

## Quick Start

### Installation

```bash
# Download binary from releases
wget https://github.com/lukuochiang/mihomo/releases/latest/download/mihomo-linux-amd64
chmod +x mihomo-linux-amd64
sudo mv mihomo-linux-amd64 /usr/local/bin/mihomo

# Or build from source
git clone https://github.com/lukuochiang/mihomo.git
cd mihomo
go build -o mihomo .
```

### Configuration

Create `config.yaml`:

```yaml
# Basic settings
bind-address: 0.0.0.0
port: 7890
socks-port: 7891
mixed-port: 7892

# Enable DNS
dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 8.8.8.8
    - 1.1.1.1

# Smart policy engine
smart:
  enabled: true
  learning-enabled: true
  selection-mode: auto
  update-interval: 5s

# Proxy nodes
proxies:
  - name: node-us-01
    type: vmess
    server: us.example.com
    port: 443
    uuid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    alter-id: 0
    security: auto
    network: ws
    ws-path: /vmess
    tls: true

  - name: node-jp-01
    type: vless
    server: jp.example.com
    port: 443
    uuid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    network: grpc
    grpc-service-name: vless

# Proxy groups
proxy-groups:
  - name: Smart
    type: smart
    proxies:
      - node-us-01
      - node-jp-01
    smart-mode: auto

  - name: Auto
    type: url-test
    proxies:
      - node-us-01
      - node-jp-01
    url: http://www.gstatic.com/generate_204
    interval: 300

# Rules
rules:
  - DOMAIN-SUFFIX,netflix.com,Smart
  - DOMAIN-SUFFIX,youtube.com,Smart
  - DOMAIN-KEYWORD,github,Smart
  - GEOSITE,CN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Auto
```

### Run

```bash
# Run directly
./mihomo -config config.yaml

# Or with systemd (Linux)
sudo systemctl enable mihomo
sudo systemctl start mihomo
```

## Smart Policy Usage

### Configuration

```yaml
proxy-groups:
  # Basic Smart group
  - name: smart-proxy
    type: smart
    proxies:
      - node-us-01
      - node-jp-01
      - node-sg-01
    smart-mode: auto              # auto, fast, stable, balanced, learning
    target-region: ""             # Optional: prefer specific region

  # Streaming optimized
  - name: streaming
    type: smart
    proxies:
      - node-us-01
      - node-jp-01
    smart-mode: fast
    target-region: netflix         # Auto-detected as US

  # Gaming optimized
  - name: gaming
    type: smart
    proxies:
      - node-jp-01
      - node-kr-01
    smart-mode: fast
    target-region: jp              # Prefer Japan
```

### Selection Modes

| Mode | Description |
|------|-------------|
| `auto` | Auto-adjust based on network conditions |
| `fast` | Low latency priority (games, video calls) |
| `stable` | High stability priority (business, file transfer) |
| `balanced` | Balanced consideration of all metrics |
| `learning` | Machine learning prediction |

### Region Matching

Smart automatically identifies services and selects optimal regions:

| Service | Recommended Region |
|---------|-------------------|
| Netflix, YouTube, Google | `us` |
| GitHub, Spotify | `us` |
| Bilibili, Baidu, Alibaba | `cn`/`hk` |

## API Reference

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/nodes` | GET | List all nodes with metrics |
| `/v1/stats` | GET | Get Smart policy statistics |
| `/v1/select` | POST | Manually select a node |
| `/v1/reload` | POST | Trigger config hot reload |
| `/health` | GET | Health check |
| `/api/ws` | WebSocket | Real-time updates |

### Examples

```bash
# Get node list
curl -H "Authorization: Bearer YOUR_SECRET" http://localhost:9090/v1/nodes

# Get statistics
curl -H "Authorization: Bearer YOUR_SECRET" http://localhost:9090/v1/stats

# Select node
curl -X POST -H "Authorization: Bearer YOUR_SECRET" \
  -d '{"node": "node-us-01"}' \
  http://localhost:9090/v1/select
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     mihomo smart                         │
├─────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐  │
│  │ Inbound │  │ DNS     │  │ Rules   │  │ Smart       │  │
│  │ Listener│  │ Server  │  │ Engine  │  │ Policy      │  │
│  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬──────┘  │
│       │            │            │               │         │
│       └────────────┴─────────────┴───────────────┘         │
│                           │                                │
│                    ┌──────┴──────┐                          │
│                    │  Outbound   │                          │
│                    │  Manager    │                          │
│                    └──────┬──────┘                          │
│                           │                                │
│       ┌───────────────────┼───────────────────┐           │
│  ┌────┴────┐  ┌────┐  ┌────┴────┐  ┌─────────┐           │
│  │ VMess   │  │HTTP│  │ SOCKS5  │  │ TUIC    │           │
│  │ VLESS   │  │    │  │         │  │ Hysteria│           │
│  │ Trojan  │  │    │  │         │  │ WireGuard│           │
│  └─────────┘  └────┘  └─────────┘  └─────────┘           │
└─────────────────────────────────────────────────────────┘
```

## Development

### Requirements

- Go 1.23+
- Make

### Build

```bash
# Clone
git clone https://github.com/lukuochiang/mihomo.git
cd mihomo

# Build
make build

# Run tests
make test
```

## License

GNU General Public License v3.0 (GPL-3.0) - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) - Base project
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - Protocol implementations
