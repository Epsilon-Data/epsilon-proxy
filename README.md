# epsilon-proxy

Secure data proxy for the [Epsilon Trusted Research Environment](https://epsilon-data.org). Encryption happens at the data source — your credentials and raw data never leave your network.

## How it works

```
Your Network                              Epsilon Infrastructure
┌──────────────────────────┐             ┌────────────────────────┐
│  ┌──────────┐            │             │                        │
│  │ Database │◄───┐       │  outbound   │  ┌──────────────────┐  │
│  └──────────┘    │       │  tunnel     │  │ Nitro Enclave    │  │
│                  │       │  (noise)    │  │ (computation)    │  │
│  ┌───────────────┴────┐  ├────────────►│  └──────────────────┘  │
│  │  epsilon-proxy     │  │             │                        │
│  │  - SQL validation  │  │             │  Your data is only     │
│  │  - Attestation     │  │             │  decrypted inside the  │
│  │  - Encryption      │  │             │  enclave. Platform     │
│  │  - Tunnel client   │  │             │  operators cannot      │
│  │  - Schema crawler  │  │             │  access it.            │
│  └────────────────────┘  │             └────────────────────────┘
└──────────────────────────┘
```

**Key guarantees:**
- Database credentials stored locally only — never sent to the platform
- SQL queries validated (SELECT only, no system tables, no dangerous functions)
- Results encrypted with the enclave's RSA public key before leaving your machine
- Enclave identity verified via AWS Nitro attestation (COSE_Sign1 + PCR0)
- Tunnel encrypted with Noise protocol (X25519 + ChaCha20-Poly1305)
- Schema metadata crawled locally and uploaded to the platform (no raw data)

## Installation

```bash
curl -fsSL https://get.epsilon-data.org/install.sh | sh
```

Or download from [GitHub Releases](https://github.com/Epsilon-Data/epsilon-proxy/releases).

### Build from source

```bash
git clone https://github.com/Epsilon-Data/epsilon-proxy.git
cd epsilon-proxy
make build
```

Requires Go 1.23+. The binary version is set automatically from the latest git tag.

## Quick start

### 1. Register

Get an install token from your Epsilon platform dashboard (Settings → Proxy), then:

```bash
epsilon-proxy register --token ept_your_token_here
```

The API URL defaults to `https://app.epsilon-data.org/api/v1/hub`. For self-hosted deployments, override with `--api-url`.

You'll be prompted for database credentials interactively. These are stored locally at `~/.epsilon-proxy/config.yaml` (mode 0600) and **never transmitted** to the platform.

### 2. Start

```bash
epsilon-proxy start
```

The proxy:
1. Connects to the platform via an encrypted reverse tunnel
2. Sends heartbeats every 30 seconds (reports database reachability)
3. Automatically crawls the database schema when the platform requests it
4. Uploads schema metadata (table/column names, ERD) — **never raw data**

Press `Ctrl+C` for graceful shutdown (sends offline notification).

### 3. Check status

```bash
epsilon-proxy status
```

## Commands

| Command | Description |
|---------|-------------|
| `register` | Register with the Epsilon platform and configure database |
| `start` | Start the proxy server, tunnel, and heartbeat |
| `dev` | Development mode (no tunnel, no attestation, no HMAC) |
| `status` | Show current proxy configuration |
| `unregister` | Remove proxy registration and local config |

### Register flags

| Flag | Default | Description |
|------|---------|-------------|
| `--token` | *(required)* | Install token from the Epsilon platform |
| `--api-url` | `https://app.epsilon-data.org/api/v1/hub` | Platform API URL (for self-hosted deployments) |

## Security model

epsilon-proxy implements six layers of security:

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **Transport** | Noise protocol (X25519 + ChaCha20-Poly1305) | Encrypt tunnel traffic |
| **Authentication** | HMAC-SHA256 with timestamp | Verify request origin, prevent replay |
| **Attestation** | AWS Nitro (COSE_Sign1 + PCR0) | Verify enclave identity |
| **Query validation** | SQL parser + blocklist | Prevent data exfiltration |
| **Encryption** | RSA-2048-OAEP + AES-256-CBC | Encrypt results for enclave only |
| **Row limits** | 50,000 row maximum | Prevent bulk extraction |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full security design.

## Heartbeat & Auto-Crawl

When running, the proxy sends a heartbeat to the platform every 30 seconds. The heartbeat reports:
- Database reachability status
- Proxy version

The platform may respond with an **action**:
- `crawl` — the proxy should crawl the database schema and upload metadata

This enables fully automated onboarding: create a PROXY project in the platform, register and start the proxy, and the schema is crawled automatically without any manual intervention. If a crawl fails, the platform can signal a re-crawl on the next heartbeat.

## Development

```bash
# Run in dev mode (no tunnel, no attestation)
export EPSILON_DB_URL="postgres://user:pass@localhost:5432/mydb"
epsilon-proxy dev

# Run tests
make test

# Lint
make lint
```

## Configuration

Config is stored at `~/.epsilon-proxy/config.yaml` (created during registration):

```yaml
proxy_id: px-abc123
platform_url: https://app.epsilon-data.org/api/v1/hub
proxy_token: pt_xxx
rathole:
  server_addr: "1.2.3.4:7000"
  token: rt_xxx
  service_name: proxy-px-abc123
  remote_public_key: base64...
database:
  url: postgres://user:pass@localhost:5432/mydb
  ssl_mode: require
  max_connections: 5
  query_timeout_s: 120
server:
  listen_addr: 127.0.0.1:8443
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/). The version is embedded at build time via Go ldflags:

```bash
# Automatic (from git tags)
make build

# Manual override
make build VERSION=0.2.0
```

The version is reported in:
- `epsilon-proxy --version`
- Registration request to the platform
- Heartbeat payloads
- `GET /health` endpoint

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Deployment guides

- [Self-hosted PostgreSQL](docs/deployment/self-hosted.md)
- [AWS RDS](docs/deployment/aws-rds.md)
- [Neon / Supabase](docs/deployment/neon-supabase.md)
- [GCP Cloud SQL / Azure](docs/deployment/gcp-azure.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE).
