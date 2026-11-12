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
- Results encrypted and authenticated with AES-256-GCM, key wrapped with the enclave's RSA-2048-OAEP public key — only the enclave can decrypt
- Enclave identity verified via AWS Nitro attestation (COSE_Sign1 + PCR0). The proxy releases data to one enclave image only: it does not start, and does not serve, without the expected PCR0
- An attestation document is accepted once, and only within five minutes of its signed time
- Every release is written to a log on your machine before the data is returned
- Tunnel encrypted with Noise protocol (X25519 + ChaCha20-Poly1305)
- Schema metadata crawled locally and uploaded to the platform (no raw data)

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Epsilon-Data/epsilon-proxy/main/scripts/install.sh | sh
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
epsilon-proxy register --token ept_your_token_here --expected-pcr0 <PCR0_OF_THE_ENCLAVE_IMAGE>
```

`--expected-pcr0` is the measurement (PCR0, 96 hex characters) of the enclave image you agree to release data to. Take it from the PCR registry published with the enclave release you reviewed ([`published/pcr-registry.json`](https://github.com/Epsilon-Data/epsilon-enclave/tree/main/published) in `epsilon-enclave`), not from the platform operator: it is your check on what code receives your data. The proxy refuses every request from any other image.

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
| `--expected-pcr0` | *(required)* | PCR0 of the enclave image to release data to (96 hex characters) |

## Heartbeat & Auto-Crawl

When running, the proxy sends a heartbeat to the platform every 30 seconds. The heartbeat reports:
- Database reachability status
- Tunnel connection status
- Proxy version and uptime

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
attestation:
  expected_pcr0: 96-hex-character PCR0 of the enclave image
  max_age_s: 300
release_log_path: /home/you/.epsilon-proxy/releases.log
```

`epsilon-proxy start` exits with an error when `attestation.expected_pcr0` is missing or is not a full PCR0, or when the release log cannot be written. When a new enclave version is released, review it and set `expected_pcr0` to its published PCR0, then restart the proxy.

## Release log

The proxy appends one JSON line to `release_log_path` for every extract it releases, and syncs it to disk before the encrypted data is returned. If the line cannot be written, nothing is released.

```json
{"time":"2026-11-12T09:30:00.123456Z","request_id":"req-7","session_id":"rsa-session-0a1b2c3d","attested":true,"pcr0":"<96 hex>","module_id":"i-0abc-enc0123","sql_query":"SELECT age, sex FROM patients","row_count":2,"column_count":2,"extract_sha256":"<64 hex>"}
```

`extract_sha256` is the SHA-256 of the plaintext CSV that was encrypted for the enclave. The enclave signs the same digest as `dataset_hash` in its record of the run, so you can check what any run was given against this file. The log is yours: `register` and `unregister` do not delete it.

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

MIT License — see [LICENSE](LICENSE).
