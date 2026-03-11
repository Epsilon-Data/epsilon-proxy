# Self-Hosted Database

Your database runs on your own server (on-premise, VPS, bare metal).
This is the simplest setup — install epsilon-proxy on the same machine or anywhere on the same network.

## Prerequisites

- Linux or macOS machine with network access to your database
- PostgreSQL 12+
- Database credentials (username, password, host, port, database name)

## Option A: Same Machine as Database

Install and run epsilon-proxy directly on the database server.

```bash
# Download
curl -fsSL https://get.epsilon-data.org/install.sh | sh

# Register (token from Epsilon platform)
# You will be prompted for database credentials interactively.
# Credentials are stored locally only — never sent to Epsilon.
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub

# Start
epsilon-proxy start
```

The interactive prompt will ask for host, port, database name, username,
and password (password input is hidden). Since the database is on `localhost`,
you can set SSL mode to `disable`.

## Option B: Separate Machine on Same Network

Run epsilon-proxy on a different server that can reach your database over the LAN.

```bash
# Register — enter your DB host (e.g., 192.168.1.50) when prompted
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub
```

Ensure the database allows connections from the proxy machine's IP
(check `pg_hba.conf` or your firewall rules).

## Option C: Docker

For Docker, pass credentials via `EPSILON_DB_URL` environment variable.
This is safe because Docker env vars are not exposed in shell history
or process listings on the host.

```bash
docker run -d \
  --name epsilon-proxy \
  --restart=always \
  -e TOKEN=ept_your_token_here \
  -e API_URL=https://app.epsilon-data.org/api/v1/hub \
  -e EPSILON_DB_URL="postgres://user:password@host.docker.internal:5432/mydb" \
  ghcr.io/epsilon-data/epsilon-proxy
```

Use `host.docker.internal` (macOS/Windows) or `--network=host` (Linux)
to reach a database on the Docker host.

## Production Setup

For long-running production use, run as a systemd service:

```ini
# /etc/systemd/system/epsilon-proxy.service
[Unit]
Description=Epsilon Secure Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=epsilon-proxy
ExecStart=/usr/local/bin/epsilon-proxy start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin epsilon-proxy
sudo systemctl enable --now epsilon-proxy
```

## Network Requirements

| Direction | Port | Purpose |
|-----------|------|---------|
| Outbound | TCP 7000 | rathole tunnel to Epsilon relay server |
| Outbound | TCP 443 | HTTPS to Epsilon API (registration, heartbeat) |
| Local | TCP 8443 | Proxy HTTP server (localhost only, not exposed) |
| Local | TCP 5432 | PostgreSQL connection |

No inbound ports need to be opened.

## Verification

```bash
# Check proxy status
epsilon-proxy status

# Check health endpoint
curl http://localhost:8443/health
```

Expected:
```json
{
  "status": "healthy",
  "tunnel_connected": true,
  "database_reachable": true
}
```
