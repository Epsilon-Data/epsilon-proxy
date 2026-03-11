# Google Cloud SQL / Azure Database

## Google Cloud SQL

Cloud SQL instances can be accessed via:
1. **Private IP** (recommended) — from a GCE VM in the same VPC
2. **Cloud SQL Auth Proxy** — Google's official proxy for secure connections
3. **Public IP** — with authorized networks

### Option A: GCE VM in Same VPC (Recommended)

```
Google Cloud VPC
┌─────────────────────────────────────────────┐
│                                             │
│  ┌─────────────┐      ┌──────────────────┐  │
│  │ Cloud SQL   │◄────│ GCE (e2-micro)   │  │
│  │ (private IP)│ 5432│ epsilon-proxy     │──┼── outbound → Epsilon
│  └─────────────┘      └──────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
```

```bash
# On the GCE instance
curl -fsSL https://get.epsilon-data.org/install.sh | sh

# Register — enter your Cloud SQL private IP, username, and password
# when prompted. Credentials stay on this VM.
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub

epsilon-proxy start
```

Cost: `e2-micro` is free tier eligible or ~$6/month.

### Option B: With Cloud SQL Auth Proxy

If you use Google's Cloud SQL Auth Proxy for authentication:

```bash
# Start Google's proxy (connects to Cloud SQL)
cloud-sql-proxy --port 5432 my-project:us-central1:my-instance &

# Register epsilon-proxy — when prompted for host, enter localhost.
# Google's proxy handles the Cloud SQL auth, epsilon-proxy handles
# the Epsilon encryption.
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub

epsilon-proxy start
```

Both proxies run on the same machine. Google's proxy handles auth,
epsilon-proxy handles encryption for Epsilon.

### Option C: Public IP

Enable "Public IP" on Cloud SQL, add your proxy's IP to "Authorized Networks":

```bash
# From any machine — credentials entered interactively
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub
```

---

## Azure Database for PostgreSQL

Azure offers two deployment modes:

### Flexible Server (Recommended)

#### Same VNET

```
Azure VNET
┌─────────────────────────────────────────────┐
│                                             │
│  ┌─────────────┐      ┌──────────────────┐  │
│  │ Flexible    │◄────│ Azure VM         │  │
│  │ Server      │ 5432│ (B1s)            │  │
│  │ (private)   │      │ epsilon-proxy    │──┼── outbound → Epsilon
│  └─────────────┘      └──────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
```

```bash
# On the Azure VM
curl -fsSL https://get.epsilon-data.org/install.sh | sh

# Register — enter your Azure DB hostname, username, and password
# when prompted. Credentials stay on this VM.
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub

epsilon-proxy start
```

Cost: Azure B1s is ~$7/month.

#### Public Access

If "Allow public access" is enabled on the Flexible Server:

```bash
# Add your proxy's IP to the firewall rules in Azure Portal
# Then from any machine — credentials entered interactively:
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub
```

### Azure-Specific Notes

- Azure enforces SSL by default (`sslmode=require`).
- Azure AD authentication: create a PostgreSQL user for the proxy
  with standard password auth. AAD tokens expire and would require
  a refresh mechanism (planned feature).

---

## Network Requirements (Both Providers)

| Direction | Port | Purpose |
|-----------|------|---------|
| VM → DB | TCP 5432 | Database connection |
| VM → Internet | TCP 7000 | rathole tunnel to Epsilon |
| VM → Internet | TCP 443 | Epsilon API |

No inbound ports need to be opened.
