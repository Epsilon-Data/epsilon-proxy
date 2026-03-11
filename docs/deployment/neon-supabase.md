# Neon / Supabase / PlanetScale (Serverless Databases)

Serverless databases expose a public connection string — there's no VPC to join.
Epsilon-proxy runs anywhere you want and connects over the internet with SSL.

## Architecture

```
Data owner's machine (anywhere)
┌─────────────────────┐          ┌──────────────┐
│ epsilon-proxy        │──SSL───►│ Neon DB       │
│                     │ internet │ (cloud)       │
└────────┬────────────┘          └──────────────┘
         │ rathole tunnel (outbound)
         ▼
   Epsilon Infrastructure
```

## Where to Run the Proxy

Pick any of these — all work:

| Option | Best For |
|--------|----------|
| Your laptop/workstation | Quick testing, demos |
| A small VPS ($5/mo) | Always-on production |
| Docker on any server | Containerized deployments |
| University server | Institutional setups |

The only requirement: outbound internet access to reach Neon/Supabase and
the Epsilon relay server.

## Neon

### Get Your Connection String

From the Neon dashboard → your project → Connection Details. Keep it handy —
you'll paste it when the proxy prompts you.

### Install and Register

```bash
curl -fsSL https://get.epsilon-data.org/install.sh | sh

# Register — you will be prompted for your Neon connection details.
# Choose "Full URL" and paste your Neon connection string.
# Credentials are stored locally only.
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub

epsilon-proxy start
```

### Neon-Specific Notes

- **Connection pooling:** Neon uses PgBouncer. The proxy works fine with pooled connections.
  If you see timeout issues, use the direct (non-pooled) connection string instead.
  - Pooled: `ep-cool-rain-123456.us-east-2.aws.neon.tech` (port 5432)
  - Direct: `ep-cool-rain-123456.us-east-2.aws.neon.tech` (port 5432, append `?options=project%3Dep-cool-rain-123456`)
- **Serverless auto-suspend:** Neon databases suspend after inactivity. The first query
  after suspension may take 1-3 seconds to wake up. The proxy's query timeout (120s default)
  handles this gracefully.
- **SSL required:** Neon enforces SSL. Always use `sslmode=require`.

## Supabase

### Get Your Connection String

From Supabase dashboard → Settings → Database → Connection string → URI.

For direct connections (recommended for epsilon-proxy), use port 5432 (not the pooler on 6543).

### Install and Register

```bash
curl -fsSL https://get.epsilon-data.org/install.sh | sh

# Register — paste your Supabase direct connection string when prompted.
epsilon-proxy register \
  --token ept_your_token_here \
  --api-url https://app.epsilon-data.org/api/v1/hub

epsilon-proxy start
```

### Supabase-Specific Notes

- **Use direct connection**, not the pooler (port 5432, not 6543).
  The pooler uses PgBouncer in transaction mode which can interfere with
  statement-level timeouts.
- **Row Level Security (RLS):** If your tables have RLS enabled, the proxy connects
  as the `postgres` role which bypasses RLS. If you want RLS enforced, create a
  dedicated role for epsilon-proxy and grant it specific permissions.

## PlanetScale (MySQL)

PlanetScale uses MySQL, not PostgreSQL. Epsilon-proxy currently supports
PostgreSQL only. MySQL support is planned.

## Docker (Any Serverless DB)

For Docker, pass credentials via `EPSILON_DB_URL` environment variable.
This is safe because Docker env vars are not exposed in shell history
or process listings on the host.

```bash
docker run -d \
  --name epsilon-proxy \
  --restart=always \
  -e TOKEN=ept_your_token_here \
  -e API_URL=https://app.epsilon-data.org/api/v1/hub \
  -e EPSILON_DB_URL="postgres://user:pass@your-cloud-db-host:5432/mydb?sslmode=require" \
  ghcr.io/epsilon-data/epsilon-proxy
```

## Security Considerations

Even though credentials travel over the internet to reach the cloud DB,
this is the same trust model the data owner already has — they access
Neon/Supabase over SSL from their own applications.

The key difference with epsilon-proxy:
- **Without proxy:** Credentials stored in Epsilon's Vault, Lambda sees raw data
- **With proxy:** Credentials stored locally on your machine, data encrypted
  before it leaves your machine

The weakest link is the SSL connection to the cloud DB — same as any application
connecting to Neon/Supabase.

## When to Use Cloud Connect Instead

If you:
- Don't have a machine to run the proxy on
- Don't want to maintain any infrastructure
- Are comfortable with credentials in Vault

Then use **Cloud Connect** (the default mode in Epsilon). Your credentials
are stored encrypted in HashiCorp Vault, and data is encrypted by the middleware
before reaching the enclave.

Secure Proxy is strictly better from a security standpoint, but Cloud Connect
is simpler if infrastructure is a constraint.
