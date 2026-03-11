# Epsilon-Proxy Architecture

## Overview

Epsilon-proxy is a Go binary that data owners install next to their database. It moves encryption to the data source — the proxy queries the local DB, validates the SQL query, verifies the enclave's attestation, encrypts results with the enclave's public key, and sends encrypted data back through a rathole reverse tunnel. The coordinator, middleware, and platform never see plaintext data or credentials.

## System Architecture

```
Data Owner's Network                          Epsilon Infrastructure
┌────────────────────────────────┐           ┌──────────────────────────────────────────┐
│                                │           │  EC2#A (always on)                       │
│  ┌──────────┐                  │           │  ┌─────────────────────┐                 │
│  │ User's DB│◄──────────┐      │           │  │ rathole server      │                 │
│  │ Postgres │           │      │           │  │ :7000 (control)     │                 │
│  └──────────┘           │      │           │  │                     │                 │
│                         │      │           │  │ :10000 (proxy-001)  │──┐              │
│  ┌──────────────────────┴───┐  │  outbound │  │ :10001 (proxy-002)  │  │              │
│  │  epsilon-proxy            ├──┼──────────┼──► :10002 (proxy-003)  │  │              │
│  │                           │  │  noise   │  └─────────────────────┘  │              │
│  │  ┌─ rathole client        │  │  tunnel  │                           │ SG: EC2#B    │
│  │  ├─ SQL validator         │  │          │  ┌────────────────────────┘  only        │
│  │  ├─ attestation verifier  │  │          │  │                                       │
│  │  ├─ DB connector          │  │          │  │  EC2#B (on-demand)                    │
│  │  ├─ hybrid encryptor      │  │          │  │  ┌─────────────────┐                  │
│  │  └─ HMAC auth             │  │          │  │  │ Coordinator     │                  │
│  └───────────────────────────┘  │          │  └──► POST /query     │                  │
│                                │           │     │ via :10000      │                  │
│  Config (local only):          │           │     └────────┬────────┘                  │
│  - db credentials              │           │              │ vsock :5005               │
│  - proxy_token                 │           │     ┌────────┴────────┐                  │
│  - noise public key            │           │     │ Enclave         │                  │
│                                │           │     │ (decrypts +     │                  │
│  No inbound ports needed.      │           │     │  executes)      │                  │
└────────────────────────────────┘           │     └─────────────────┘                  │
                                             └──────────────────────────────────────────┘
```

## Data Flow — Query Execution

```
Coordinator          Middleware         Proxy (via rathole)      Enclave
    │                    │                    │                      │
    │ 1. generate_rsa_keypair (vsock)         │                      │
    │───────────────────────────────────────────────────────────────►│
    │◄──────────────────────────────── (public_key, session_id) ────│
    │                    │                    │                      │
    │ 2. POST /fetch-csv │                    │                      │
    │    mode=proxy       │                    │                      │
    │───────────────────►│                    │                      │
    │  { sql_query,      │                    │                      │
    │    proxy_id }      │                    │                      │
    │◄───────────────────│                    │                      │
    │                    │                    │                      │
    │ 3. get_attestation_for_proxy (vsock)    │                      │
    │───────────────────────────────────────────────────────────────►│
    │◄──────────────────────────── (attestation_doc) ───────────────│
    │                    │                    │                      │
    │ 4. POST /query  (via EC2#A:10000 → tunnel → proxy:8443)      │
    │    + X-Signature header (HMAC-SHA256)   │                      │
    │────────────────────────────────────────►│                      │
    │                    │                    │ 5. Verify HMAC       │
    │                    │                    │ 6. Validate SQL      │
    │                    │                    │ 7. Verify attestation│
    │                    │                    │ 8. Query local DB    │
    │                    │                    │ 9. Encrypt results   │
    │◄──────────────────────── { encrypted_csv } ──────────────────│
    │                    │                    │                      │
    │ 10. execute_script_rsa_hybrid (vsock)   │                      │
    │    encrypted_zip + encrypted_csv        │                      │
    │───────────────────────────────────────────────────────────────►│
    │◄──────────────── { output, attestation } ─────────────────────│
```

## What Each Component Sees

| Component | Sees SQL? | Sees Raw Data? | Sees Credentials? | Sees Ciphertext? |
|-----------|-----------|----------------|-------------------|-----------------|
| Middleware | Yes | No | No | No |
| Coordinator | Yes | No | No | Yes (passes through) |
| rathole tunnel | No | No | No | Yes (encrypted bytes) |
| Proxy | Yes | Yes (encrypts immediately) | Yes (local only) | Yes (produces it) |
| Enclave | Yes | Yes (decrypts) | No | Yes (receives it) |

## Security Layers

### Layer 1: Network Isolation

```
Internet ──► :7000 (control channel)     ← proxies connect from anywhere
EC2#B   ──► :10000-10099 (data ports)    ← ONLY coordinator, Security Group enforced
```

- Port 7000: open to internet (data owners' proxies connect outbound)
- Port 10000-10099: locked to EC2#B private IP via AWS Security Group
- Proxy listens on `127.0.0.1:8443` only — never exposed to network
- Data owner needs zero inbound ports open

### Layer 2: Tunnel Encryption (Noise Protocol)

```
rathole transport: Noise_NK_25519_ChaChaPoly_BLAKE2s
  - X25519 key exchange
  - ChaCha20-Poly1305 symmetric encryption
  - BLAKE2s hashing
  - Server authenticated via static public key
  - Client authenticated via application-layer token
```

Server config:
```toml
[server]
bind_addr = "0.0.0.0:7000"

[server.transport]
type = "noise"

[server.transport.noise]
local_private_key = "<generated_private_key>"

[server.services.proxy-001]
token = "<unique_per_proxy>"
bind_addr = "0.0.0.0:10000"
```

Client config (auto-generated by epsilon-proxy):
```toml
[client]
remote_addr = "<ec2a_ip>:7000"

[client.transport]
type = "noise"

[client.transport.noise]
remote_public_key = "<server_public_key>"

[client.services.proxy-001]
token = "<unique_per_proxy>"
local_addr = "127.0.0.1:8443"
```

### Layer 3: Request Authentication (HMAC-SHA256)

```
signature = HMAC-SHA256(key=proxy_token, message=request_id+session_id+timestamp)
Header: X-Signature: <hex_encoded_signature>
```

- Replay protection: reject if |now - timestamp| > 300s
- Per-proxy unique token
- Coordinator computes signature using token from platform API

### Layer 4: SQL Query Validation

The proxy validates every query before execution:

```
✓ Allowed: SELECT, WITH (CTEs)
✗ Blocked: INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, CREATE, GRANT, REVOKE, COPY
✗ Blocked: information_schema, pg_catalog, pg_* system tables
✗ Blocked: pg_sleep, dblink, pg_read_file, pg_ls_dir (dangerous functions)
✗ Blocked: Multiple statements (semicolon injection)
✗ Blocked: Results exceeding 50,000 rows (DoS protection)
```

All queries execute in a read-only transaction as an additional safety net.

### Layer 5: Attestation Verification

The proxy verifies the enclave's identity before trusting its public key:

1. Base64 decode attestation_doc
2. CBOR decode → COSE_Sign1 structure
3. Extract certificate chain (cabundle + leaf cert)
4. Verify chain against AWS Nitro Root G1 cert (embedded in binary)
5. Verify COSE_Sign1 signature with leaf cert
6. Extract PCR0 (48 bytes SHA-384) → compare against configured value
7. Extract public_key from user_data → verify matches provided key
8. All pass → encrypt with this key. Any fail → reject request.

### Layer 6: Payload Encryption (RSA-2048-OAEP + AES-256-CBC)

```
Encrypt(plaintext, enclave_public_key):
  1. aes_key = random(32 bytes)              // AES-256
  2. iv = random(16 bytes)                   // CBC IV
  3. ciphertext = AES-256-CBC(plaintext, aes_key, iv, PKCS7)
  4. encrypted_key = RSA-OAEP(aes_key, enclave_public_key, SHA-256, MGF1-SHA256)
  5. combined = encrypted_key (256 bytes) || iv (16 bytes) || ciphertext
  6. return base64(combined)
```

Byte layout:
```
Offset 0              256             272              N
  ┌───────────────────┬────────────────┬────────────────┐
  │ RSA-encrypted key │       IV       │   AES cipher   │
  │    (256 bytes)    │   (16 bytes)   │   (variable)   │
  └───────────────────┴────────────────┴────────────────┘
  └─────────────────── base64 encoded ──────────────────┘
```

Only the enclave has the private key to decrypt. Cross-language compatible (Go encrypt ↔ Python decrypt verified).

## Security Summary

| Property | How |
|----------|-----|
| Platform can't read data | Proxy encrypts with enclave's public key before data leaves data owner's network |
| Coordinator can't read data | Only passes ciphertext, doesn't have private key |
| Credentials stay local | Stored in proxy config, never sent to platform |
| MITM protection | Proxy verifies Nitro attestation before trusting public key |
| Replay protection | HMAC + timestamp window (300s) |
| Tunnel encryption | Noise protocol (ChaCha20-Poly1305 + X25519) |
| Payload encryption | RSA-2048-OAEP + AES-256-CBC (application layer) |
| Forward secrecy | Fresh RSA keypair per enclave session |
| SQL injection blocked | Query validator rejects non-SELECT, system tables, dangerous functions |
| DoS protection | 50k row limit, query timeout, read-only transactions |
| Network isolation | Tunnel ports locked to coordinator via AWS Security Group |
| No inbound ports | Data owner's proxy connects outbound only |

## API Endpoints

### POST /query

Request:
```json
{
  "request_id": "req_abc123",
  "session_id": "rsa-session-def456",
  "sql_query": "SELECT p.age AS \"Age\" FROM public.patient AS p LIMIT 100000",
  "enclave_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBI...",
  "attestation_document": "base64_cbor...",
  "timestamp": 1741612800
}
Header: X-Signature: hmac_sha256(proxy_token, request_id+session_id+timestamp)
```

Response (success):
```json
{
  "success": true,
  "encrypted_csv": "base64(rsa_encrypted_key + iv + aes_ciphertext)",
  "metadata": {
    "row_count": 1523,
    "column_count": 7,
    "encrypted_size_bytes": 48210,
    "query_duration_ms": 245,
    "encryption_duration_ms": 12
  }
}
```

Response (error):
```json
{
  "success": false,
  "error": "ATTESTATION_INVALID | PCR_MISMATCH | SIGNATURE_INVALID | QUERY_BLOCKED | DATABASE_UNREACHABLE | QUERY_FAILED | QUERY_TIMEOUT | ENCRYPTION_FAILED",
  "message": "human readable"
}
```

### GET /health

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "tunnel_connected": true,
  "database_reachable": true,
  "uptime_seconds": 84210
}
```

## Registration Flow

```
$ epsilon-proxy register --token ept_a1b2c3d4 --api-url https://app.epsilon-data.org/api/v1/hub

Database credentials (stored locally only, never sent to Epsilon)
─────────────────────────────────────────────────────────────────

Enter connection details:
  [1] Full URL  (postgres://user:pass@host:port/dbname)
  [2] Field-by-field
> 2

Host [localhost]: localhost
Port [5432]: 5432
Database name: clinical_data
Username: admin
Password: ********
SSL mode [require]: disable

Testing database connection... OK
Registering with Epsilon platform... OK

Proxy ID:     px_a1b2c3d4
Config saved: ~/.epsilon-proxy/config.yaml
Credentials stored LOCALLY ONLY — they never leave this machine.

Run 'epsilon-proxy start' to connect.
```

## Config File (~/.epsilon-proxy/config.yaml)

```yaml
proxy_id: "px_a1b2c3d4"
dataset_id: "2a45cf39-85f5-4949-a6fd-0f85d334dc05"
platform_url: "https://app.epsilon-data.org"
proxy_token: "ept_xxxxxxxxxxxx"
rathole:
  server_addr: "relay.epsilon-data.org:7000"
  token: "rt_xxxxxxxxxxxx"
  service_name: "proxy-px_a1b2c3d4"
  remote_public_key: "xrpknQcAagcd/b9foMwxSCD+..."
database:
  url: "postgres://user:pass@localhost:5432/mydb"
  ssl_mode: "require"
  max_connections: 5
  query_timeout_s: 120
server:
  listen_addr: "127.0.0.1:8443"
attestation:
  expected_pcr0: "hex_encoded_48_bytes..."
```

## Production Flow (Automated)

```
Data Owner                      Platform API                    EC2#A (Rathole)
─────────                       ────────────                    ───────────────
1. Install proxy
   curl | sh

2. epsilon-proxy register
   --token <from UI>
        ──────────────────→  3. Validate token
                                Generate unique:
                                - proxy_id
                                - rathole_token
                                - noise keypair
                                - port assignment
                             4. Update rathole
                                server.toml (add service)
                                  ──────────────────────→  5. Hot-reload config
                                                              (rathole watches file)
                          ←──  6. Return to proxy:
                                - rathole_token
                                - noise_public_key
                                - server_addr
                                - service_name

7. Proxy saves config locally
   Prompts for DB credentials
   (never sent to platform)

8. epsilon-proxy start
   → tunnel connects automatically
   → heartbeat starts
                                                           9. Coordinator can now
                                                              reach proxy via tunnel

Port allocation (auto-assigned):
  proxy-001 → :10000
  proxy-002 → :10001
  proxy-003 → :10002
  ...
```

## Verified E2E Test Results

Tested 2026-03-10: MacBook (proxy + Postgres) ↔ rathole tunnel ↔ EC2#A (Sydney):

```
EC2#A $ python3 e2e-tunnel-test.py
1. Generating RSA-2048 keypair... OK
2. Health check via tunnel... OK
3. Sending query: SELECT * FROM patient LIMIT 5
   OK - Rows: 5 | Cols: 6 | Encrypted: 896B
4. Decrypting... OK

=== Decrypted CSV ===
patient_id,age,medications,admission_date,diagnosis,critical
1,67,"{Lisinopril,Atorvastatin}",2024-01-15T09:15:00Z,Hypertension,false
...

=== EC2 → TUNNEL → MacBook E2E PASSED ===
```

Flow verified: EC2#A:10000 → rathole tunnel → MacBook:8443 → proxy → Postgres → encrypt → ciphertext back through tunnel → EC2#A decrypts with private key.

## Implementation Phases

| Phase | Component | Status |
|-------|-----------|--------|
| 0 | rathole infra (EC2#A) | **Done** — systemd service running |
| 2 | epsilon-proxy (Go binary) | **Done** — all core features |
| — | Hybrid encryption (Go ↔ Python compatible) | **Done** — cross-language verified |
| — | SQL query validation | **Done** — SELECT only, system tables blocked |
| — | Noise protocol support | **Done** — config ready, needs key generation |
| — | E2E tunnel test | **Done** — MacBook ↔ EC2#A verified |
| 1 | Platform API (proxy register/heartbeat) | Not started |
| 3 | Enclave (get_attestation_for_proxy) | Not started |
| 4 | Middleware (mode=proxy) | Not started |
| 5 | Coordinator (ProxyClient + flow) | Not started |
| 6 | Frontend (Trust Center proxy UX) | Not started |
| 7 | Heartbeat + online/offline detection | Not started |

## Project Structure

```
epsilon-proxy/
├── cmd/proxy/main.go              # CLI (register, start, dev, status, unregister)
├── internal/
│   ├── config/config.go           # YAML config management
│   ├── crypto/
│   │   ├── hybrid.go              # RSA-OAEP + AES-256-CBC encryption
│   │   ├── hybrid_test.go         # Roundtrip + byte layout tests
│   │   ├── attestation.go         # AWS Nitro attestation verification
│   │   ├── hmac.go                # HMAC-SHA256 request signing
│   │   └── hmac_test.go           # Signature verification tests
│   ├── db/
│   │   ├── postgres.go            # Read-only query execution, CSV output
│   │   ├── validate.go            # SQL query validation + row limits
│   │   └── validate_test.go       # Allowed/blocked query tests
│   ├── server/server.go           # HTTP server (/query, /health)
│   ├── tunnel/rathole.go          # rathole client subprocess + noise config
│   └── registration/register.go   # Interactive registration + DB credential prompt
├── scripts/
│   ├── install.sh                 # curl | sh installer
│   ├── e2e-test/main.go           # Direct e2e test
│   ├── e2e-test-tunnel/main.go    # Tunnel e2e test
│   ├── cross-language-test.py     # Go↔Python crypto verification
│   └── generate-test-vectors/     # Crypto test vector generator
├── docs/deployment/
│   ├── self-hosted.md             # On-premise / VPS guide
│   ├── aws-rds.md                 # AWS RDS guide
│   ├── neon-supabase.md           # Serverless DB guide
│   └── gcp-azure.md              # GCP / Azure guide
├── .github/workflows/release.yml  # CI: test + goreleaser
├── .goreleaser.yaml               # Cross-platform binary releases
├── Dockerfile                     # Multi-stage build with rathole
└── Makefile                       # build, test, install targets
```
