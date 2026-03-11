# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-11

### Added

- CLI with `register`, `start`, `dev`, `status`, and `unregister` commands
- Interactive registration with hidden password input
- Heartbeat goroutine (30s interval) with database health reporting
- Graceful shutdown with offline notification on SIGTERM
- SQL query validation (SELECT only, blocks system tables and dangerous functions)
- 50,000 row limit per query
- Hybrid encryption: RSA-2048-OAEP + AES-256-CBC (compatible with Python enclave)
- AWS Nitro attestation verification (COSE_Sign1, certificate chain, PCR0)
- HMAC-SHA256 request authentication with 300s replay protection
- Rathole reverse tunnel client with Noise protocol support
- Automatic tunnel reconnection with exponential backoff
- Cross-platform builds: Linux and macOS (amd64 + arm64)
- One-line installer script
- Deployment guides for self-hosted, AWS RDS, Neon/Supabase, GCP/Azure
