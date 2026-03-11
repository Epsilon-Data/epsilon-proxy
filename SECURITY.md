# Security Policy

## Reporting vulnerabilities

If you discover a security vulnerability in epsilon-proxy, please report it responsibly.

**Do not** open a public GitHub issue for security vulnerabilities.

Email **security@epsilon-data.org** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes      |

## Security model

epsilon-proxy is designed with a zero-trust architecture. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full security design including:

- Transport encryption (Noise protocol)
- Request authentication (HMAC-SHA256)
- Enclave attestation (AWS Nitro)
- SQL query validation
- Hybrid encryption (RSA-OAEP + AES-256-CBC)
- Row limits
