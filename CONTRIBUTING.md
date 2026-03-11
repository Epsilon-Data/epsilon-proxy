# Contributing to epsilon-proxy

Thank you for your interest in contributing to epsilon-proxy.

## Getting started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/epsilon-proxy.git`
3. Create a branch: `git checkout -b feat/your-feature`
4. Make your changes
5. Run tests: `make test`
6. Commit and push
7. Open a pull request

## Development setup

**Requirements:**
- Go 1.23+
- PostgreSQL (for integration tests)
- [golangci-lint](https://golangci-lint.run/) (for linting)

```bash
# Build
make build

# Run tests with race detector
make test

# Lint
make lint

# Dev mode (no tunnel/attestation)
export EPSILON_DB_URL="postgres://user:pass@localhost:5432/testdb"
epsilon-proxy dev
```

## Code standards

- Follow standard Go conventions (`gofmt`, `go vet`)
- All exported functions must have doc comments
- New features should include tests
- Security-sensitive code requires review from maintainers

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add heartbeat goroutine
fix: handle nil attestation response
docs: update deployment guide for RDS
test: add SQL validation edge cases
```

## Security

If you discover a security vulnerability, **do not** open a public issue. Instead, email security@epsilon-data.org. See [SECURITY.md](SECURITY.md) for details.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
