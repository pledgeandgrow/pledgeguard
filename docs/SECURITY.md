# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a vulnerability
in PledgeGuard, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue.
2. Email: **security@pledgeandgrow.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Fix Release**: Within 30 days (severity-dependent)

### Scope

- Vulnerabilities in PledgeGuard's own code
- Vulnerabilities in dependencies we ship
- False negatives (missed secrets) that could lead to exposure

### Out of Scope

- Vulnerabilities in third-party tools used alongside PledgeGuard
- Social engineering attacks
- Physical security issues

## Security Measures

PledgeGuard implements the following security measures:

- **Secret redaction** — all matched secrets are redacted in CLI output by default
- **No telemetry** — PledgeGuard does not phone home or send scan results anywhere
- **Offline capable** — all scanning works without network access (except `--verify`)
- **Sandboxed plugins** — WASM plugins run in a wasmtime sandbox
- **RBAC** — role-based access control for MCP server
- **Audit logging** — all scan and verification actions are logged
- **Dependency auditing** — `cargo audit` runs in CI

## Disclosure Policy

- We follow responsible disclosure
- Credit will be given to reporters (unless they prefer to remain anonymous)
- We request a 90-day embargo before public disclosure
