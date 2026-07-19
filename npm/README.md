# pledgeguard

Rust-native secret scanner with 200+ detectors, live verification, SARIF output, MCP server, enterprise features — a TruffleHog/Gitleaks alternative.

## Install

```sh
npm install -g pledgeguard
```

## Usage

```sh
# Scan the working tree
pledgeguard scan .

# Scan git commit history
pledgeguard history .

# Install a git pre-commit hook
pledgeguard install-pre-commit

# Run as MCP server for AI agents
pledgeguard mcp

# Generate compliance report (SOC2, PCI-DSS, ISO27001, HIPAA, GDPR, NIST CSF)
pledgeguard compliance --framework soc2 .

# Diff two scan reports
pledgeguard diff old-scan.json new-scan.json

# Notify a webhook (Slack, Teams, Discord)
pledgeguard notify --url https://hooks.slack.com/... --webhook-type slack .

# Multi-project scan from registry
pledgeguard multi-scan --registry projects.json

# Manage scheduled scans
pledgeguard schedule --action add --name nightly --cron "0 2 * * *" --paths ./src,./config

# Email notification for critical findings
pledgeguard email-notify --smtp-host smtp.gmail.com --from alerts@corp.com --to team@corp.com .

# Benchmark scan throughput
pledgeguard bench .
```

## Features

- **200+ secret detectors** — AWS, GitHub, Slack, Stripe, Google, npm, PEM keys, JWTs, connection strings, and more
- **Live provider verification** (`--verify`) — GitHub, Slack, Stripe, npm, and 100+ other providers
- **Git history scanning** — `git log --all -p`, added lines only, parallel mode available
- **AST-based false-positive refinement** for JS/TS (via [oxc](https://oxc.rs))
- **Baseline/allowlist mode** (`--baseline`/`--save-baseline`)
- **14 output formats** — table, JSON, SARIF 2.1.0, CSV, JUnit, GitHub Actions, HTML, Markdown, SPDX, CycloneDX, Prometheus, JSONL, XML, template
- **MCP server** for AI agent integration (`pledgeguard mcp`)
- **WASM plugin system** (`--plugin-dir`)
- **Pre-commit hook installer** (`pledgeguard install-pre-commit`)
- **Enterprise features**:
  - RBAC, audit logging, SSO (SAML/OIDC)
  - Scan scheduling with cron expressions
  - Custom severity levels and categories
  - Finding lifecycle (tags, assignments, comments, evidence)
  - Multi-project scanning with project grouping
  - Global baseline for cross-project suppression
  - Compliance reporting (SOC2, PCI-DSS, ISO27001, HIPAA, GDPR, NIST CSF)
  - Webhook notifications (Slack, Teams, Discord)
  - Email notifications with sendmail fallback
- **Performance**: memory-mapped I/O, streaming, parallel scanning, incremental cache, Aho-Corasick prefilter
- **Content decoding**: zip, tar, gzip, PDF, Word, Excel, PowerPoint, OCR, binary strings

## License

MIT
