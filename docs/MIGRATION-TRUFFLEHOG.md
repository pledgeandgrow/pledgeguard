# Migration Guide: TruffleHog → PledgeGuard

## Quick Mapping

| TruffleHog | PledgeGuard |
|---|---|
| `trufflehog filesystem .` | `pledgeguard scan .` |
| `trufflehog git file://.` | `pledgeguard history .` |
| `trufflehog --json` | `pledgeguard scan . --format json` |
| `trufflehog --results=sonar` | `pledgeguard scan . --format sarif` |
| `trufflehog --no-update` | (default — no auto-update) |
| `trufflehog --no-verification` | (default — use `--verify` to enable) |
| `trufflehog --only-verified` | `pledgeguard scan . --only-verified` |
| `trufflehog --exclude-paths=.git` | `pledgeguard scan . --ignore-path .git` |
| `trufflehog --exclude-detectors=aws` | `pledgeguard scan . --no-verify-detector aws` |
| `trufflehog s3` | `pledgeguard scan-source s3 --bucket my-bucket` |
| `trufflehog github` | `pledgeguard scan-source github --repo owner/repo` |

## Config File Migration

TruffleHog doesn't use a config file — it relies on built-in detectors.
PledgeGuard supports both built-in detectors AND custom TOML rules.

### Adding a custom rule in PledgeGuard

```toml
# .pledgeguard.toml
[[rules]]
id = "my-custom-token"
description = "My Custom API Token"
severity = "high"
regex = 'my_token_[a-zA-Z0-9]{32}'

[allowlist]
paths = ["test/fixtures/*", "vendor/*"]
```

```bash
pledgeguard scan . --config .pledgeguard.toml
```

## Feature Parity

| Feature | TruffleHog | PledgeGuard |
|---|:---:|:---:|
| Working tree scan | ✅ | ✅ |
| Git history scan | ✅ | ✅ |
| Live verification | ✅ (800+) | ✅ (191 rule IDs) |
| Custom detectors | ✅ | ✅ (TOML + WASM) |
| Allowlist | ✅ | ✅ |
| SARIF output | ✅ | ✅ |
| JSON output | ✅ | ✅ |
| GitHub Actions | ✅ | ✅ |
| S3/GCS/Azure scanning | ✅ | ✅ |
| Docker image scanning | ✅ | ✅ |
| Pre-commit hook | ❌ | ✅ |
| MCP server | ❌ | ✅ |
| AI integration | ❌ | ✅ |
| Compliance reports | ❌ | ✅ |
| Scan diffing | ❌ | ✅ |
| Webhook notifications | ❌ | ✅ |
| npm/npx | ❌ | ✅ |
| Offline | ✅ | ✅ |
| Rust-native | ❌ | ✅ |

## GitHub Action Migration

### Before (TruffleHog)
```yaml
- uses: trufflesecurity/trufflehog@main
  with:
    path: .
    extra_args: --json --results=sonar
```

### After (PledgeGuard)
```yaml
- uses: pledgeandgrow/pledgeguard@v0.1.1
  with:
    path: .
    format: github-actions
    min-severity: high
    fail-on-findings: true
```

## Verification

Both tools support live verification, but the workflow differs:

### TruffleHog
```bash
trufflehog filesystem .  # verification is ON by default
trufflehog filesystem . --no-verification  # turn OFF
```

### PledgeGuard
```bash
pledgeguard scan .  # verification is OFF by default (faster)
pledgeguard scan . --verify  # turn ON
pledgeguard scan . --only-verified  # only show confirmed active secrets
```

## Key Advantages of Switching

1. **npm/npx support** — `npx pledgeguard scan .` with zero install
2. **`--diff` mode** — scan only changed files for fast PR checks
3. **AI integration** — classification, remediation, FP detection
4. **MCP server** — integrate with AI coding agents
5. **Compliance reports** — SOC2, PCI-DSS, ISO27001, HIPAA, GDPR, NIST CSF
6. **Scan diffing** — track finding changes between scans
7. **Webhook notifications** — Slack/Teams/Discord alerts
8. **WASM plugins** — sandboxed custom detectors
9. **Rust-native** — memory-safe, fast, small binary
