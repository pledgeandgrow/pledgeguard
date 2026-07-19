# Migration Guide: Gitleaks → PledgeGuard

## Quick Mapping

| Gitleaks | PledgeGuard |
|---|---|
| `gitleaks detect` | `pledgeguard scan .` |
| `gitleaks detect --source . --report-path results.json` | `pledgeguard scan . --format json --report-file results.json` |
| `gitleaks detect --no-banner` | (default — no banner) |
| `gitleaks detect --redact` | (default — always redacted) |
| `gitleaks detect --verbose` | `pledgeguard scan . --verbose` |
| `gitleaks detect --config .gitleaks.toml` | `pledgeguard scan . --config .pledgeguard.toml` |
| `gitleaks detect --baseline .gitleaks-baseline` | `pledgeguard scan . --baseline .pledgeguard-baseline.json` |
| `gitleaks detect --commit-since="2024-01-01"` | `pledgeguard history .` |
| `gitleaks dir` | `pledgeguard scan .` |
| `gitleaks git` | `pledgeguard history .` |

## Config File Migration

### Gitleaks format (`.gitleaks.toml`)

```toml
[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "key"]

[allowlist]
paths = ['''test/.*''']
```

### PledgeGuard format (`.pledgeguard.toml`)

```toml
[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
severity = "critical"
regex = 'AKIA[0-9A-Z]{16}'

[allowlist]
paths = ["test/.*"]
```

### Key Differences

| Feature | Gitleaks | PledgeGuard |
|---|---|---|
| Rule format | `[[rules]]` | `[[rules]]` (same) |
| Severity | `tags` | `severity` (low/medium/high/critical) |
| Allowlist paths | regex strings | glob patterns |
| Entropy | `[[rules.allowlist]]` per-rule | `entropy_threshold` per-rule |
| Path filters | `[[rules.allowlist]]` | `path_filter` per-rule |

## Feature Parity

| Feature | Gitleaks | PledgeGuard |
|---|:---:|:---:|
| Working tree scan | ✅ | ✅ |
| Git history scan | ✅ | ✅ |
| Custom rules | ✅ | ✅ |
| Allowlist | ✅ | ✅ |
| Baseline | ✅ | ✅ |
| SARIF output | ✅ | ✅ |
| JSON output | ✅ | ✅ |
| GitHub Actions | ✅ | ✅ |
| Pre-commit hook | ❌ | ✅ |
| Live verification | ❌ | ✅ |
| MCP server | ❌ | ✅ |
| AI integration | ❌ | ✅ |
| WASM plugins | ❌ | ✅ |
| Compliance reports | ❌ | ✅ |
| Scan diffing | ❌ | ✅ |
| Webhook notifications | ❌ | ✅ |
| npm/npx | ❌ | ✅ |

## GitHub Action Migration

### Before (Gitleaks)
```yaml
- uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
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

No `GITHUB_TOKEN` secret needed — PledgeGuard doesn't require API access for basic scanning.

## Pre-commit Hook Migration

### Before (Gitleaks)
Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

### After (PledgeGuard)
```bash
pledgeguard install-pre-commit .
```

Or add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/pledgeandgrow/pledgeguard
    rev: v0.1.1
    hooks:
      - id: pledgeguard
```
