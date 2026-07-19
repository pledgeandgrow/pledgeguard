# PledgeGuard Tutorial

A hands-on guide to using PledgeGuard — from first scan to CI integration.

## Prerequisites

- [Rust](https://rustup.rs) (stable, 1.85+)
- Git
- A terminal

## Installation

### From source (current)

```sh
git clone https://github.com/pledgeandgrow/pledgeguard.git
cd pledgeguard
cargo install --path crates/pledgeguard-cli
```

This installs the `pledgeguard` binary to `~/.cargo/bin/` (make sure it's on your PATH).

### From crates.io (once published)

```sh
cargo install pledgeguard-cli
```

### From npm (once published)

```sh
npm install -g pledgeguard
```

### From Homebrew (once published)

```sh
brew install pledgeandgrow/tap/pledgeguard
```

## Quick Start

### 1. Scan your project

```sh
pledgeguard scan .
```

Output:
```
SEVERITY   RULE                         MATCH                                     COMMIT    VERIFIED   FILE:LINE
critical   aws-access-key-id            AKIA***REDACTED                          -         -          src/config.rs:42
critical   github-pat                   ghp_***REDACTED                          -         -          src/auth.ts:17
high       slack-token                  xoxb***REDACTED                          -         -          .env:3

3 finding(s).
```

Secrets are **redacted by default**. Use `--no-redact` to see full values (useful for verifying findings).

### 2. Scan git history

Secrets may have been committed and removed in past commits. Scan the full history:

```sh
pledgeguard history .
```

This runs `git log --all -p` and scans only **added lines** (not deleted), so it catches secrets that were committed at any point.

### 3. Fail your CI on secrets

```sh
pledgeguard scan . --fail-on-findings
```

Exits with code `1` if any secrets are found, `0` if clean. Use this in CI pipelines:

```yaml
# .github/workflows/security.yml
name: Security
on: [pull_request]
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install pledgeguard-cli
      - run: pledgeguard scan . --fail-on-findings
```

## Feature Walkthroughs

### Baseline / Allowlist Mode

When you first run PledgeGuard on a large codebase, you may get many findings for known test keys or false positives. Baseline mode lets you suppress them.

**Step 1: Save the current findings as a baseline:**

```sh
pledgeguard scan . --save-baseline .pledgeguard-baseline.json
```

This creates a JSON file with fingerprints (rule_id + path + matched value hash) of all current findings.

**Step 2: Review the baseline file:**

```sh
cat .pledgeguard-baseline.json
```

Remove entries that are real secrets you want to keep catching. Keep entries for known false positives.

**Step 3: Add baseline to .gitignore:**

```sh
echo ".pledgeguard-baseline.json" >> .gitignore
```

> **Warning:** Baseline files contain raw secret values. Treat them as sensitive and never commit them.

**Step 4: Run scans with the baseline:**

```sh
pledgeguard scan . --baseline .pledgeguard-baseline.json
```

Now only **new** secrets (not in the baseline) will be reported. This is perfect for CI — you baseline once, then every PR scan only fails on new leaks.

### Pre-commit Hook

Install a git hook that automatically scans before every commit:

```sh
pledgeguard install-pre-commit
```

Output:
```
Pre-commit hook installed at .git/hooks/pre-commit.
The hook runs `pledgeguard scan --fail-on-findings` before each commit.
To customize, edit the hook file or re-run with --force after editing.
```

Now every `git commit` will be blocked if secrets are detected. On Windows, a `pre-commit.bat` wrapper is also installed for Git Bash compatibility.

To overwrite an existing hook:

```sh
pledgeguard install-pre-commit --force
```

To install in a specific repo:

```sh
pledgeguard install-pre-commit /path/to/other/repo
```

### Live Provider Verification

PledgeGuard can verify detected secrets against the actual provider API — confirming whether a token is still **active** or already **revoked**.

```sh
pledgeguard scan . --verify
```

Supported providers:

| Provider | Rule IDs | Verification method |
|---|---|---|
| GitHub | `github-pat`, `github-fine-grained-pat` | API call to `api.github.com/user` |
| Slack | `slack-token` | `auth.test` API call |
| Stripe | `stripe-secret-key` | API call to `stripe.com` |
| npm | `npm-token` | API call to `registry.npmjs.org` |

The `VERIFIED` column in the output shows the result:

- `active` — the secret is live and working
- `revoked` — the secret was valid but is now revoked/expired
- `error` — verification failed (rate limit, network error, etc.)

> **Note:** Verification makes real API requests. Use sparingly to avoid rate limits.

### SARIF Output (for GitHub Code Scanning)

Generate SARIF 2.1.0 output for integration with GitHub Code Scanning or other security tools:

```sh
pledgeguard scan . --format sarif > pledgeguard-results.sarif
```

Upload to GitHub Code Scanning in your CI:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pledgeguard-results.sarif
```

### JSON Output (for scripting)

```sh
pledgeguard scan . --format json
```

Returns a JSON array of findings — useful for piping to other tools:

```sh
pledgeguard scan . --format json | jq '.[] | select(.severity == "critical") | .path'
```

### MCP Server (for AI coding agents)

PledgeGuard includes a Model Context Protocol (MCP) server that lets AI coding assistants (Cursor, Windsurf, Claude Desktop) automatically scan code for secrets.

**Start the server:**

```sh
pledgeguard mcp
```

**Configure in Cursor / Windsurf:**

Add to your MCP client config:

```json
{
  "mcpServers": {
    "pledgeguard": {
      "command": "pledgeguard",
      "args": ["mcp"]
    }
  }
}
```

The AI agent can now call two tools:
- `scan_path` — scan a directory for secrets
- `scan_git_history` — scan git commit history

The agent will automatically detect secrets in code it reads or generates, without the user needing to manually run scans.

### WASM Plugins

PledgeGuard supports custom detectors loaded as WASM modules.

**Create a plugin directory:**

```sh
mkdir -p .pledgeguard/plugins
```

**Add a `.wasm` detector file** (see the `Detector` trait in `pledgeguard-core` for the expected interface).

**Run with plugins:**

```sh
pledgeguard scan . --plugin-dir .pledgeguard/plugins
```

### Severity Filtering

Show only findings at or above a severity level:

```sh
pledgeguard scan . --min-severity critical
```

Severity levels: `critical` > `high` > `medium` > `low`

### Show All Findings (Including False Positives)

By default, PledgeGuard hides findings it thinks are false positives (secrets in comments, test files, fixture paths). To see everything:

```sh
pledgeguard scan . --show-all
```

False positives are flagged with `likely_false_positive: true` in JSON output.

## CLI Reference

```
pledgeguard <COMMAND>

Commands:
  scan                Scan working tree for secrets
  history             Scan git commit history for secrets
  install-pre-commit  Install a git pre-commit hook
  mcp                 Run as MCP server for AI agent integration
  help                Print this message

Scan options:
  --format <FORMAT>        Output format: table, json, sarif [default: table]
  --min-severity <LEVEL>   Minimum severity to report [default: low]
  --no-redact              Show full secret values (default: redacted)
  --fail-on-findings       Exit non-zero if secrets found
  --plugin-dir <DIR>       Load WASM detectors from directory
  --show-all               Include likely false positives
  --verify                 Verify secrets against provider APIs
  --baseline <FILE>        Suppress findings listed in baseline file
  --save-baseline <FILE>   Save current findings as baseline

Install-pre-commit options:
  --force                  Overwrite existing hook
  <PATH>                   Target git repo path [default: .]
```

## Try It Right Now

You can test PledgeGuard on any project in under 2 minutes:

```sh
# Install
cargo install --path crates/pledgeguard-cli

# Create a test file with a fake secret
echo 'AWS_KEY=AKIAIOSFODNN7EXAMPLE' > test.env

# Scan
pledgeguard scan .

# Clean up
rm test.env
```

## FAQ

**Is PledgeGuard free?**
Yes — MIT licensed, free forever, including commercial use.

**Does it send my code anywhere?**
No. All scanning is local. The only network calls happen with `--verify`, which contacts provider APIs (GitHub, Slack, etc.) to check if detected tokens are active.

**How does it compare to Gitleaks?**
PledgeGuard is Rust-native (faster startup, lower memory), has an MCP server for AI agent integration, AST-based false-positive reduction for JS/TS, and WASM plugin support. Gitleaks is more mature with a larger community and more tuned rules.

**Can I use it in CI?**
Yes — `--fail-on-findings` makes it a drop-in CI gate. SARIF output integrates with GitHub Code Scanning.

**Does it work on Windows?**
Yes — tested on Windows. The pre-commit hook installer writes both a shell script and a `.bat` wrapper.
