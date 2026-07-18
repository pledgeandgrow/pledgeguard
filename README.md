# PledgeGuard

Rust-native secret scanner — a TruffleHog/Gitleaks alternative.

## Status

**v0.1.0 — all roadmap features implemented.** PledgeGuard is a working secret
scanner with regex + entropy detection, git history scanning, WASM plugins,
live provider verification, MCP server, SARIF output, baseline/allowlist mode,
pre-commit hook installer, and AST-based false-positive refinement for JS/TS.

It is functional and tested but **not yet production-hardened** — detector
regexes may need tuning for precision/recall on large codebases, and it has
not been audited against real-world repositories at scale.

## Installation

### From source

```sh
git clone https://github.com/pledgeandgrow/pledgeguard.git
cd pledgeguard
cargo install --path crates/pledgeguard-cli
```

This installs the `pledgeguard` binary to `~/.cargo/bin`.

### From crates.io (not yet published)

```sh
cargo install pledgeguard
```

## Usage

```sh
# Scan the working tree
pledgeguard scan .
pledgeguard scan ./src --format json
pledgeguard scan . --min-severity high --fail-on-findings

# Scan git commit history (all refs, added lines only)
pledgeguard history .

# Load custom WASM detectors
pledgeguard scan . --plugin-dir ./plugins

# Show findings flagged as likely false positives (hidden by default)
pledgeguard scan . --show-all

# Verify matched secrets against provider APIs (GitHub, Slack, Stripe, npm)
pledgeguard scan . --verify

# Output SARIF 2.1.0 for GitHub Code Scanning
pledgeguard scan . --format sarif

# Save a baseline of current findings for future suppression
pledgeguard scan . --save-baseline .pledgeguard-baseline.json

# Suppress findings matching a previously saved baseline
pledgeguard scan . --baseline .pledgeguard-baseline.json

# Install a git pre-commit hook
pledgeguard install-pre-commit
pledgeguard install-pre-commit --force  # overwrite existing hook

# Run as an MCP server over stdio (for AI agents)
pledgeguard mcp
```

`--fail-on-findings` makes the CLI exit non-zero when findings are present,
for use as a CI gate. `history` requires `git` on `PATH` and the target path
to be inside a git working tree.

## Built-in detectors

- AWS Access Key ID / Secret Access Key
- GitHub Personal Access Token (classic + fine-grained)
- Slack token / incoming webhook
- Stripe secret key
- Google API key
- npm access token
- PEM-encoded private keys (RSA/EC/DSA/OpenSSH/PGP)
- JSON Web Tokens
- PostgreSQL / MySQL connection strings with embedded credentials
- Generic bearer tokens
- Generic high-entropy strings assigned to key/token/secret-like variables (Shannon entropy)

All matched secrets are redacted by default in CLI output (`--no-redact` to disable).

## Features

### Git history scanning

`pledgeguard history <path>` shells out to the system `git` binary and walks
every commit reachable from any ref (`git log --all`), scanning only the
lines *added* in each commit's diff against its parent. Findings include the
commit SHA that introduced the secret.

### False-positive reduction

Two layers of false-positive filtering:

1. **Lexical heuristic** (`context.rs`) — flags findings in same-line comments
   or test/fixture/example paths. Language-agnostic, applied to all files.
2. **AST-based refinement** (`ast.rs`) — uses the [oxc](https://oxc.rs) parser
   for accurate comment span detection on JS/TS files (`.js`, `.jsx`, `.ts`,
   `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`). Handles multi-line block comments
   and ignores `//` inside string literals — two cases the lexical heuristic
   gets wrong. Applied automatically during working-tree scans.

Findings are never dropped, only flagged; the CLI hides them by default and
`--show-all` reveals them.

### Live provider verification

`--verify` calls provider APIs (GitHub, Slack, Stripe, npm) to check whether
a matched secret is still active. Results appear as `Active`, `Inactive`,
`Unknown`, or `Error` in the `VERIFIED` column (table), `verification` JSON
field, or SARIF result message. Off by default (makes outbound network
requests). Only bearer-style tokens whose match text is a complete credential
can be verified.

### Baseline / allowlist mode

`--save-baseline <path>` writes all current findings to a JSON baseline file.
`--baseline <path>` suppresses findings whose fingerprint (rule_id + path +
matched text) appears in the baseline. Fingerprints are line-number-agnostic
so suppressions survive reformatting. The baseline file contains raw matched
secret values — treat it as sensitive (add to `.gitignore` or store securely).

### Pre-commit hook installer

`pledgeguard install-pre-commit` installs a git pre-commit hook that runs
`pledgeguard scan --fail-on-findings` before each commit. Use `--force` to
overwrite an existing hook. The hook is a shell script (requires Git Bash on
Windows, which is included with Git for Windows).

### SARIF output

`--format sarif` produces a SARIF 2.1.0 log document with deduplicated rules
and per-finding results, for GitHub Code Scanning integration.

### MCP server

`pledgeguard mcp` runs a Model Context Protocol server over stdio (JSON-RPC
2.0), exposing `scan_path` and `scan_git_history` as tools for AI agents.
Supports `initialize`, `tools/list`, and `tools/call`.

### WASM plugin system

Custom detectors can be loaded from `.wasm` modules at runtime with
`--plugin-dir <dir>` (repeatable), without recompiling PledgeGuard. See
`crates/pledgeguard-core/src/plugin.rs` for the plugin ABI documentation and
`examples/plugins/example-plugin/` for a minimal working plugin. Plugins run
via `wasmtime` and are called from at most one thread at a time.

## Workspace layout

```
pledgeguard/
├── Cargo.toml                     # workspace manifest
├── examples/plugins/example-plugin/  # sample WASM detector plugin
└── crates/
    ├── pledgeguard-core/          # detection engine library
    │   ├── detector.rs            # Detector trait + RegexDetector
    │   ├── detectors.rs           # built-in detector definitions
    │   ├── entropy.rs             # Shannon-entropy helper
    │   ├── finding.rs             # Finding, Severity, VerificationStatus types
    │   ├── redact.rs              # secret redaction for display
    │   ├── scanner.rs             # Scanner: file walking + parallel scan
    │   ├── context.rs             # lexical comment/fixture-path false-positive heuristic
    │   ├── ast.rs                 # oxc-based AST false-positive refinement for JS/TS
    │   ├── git_history.rs         # git history scan (shells out to `git log -p`)
    │   ├── plugin.rs              # WASM plugin loader + ABI (wasmtime)
    │   ├── verify.rs              # live provider verification (GitHub, Slack, Stripe, npm)
    │   ├── sarif.rs               # SARIF 2.1.0 output for GitHub Code Scanning
    │   └── baseline.rs            # baseline/allowlist persistence and filtering
    └── pledgeguard-cli/           # `pledgeguard` binary
        ├── main.rs                # clap CLI: scan + history + mcp + install-pre-commit
        └── mcp.rs                 # MCP server over stdio (JSON-RPC 2.0)
```

## CLI reference

```
pledgeguard scan <path> [OPTIONS]
pledgeguard history <path> [OPTIONS]
pledgeguard mcp [OPTIONS]
pledgeguard install-pre-commit [OPTIONS] [path]

Common options (scan & history):
  --format <table|json|sarif>    Output format (default: table)
  --min-severity <low|medium|high|critical>  Minimum severity to report
  --no-redact                    Show full secret values (default: redacted)
  --fail-on-findings             Exit non-zero if findings are present
  --plugin-dir <dir>             Load .wasm detectors from directory (repeatable)
  --show-all                     Include likely false positives (hidden by default)
  --verify                       Call provider APIs to check if secrets are active
  --baseline <path>              Suppress findings matching a baseline file
  --save-baseline <path>         Save current findings as a baseline file

install-pre-commit options:
  --force                        Overwrite existing pre-commit hook
  path                           Git repository path (default: .)
```

## Limitations

- **AST refinement is JS/TS only** — Python, Go, Ruby, etc. use the lexical heuristic.
- **Git history scans use lexical-only filtering** — only added-line text is available, not the full file.
- **Live verification covers 4 providers** — GitHub, Slack, Stripe, npm. AWS keys, PEM keys, JWTs, and connection strings cannot be verified.
- **Baseline files contain raw secret values** — treat as sensitive.
- **Early-stage / unaudited** — detector regexes may need tuning; limited real-world testing.

## License

MIT
