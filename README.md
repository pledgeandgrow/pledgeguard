# PledgeGuard

Rust-native secret scanner — a TruffleHog/Gitleaks alternative.

## Status

🚧 **Early scaffold.** Regex + Shannon-entropy detection engine, git history
scanning, a lightweight false-positive filter, and a WASM plugin system are
implemented and tested. See [Roadmap](#roadmap) for what's next.

## Workspace layout

```
pledgeguard/
├── Cargo.toml                     # workspace manifest
├── examples/plugins/example-plugin/  # sample WASM detector plugin
└── crates/
    ├── pledgeguard-core/          # detection engine (Detector trait, built-in rules, Scanner,
    │                               # git history scan, WASM plugin loader, context filter)
    └── pledgeguard-cli/           # `pledgeguard` binary
```

## Usage

```sh
# Scan the working tree
cargo run -p pledgeguard-cli -- scan .
cargo run -p pledgeguard-cli -- scan ./src --format json
cargo run -p pledgeguard-cli -- scan . --min-severity high --fail-on-findings

# Scan all commits reachable from any ref for secrets introduced in the past
cargo run -p pledgeguard-cli -- history .

# Load custom detectors from a directory of .wasm plugins (see
# examples/plugins/example-plugin for the plugin ABI and a working sample)
cargo run -p pledgeguard-cli -- scan . --plugin-dir ./plugins

# Show findings flagged as likely false positives (same-line comments or
# test/fixture/example paths), which are hidden by default
cargo run -p pledgeguard-cli -- scan . --show-all
```

`--fail-on-findings` makes the CLI exit non-zero when findings are present,
for use as a CI gate (pre-commit hook or pipeline step). `history` requires
`git` to be on `PATH` and the target path to be inside a git working tree.

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

## Git history scanning

`pledgeguard history <path>` shells out to the system `git` binary and walks
every commit reachable from any ref (`git log --all`), scanning only the
lines *added* in each commit's diff against its parent. Findings include the
commit SHA that introduced the secret. This deliberately avoids embedding
`libgit2` to keep the dependency graph and build light.

## False-positive filtering (context heuristic)

Every finding is annotated with `likely_false_positive` based on two cheap,
language-agnostic checks (see `pledgeguard_core::context`):

- The match sits at or after a same-line comment marker for the file's extension.
- The file path looks like a test/fixture/example directory (`tests/`, `fixtures/`, `examples/`, `mocks/`, `spec/`, `testdata/`).

This is a lexical heuristic, not a real parser — it does not track multi-line
block comments or string-literal state, so a comment marker inside an
earlier string on the same line (e.g. a URL) can cause false negatives.
Findings are never dropped, only flagged; the CLI hides them by default and
`--show-all` reveals them.

## WASM plugin system

Custom detectors can be loaded from `.wasm` modules at runtime with
`--plugin-dir <dir>` (repeatable), without recompiling PledgeGuard. See
`crates/pledgeguard-core/src/plugin.rs` for the plugin ABI documentation and
`examples/plugins/example-plugin/` for a minimal working plugin. Plugins run
via `wasmtime` and are called from at most one thread at a time.

## Roadmap

Not yet built (see `IDEAS.md` idea #18 for the full vision):

- **Live provider verification** — optionally call provider APIs to confirm a found key is still active (like TruffleHog/leakferret).
- **MCP server** — expose scan results to AI agents for triage (like leakferret).
- **SARIF output** — for GitHub code scanning integration.
- **Baseline / allowlist mode** — suppress known false positives across scans.
- **Pre-commit hook installer**.
- **Full Oxc-based AST parsing for JS/TS** — the current false-positive filter is a lexical heuristic (see above); real AST parsing would allow deeper JS/TS-specific semantic checks.
