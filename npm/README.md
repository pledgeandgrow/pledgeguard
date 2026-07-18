# @pledgeandgrow/pledgeguard

Rust-native secret scanner — a TruffleHog/Gitleaks alternative.

## Install

```sh
npm install -g @pledgeandgrow/pledgeguard
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
```

## Features

- Regex + Shannon-entropy secret detection (AWS, GitHub, Slack, Stripe, Google, npm, PEM keys, JWTs, connection strings)
- Git history scanning (`git log --all -p`, added lines only)
- AST-based false-positive refinement for JS/TS (via [oxc](https://oxc.rs))
- Live provider verification (`--verify`: GitHub, Slack, Stripe, npm)
- Baseline/allowlist mode (`--baseline`/`--save-baseline`)
- SARIF 2.1.0 output (`--format sarif`)
- MCP server for AI agent integration (`pledgeguard mcp`)
- WASM plugin system (`--plugin-dir`)
- Pre-commit hook installer (`pledgeguard install-pre-commit`)

## License

MIT
