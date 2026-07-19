# PledgeGuard — Project Overview

## 1. What it is

PledgeGuard is a Rust-native secret scanner: it walks a filesystem path and
flags hardcoded secrets (API keys, tokens, private keys, credentials) using
regex pattern matching and Shannon-entropy analysis. It is designed to be run
as a CLI tool, either locally or as a CI/pre-commit gate.

It is positioned as a lighter, faster, Rust-native alternative to tools like
**Gitleaks** and **TruffleHog**, which are written in Go.

## 2. Architecture

The project is a Cargo workspace with two crates, plus a standalone example plugin:

```
pledgeguard/
├── Cargo.toml                     # workspace manifest
├── action.yml                     # GitHub Action definition
├── gitlab-ci.yml                  # GitLab CI template
├── templates/                     # publishable CI/CD templates
│   ├── circleci-orb.yml
│   ├── Jenkinsfile
│   ├── drone.yml
│   ├── azure-pipelines.yml
│   ├── bitbucket-pipelines.yml
│   ├── teamcity.config
│   ├── husky-pre-commit
│   └── lint-staged.json
├── examples/plugins/example-plugin/  # sample WASM detector plugin (own [workspace], not a member)
└── crates/
    ├── pledgeguard-core/          # detection engine (library)
    │   ├── detector.rs            # Detector trait + RegexDetector
    │   ├── detectors.rs           # built-in detector definitions
    │   ├── entropy.rs             # Shannon-entropy helper
    │   ├── finding.rs             # Finding, Severity, VerificationStatus types
    │   ├── redact.rs              # secret redaction for display
    │   ├── scanner.rs             # Scanner: file walking + parallel scan + IaC detection
    │   ├── context.rs             # lightweight comment/fixture-path false-positive heuristic
    │   ├── git_history.rs         # git history scan + scoped history scan
    │   ├── plugin.rs              # WASM plugin loader + ABI (wasmtime)
    │   ├── verify.rs              # live provider verification (GitHub, Slack, Stripe, npm)
    │   ├── sarif.rs               # SARIF 2.1.0 output for GitHub Code Scanning
    │   ├── baseline.rs            # baseline/allowlist persistence and filtering
    │   ├── ast.rs                 # oxc-based AST false-positive refinement for JS/TS
    │   ├── ci_cd.rs               # CI/CD templates, scan scope, exit code config, PR comments
    │   └── iac_detection.rs       # IaC secret detection (30+ file types)
    └── pledgeguard-cli/           # `pledgeguard` binary
        ├── main.rs                # clap CLI: scan + history + scan-source + mcp + compliance + diff
        └── mcp.rs                 # MCP server over stdio (JSON-RPC 2.0)
```

### Core abstractions (`pledgeguard-core`)

- **`Detector` trait** (`detector.rs`) — inspects a single line of text and
  returns zero or more `DetectorMatch`es. Any detector (regex-based today,
  AST- or WASM-based in the future) can implement this trait without the
  `Scanner` needing to change.
- **`RegexDetector`** — the concrete implementation used by all built-in
  rules; wraps a compiled `regex::Regex` plus an `id`, `description`, and
  `Severity`.
- **`Scanner`** (`scanner.rs`) — orchestrates a scan:
  1. Walks the target path via the `ignore` crate (`WalkBuilder`), which
     respects `.gitignore`/`.ignore` files.
  2. Filters out files above `ScanOptions::max_file_size` (default 5 MB).
  3. Reads each file and runs every configured `Detector` against every
     line, in parallel across files via `rayon`.
  4. Collects results into `Finding` values.
- **`Finding`** (`finding.rs`) — rule id, description, severity, file path,
  line/column, matched text, surrounding line context, an optional `commit`
  SHA (set only for git-history scans), a `likely_false_positive` flag, and
  an optional `verification` field (`VerificationStatus`: Active, Inactive,
  Unknown, or Error) populated by live provider checks. Supports `.redacted()`
  to mask the matched secret for safe display.
- **`redact.rs`** — redaction logic used by `Finding::redacted()` and the CLI's
  default (non-`--no-redact`) output mode.
- **`context.rs`** — lightweight, language-agnostic false-positive heuristic.
  Flags (never drops) a finding as `likely_false_positive` if the match sits
  after a same-line comment marker for the file's extension, or the path
  looks like a test/fixture/example directory. This is a lexical heuristic,
  not a real parser: it doesn't track multi-line block comments or string
  state, so a comment marker inside an earlier string (e.g. a URL) can cause
  false negatives. Applied automatically by both `Scanner::scan_str` and
  `scan_git_history`.
- **`git_history.rs`** — `scan_git_history(repo_root, detectors)` shells out
  to `git log --all -p --unified=0`, parses the unified diff and runs
  every detector against each *added* line only. `scan_git_history_with_scope()`
  extends this with `ScanScope` support for incremental/PR-scoped scanning
  (since-commit, since-date, branch, commit-range). Avoids embedding `libgit2`
  to keep the dependency graph and build light — requires `git` on `PATH`.
- **`plugin.rs`** — `WasmDetector` implements `Detector` by calling into a
  loaded `.wasm` module via `wasmtime`. Plugins export `pg_alloc`,
  `pg_metadata`, and `pg_scan_line` using a packed `(ptr << 32) | len`
  calling convention over the module's linear memory (see the module's
  rustdoc for the full ABI). `load_plugins(dir)` loads every `.wasm` file in
  a directory, skipping (and warning on) any that fail to load. Each
  `WasmDetector` serializes calls behind a `Mutex` since a single module
  instance is not safely callable concurrently.
- **`verify.rs`** — `verify_findings(&mut [Finding])` performs live provider
  verification in parallel (via `rayon`). Each finding whose `rule_id` has a
  registered verifier (GitHub PATs, Slack tokens, Stripe secret keys, npm
  tokens) gets an HTTP call to the provider's "who am I" endpoint; the result
  (`Active`, `Inactive`, `Unknown`, or `Error`) is stored in
  `Finding::verification`. Rules whose match text is not a complete credential
  (AWS key IDs, PEM keys, JWTs, connection strings, entropy matches) are left
  unverified. Uses `ureq` for sync HTTP with a 10s timeout.
- **`sarif.rs`** — `to_sarif(&[Finding]) -> serde_json::Value` produces a
  SARIF 2.1.0 log document with one `run`, a deduplicated `rules` array, and
  one `result` per finding (with `level` mapped from severity, `artifactLocation`
  with forward-slash URIs, and a `partialFingerprints` entry for dedup).
- **`baseline.rs`** — persistent baseline/allowlist for suppressing known
  findings across scans. A `Baseline` is a JSON file containing
  `BaselineEntry` records (rule_id + path + matched text). `filter()` removes
  findings whose fingerprint appears in the baseline; `from_findings()` builds
  a baseline from a scan's results; `load()`/`save()` handle file I/O. The
  fingerprint is line-number-agnostic so suppressions survive reformatting.
- **`ci_cd.rs`** — CI/CD integration features: pipeline templates (GitLab CI,
  CircleCI orb, Jenkins, DroneCI, Azure DevOps, Bitbucket Pipelines, TeamCity,
  Husky, lint-staged), `ScanScope` for incremental/PR-scoped scanning,
  `ExitCodeConfig` for configurable CI exit codes, `BaselineCiConfig` for
  baseline auto-creation/enforcement, `PrCommentConfig` for posting findings
  as PR/MR comments (GitHub, GitLab, Azure DevOps), SARIF auto-upload to
  GitHub Code Scanning, and JUnit XML generation for CI test runners.
- **`iac_detection.rs`** — Infrastructure-as-Code secret detection covering
  30+ file types: `.env` files, AWS credentials, Docker Compose, Kubernetes,
  Terraform, Ansible, Chef, Puppet, CloudFormation, Pulumi, Serverless, AWS CDK,
  Terraform Cloud, GitHub Actions, GitLab CI, CircleCI, Jenkins, DroneCI,
  ArgoCD, Helm, Kustomize, Skaffold, Tilt, Garden, DevSpace, Okteto, Acorn,
  Cosign. Also detects secret pairs (AWS Access Key ID + Secret Key) and
  secret chains (client_id + client_secret + tenant_id). Integrated into
  `Scanner::scan_str` and `Scanner::scan_bytes` via `scan_iac_file()`.
- **`ast.rs`** — AST-based false-positive refinement for JS/TS files using the
  `oxc` parser. `refine_annotation()` overrides the lexical comment heuristic
  from `context.rs` with accurate comment span detection (handles multi-line
  block comments, ignores `//` inside string literals). Called automatically
  by `Scanner::scan_str` for `.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs`/`.mts`/`.cts`
  files; git history scans still use the lexical heuristic (only added-line
  text is available, not the full file).

### CLI (`pledgeguard-cli`)

Subcommands (via `clap`):
- **`scan <path>`** — working-tree scan. Accepts a path (file or directory,
  defaults to `.`), or `-` for stdin.
- **`history <path>`** — git history scan via `scan_git_history`, defaults to `.`.
  Supports scoped scanning (`--since-commit`, `--since-date`, `--branch`,
  `--commit-range`, `--pr-number`).
- **`scan-source <source>`** — scan remote sources (Confluence, Slack, Jira, S3,
  GCS, Azure Blob, CircleCI, Travis CI, Jenkins, DroneCI, etc.) via API.
- **`mcp`** — runs a Model Context Protocol server over stdio or TCP, exposing
  `scan_path` and `scan_git_history` as JSON-RPC tools for AI agents.
- **`install-pre-commit`** — installs a git pre-commit hook.
- **`init`** — initializes `.pledgeguard.toml` config.
- **`compliance <path>`** — generates compliance reports (SOC2, PCI-DSS, ISO27001,
  HIPAA, GDPR, NIST CSF).
- **`diff <previous.json> <current.json>`** — compares two scan reports.
- **`notify`** — sends webhook notifications (Slack, Teams, Discord).
- **`install-ai-hooks`** — installs hooks for AI coding tools (Cursor, Claude
  Code, Copilot).
- **`ai-analyze`** — AI-powered analysis of scan results.

`scan` and `history` share:
- `--format table|json|sarif|csv|junit|github-actions|html|markdown|spdx|cyclonedx|prometheus|jsonl|xml`, `--min-severity`, `--no-redact`, `--fail-on-findings`.
- `--plugin-dir <dir>` (repeatable) — loads additional `.wasm` detectors.
- `--show-all` — includes findings flagged `likely_false_positive`.
- `--verify` — calls provider APIs to check whether matched secrets are active.
- `--baseline <path>` / `--save-baseline <path>` — baseline management.
- `--config <path>` — load custom TOML rules.
- `--report-file <path>` — write output to file.
- `--diff` — scan only git-changed files (PR mode).

`scan` also supports CI/CD flags:
- `--since-commit <SHA>`, `--since-date <date>`, `--branch <name>`,
  `--pr-number <N>`, `--commit-range <A..B>` — incremental/PR-scoped scanning.
- `--exit-code <N>`, `--ignore-exit-code`, `--fail-on-severity <level>`,
  `--max-findings <N>`, `--ci-mode` — configurable exit code behavior.
- `--report-append` — append to report file for multi-scan aggregation.
- `--baseline-auto`, `--enforce-baseline` — baseline auto-creation and enforcement.
- `--pr-comment-platform <github|gitlab|azure-devops>`, `--pr-comment-repo`,
  `--pr-comment-token` — post findings as PR/MR comments.
- `--sarif-upload`, `--sarif-upload-token` — upload SARIF to GitHub Code Scanning.
- `--junit-upload` — write JUnit XML for CI test runner integration.

### Data flow

```
CLI args ──> Scanner::scan_path(root)
                 │
                 ├─ collect_files(root)   [ignore::WalkBuilder, respects .gitignore]
                 │
                 └─ par_iter over files   [rayon]
                        └─ scan_str(path, contents)
                               └─ for each line × each Detector
                                     └─ Detector::scan_line(line) -> DetectorMatch
                                           └─ Finding { .. }
                 ──> (optional) baseline filter   [suppress known findings]
                 ──> filter by severity, sort, redact
                 ──> (optional) verify_findings  [parallel HTTP calls to provider APIs]
                 ──> print_table / print_json / print_sarif
                 ──> ExitCode (FAILURE if --fail-on-findings and findings exist)
```

## 3. Built-in detectors

Currently implemented (`detectors.rs`):
AWS access keys, GitHub PATs (classic + fine-grained), Slack tokens/webhooks,
Stripe secret keys, Google API keys, npm tokens, PEM private keys (RSA/EC/DSA/
OpenSSH/PGP), JWTs, Postgres/MySQL connection strings with embedded
credentials, generic bearer tokens, and generic high-entropy strings assigned
to key/token/secret-like variable names (Shannon entropy, `entropy.rs`).
Additional detectors can be loaded at runtime as WASM plugins (`plugin.rs`).

## 4. Current limitations

- **Git history scanning is diff-based, not full history semantics** — it
  scans each commit's first-parent diff (added lines only), which matches
  Gitleaks/TruffleHog's usual reporting model but does not scan merge commits'
  full ancestry or detect a secret that was present in a file without ever
  appearing as an added diff line in a captured commit range. It also shells
  out to `git`, so it requires `git` on `PATH` and only works inside a git
  working tree.
- **AST-based false-positive refinement is JS/TS only** — `ast.rs` uses the
  `oxc` parser for accurate comment span detection (multi-line block comments,
  `//` inside string literals) on `.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs`/`.mts`/`.cts`
  files. Git history scans still use the lexical heuristic from `context.rs`
  (only added-line text is available, not the full file). Non-JS/TS files always
  use the lexical heuristic. Neither approach tracks string-literal assignment
  semantics (e.g. distinguishing a real secret from a code example string).
- **WASM plugin ABI is minimal/custom** — plugins implement a small hand-rolled
  ABI (`pg_alloc`/`pg_metadata`/`pg_scan_line` over packed pointers), not a
  standardized interface like WASI or the Component Model; plugin calls are
  serialized behind a mutex (no concurrent calls into one plugin instance),
  and a malformed `.wasm` file is skipped with a warning rather than failing
  the whole scan.
- **Live verification is best-effort and limited to bearer-style tokens** —
  only detectors whose match text is a complete, usable credential on its own
  (GitHub PATs, Slack tokens, Stripe secret keys, npm tokens) can be verified.
  AWS key IDs, PEM private keys, JWTs, connection strings, and generic
  high-entropy strings cannot be verified because the match alone is not
  sufficient to authenticate. Verification also makes outbound network
  requests, so it is opt-in (`--verify`) and never run implicitly.
- **Baseline fingerprints are line-number-agnostic** — suppressions match on
  `rule_id + path + matched` (not line number), so they survive reformatting /
  line shifts but will also suppress the same secret if it appears on a
  different line in a different context. The baseline file contains raw matched
  secret values and should be treated as sensitive (add to `.gitignore` or
  store securely).
- **Pre-commit hook is a simple shell script** — runs `pledgeguard scan
  --fail-on-findings` with no configuration; users who need custom flags
  (e.g. `--baseline`, `--min-severity`) should edit the hook file manually.
- **MCP server is a minimal stdio transport** — implements just enough
  JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`) to serve AI agents;
  no streaming, no resource subscriptions, no external MCP SDK dependency.
- **Early-stage / unaudited** — version `0.1.0`, limited real-world testing
  against large/diverse codebases; detector regexes may need tuning for
  precision/recall.

## 5. Comparison to existing tools

| | **PledgeGuard** | **Gitleaks** | **TruffleHog** |
|---|---|---|---|
| Language | Rust | Go | Go |
| Detection method | Regex + entropy | Regex + entropy | Regex + entropy + **live credential verification** |
| Git history scanning | ✅ (`git log -p`, added-lines diff) | ✅ | ✅ |
| Custom/plugin rules | ✅ (WASM plugins via `wasmtime`) | ✅ (TOML config) | ✅ (custom detectors) |
| False-positive reduction | ✅ lexical + AST (oxc for JS/TS) | partial (allowlist) | partial (allowlist + verification) |
| Live secret verification | ✅ (opt-in `--verify`, 4 providers) | ❌ | ✅ (flagship feature) |
| CI gate exit code | ✅ (`--fail-on-findings`) | ✅ | ✅ |
| SARIF output | ✅ (`--format sarif`) | ✅ | ✅ (some formats) |
| MCP server | ✅ (`pledgeguard mcp`, stdio JSON-RPC) | ❌ | ❌ |
| Baseline/allowlist | ✅ (`--baseline`/`--save-baseline`) | ✅ | ✅ |
| Pre-commit hook installer | ✅ (`pledgeguard install-pre-commit`) | ✅ | ❌ |
| Maturity | 🚧 early scaffold (0.1.0) | Stable, widely adopted | Stable, widely adopted |

**Where PledgeGuard aims to differentiate:**
- A memory-safe, dependency-light, single static binary via Rust, with
  potentially lower resource usage/startup latency than Go/JVM-based scanners.
- A `Detector` trait designed from the start to support pluggable detection
  strategies — regex, entropy, and now WASM-loaded custom detectors — without
  changing the scanning engine (`Scanner`/`scan_git_history` treat every
  detector uniformly).
- Git history scanning without embedding `libgit2` (shells out to `git`),
  keeping the dependency graph and build lighter than a bundled-libgit2 approach.
- Native exposure of results to AI coding agents via an MCP server
  (`pledgeguard mcp`), aimed at automated triage rather than only human review.
- Live provider verification (`--verify`) and SARIF output (`--format sarif`)
  built in, closing the gap with TruffleHog on verification and with
  Gitleaks on CI/code-scanning integration.
- Baseline/allowlist (`--baseline`/`--save-baseline`) and pre-commit hook
  installer (`pledgeguard install-pre-commit`) for CI workflow integration.
- AST-based false-positive refinement for JS/TS via `oxc`, going beyond
  lexical heuristics for the most common secret-leak file types.

**Where it currently falls short of the established tools:** live
verification covers fewer providers than TruffleHog's deep verifier set,
AST refinement is JS/TS only (not Python, Go, Ruby, etc.), and far less
production hardening/community testing than Gitleaks or TruffleHog.

## 6. Goals / Roadmap

Implemented this session:

1. ✅ **Git history scanning** — `pledgeguard history <path>` (`git_history.rs`).
2. ✅ **False-positive reduction heuristic** — lexical comment/fixture-path
   filter (`context.rs`), flagged via `Finding::likely_false_positive` and
   hidden by default in the CLI. *Not* full Oxc/AST parsing (see limitations).
3. ✅ **WASM plugin system** — `--plugin-dir` loads custom `Detector`s from
   `.wasm` modules via `wasmtime` (`plugin.rs`), with a working example in
   `examples/plugins/example-plugin/`.
4. ✅ **Live provider verification** — `--verify` on `scan`/`history` calls
   provider APIs (GitHub, Slack, Stripe, npm) to check whether a matched
   secret is still active, recording the result in `Finding::verification`
   (`verify.rs`). Best-effort: only bearer-style tokens whose match text is
   a complete credential can be verified.
5. ✅ **MCP server** — `pledgeguard mcp` runs a stdio JSON-RPC 2.0 server
   exposing `scan_path` and `scan_git_history` tools for AI agents
   (`mcp.rs`). Supports `initialize`, `tools/list`, `tools/call`.
6. ✅ **SARIF output** — `--format sarif` on `scan`/`history` produces a
   SARIF 2.1.0 log with deduplicated rules and per-finding results for
   GitHub Code Scanning integration (`sarif.rs`).
7. ✅ **Baseline/allowlist mode** — `--baseline <path>` loads a JSON baseline
   and suppresses matching findings; `--save-baseline <path>` writes a
   baseline from the current scan's findings (`baseline.rs`). Fingerprints
   are line-number-agnostic (rule_id + path + matched).
8. ✅ **Pre-commit hook installer** — `pledgeguard install-pre-commit [--force]`
   installs a git pre-commit hook that runs `pledgeguard scan
   --fail-on-findings` before each commit.
9. ✅ **Oxc-based AST parsing for JS/TS** — `ast.rs` uses the `oxc` parser to
   accurately detect comment spans (including multi-line block comments) and
   ignore `//` inside string literals, overriding the lexical heuristic for
   `.js`/`.jsx`/`.ts`/`.tsx`/`.mjs`/`.cjs`/`.mts`/`.cts` files during
   working-tree scans.

All roadmap items from the original `README.md` are now implemented.

The long-term goal is to reach feature parity with Gitleaks/TruffleHog on
detection breadth and CI integration, while differentiating on performance
(Rust), extensibility (WASM plugins), and AI-agent integration (MCP server).
