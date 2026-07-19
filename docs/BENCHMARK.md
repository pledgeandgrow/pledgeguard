# PledgeGuard — Competitive Benchmark

How PledgeGuard compares against the leading open-source and commercial secret scanners.

> **Last updated:** July 2026 · **PledgeGuard version:** v0.2.0 (Phase 3 — AI Integration)

---

## At-a-Glance Comparison

| Feature | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian (ggshield) | Trivy |
|---|---|---|---|---|---|---|
| **Language** | Rust | Go | Go | Go | Python | Go |
| **License** | MIT | AGPL-3.0 | MIT | MIT | MIT (CLI) / Commercial (platform) | Apache-2.0 |
| **Detectors** | 708 | 800+ | ~150 | ~150 (inherits Gitleaks rules) | 500+ | ~70 |
| **Live verification** | 48 providers | 800+ (all detectors) | None | Expr-based (config-defined) | 500+ (via API) | None |
| **Architecture** | Native binary + WASM plugins | Native binary | Native binary | Native binary | API-dependent (cloud) | Native binary |
| **Offline scanning** | Yes | Yes | Yes | Yes | No (requires API key) | Yes |
| **MCP server (AI agents)** | Yes | No | No | No | No | No |
| **WASM plugin system** | Yes | No | No | No | No | No |
| **AST-based FP reduction** | Yes (JS/TS via oxc) | No | No | No (Expr filters) | Yes (proprietary) | No |
| **Pre-commit hook** | Yes | Yes | Yes | Yes | Yes | Yes (via CI) |
| **GitHub Action** | Planned | Yes | Yes | Planned | Yes | Yes |

---

## Detailed Feature Comparison

### 1. Detector Coverage

| Tool | Total Detectors | Approach | Notes |
|---|---|---|---|
| **PledgeGuard** | 708 | Regex + Shannon entropy | Aho-Corasick prefilter on every detector for speed |
| **TruffleHog** | 800+ | Regex + programmatic | Every detector has a built-in verifier |
| **Gitleaks** | ~150 | Regex + entropy | Feature-complete; no new rules being added |
| **Betterleaks** | ~150+ | Regex + Expr filters | Inherits Gitleaks rules; adds Expr-based validation |
| **GitGuardian** | 500+ | Proprietary engine | Cloud-based detection; requires API key |
| **Trivy** | ~70 | Regex + keywords | Focused on container/image scanning; limited secret rules |

**PledgeGuard advantage:** 708 detectors is significantly more than Gitleaks/Betterleaks/Trivy, and approaches TruffleHog's coverage. All detectors use Aho-Corasick prefilters for fast scanning, similar to Gitleaks' keyword optimization.

**Gap:** TruffleHog has 800+ detectors with verification built into every one. PledgeGuard has 48 verified providers — significant but not yet full coverage.

---

### 2. Live Verification

| Tool | Verified Providers | Verification Approach |
|---|---|---|
| **PledgeGuard** | 48 | Stateless HTTP calls (GET /me, /user, /validate, etc.) |
| **TruffleHog** | 800+ | Every detector has a verifier; stateless HTTP |
| **Gitleaks** | 0 | No verification |
| **Betterleaks** | Config-defined | Expr-based HTTP validation in rule config |
| **GitGuardian** | 500+ | Cloud API-based verification |
| **Trivy** | 0 | No verification |

**PledgeGuard verified providers (48):**
GitHub, GitLab, Slack, Stripe, npm, DigitalOcean, Telegram, Twilio, OpenAI, Anthropic, PyPI, Docker Hub, SendGrid, Mailgun, Mailchimp, Opsgenie, PagerDuty, Google API, Google OAuth, HuggingFace, Shopify, Heroku, Vercel, Datadog, Cloudflare, Linear, Okta, Auth0, Supabase, CircleCI, Discord, Atlassian, New Relic, Notion, AWS STS, Azure AD, GCP IAM, Private Key (PEM), DB Connection, Slack Webhook, Vault Token, Bitbucket, SonarQube, Snyk, Twitch, Pulumi, Square, Postman, Buildkite, Terraform Cloud.

**PledgeGuard advantage:** Verification is built-in and offline-capable (no cloud API dependency like GitGuardian). Includes `--verify-detectors` / `--no-verify-detectors` flags for granular control (matching TruffleHog's feature). Verification caching and rate-limit backoff.

**Gap:** TruffleHog verifies all 800+ detectors. GitGuardian verifies 500+ via their cloud API. PledgeGuard needs to expand verification to more providers.

---

### 3. Scanning Sources

| Source | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Working tree / files** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Stdin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Git history (all refs)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Docker images** | ✅ (library) | ✅ | ❌ | ❌ | ✅ | ✅ |
| **GitHub repos (API)** | ✅ (library) | ✅ | ❌ | ✅ | ✅ | ❌ |
| **GitLab repos (API)** | ✅ (library) | ✅ | ❌ | ✅ | ✅ | ❌ |
| **S3 buckets** | ✅ (CLI + library) | ✅ | ❌ | ✅ | ✅ | ❌ |
| **GCS buckets** | ✅ (library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Azure Blob Storage** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Alibaba OSS** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **AWS Secrets Manager** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ✅ (vault) | ❌ |
| **Confluence** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Slack** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Jira** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Postman** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Gerrit** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Buildkite** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Artifactory** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **CircleCI** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Travis CI** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Jenkins** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **DroneCI** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Syslog TCP stream** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Hugging Face** | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ |
| **SharePoint** | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Microsoft Teams** | ❌ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **PyPI packages** | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Archives (zip/tar)** | ✅ (library) | ✅ | ✅ (depth-limited) | ✅ | ✅ | ✅ |
| **Base64 decoding** | ✅ (recursive, 2 levels) | ✅ | ✅ (configurable depth) | ✅ | ✅ | ✅ |
| **Helm charts** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Terraform state** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Kubernetes secrets** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |

**PledgeGuard advantage:** Broadest source coverage of any open-source scanner. Unique sources: Alibaba OSS, AWS Secrets Manager, Postman, Gerrit, DroneCI, Syslog TCP, Helm charts, Terraform state, Kubernetes secrets. CLI `scan-source` subcommand provides direct access to all remote sources.

**Gap:** Missing Hugging Face, SharePoint, MS Teams, PyPI package scanning (TruffleHog/Betterleaks/GitGuardian have some of these).

---

### 4. Output Formats

| Format | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Table** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **JSON** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SARIF** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **CSV** | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| **JUnit** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Template** | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **GitHub Actions** | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ |
| **JSON Legacy** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |

**PledgeGuard advantage:** 6 output formats including CSV, JUnit, and custom templates — more than TruffleHog.

---

### 5. False-Positive Reduction

| Technique | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Lexical comment detection** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **AST-based comment detection** | ✅ (JS/TS via oxc) | ❌ | ❌ | ❌ | ✅ (proprietary) | ❌ |
| **Test/fixture path filtering** | ✅ | ❌ | ✅ (allowlist) | ✅ (Expr) | ✅ | ✅ (allow rules) |
| **Entropy filtering** | ✅ (Shannon) | ✅ | ✅ (Shannon) | ✅ (Shannon + BPE) | ✅ | ❌ |
| **Inline comment suppression** | ✅ (`# pledgeguard:ignore`) | ❌ | ✅ (`gitleaks:allow`) | ✅ | ✅ | ❌ |
| **Baseline suppression** | ✅ | ❌ | ✅ | ✅ | ✅ (dashboard) | ❌ |
| **Allowlists** | ✅ (per-detector) | ✅ | ✅ | ✅ (Expr) | ✅ | ✅ |
| **BPE tokenization** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Expr-based contextual filters** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |

**PledgeGuard advantage:** AST-based false-positive reduction for JS/TS is unique among open-source scanners (only GitGuardian has similar capability, but it's proprietary). Inline comment suppression and baseline mode are supported.

**Gap:** Betterleaks has Expr-based contextual filtering and BPE tokenization for FP reduction — more expressive than PledgeGuard's current approach.

---

### 6. Extensibility & Plugin System

| Feature | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **WASM plugins** | ✅ (wasmtime) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Custom TOML rules** | ✅ | ✅ (YAML) | ✅ (TOML) | ✅ (TOML + Expr) | ✅ (dashboard) | ✅ (YAML) |
| **Custom verifiers** | ❌ | ✅ (config) | ❌ | ✅ (Expr) | ✅ (dashboard) | ❌ |
| **MCP server** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

**PledgeGuard advantage:** Only scanner with a WASM plugin system for custom detectors. Only scanner with an MCP server for AI agent integration (scan via JSON-RPC over stdio).

**Gap:** No custom verifier configuration (TruffleHog and Betterleaks allow user-defined verification endpoints). Betterleaks' Expr-based validation is more flexible.

---

### 7. Performance & Architecture

| Aspect | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Language** | Rust | Go | Go | Go | Python | Go |
| **Parallel scanning** | ✅ (rayon) | ✅ | ✅ | ✅ | ✅ (cloud) | ✅ |
| **Aho-Corasick prefilter** | ✅ (all detectors) | ✅ | ✅ (keywords) | ✅ | ❌ (cloud) | ✅ (keywords) |
| **Binary size** | ~5 MB | ~50 MB | ~5 MB | ~10 MB | ~50 MB (Python) | ~50 MB |
| **Memory usage** | Low | Medium | Low | Low | High (Python) | Medium |
| **Scan speed** | Fast (Rust + prefilters) | Fast | Fast | Fast | Slow (network-bound) | Fast |

**PledgeGuard advantage:** Rust provides memory safety and speed. Small binary size. Aho-Corasick prefilters on every detector ensure fast scanning even with 708 detectors.

#### Real-World Benchmark (July 2026)

Benchmark target: PledgeGuard project codebase (Rust, ~120 files, ~80k lines)

| Tool | Version | Language | Time | Findings | Unique Rules |
|---|---|---|---|---|---|
| **PledgeGuard** | v0.1.0 | Rust | **427 ms** | **383** | **180** |
| **Gitleaks** | v8.30.1 | Go | 681 ms | 96 | 12 |
| **Trivy** | v0.72.0 | Go | 1,777 ms | 7 | 2 |

**PledgeGuard severity breakdown:**

| Severity | Count |
|---|---|
| Critical | 95 |
| High | 167 |
| Medium | 107 |
| Low | 14 |

**PledgeGuard top 10 rules triggered:**

| Rule | Findings |
|---|---|
| `generic-high-entropy` | 94 |
| `aws-access-key-id` | 77 |
| `generic-api-key-assignment` | 11 |
| `github-pat` | 7 |
| `private-key-pem` | 6 |
| `uri-embedded-credentials` | 4 |
| `curl-auth-string` | 3 |
| `postgres-connection-string` | 3 |
| `generic-bearer-token` | 3 |
| `hashicorp-vault-token` | 3 |

**Gitleaks top rules:** `generic-api-key` (46), `github-pat` (10), `finicity-client-secret` (8), `codecov-access-token` (5), `snyk-api-token` (5)

**Key takeaways:**

- PledgeGuard is **1.6x faster** than Gitleaks and **4.2x faster** than Trivy
- PledgeGuard finds **4x more findings** than Gitleaks and **54.7x more** than Trivy
- PledgeGuard triggers **180 unique rules** vs Gitleaks' 12 and Trivy's 2 — demonstrating significantly broader detector coverage
- Higher finding count is partly due to 708 detectors vs Gitleaks' ~150 and Trivy's ~70, plus PledgeGuard's entropy detector catching high-entropy strings that pattern-only scanners miss
- Note: many findings are in test/fixture files (test secrets, example patterns in detector code). Use `--show-all` to see all; default mode filters likely false positives

---

### 8. CI/CD Integration

| Feature | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Pre-commit hook** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (via CI) |
| **`--fail-on-findings`** | ✅ | ✅ | ✅ (exit code) | ✅ | ✅ | ✅ |
| **GitHub Action** | Planned | ✅ | ✅ | Planned | ✅ | ✅ |
| **GitLab CI** | Manual | ✅ | ✅ | Manual | ✅ | ✅ |
| **SARIF for Code Scanning** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AI coding tool hooks** | ✅ (Cursor, Claude Code, Copilot, Codex) | ❌ | ❌ | ❌ | ✅ (Cursor, Claude Code, Copilot) | ❌ |


---

### 9. Unique PledgeGuard Features

Features not found in any other scanner:

- **MCP server v2** — JSON-RPC 2.0 over stdio + TCP for AI agents, with `scan_path`, `scan_git_history`, `scan_source`, `verify_secret`, `list_detectors` tools, streaming progress, token-based auth, and TCP remote mode
- **WASM plugin system** — load custom detectors from `.wasm` files at runtime (wasmtime)
- **Syslog TCP stream scanning** — real-time secret detection in log streams with Vault token detection
- **Helm chart scanning** — dedicated Helm chart parser (values.yaml, templates, Chart.yaml)
- **Terraform state scanning** — parse `.tfstate` files for plaintext secrets
- **Kubernetes secret scanning** — decode base64 data fields in K8s Secret manifests
- **Alibaba OSS scanning** — scan Alibaba Cloud Object Storage for secrets
- **AWS Secrets Manager scanning** — scan stored secrets in AWS Secrets Manager
- **Postman scanning** — scan Postman collections and environments for leaked secrets
- **Gerrit scanning** — scan Gerrit changes and file contents
- **DroneCI scanning** — scan DroneCI build logs and artifacts
- **AST-based FP reduction (oxc)** — JS/TS comment detection via AST parsing (open-source, vs GitGuardian's proprietary)
- **Rust-native** — memory-safe, fast, small binary

---

### 10. Areas Where Competitors Lead

| Gap | Leader | What's Needed |
|---|---|---|
| **Detector count** | TruffleHog (800+) | Add ~100 more detectors to match |
| **Verification coverage** | TruffleHog (800+), GitGuardian (500+) | Expand from 191 to 200+ verified rule IDs (143 unique verifier functions) |
| **Hugging Face scanning** | TruffleHog, Betterleaks | Add HF models/datasets/Spaces scanning |
| **SharePoint scanning** | TruffleHog, GitGuardian | Add SharePoint document scanning |
| **MS Teams scanning** | TruffleHog, GitGuardian | Add Teams message/channel scanning |
| **PyPI package scanning** | GitGuardian | Add PyPI package download + scan |
| **GitHub Action** | ~~TruffleHog, Gitleaks, GitGuardian~~ ✅ Done | Published composite GitHub Action with SARIF support |
| **Expr-based filtering** | Betterleaks | Consider Expr or similar for contextual rules |
| **BPE tokenization** | Betterleaks | Consider token-efficiency FP filtering |
| **Custom verifier config** | TruffleHog, Betterleaks | Allow user-defined verification endpoints in TOML config |
| **AI coding tool hooks** | ~~GitGuardian~~ ✅ Done | Added in Phase 3 — Cursor, Claude Code, Copilot, Codex |
| **Enterprise features** | ~~GitGuardian~~ ✅ Done | RBAC, audit logging, compliance reporting, scan diffing, finding lifecycle, webhook notifications |
| **HTML decoding** | TruffleHog | Decode HTML-encoded content from Confluence/Teams before scanning |

---

## Summary Scorecard

| Category | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Detectors** | ★★★★☆ | ★★★★★ | ★★★☆☆ | ★★★☆☆ | ★★★★☆ | ★★☆☆☆ |
| **Verification** | ★★★☆☆ | ★★★★★ | ☆☆☆☆☆ | ★★★☆☆ | ★★★★★ | ☆☆☆☆☆ |
| **Sources** | ★★★★★ | ★★★★☆ | ★★☆☆☆ | ★★★☆☆ | ★★★★☆ | ★★☆☆☆ |
| **Output formats** | ★★★★★ | ★★★☆☆ | ★★★★★ | ★★★★★ | ★★★★☆ | ★★★★☆ |
| **FP reduction** | ★★★★☆ | ★★☆☆☆ | ★★★☆☆ | ★★★★★ | ★★★★★ | ★★★☆☆ |
| **Extensibility** | ★★★★☆ | ★★★☆☆ | ★★★☆☆ | ★★★★☆ | ★★★☆☆ | ★★★☆☆ |
| **Performance** | ★★★★★ | ★★★★☆ | ★★★★★ | ★★★★★ | ★★☆☆☆ | ★★★★☆ |
| **AI integration** | ★★★★★ | ☆☆☆☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★★☆☆ | ☆☆☆☆☆ |
| **CI/CD** | ★★★★☆ | ★★★★☆ | ★★★★☆ | ★★★☆☆ | ★★★★★ | ★★★★☆ |
| **Offline** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Enterprise** | ★★★★☆ | ★★★☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★★★★ | ☆☆☆☆☆ |

| **Overall** | **★★★★☆** | **★★★★★** | **★★★☆☆** | **★★★★☆** | **★★★★☆** | **★★★☆☆** |

---

## Roadmap Priorities (Based on Gaps)

1. **Expand verification to 100+ providers** — highest impact gap vs TruffleHog
2. **Add Hugging Face scanning** — growing AI/ML ecosystem
3. **Publish GitHub Action** — critical for CI/CD adoption
4. **Add HTML decoder** — improve Confluence/Teams/Jira scan results
5. **Add custom verifier config** — let users define verification endpoints in TOML
6. **Add SharePoint + MS Teams sources** — enterprise coverage
7. **Consider Expr-based filtering** — more expressive FP reduction
8. **Private key verification (Driftwood-style)** — verify against GitHub/TLS
