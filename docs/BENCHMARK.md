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
| **AST-based FP reduction** | Yes (JS/TS via oxc, Python/Go/Ruby/Java/C/C++/C#/PHP) | No | No | No (Expr filters) | Yes (proprietary) | No |
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
| **Hugging Face** | ✅ (CLI + library) | ✅ | ❌ | ✅ | ❌ | ❌ |
| **SharePoint** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Microsoft Teams** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **PyPI packages** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Archives (zip/tar)** | ✅ (library) | ✅ | ✅ (depth-limited) | ✅ | ✅ | ✅ |
| **Base64 decoding** | ✅ (recursive, 2 levels) | ✅ | ✅ (configurable depth) | ✅ | ✅ | ✅ |
| **Helm charts** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Terraform state** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Kubernetes secrets** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Gitea** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Bitbucket Cloud** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Bitbucket Server** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Azure DevOps repos** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **LaunchDarkly** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Consul KV** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **etcd** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Redis** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Elasticsearch** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **AWS SSM Parameter Store** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ✅ | ❌ |
| **GCP Secret Manager** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Azure Key Vault** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ✅ | ❌ |
| **HashiCorp Vault** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Doppler** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **1Password** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **LastPass** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Bitwarden** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **K8s ConfigMaps** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **K8s etcd** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Cloudflare Workers** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Vercel env vars** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Netlify env vars** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Railway env vars** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Render env vars** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Fly.io secrets** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Supabase env vars** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **GitHub Gists** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **GitHub Issues/PRs** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **GitHub Actions logs** | ✅ (CLI + library) | ✅ | ❌ | ❌ | ✅ | ❌ |
| **GitLab Issues/MRs** | ✅ (CLI + library) | ✅ | ❌ | ✅ | ✅ | ❌ |
| **GitLab CI logs** | ✅ (CLI + library) | ✅ | ❌ | ✅ | ✅ | ❌ |
| **Discord** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Mattermost** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **RSS/Atom feeds** | ✅ (CLI + library) | ❌ | ❌ | ❌ | ❌ | ❌ |

**PledgeGuard advantage:** Broadest source coverage of any open-source scanner (40 sources). Unique sources: Alibaba OSS, AWS Secrets Manager, Postman, Gerrit, DroneCI, Syslog TCP, Helm charts, Terraform state, Kubernetes secrets, Gitea, LaunchDarkly, Consul, etcd, Redis, Elasticsearch, Doppler, 1Password, LastPass, Bitwarden, K8s ConfigMaps, K8s etcd, Cloudflare Workers, Railway, Render, Fly.io, Supabase, Discord, Mattermost, RSS feeds. CLI `scan-source` subcommand provides direct access to all remote sources.

**Gap:** None — all planned scanning sources (goals 201-240) are now implemented.

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
| **GitHub Actions** | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| **HTML** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Markdown** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **SPDX** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **CycloneDX** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Prometheus** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **JSON Lines** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **XML** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **JSON Legacy** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |

**PledgeGuard advantage:** 14 output formats including HTML reports with charts, Markdown for PR comments, SPDX/CycloneDX for SBOM integration, Prometheus for monitoring, JSON Lines for streaming, and XML for enterprise — far more than any competitor.

---

### 5. False-Positive Reduction

| Technique | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Lexical comment detection** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **AST-based comment detection** | ✅ (JS/TS via oxc, Python/Go/Ruby/Java/C/C++/C#/PHP) | ❌ | ❌ | ❌ | ✅ (proprietary) | ❌ |
| **Test/fixture path filtering** | ✅ | ❌ | ✅ (allowlist) | ✅ (Expr) | ✅ | ✅ (allow rules) |
| **Entropy filtering** | ✅ (Shannon + Renyi + Min + context-aware) | ✅ | ✅ (Shannon) | ✅ (Shannon + BPE) | ✅ | ❌ |
| **Inline comment suppression** | ✅ (`# pledgeguard:ignore`) | ❌ | ✅ (`gitleaks:allow`) | ✅ | ✅ | ❌ |
| **Baseline suppression** | ✅ | ❌ | ✅ | ✅ | ✅ (dashboard) | ❌ |
| **Allowlists** | ✅ (per-detector) | ✅ | ✅ | ✅ (Expr) | ✅ | ✅ |
| **BPE tokenization** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Expr-based contextual filters** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Shell/YAML/TOML/Dockerfile/HCL/SQL comments** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **.env file-aware scanning** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Generated/vendored/minified/lock file detection** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Binary/certificate file detection** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Example value/canary token detection** | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Secret rotation detection** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Multi-line secret detection** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Hex blob/UUID filtering** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **JWT structure validation** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

**PledgeGuard advantage:** AST-based false-positive reduction for JS/TS, Python, Go, Ruby, Java, C/C++, C#, and PHP is unique among open-source scanners (only GitGuardian has similar capability, but it's proprietary). Expr-based contextual filtering and BPE tokenization match Betterleaks. Additional FP filters include .env-aware scanning, generated/vendored/minified/lock/binary/cert file detection, example value/canary token detection, context-aware entropy, secret rotation detection, multi-line secret detection, hex blob/UUID filtering, and JWT structure validation.

**Gap:** None — PledgeGuard now matches or exceeds all competitors in FP reduction.

---

### 6. Extensibility & Plugin System

| Feature | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **WASM plugins** | ✅ (wasmtime + ABI v2) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Custom TOML rules** | ✅ | ✅ (YAML) | ✅ (TOML) | ✅ (TOML + Expr) | ✅ (dashboard) | ✅ (YAML) |
| **Custom verifiers** | ✅ (TOML + Expr + WASM) | ✅ (config) | ❌ | ✅ (Expr) | ✅ (dashboard) | ❌ |
| **MCP server** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Rule profiles** | ✅ (cloud/payments/ai-ml/minimal) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Conditional rules** | ✅ (file type/path/env) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Rule inheritance** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Rule deprecation/retirement** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Rule testing framework** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Rule documentation generator** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Plugin marketplace** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Multi-pattern regex** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Negative lookahead** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Capture group transformation** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

**PledgeGuard advantage:** Only scanner with a WASM plugin system (with ABI v2 for context passing) for custom detectors and verifiers. Only scanner with an MCP server for AI agent integration. Only scanner with rule profiles, conditional rules, rule deprecation, rule testing framework, rule documentation generator, plugin marketplace, multi-pattern regex, negative lookahead, and capture group transformation.

**Gap:** None — PledgeGuard now matches or exceeds all competitors in extensibility.

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
- **AST-based FP reduction (oxc + custom)** — JS/TS comment detection via oxc AST parsing, plus Python/Go/Ruby/Java/C/C++/C#/PHP comment detection via custom span extraction (open-source, vs GitGuardian's proprietary)
- **Expr-based contextual filtering** — boolean expression language for finding filtering with regex matching and field comparisons
- **BPE tokenization FP filter** — Byte Pair Encoding tokenizer optimized for secret detection
- **17 FP filters** — .env-aware scanning, docs/generated/vendored/minified/lock/binary/cert path detection, example value/canary token detection, context-aware entropy, secret rotation, multi-line secret, hex blob/UUID filtering, JWT validation
- **Rule profiles** — preset rule bundles (cloud, payments, ai-ml, minimal)
- **Conditional rules** — rules that activate based on file type, path, or environment
- **Rule testing framework** — validate custom rules with test cases
- **Rule documentation generator** — auto-generate Markdown docs for custom rules
- **Plugin marketplace** — community-contributed detector/verifier plugins
- **Multi-pattern regex & negative lookahead** — advanced regex features for rule definitions
- **Capture group transformation** — extract and transform captured groups from regex matches
- **Air-gapped mode** — `--offline` flag disables all network calls, with offline verification cache and bundled documentation
- **Zero-knowledge verification** — verify secrets without sending full value to API (challenge-response proof)
- **Local secret rotation** — generate replacement secrets matching the format of detected secret types
- **Encrypted baseline & report storage** — encrypt sensitive files at rest with passphrase-derived keys
- **20 content decoders** — HTML entities, HTML tags, URL decoding, Unicode NFC, JSON unescaping, YAML multi-doc, XML, CSV, INI, .env, Dockerfile, HCL, Markdown code blocks, Jupyter notebooks, PDF, Word, Excel, PowerPoint, OCR, binary strings
- **Rust-native** — memory-safe, fast, small binary

---

### 10. Areas Where Competitors Lead

| Gap | Leader | What's Needed |
|---|---|---|
| **Detector count** | TruffleHog (800+) | 708 detectors — add ~100 more to match |
| **Verification coverage** | TruffleHog (800+), GitGuardian (500+) | 191 verified rule IDs (143 unique verifier functions) — expand further |
| ~~Hugging Face scanning~~ | ~~TruffleHog, Betterleaks~~ ✅ Done | Added HF models/datasets/Spaces scanning |
| ~~SharePoint scanning~~ | ~~TruffleHog, GitGuardian~~ ✅ Done | Added SharePoint document scanning |
| ~~MS Teams scanning~~ | ~~TruffleHog, GitGuardian~~ ✅ Done | Added Teams message/channel scanning |
| ~~PyPI package scanning~~ | ~~GitGuardian~~ ✅ Done | Added PyPI package scanning |
| ~~GitHub Action~~ | ~~TruffleHog, Gitleaks, GitGuardian~~ ✅ Done | Published composite GitHub Action with SARIF support |
| ~~AI coding tool hooks~~ | ~~GitGuardian~~ ✅ Done | Added in Phase 3 — Cursor, Claude Code, Copilot, Codex |
| ~~Enterprise features~~ | ~~GitGuardian~~ ✅ Done | RBAC, audit logging, compliance reporting, scan diffing, finding lifecycle, webhook notifications |
| ~~Homebrew + Scoop~~ | ~~Competitors~~ ✅ Done | Homebrew formula + Scoop manifest created |
| ~~SECURITY.md + checksums~~ | ~~Competitors~~ ✅ Done | SECURITY.md + SHA256 checksums in release workflow |
| ~~Migration guides~~ | ~~Competitors~~ ✅ Done | Gitleaks + TruffleHog migration guides |
| ~~Pre-commit hook~~ | ~~Competitors~~ ✅ Done | .pre-commit-hooks.yaml published |
| ~~`--diff` flag~~ | ~~Competitors~~ ✅ Done | Scan only git-changed files for PR checks |
| ~~`pledgeguard init`~~ | ~~Competitors~~ ✅ Done | Config scaffolding command |
| ~~Gitea, Bitbucket, Azure DevOps~~ | ~~Competitors~~ ✅ Done | Added scanning for Gitea, Bitbucket Cloud/Server, Azure DevOps repos |
| ~~KV stores (Consul, etcd, Redis, ES)~~ | ~~Competitors~~ ✅ Done | Added scanning for Consul, etcd, Redis, Elasticsearch |
| ~~Cloud secret managers~~ | ~~Competitors~~ ✅ Done | Added AWS SSM, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler |
| ~~Password managers~~ | ~~Competitors~~ ✅ Done | Added 1Password, LastPass, Bitwarden scanning |
| ~~K8s ConfigMaps + etcd~~ | ~~Competitors~~ ✅ Done | Added K8s ConfigMap and etcd backend scanning |
| ~~PaaS env vars~~ | ~~Competitors~~ ✅ Done | Added Vercel, Netlify, Railway, Render, Fly.io, Supabase env var scanning |
| ~~GitHub/GitLab integrations~~ | ~~Competitors~~ ✅ Done | Added GitHub Gists, Issues/PRs, Actions logs, GitLab Issues/MRs, CI logs |
| ~~Discord, Mattermost, RSS~~ | ~~Competitors~~ ✅ Done | Added Discord, Mattermost, RSS/Atom feed scanning |
| ~~HTML report format~~ | ~~Competitors~~ ✅ Done | Self-contained HTML report with charts and styling |
| ~~Markdown report format~~ | ~~Competitors~~ ✅ Done | Markdown format for PR comment integration |
| ~~SPDX + CycloneDX~~ | ~~Competitors~~ ✅ Done | SBOM-compatible output formats |
| ~~Prometheus + JSONL + XML~~ | ~~Competitors~~ ✅ Done | Monitoring, streaming, and enterprise output formats |
| ~~Expr-based filtering~~ | ~~Betterleaks~~ ✅ Done | Expr filter language with regex matching and field comparisons |
| ~~BPE tokenization~~ | ~~Betterleaks~~ ✅ Done | BPE tokenizer optimized for secret detection |
| ~~Custom verifier config~~ | ~~TruffleHog, Betterleaks~~ ✅ Done | TOML + Expr + WASM verifiers, rule profiles, conditional rules |
| ~~HTML decoding~~ | ~~TruffleHog~~ ✅ Done | 20 content decoders: HTML, PDF, Word, Excel, PowerPoint, OCR, binary strings, YAML, XML, CSV, INI, .env, Dockerfile, HCL, Markdown, Jupyter, URL, Unicode, JSON |

---

## Summary Scorecard

| Category | PledgeGuard | TruffleHog | Gitleaks | Betterleaks | GitGuardian | Trivy |
|---|---|---|---|---|---|---|
| **Detectors** | ★★★★☆ | ★★★★★ | ★★★☆☆ | ★★★☆☆ | ★★★★☆ | ★★☆☆☆ |
| **Verification** | ★★★☆☆ | ★★★★★ | ☆☆☆☆☆ | ★★★☆☆ | ★★★★★ | ☆☆☆☆☆ |
| **Sources** | ★★★★★ | ★★★★☆ | ★★☆☆☆ | ★★★☆☆ | ★★★★☆ | ★★☆☆☆ |
| **Output formats** | ★★★★★ | ★★★☆☆ | ★★★★★ | ★★★★★ | ★★★★☆ | ★★★★☆ |
| **FP reduction** | ★★★★★ | ★★☆☆☆ | ★★★☆☆ | ★★★★★ | ★★★★★ | ★★★☆☆ |
| **Extensibility** | ★★★★★ | ★★★☆☆ | ★★★☆☆ | ★★★★☆ | ★★★☆☆ | ★★★☆☆ |
| **Performance** | ★★★★★ | ★★★★☆ | ★★★★★ | ★★★★★ | ★★☆☆☆ | ★★★★☆ |
| **AI integration** | ★★★★★ | ☆☆☆☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★★☆☆ | ☆☆☆☆☆ |
| **CI/CD** | ★★★★☆ | ★★★★☆ | ★★★★☆ | ★★★☆☆ | ★★★★★ | ★★★★☆ |
| **Offline** | ★★★★★ | ★★★☆☆ | ★★★☆☆ | ★★★☆☆ | ❌ | ★★★☆☆ |
| **Content decoding** | ★★★★★ | ★★☆☆☆ | ★☆☆☆☆ | ★★☆☆☆ | ★★★☆☆ | ★☆☆☆☆ |
| **Enterprise** | ★★★★★ | ★★★☆☆ | ☆☆☆☆☆ | ☆☆☆☆☆ | ★★★★★ | ☆☆☆☆☆ |

| **Overall** | **★★★★★** | **★★★★★** | **★★★☆☆** | **★★★★☆** | **★★★★☆** | **★★★☆☆** |

---

## Roadmap Priorities (Based on Gaps)

1. ~~Expand verification to 100+ providers~~ ✅ Done (191 rule IDs)
2. ~~Add Hugging Face scanning~~ ✅ Done
3. ~~Publish GitHub Action~~ ✅ Done
4. ~~Add HTML decoder~~ ✅ Done — HTML entity decoder, tag stripper, URL decoder, Unicode NFC, JSON unescaper, YAML multi-doc, XML, CSV, INI, .env, Dockerfile, HCL, Markdown, Jupyter, PDF, Word, Excel, PowerPoint, OCR, binary strings (20 decoders)
5. ~~Add Expr-based filtering~~ ✅ Done — match Betterleaks FP reduction (Expr filters, BPE, AST comments for 13 languages, 17 FP filters)
6. ~~Add more scanning sources~~ ✅ Done (40 sources: Gitea, Bitbucket, Azure DevOps, KV stores, cloud secret managers, password managers, K8s, PaaS env vars, GitHub/GitLab integrations, Discord, Mattermost, RSS)
7. ~~Add content decoders~~ ✅ Done — 20 content decoders (HTML, PDF, Word, Excel, PowerPoint, OCR, binary strings, YAML, XML, CSV, INI, .env, Dockerfile, HCL, Markdown, Jupyter, URL, Unicode, JSON)
8. **Add advanced IaC detection** — goals 471-500
9. ~~Add custom verifier config~~ ✅ Done — TOML + Expr + WASM verifiers, rule profiles, conditional rules, rule deprecation, testing framework, docs generator
10. ~~Add SharePoint + MS Teams sources~~ ✅ Done
11. ~~Add HTML, Markdown, SPDX, CycloneDX, Prometheus, JSONL, XML output formats~~ ✅ Done (14 formats total)
12. ~~Private key verification (Driftwood-style)~~ ✅ Done
