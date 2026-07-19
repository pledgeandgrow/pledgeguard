# PledgeGuard — Supported Platforms & Capabilities

This document lists all detectors, verification providers, output formats, scanning sources, and configuration options currently supported by PledgeGuard.

---

## Built-in Detectors

PledgeGuard ships with **76 regex-based detectors** covering major cloud providers, SaaS platforms, CI/CD systems, and generic secret patterns. Each detector has a prefilter (Aho-Corasick) for fast scanning and a regex for precise matching.

### Cloud Providers

| Rule ID | Description | Severity |
|---|---|---|
| `aws-access-key-id` | AWS Access Key ID (AKIA/ASIA/AGPA/AIDA/AROA/AIPA/ANPA/ANVA/ASCA prefixes) | Critical |
| `aws-secret-access-key` | AWS Secret Access Key (40-char base64 assigned to `aws_secret_access_key`) | Critical |
| `aws-session-token` | AWS Session Token | Critical |
| `aws-mws-auth-token` | Amazon MWS Auth Token (amzn.mws. UUID format) | High |
| `aws-bedrock-api-key-long-lived` | Amazon Bedrock API Key — long-lived (ABSK prefix, 109+ chars) | Critical |
| `aws-bedrock-api-key-short-lived` | Amazon Bedrock API Key — short-lived (bedrock-api-key- prefix) | High |
| `aws-account-id` | AWS Account ID (12-digit numeric assignment) | Low |
| `azure-connection-string` | Azure Storage Connection String | Critical |
| `azure-sas-token` | Azure Shared Access Signature Token | High |
| `azure-client-secret` | Azure Client Secret | High |
| `azure-ad-client-secret` | Azure AD (Entra ID) Client Secret (Q~ marker pattern) | High |
| `azure-batch-key` | Azure Batch Account Key | High |
| `azure-function-key` | Azure Function Key (FUNCTIONS_KEY/code= assignment) | High |
| `azure-devops-pat` | Azure DevOps Personal Access Token (52-char alphanumeric) | High |
| `azure-cosmos-key` | Azure Cosmos DB Key (AccountKey= 88-char base64) | Critical |
| `google-api-key` | Google API Key (AIza prefix) | High |
| `google-oauth-access-token` | Google OAuth Access Token (ya29 prefix) | High |
| `google-service-account-json` | Google Service Account Private Key JSON | Critical |
| `gcp-service-account-private-key` | GCP Service Account Private Key (private_key field with PEM block) | Critical |
| `gcp-oauth-client-id` | GCP OAuth Client ID (xxx.apps.googleusercontent.com) | Medium |
| `alibaba-access-key-id` | Alibaba Cloud Access Key ID (LTAI prefix) | Critical |
| `tencent-secret-id` | Tencent Cloud Secret ID (AKID prefix) | Critical |
| `digitalocean-pat` | DigitalOcean Personal Access Token (dop_v1_ prefix) | High |
| `digitalocean-spaces-key` | DigitalOcean Spaces Access Key | High |

### Version Control & CI/CD

| Rule ID | Description | Severity |
|---|---|---|
| `github-pat` | GitHub Personal Access Token (ghp_/gho_/ghu_/ghs_/ghr_ prefixes) | Critical |
| `github-fine-grained-pat` | GitHub Fine-Grained PAT (github_pat_ prefix) | Critical |
| `gitlab-pat` | GitLab Personal Access Token (glpat- prefix) | Critical |
| `gitlab-pipeline-trigger-token` | GitLab Pipeline Trigger Token (glptt- prefix) | High |
| `gitlab-runner-registration-token` | GitLab Runner Registration Token (GR1348921 prefix) | High |
| `bitbucket-app-password` | Bitbucket App Password | High |
| `circleci-api-token` | CircleCI API Token (CCIPVJ_ prefix) | High |
| `heroku-api-key` | Heroku API Key | High |

### Communication & Collaboration

| Rule ID | Description | Severity |
|---|---|---|
| `slack-token` | Slack Token (xoxb-/xoxa-/xoxp-/xoxr-/xoxs- prefixes) | High |
| `slack-webhook` | Slack Incoming Webhook URL | High |
| `discord-bot-token` | Discord Bot Token | High |
| `discord-webhook` | Discord Webhook URL | Medium |
| `telegram-bot-token` | Telegram Bot Token | High |
| `atlassian-api-token` | Atlassian API Token (Jira/Confluence) | High |
| `notion-integration-token` | Notion Integration Token | Medium |

### Payments & E-Commerce

| Rule ID | Description | Severity |
|---|---|---|
| `stripe-secret-key` | Stripe Secret Key (sk_live_/sk_test_/rk_live_/rk_test_ prefixes) | Critical |
| `stripe-publishable-key` | Stripe Publishable Key (pk_live_/pk_test_ prefixes) | Low |
| `shopify-access-token` | Shopify Access Token (shpat_ prefix) | High |

### AI/ML Providers

| Rule ID | Description | Severity |
|---|---|---|
| `openai-api-key` | OpenAI API Key (sk- prefix, 48 chars) | Critical |
| `anthropic-api-key` | Anthropic API Key (sk-ant- prefix) | Critical |
| `huggingface-token` | HuggingFace Access Token (hf_ prefix) | High |

### Email & Messaging

| Rule ID | Description | Severity |
|---|---|---|
| `sendgrid-api-key` | SendGrid API Key (SG. prefix) | High |
| `mailgun-api-key` | Mailgun API Key (key- prefix) | High |
| `mailchimp-api-key` | Mailchimp API Key (hex-us## format) | High |

### Monitoring & Observability

| Rule ID | Description | Severity |
|---|---|---|
| `datadog-api-key` | Datadog API Key | High |
| `new-relic-license-key` | New Relic License Key | High |
| `pagerduty-api-key` | PagerDuty API Key | High |
| `opsgenie-api-key` | Opsgenie API Key | High |

### Auth & Identity

| Rule ID | Description | Severity |
|---|---|---|
| `auth0-api-token` | Auth0 API Token | High |
| `okta-api-token` | Okta API Token | High |

### Hosting & Backend

| Rule ID | Description | Severity |
|---|---|---|
| `vercel-token` | Vercel Access Token | High |
| `netlify-token` | Netlify Access Token | High |
| `supabase-service-key` | Supabase Service Key (sbp_ prefix) | High |
| `cloudflare-api-key` | Cloudflare API Key | High |
| `cloudflare-api-token` | Cloudflare API Token | High |

### Social & Developer Platforms

| Rule ID | Description | Severity |
|---|---|---|
| `twitch-client-secret` | Twitch Client Secret | High |
| `twitter-bearer-token` | Twitter/X Bearer Token | High |
| `facebook-app-secret` | Facebook App Secret | High |
| `linkedin-client-secret` | LinkedIn Client Secret | High |
| `linear-api-key` | Linear API Key (lin_api_ prefix) | High |
| `figma-token` | Figma Access Token | Medium |
| `npm-token` | npm Access Token (npm_ prefix) | High |

### Database Connection Strings

| Rule ID | Description | Severity |
|---|---|---|
| `postgres-connection-string` | PostgreSQL connection string with embedded credentials | High |
| `mysql-connection-string` | MySQL connection string with embedded credentials | High |
| `mongodb-connection-string` | MongoDB connection string with embedded credentials | High |
| `redis-connection-string` | Redis connection string with embedded credentials | High |

### Cryptographic Keys & Tokens

| Rule ID | Description | Severity |
|---|---|---|
| `private-key-pem` | PEM-Encoded Private Key (RSA/EC/DSA/OpenSSH/PGP/Encrypted) | Critical |
| `jwt` | JSON Web Token (eyJ header prefix) | Medium |

### Generic / Catch-All

| Rule ID | Description | Severity |
|---|---|---|
| `generic-bearer-token` | Generic Bearer Token assignment | Low |
| `generic-api-key-assignment` | Generic API Key assignment (api_key/apikey = ...) | Low |
| `generic-high-entropy` | High-entropy string assigned to key/token/secret-like variables (Shannon entropy) | Low |

---

## Live Verification Providers

PledgeGuard can verify matched secrets against provider APIs to determine if they are **Active**, **Inactive**, **Unknown**, or if verification **Error**ed. Verification is opt-in via `--verify` or `--only-verified`.

| Provider | Rule IDs Verified | Method |
|---|---|---|
| **GitHub** | `github-pat`, `github-fine-grained-pat` | `GET /user` with token auth |
| **GitLab** | `gitlab-pat`, `gitlab-token` | `GET /api/v4/user` with bearer |
| **Slack** | `slack-token` | `POST /api/auth.test` with bearer |
| **Stripe** | `stripe-secret-key` | `GET /v1/customers?limit=1` with bearer |
| **npm** | `npm-token` | `GET /-/npm/v1/user` with bearer |
| **DigitalOcean** | `digitalocean-pat`, `digitalocean-token` | `GET /v2/account` with bearer |
| **Telegram** | `telegram-bot-token` | `GET /bot{token}/getMe` |
| **Twilio** | `twilio-api-key`, `twilio-account-sid`, `twilio-auth-token` | `GET /Accounts.json` with bearer |
| **OpenAI** | `openai-api-key` | `GET /v1/models` with bearer |
| **Anthropic** | `anthropic-api-key` | `GET /v1/models` with `x-api-key` header |
| **PyPI** | `pypi-api-token` | `GET /pypi/user/info/` with bearer |
| **Docker Hub** | `dockerhub-token` | `GET /v2/userinfo/` with bearer |
| **SendGrid** | `sendgrid-api-key` | `GET /v3/user/account` with bearer |
| **Mailgun** | `mailgun-api-key` | `GET /v4/domains` with bearer |
| **Mailchimp** | `mailchimp-api-key` | `GET /3.0/ping` with bearer (datacenter extracted from key) |
| **Opsgenie** | `opsgenie-api-key` | `GET /v2/user` with GenieKey header |
| **PagerDuty** | `pagerduty-api-key` | `GET /users` with Token header |
| **Google API** | `google-api-key` | `GET /storage/v1/b` with key as query param |
| **Google OAuth** | `google-oauth-access-token` | `GET /oauth2/v1/userinfo` with bearer |
| **HuggingFace** | `huggingface-token` | `GET /api/whoami-v2` with bearer |
| **Shopify** | `shopify-access-token` | `GET /admin/api/shop.json` with X-Shopify-Access-Token |
| **Heroku** | `heroku-api-key` | `GET /account` with bearer |
| **Vercel** | `vercel-token` | `GET /v2/user` with bearer |
| **Datadog** | `datadog-api-key` | `GET /api/v1/validate` with DD-API-KEY header |
| **Cloudflare** | `cloudflare-api-token` | `GET /user/tokens/verify` with bearer |
| **Linear** | `linear-api-key` | `POST /graphql` with API key |
| **Okta** | `okta-api-token` | `GET /api/v1/users/me` with SSWS header |
| **Auth0** | `auth0-api-token` | `GET /userinfo` with bearer |
| **Supabase** | `supabase-service-key` | `GET /v1/projects` with bearer |
| **CircleCI** | `circleci-api-token` | `GET /v2/me` with Circle-Token header |
| **Discord** | `discord-bot-token` | `GET /users/@me` with bearer |
| **Atlassian** | `atlassian-api-token` | `GET /me` with bearer |
| **New Relic** | `new-relic-license-key` | `GET /v2/user.json` with Api-Key header |
| **Notion** | `notion-integration-token` | `GET /v1/users` with bearer |

---

## Output Formats

| Format | CLI Flag | Use Case |
|---|---|---|
| **Table** | `--format table` | Default human-readable terminal output |
| **JSON** | `--format json` | Machine-readable, piping to `jq`, custom processing |
| **SARIF** | `--format sarif` | GitHub Code Scanning, Azure DevOps, SonarQube integration |
| **CSV** | `--format csv` | Spreadsheet analysis, SIEM ingestion, reporting |
| **JUnit** | `--format junit` | CI/CD test result integration (Jenkins, GitLab CI, etc.) |
| **Template** | `--format template` | Custom output via `{{.Field}}` template syntax |

---

## Scanning Sources

| Source | How to Use | Description |
|---|---|---|
| **Working tree** | `pledgeguard scan <path>` | Scan files in a directory or single file |
| **Stdin** | `pledgeguard scan -` | Read file contents from stdin |
| **Git history** | `pledgeguard history <path>` | Scan all commits across all refs for secrets in added lines |
| **Docker images** | `scan_docker_image()` API | Scan Docker image tarballs (from `docker save`) for secrets in layers |
| **GitHub repos** | `scan_github_repo()` API | Scan remote GitHub repos via REST API (no local clone needed) |
| **GitLab repos** | `scan_gitlab_repo()` API | Scan remote GitLab repos via REST API |
| **S3 buckets** | `scan_s3_bucket()` API | Scan AWS S3 bucket objects for secrets |
| **GCS buckets** | `scan_gcs_bucket()` API | Scan Google Cloud Storage bucket objects for secrets |
| **Archives** | `scan_archive()` API | Scan `.zip`, `.tar`, `.tar.gz` archives for secrets in contained files |
| **Base64-encoded** | Automatic during scan | Recursive base64 decoding (up to 2 levels) to find encoded secrets |

---

## CLI Flags

### `scan` subcommand

| Flag | Description |
|---|---|
| `--format <table\|json\|sarif\|csv\|junit\|template>` | Output format (default: table) |
| `--min-severity <low\|medium\|high\|critical>` | Minimum severity to report (default: low) |
| `--no-redact` | Show full secret values (default: redacted) |
| `--fail-on-findings` | Exit non-zero if findings are present (CI gate) |
| `--plugin-dir <dir>` | Load `.wasm` plugin detectors (repeatable) |
| `--show-all` | Include likely false positives (hidden by default) |
| `--verify` | Call provider APIs to check if secrets are active |
| `--baseline <path>` | Suppress findings matching a baseline file |
| `--save-baseline <path>` | Save current findings as a baseline file |
| `--config <path>` | Load custom detector rules from a TOML config file |
| `--report-file <path>` | Write output to a file instead of stdout |
| `--verbose` | Print scan progress and stats to stderr |
| `--ignore-path <pattern>` | Glob patterns to ignore during scan (repeatable) |
| `--enable-rule <id>` | Only run rules with the given IDs (repeatable) |
| `--only-verified` | Only show findings verified as Active (implies `--verify`) |
| `--timeout <seconds>` | Scan timeout in seconds (default: 300) |

### `history` subcommand

Supports the same flags as `scan` (except `--ignore-path`), plus scans git commit history across all refs.

### `mcp` subcommand

| Flag | Description |
|---|---|
| `--plugin-dir <dir>` | Load `.wasm` plugin detectors (repeatable) |

### `install-pre-commit` subcommand

| Flag | Description |
|---|---|
| `--force` | Overwrite existing pre-commit hook |
| `path` | Git repository path (default: `.`) |

---

## Configuration File (`pledgeguard.toml`)

Custom rules can be defined in a TOML config file and loaded with `--config`.

### Custom Rule Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique rule identifier |
| `description` | string | Yes | Human-readable description |
| `severity` | string | Yes | `low`, `medium`, `high`, or `critical` |
| `pattern` | string | Yes | Regex pattern to match |
| `prefilter` | [string] | No | Aho-Corasick prefilter patterns for fast scanning |
| `entropy` | float | No | Shannon entropy threshold (0.0–6.0); matches below this are discarded |
| `secretGroup` | int | No | Capture group index to extract as the secret (default: full match) |
| `path` | string | No | Regex to filter which file paths this rule applies to |
| `allowlists` | [ConfigAllowlist] | No | Per-rule allowlist entries to suppress matches |

### Allowlist Fields

| Field | Type | Description |
|---|---|---|
| `regexes` | [string] | Regex patterns; matched secrets matching these are suppressed |
| `paths` | [string] | Regex patterns; findings in matching file paths are suppressed |
| `stopwords` | [string] | Literal strings; matched secrets containing these are suppressed |

### Global Config

| Field | Type | Description |
|---|---|---|
| `rules` | [CustomRule] | List of custom rules |
| `extend` | string | Path to another config file to extend (rules are merged) |
| `allowlist` | ConfigAllowlist | Global allowlist applied to all findings |

### Example

```toml
[[rules]]
id = "custom-api-key"
description = "My Custom API Key"
severity = "high"
pattern = '\bMYKEY_[A-Za-z0-9]{32}\b'
prefilter = ["MYKEY_"]
entropy = 3.5
secretGroup = 1

[[rules.allowlists]]
regexes = ['EXAMPLE$', 'test.*']

[[rules]]
id = "internal-token"
description = "Internal Service Token"
severity = "critical"
pattern = '\bINT_[A-Fa-f0-9]{40}\b'
prefilter = ["INT_"]
path = '\.env$'

[allowlist]
paths = ['vendor/.*', 'node_modules/.*']
```

---

## False-Positive Reduction

| Layer | Description | Scope |
|---|---|---|
| **Lexical heuristic** | Flags findings in same-line comments or test/fixture/example paths | All files |
| **AST-based refinement** | Uses oxc parser for accurate comment span detection on JS/TS | `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts` |
| **Per-rule entropy threshold** | Discards matches below a Shannon entropy threshold | Configurable per rule |
| **Per-rule allowlists** | Suppresses matches by regex, path, or stopwords | Configurable per rule |
| **Global allowlist** | Suppresses matches across all rules | Configurable in `pledgeguard.toml` |
| **Inline comment suppression** | `pledgeguard:allow` in a comment suppresses findings on that line | All files |
| **Baseline mode** | Suppresses findings matching a previously saved baseline | All scans |

---

## WASM Plugin System

Custom detectors can be loaded from `.wasm` modules at runtime via `--plugin-dir`. Plugins run in a `wasmtime` sandbox and implement the PledgeGuard detector ABI. See `examples/plugins/example-plugin/` for a minimal working plugin.

---

## MCP Server

`pledgeguard mcp` runs a Model Context Protocol server over stdio (JSON-RPC 2.0), exposing:

| Tool | Description |
|---|---|
| `scan_path` | Scan a file or directory for secrets |
| `scan_git_history` | Scan git history for secrets |

---

## CI/CD Integrations

| Platform | Integration |
|---|---|
| **GitHub Actions** | Workflow template available at `.github/workflows/pledgeguard.yml` |
| **GitLab CI** | Template available at `gitlab-ci.yml` |
| **Pre-commit hook** | `pledgeguard install-pre-commit` installs a git hook |
| **SARIF output** | Compatible with GitHub Code Scanning, Azure DevOps |
| **JUnit output** | Compatible with Jenkins, GitLab CI test reporting |
| **Docker** | Multi-stage Dockerfile available for containerized scanning |

---

## Platforms Not Yet Supported (Roadmap)

The following are supported by competitors (TruffleHog, Gitleaks) but not yet by PledgeGuard:

| Feature | Competitor | Status |
|---|---|---|
| **AWS STS verification** | TruffleHog | Planned — requires AWS SDK signing |
| **Azure AD verification** | TruffleHog | Planned — requires OAuth2 flow |
| **GCP IAM verification** | TruffleHog | Planned — requires Google Cloud auth |
| **Shopify verification** | TruffleHog | Planned |
| **Postman verification** | TruffleHog | Planned |
| **Snowflake verification** | TruffleHog | Planned |
| **`--only-verified` flag** | TruffleHog | Planned — show only verified results |
| **Confluence scanning** | TruffleHog | Under consideration |
| **Slack-as-source scanning** | TruffleHog | Under consideration |
| **Syslog scanning** | TruffleHog | Under consideration |
| **Incremental/PR-scoped history** | TruffleHog/Gitleaks | Planned — `--since-commit` flag |
| **CEL-based rule validation** | Betterleaks | Under consideration |
| **Python/Go/Ruby AST refinement** | — | Planned — currently JS/TS only |
