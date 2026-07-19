# PledgeGuard

Rust-native secret scanner — a TruffleHog/Gitleaks alternative.

[![CI](https://github.com/pledgeandgrow/pledgeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/pledgeandgrow/pledgeguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-red)](https://github.com/sponsors/pledgeandgrow)

## Status

**v0.2.0 — comprehensive feature set.** PledgeGuard is a working secret
scanner with 708 built-in detectors, 34 live verification providers, git history
scanning, WASM plugins, MCP server, 6 output formats (Table/JSON/SARIF/CSV/JUnit/Template),
baseline/allowlist mode, pre-commit hook installer, AST-based false-positive
refinement for JS/TS, custom TOML rules with entropy/allowlists/path filters,
inline comment suppression, recursive base64 decoding, composite/proximity rules,
Docker image scanning, GitHub/GitLab API scanning, S3/GCS bucket scanning, and
archive (zip/tar) scanning.

> **Full list of supported detectors, verifiers, and platforms:** see **[SUPPORT.md](docs/SUPPORT.md)**
>
> **Future providers roadmap (competitor comparison):** see **[PROVIDERS-FUTURE.md](docs/PROVIDERS-FUTURE.md)**

It is functional and tested but **not yet production-hardened** — detector
regexes may need tuning for precision/recall on large codebases, and it has
not been audited against real-world repositories at scale.

> **New here?** Read the **[Tutorial](docs/TUTORIAL.md)** for a hands-on walkthrough.

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

708 detectors covering AWS (Access Key, Secret, Session Token, MWS, Bedrock,
Account ID), Azure (Storage, SAS, Client Secret, AD/Entra ID, Batch, Function,
DevOps PAT, Cosmos DB), Google Cloud (API Key, OAuth, Service Account, Client ID,
Gemini/PaLM), Alibaba, Tencent, DigitalOcean, IBM Cloud, Oracle Cloud, Scaleway,
Vultr, Linode, Cloudflare (API Key, Token, CA Key, Global),
GitHub, GitLab, Bitbucket (App Password, Client ID/Secret, DataCenter), Slack,
Discord (Bot Token, Webhook, Client ID/Secret), Telegram, Microsoft Teams,
Atlassian (API Token, Jira), Notion, Gitter, Webex, Intercom, HelpScout,
HelpCrunch, Canny, Pipedrive, Beamer, Frame.io, Zeplin, Trello, Asana
(Client ID/Secret, PAT),
Stripe (Secret, Publishable, Restricted), Shopify (Access, Shared Secret,
Custom/Private App), PayPal (OAuth, Client Secret), Square (Token, App Secret),
Coinbase, RazorPay, Paystack, Plaid (Token, Key), Flutterwave (Secret, Encryption),
Paddle, FastSpring, Sellfy, Duffel, EasyPost (API, Test), Finicity (Token, Secret),
Freshbooks, GoCardless, Taxjar, Etsy, PostHog, Amplitude, Segment, Mixpanel, Heap,
Pendo, Keen.io, Fathom, Plausible, Hotjar, FullStory, Bitly, Calendly,
Calendarific, AppFollow, Appcues, Mailchimp, OpenAI, Anthropic (API, Admin),
HuggingFace, Cohere, Replicate, Stability AI, AssemblyAI, Clarifai, OpenRouter,
Together AI, Perplexity, Mistral, Groq, DeepSeek, ElevenLabs, SendGrid, Mailgun,
Postmark, Mailjet (Basic, SMS), Brevo/SendinBlue, Elastic Email, Pepipost,
Mailmodo, Verimail, ZeroBounce, Mailboxlayer, D7Networks, Sinch, MessageBird,
Vonage/Nexmo, Plivo, Postman, PubNub, Pusher, PushBullet, Doppler, Datadog
(API Key, Access Token), New Relic (License, Personal API Key), PagerDuty,
Opsgenie, Sentry, SumoLogic, Splunk Observability, AppOptics, Airbrake, LogDNA,
Loggly, Better Stack, Statuspage, UptimeRobot, Pingdom, Auth0 (API, Management,
OAuth), Okta, OneLogin, JumpCloud, Authress, Keycloak, FusionAuth, Stytch, Clerk,
WorkOS, Supabase (Service Key, Anon Key), Firebase (Token, FCM), KubeConfig,
HashiCorp Vault, 1Password (Secret Key, Service Account), Vercel, Netlify, Heroku,
WP Engine, Fastly, Akamai, Equinix, Fly.io, Railway, Render, Koyeb, Twitch
(Client Secret, Access Token), Twitter/X, Facebook (App Secret, Access Token,
OAuth), LinkedIn, Linear, Figma (Token, PAT), npm, PyPI, Docker Hub, Spotify,
YouTube, Flickr, Dropbox (API Secret, Long/Short-Lived Token), Reddit (Client
Secret, Access Token), Instagram, Pinterest, TikTok, Zoom, Zapier Webhook,
PostgreSQL, MySQL, MongoDB, Redis, JDBC, SQL Server, Elasticsearch, InfluxDB,
Couchbase, Cassandra, Neo4j, Supabase DB, PlanetScale, Neon, Turso, Convex,
Age Secret Key, Kubernetes Secret Manifest, Terraform Cloud, Ansible Vault,
Docker Registry, Harbor, Nexus, Confluent (Access Token, Secret Key), Databricks,
Snowflake, Dynatrace, LaunchDarkly, ConfigCat, Flagsmith, Shodan, AbuseIPDB,
AlienVault OTX, VirusTotal, Hunter.io, IPStack, MaxMind, CloudSight, RapidAPI,
ScrapingBee, ipinfo.io, Google Maps, MapBox, MapQuest, Here Maps, OpenCage,
HubSpot (API Key, OAuth), Salesforce OAuth2, Zendesk, Elastic Path, ButterCMS,
Contentful (Delivery, PAT), Sanity, Storyblok, Strapi, Airtable (API Key, PAT,
OAuth), Algolia Admin, Lokalise, Bitcoin (WIF), Ethereum, Solana, Infura, Alchemy,
Moralis, QuickNode, Bitfinex, Bittrex (Access, Secret),
Curl Authentication String, URI with Embedded Credentials, Generic OAuth Client
Secret, .env File Secrets, Firebase Web Config,
Twilio, Line (Messaging, Notify), Mattermost, WeChat, KakaoTalk, LiveAgent, Front,
RingCentral, TeleSign, TeamViewer, CometChat, Mesibo, Bulbul, Tyntec, Kaleyra,
Onbuka, ClickSend, Clockwork SMS, BombBomb, DFuse, ApiFonica, Mandrill, SparkPost,
MailerLite, ConvertKit, Omnisend, Customer.io, Moosend, Dotdigital, Dyspatch,
PostageApp, Nicereply, AutoPilot, Airship,
Freshworks, Close CRM, Copper CRM, Streak CRM, GrooveHQ, GetGist, Autoklose,
Salesflare, SalesBlink, Salescookie, Metrilo, RevampCRM, KarmaCRM, Less Annoying CRM,
NetHunt CRM, Nimble CRM, Apptivo CRM, Capsule CRM, Insightly CRM, Kylas CRM,
OnePageCRM, Prospect CRM, Really Simple Systems CRM, Central Station CRM, Teamgate,
Axonaut, FlowFlu, Clientary, Clinchpad, CompanyHub, Campayn, Hiveage, Billomat,
Alegra, Loyverse, CommerceJS, Snipcart, PartnerStack, Vouchery, Monday.com,
Smartsheets, Wrike, Apollo.io, UpLead, RocketReach, Clearbit, Brandfetch,
Leadfeeder, GetEmail, GetEmails, Skrappio, Powrbot,
ClickUp, Todoist, Shortcut, TMetric, Clockify, Everhour, Harvest, Humanity,
Toggl Track, RunRunIt, Workstack, EasyInsight, Dovico, Mavenlink, Float,
Daily.co, T.ly, Rebrandly, Timezone, Jotform,
Typeform, SurveySparrow, Survicate, Delighted, Feedier, Zonka Feedback,
Satismeter (Project, Write), Simplesat, SurveyAnyplace, SurveyBot, Qualaroo,
CustomerGuru, Abyssale, Magnetic, Refiner, Simvoly, Checkmarket, Webengage,
Twelve Data, Fixer.io, Alpha Vantage, Tradier, Finnhub, Tiingo, Finage,
IEX Cloud, Intrinio, Financial Modeling Prep, Nasdaq Data Link, Qubole,
Enigma, Data.gov, Stockdata, Marketstack, Commodities, Baremetrics, Dwolla,
WePay, Checkout.com, Paymongo, Avalara, Carbon Interface, Currency Layer,
Exchange Rates, CurrencyScoop, CurrencyFreaks, Country Layer, FX Market,
Currency Cloud,
Kraken, Poloniex, BitMEX, CoinAPI, Coinlayer, Coinlib, CryptoCompare,
Bitcoin Average, World Coin Index, Glassnode, Tatum.io, Ethplorer, NFTPort,
Messari, CoinGecko,
OpenWeather, WeatherStack, AccuWeather, World Weather, Tomorrow.io,
AirVisual, Visual Crossing, Stormglass, Aeris Weather, Ambee, OpenUV,
Edge Token, Calendly Webhook,
TomTom, Geoapify, Geocodify, Geocode, Geocodio, PositionStack, LocationIQ,
Graphhopper, SmartyStreets, Route4me, ZipCode, OnWater, GeoIPify, IPGeolocation,
IPinfoDB, ipify, ipapi, VPN, DNS Check, Walk Score, Besttime, Hypertrack, Fulcrum, Samsara,
Unsplash, Pixabay, Gyazo, Imgur, Shutterstock, IconFinder, ImageKit, Bannerbear,
Imagga, Face++, SkyBiometry, Cloudmersive, ScreenshotAPI, ScreenshotLayer, Browshot,
LinkPreview, Mixcloud, RAWG, Strava, FourSquare, TicketMaster, Riot Games, Cricket,
All Sports, SportsMonk, Edamam, Nutritionix, Spoonacular, Calorie Ninja, Protocols.io,
HypeAuditor, NewsAPI, Newscatcher, Currents, Guardian, Aylien, Cicero, Lexigram,
Blogger, MediaStack, ClickHelp, Storychief, Noticeable, ReadMe, Pastebin, Crowdin,
Alconost, Gengo, HappyScribe, RiteKit, RubyGems, Codacy, Coveralls, SauceLabs, Bitbar,
Bugsnag, Adafruit IO, Apify, Keygen, Aiven, File.io, Flat.io, Dynalist, Sheety, Swell,
M3o, JSONbin, UserStack, PureStake, Host, BaseAPI, SslMate, Adobe IO, EdenAI, Deepgram,
Voicegain, Audd.io, OwlBot, DetectLanguage, LanguageLayer, ParallelDots, Veriphone,
Verifier, API2Cart, APIDeck, APIFlash, Fleetbase, Agora, Yandex, Artsy, Blit.app,
Censys, SecurityTrails, URLScan, Aletheia, Whoxy, Mailsac, LoginRadius, Rev,
YouNeedABudget, Filestack, Bubble, Shopee, Kite Connect, Veeva Vault, Cloudways,
Duda, Yext, ContentStack, Surge, Kairos, FullContact, Eversign, NetCore, Bored,
HTML2PDF, PDF Layer, PDF Shift, Restpack (HTML-to-PDF, Screenshot), Documo, ClustDoc,
PandaDoc, HelloSign, Juro, YouSign, VatLayer, UPC Database,
ScraperAPI, ScrapingDog, ScrapeOwl, WebScraping, ZenScrape, ZenSerp, SerpStack,
ScraperBox, ScrapingAnt, ScrapeStack, ProxyCrawl,
Debounce, Kickbox, IPQuality, Roaring, OOPSpam, Numverify,
Webflow, Squarespace, Siteleaf, GraphCMS, Kontent,
Wakatime, Ubidots, Raven, Guru, Hive, Technical Analysis, Impala, Unplugg,
Cloverly, Flight, AviationStack, Distribusion, Words, Holiday, Amadeus,
Exchange Rate, Abstract,
Auth0, Okta, Vercel, Netlify, Supabase, CircleCI, Heroku, Travis CI, DroneCI,
Buildkite, TeamCity, Jenkins, GoCD, ArgoCD, Spinnaker, Harness, Codecov,
SonarQube, Snyk, Artifactory, Terraform Cloud, Pivotal Tracker, Clojars, Linear,
Figma, Twitch, Twitter/X, Facebook, LinkedIn, npm, PEM private keys, JWTs,
PostgreSQL/MySQL/MongoDB/Redis connection strings, and generic entropy-based
detection.

See **[SUPPORT.md](docs/SUPPORT.md)** for the complete list.

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

`--verify` calls provider APIs to check whether a matched secret is still active.
34 providers are supported: GitHub, GitLab, Slack, Stripe, npm, DigitalOcean,
Telegram, Twilio, OpenAI, Anthropic, PyPI, Docker Hub, SendGrid, Mailgun,
Mailchimp, Opsgenie, PagerDuty, Google API, Google OAuth, HuggingFace, Shopify,
Heroku, Vercel, Datadog, Cloudflare, Linear, Okta, Auth0, Supabase, CircleCI,
Discord, Atlassian, New Relic, and Notion. Use `--only-verified` to show only
findings confirmed as Active. See **[SUPPORT.md](docs/SUPPORT.md)** for the full list.

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
- **Live verification covers 34 providers** — see [SUPPORT.md](docs/SUPPORT.md) for the full list. AWS keys, PEM keys, JWTs, and connection strings cannot be verified.
- **Docker/GitHub/GitLab/S3/GCS scanning via library API** — not yet wired to CLI subcommands.
- **Baseline files contain raw secret values** — treat as sensitive.
- **Early-stage / unaudited** — detector regexes may need tuning; limited real-world testing.

## Sponsors

If PledgeGuard saves you from leaking a secret, consider supporting development:

- **[GitHub Sponsors](https://github.com/sponsors/pledgeandgrow)** — monthly or one-time
- **[Buy Me a Coffee](https://buymeacoffee.com/pledgeandgrow)** — one-time

## License

MIT
