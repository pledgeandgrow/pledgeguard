# PledgeGuard — Future Providers Roadmap

This document lists all secret providers that PledgeGuard **could** support in the future, based on a comprehensive comparison with competitors (TruffleHog 700+ detectors, Gitleaks 150+ rules). Providers are organized by category and marked with status:

- **Supported** — already implemented as a detector and/or verifier
- **Detector only** — we detect the secret but don't verify it live
- **Future** — not yet implemented; listed for roadmap planning

---

## Cloud Providers

### AWS

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| AWS Access Key ID (AKIA/ASIA/...) | **Supported** | Future | Verification requires STS GetCallerIdentity with signed requests |
| AWS Secret Access Key | **Supported** | Future | Paired with Access Key ID; needs AWS SigV4 signing |
| AWS Session Token | **Supported** | Future | Needs STS API with temporary credentials |
| AWS MWS Auth Token | **Supported** | Future | Amazon Marketplace Web Service |
| AWS Amazon Bedrock API Key (long-lived) | **Supported** | Future | ABSK prefix, 109+ chars |
| AWS Amazon Bedrock API Key (short-lived) | **Supported** | Future | bedrock-api-key- prefix |
| AWS Account ID | **Supported** | N/A | 12-digit numeric, Low severity |

### Azure

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Azure Storage Connection String | **Supported** | Future | Could verify by listing blobs |
| Azure SAS Token | **Supported** | Future | |
| Azure Client Secret | **Supported** | Future | Needs Azure AD OAuth2 token endpoint |
| Azure AD Client Secret | **Supported** | Future | Entra ID, Q~ marker pattern |
| Azure Batch Key | **Supported** | Future | BatchAccountKey= assignment |
| Azure Function Key | **Supported** | Future | FUNCTIONS_KEY/function_key/code= assignment |
| Azure DevOps PAT | **Supported** | Future | 52-char alphanumeric near devops/vsts context |
| Azure Cosmos DB Key | **Supported** | Future | AccountKey= with 88-char base64 |

### Google Cloud

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Google API Key (AIza) | **Supported** | **Supported** | |
| Google OAuth Access Token (ya29) | **Supported** | **Supported** | |
| Google Service Account JSON | **Supported** | Future | Verification: exchange key for OAuth2 token |
| GCP Service Account Key | **Supported** | Future | private_key field with PEM block |
| GCP OAuth Client ID | **Supported** | N/A | xxx-32chars.apps.googleusercontent.com, Medium severity |

### Other Cloud Providers

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Alibaba Cloud Access Key ID | **Supported** | Future | |
| Alibaba Cloud Secret Key | **Supported** | Future | 30-char base64 assignment |
| Tencent Cloud Secret ID | **Supported** | Future | |
| Tencent Cloud Secret Key | **Supported** | Future | 36-char assignment |
| DigitalOcean PAT | **Supported** | **Supported** | |
| DigitalOcean Spaces Key | **Supported** | Future | |
| IBM Cloud User Key | **Supported** | Future | 44-char assignment |
| Oracle Cloud (OCI) | **Supported** | Future | |
| Scaleway Key | **Supported** | Future | UUID format |
| Vultr API Key | **Supported** | Future | 36-char hex |
| Linode/Akamai Token | **Supported** | Future | 64-char hex |
| Cloudflare API Key | **Supported** | Future | |
| Cloudflare API Token | **Supported** | **Supported** | |
| Cloudflare CA Key | **Supported** | Future | v1.0- prefix |
| Cloudflare Global API Key | **Supported** | Future | 37-char hex |

---

## Version Control & CI/CD

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| GitHub PAT (ghp_) | **Supported** | **Supported** | |
| GitHub Fine-Grained PAT | **Supported** | **Supported** | |
| GitHub OAuth Token (gho_) | **Supported** | **Supported** | Covered by github-pat detector |
| GitHub App Token (ghu_/ghs_) | **Supported** | **Supported** | Covered by github-pat detector |
| GitHub Refresh Token (ghr_) | **Supported** | **Supported** | Covered by github-pat detector |
| GitHub Old PAT | **Supported** | Future | Legacy 40-char hex format |
| GitLab PAT (glpat-) | **Supported** | **Supported** | |
| GitLab Pipeline Trigger Token | **Supported** | Future | |
| GitLab Runner Registration Token | **Supported** | Future | |
| Bitbucket App Password | **Supported** | Future | |
| Bitbucket Client ID | **Supported** | Future | |
| Bitbucket Client Secret | **Supported** | Future | |
| Bitbucket Data Center Token | **Supported** | Future | |
| CircleCI API Token | **Supported** | **Supported** | |
| Travis CI Token | **Supported** | Future | |
| DroneCI Access Token | **Supported** | Future | |
| Buildkite Token | **Supported** | Future | bk[cuor]_ prefix |
| TeamCity Token | **Supported** | Future | |
| Jenkins API Token | **Supported** | Future | |
| GoCD Token | **Supported** | Future | |
| ArgoCD Token | **Supported** | Future | |
| Spinnaker Token | **Supported** | Future | |
| Harness API Key | **Supported** | Future | |
| Codecov Access Token | **Supported** | Future | |
| SonarQube Token | **Supported** | Future | squ_ prefix |
| Snyk API Key | **Supported** | Future | |
| Artifactory API Key | **Supported** | Future | AKC prefix |
| Artifactory Reference Token | **Supported** | Future | cmV prefix |
| Terraform Cloud Token | **Supported** | Future | atlasv1. suffix |
| Pivotal Tracker Token | **Supported** | Future | |
| Clojars API Token | **Supported** | Future | CLOJARS_ prefix |

---

## Communication & Collaboration

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Slack Token (xox) | **Supported** | **Supported** | |
| Slack Webhook URL | **Supported** | Future | TruffleHog verifies by sending malformed JSON |
| Discord Bot Token | **Supported** | **Supported** | |
| Discord Webhook URL | **Supported** | Future | |
| Discord Client ID | **Supported** | Future | 18-digit assignment |
| Discord Client Secret | **Supported** | Future | 32-char assignment |
| Telegram Bot Token | **Supported** | **Supported** | |
| Microsoft Teams Webhook | **Supported** | Future | webhook.office.com URL |
| Atlassian API Token | **Supported** | **Supported** | |
| Atlassian (Jira) Token | **Supported** | Future | Jira-specific API token |
| Notion Integration Token | **Supported** | **Supported** | |
| Gitter Access Token | **Supported** | Future | 40-char assignment |
| Webex Token | **Supported** | Future | |
| Intercom Token | **Supported** | Future | |
| HelpScout Token | **Supported** | Future | |
| HelpCrunch Token | **Supported** | Future | |
| Canny.io Token | **Supported** | Future | |
| Pipedrive Token | **Supported** | Future | 40-char assignment |
| Beamer API Token | **Supported** | Future | |
| Frame.io API Token | **Supported** | Future | fio- prefix |
| Zeplin Token | **Supported** | Future | |
| Trello API Key | **Supported** | Future | 32-char assignment |
| Asana Client ID | **Supported** | Future | |
| Asana Client Secret | **Supported** | Future | |
| Asana Personal Access Token | **Supported** | Future | |

---

## Payments & E-Commerce

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Stripe Secret Key | **Supported** | **Supported** | |
| Stripe Publishable Key | **Supported** | Future | Publishable keys are not secret |
| Stripe Restricted Key (rk_) | **Supported** | **Supported** | |
| Shopify Access Token (shpat_) | **Supported** | **Supported** | |
| Shopify Shared Secret (shpss_) | **Supported** | Future | |
| Shopify Custom App Token (shpca_) | **Supported** | Future | |
| Shopify Private App Token (shppa_) | **Supported** | Future | |
| PayPal OAuth Token | **Supported** | Future | |
| PayPal Client Secret | **Supported** | Future | 80-char assignment |
| Square Token | **Supported** | Future | sq0atp- prefix |
| Square App Token | **Supported** | Future | sq0csp- prefix |
| Coinbase Access Token | **Supported** | Future | |
| RazorPay Key | **Supported** | Future | rzp_ prefix |
| Paystack Token | **Supported** | Future | sk_live_/sk_test_ prefix |
| Plaid Token | **Supported** | Future | access-sandbox/production/development- prefix |
| Plaid Key | **Supported** | Future | Client ID assignment |
| Flutterwave Secret Key | **Supported** | Future | FLWSECK- prefix |
| Flutterwave Encryption Key | **Supported** | Future | FLWSECK_TEST- prefix |
| Paddle Token | **Supported** | Future | |
| FastSpring Token | **Supported** | Future | |
| Sellfy Token | **Supported** | Future | |
| Duffel API Token | **Supported** | Future | duffel_ prefix |
| EasyPost API Token | **Supported** | Future | EZ prefix |
| EasyPost Test API Token | **Supported** | Future | EZTK prefix |
| Finicity API Token | **Supported** | Future | |
| Finicity Client Secret | **Supported** | Future | |
| Freshbooks Access Token | **Supported** | Future | |
| GoCardless API Token | **Supported** | Future | |
| Taxjar API Key | **Supported** | Future | |
| Etsy API Key | **Supported** | Future | Deprecated |
| Amazon MWS Token | **Supported** | Future | Already covered by aws-mws-auth-token |

---

## AI/ML Providers

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| OpenAI API Key (sk-) | **Supported** | **Supported** | |
| Anthropic API Key (sk-ant-) | **Supported** | **Supported** | |
| Anthropic Admin API Key | **Supported** | Future | sk-ant-admin prefix |
| HuggingFace Token (hf_) | **Supported** | **Supported** | |
| Google Gemini / PaLM Key | **Supported** | Future | AIza prefix |
| Cohere API Key | **Supported** | Future | |
| Replicate API Token | **Supported** | Future | r8_ prefix |
| Stability AI Key | **Supported** | Future | |
| AssemblyAI Key | **Supported** | Future | |
| Clarifai Key | **Supported** | Future | |
| OpenRouter Key | **Supported** | Future | sk-or- prefix |
| Together AI Key | **Supported** | Future | |
| Perplexity API Key | **Supported** | Future | pplx- prefix |
| Mistral API Key | **Supported** | Future | |
| Groq API Key | **Supported** | Future | gsk_ prefix |
| DeepSeek API Key | **Supported** | Future | |
| ElevenLabs API Key | **Supported** | Future | |

---

## Email & Messaging

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| SendGrid API Key (SG.) | **Supported** | **Supported** | |
| Mailgun API Key (key-) | **Supported** | **Supported** | |
| Mailchimp API Key | **Supported** | **Supported** | |
| Postmark Token | **Supported** | Future | po_ prefix |
| MailJet Basic Auth | **Supported** | Future | MJ prefix |
| MailJet SMS | **Supported** | Future | |
| SendinBlue / Brevo Token | **Supported** | Future | xkeysib- prefix |
| Elastic Email Key | **Supported** | Future | |
| Pepipost Token | **Supported** | Future | |
| Mailmodo Token | **Supported** | Future | |
| Verimail Token | **Supported** | Future | |
| ZeroBounce Token | **Supported** | Future | |
| Mailboxlayer Token | **Supported** | Future | |
| D7Network Token | **Supported** | Future | |
| Sinch Message Token | **Supported** | Future | |
| MessageBird Token | **Supported** | Future | |
| Vonage/Nexmo API Key | **Supported** | Future | |
| Plivo Token | **Supported** | Future | |
| Postman API Key | **Supported** | Future | PMAK- prefix |
| PubNub Publish/Subscription Key | **Supported** | Future | sub-c- prefix |
| Pusher Channel Key | **Supported** | Future | |
| PushBullet API Key | **Supported** | Future | |
| Doppler API Token | **Supported** | Future | dp.pt. prefix |

---

## Monitoring & Observability

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Datadog API Key | **Supported** | **Supported** | |
| Datadog Access Token (dt0) | **Supported** | Future | dt0 format |
| New Relic License Key | **Supported** | **Supported** | |
| New Relic Personal API Key | **Supported** | Future | NRAK prefix |
| PagerDuty API Key | **Supported** | **Supported** | |
| Opsgenie API Key | **Supported** | **Supported** | |
| Sentry Token | **Supported** | Future | sntrys_ prefix |
| SumoLogic Key | **Supported** | Future | |
| Splunk Observability Token | **Supported** | Future | SPL prefix |
| AppOptics Token | **Supported** | Future | |
| Airbrake Project/User Key | **Supported** | Future | |
| LogDNA Key | **Supported** | Future | |
| Loggly Token | **Supported** | Future | |
| Better Stack / Better Uptime Key | **Supported** | Future | |
| Statuspage API Key | **Supported** | Future | |
| UptimeRobot API Key | **Supported** | Future | |
| Pingdom Token | **Supported** | Future | |

---

## Analytics & Product

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| PostHog API Key | **Supported** | Future | phc_ prefix |
| Amplitude API Key | **Supported** | Future | |
| Segment API Key | **Supported** | Future | |
| Mixpanel Token | **Supported** | Future | |
| Heap API Key | **Supported** | Future | |
| Pendo Integration Key | **Supported** | Future | |
| Keen.io Key | **Supported** | Future | |
| Fathom Analytics Key | **Supported** | Future | |
| Plausible Analytics Key | **Supported** | Future | |
| Hotjar Token | **Supported** | Future | |
| FullStory Token | **Supported** | Future | |
| Amplitude Key | **Supported** | Future | Duplicate of Amplitude API Key |
| Bitly Access Token | **Supported** | Future | |
| Calendly API Key | **Supported** | Future | |
| Calendarific Token | **Supported** | Future | |
| AppFollow Token | **Supported** | Future | |
| Appcues Token | **Supported** | Future | |

---

## Auth & Identity

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Auth0 API Token | **Supported** | **Supported** | |
| Auth0 Management API Token | **Supported** | Future | |
| Auth0 OAuth Token | **Supported** | Future | |
| Okta API Token | **Supported** | **Supported** | |
| OneLogin Token | **Supported** | Future | |
| JumpCloud Token | **Supported** | Future | |
| Authress Service Client Key | **Supported** | Future | sc_ prefix |
| Keycloak Token | **Supported** | Future | |
| FusionAuth Token | **Supported** | Future | |
| Stytch Token | **Supported** | Future | |
| Clerk Token | **Supported** | Future | sk_ prefix |
| WorkOS Token | **Supported** | Future | |
| Supabase Service Key | **Supported** | **Supported** | |
| Supabase Anon Key | **Supported** | Future | eyJ JWT format |
| Firebase Token | **Supported** | Future | |
| Firebase Cloud Messaging Key | **Supported** | Future | AAAA prefix |
| KubeConfig | **Supported** | Future | client_key_data |
| HashiCorp Vault Token | **Supported** | Future | hvs./hvb./s. prefixes |
| 1Password Secret Key | **Supported** | Future | a3- format |
| 1Password Service Account Token | **Supported** | Future | ops_ prefix |
| Doppler Token | **Supported** | Future | dp.pt. prefix |

---

## Hosting & Backend

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Vercel Token | **Supported** | **Supported** | |
| Netlify Token | **Supported** | Future | |
| Heroku API Key | **Supported** | **Supported** | |
| Supabase Service Key | **Supported** | **Supported** | |
| WP Engine Token | **Supported** | Future | |
| Fastly API Key | **Supported** | Future | |
| Akamai Token | **Supported** | Future | |
| Equinix OAuth Token | **Supported** | Future | |
| Fly.io Token | **Supported** | Future | |
| Railway Token | **Supported** | Future | |
| Render Token | **Supported** | Future | rnd_ prefix |
| Koyeb Token | **Supported** | Future | |
| Edge Token | Future | Future | |

---

## Social & Developer Platforms

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Twitch Client Secret | **Supported** | Future | |
| Twitter/X Bearer Token | **Supported** | Future | |
| Facebook App Secret | **Supported** | Future | |
| Facebook Access Token | **Supported** | Future | EAAD prefix |
| Facebook OAuth Token | **Supported** | Future | |
| LinkedIn Client Secret | **Supported** | Future | |
| Linear API Key | **Supported** | **Supported** | |
| Figma Token | **Supported** | Future | |
| Figma Personal Access Token | **Supported** | Future | figd_ prefix |
| npm Token (npm_) | **Supported** | **Supported** | |
| PyPI Token (pypi-AgEI...) | **Supported** | Future | |
| Docker Hub Token | **Supported** | **Supported** | |
| Spotify Key | **Supported** | Future | |
| YouTube API Key | **Supported** | Future | AIza prefix |
| Twitch Access Token | **Supported** | Future | |
| Flickr Access Token | **Supported** | Future | |
| Dropbox API Secret | **Supported** | Future | |
| Dropbox Long-Lived Token | **Supported** | Future | sl. prefix |
| Dropbox Short-Lived Token | **Supported** | Future | sl. prefix |
| Reddit Client Secret | **Supported** | Future | |
| Reddit Access Token | **Supported** | Future | |
| Instagram Access Token | **Supported** | Future | IG prefix |
| Pinterest Token | **Supported** | Future | |
| TikTok Access Token | **Supported** | Future | |
| Zoom API Key/Secret | **Supported** | Future | |
| Calendly Webhook | Future | Future | |
| Zapier Webhook URL | **Supported** | Future | |

---

## Database & Data

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| PostgreSQL Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| MySQL Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| MongoDB Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| Redis Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| JDBC Connection String | **Supported** | Future | MySQL/PostgreSQL/SQL Server |
| SQL Server Connection String | **Supported** | Future | |
| Elasticsearch Connection | **Supported** | Future | |
| InfluxDB Token | **Supported** | Future | |
| Couchbase Connection String | **Supported** | Future | |
| Cassandra Connection | **Supported** | Future | |
| Neo4j Connection String | **Supported** | Future | |
| Supabase DB Connection | **Supported** | Future | |
| PlanetScale Token | **Supported** | Future | pscale_ prefix |
| Neon Database Token | **Supported** | Future | |
| Turso Token | **Supported** | Future | |
| Convex Token | **Supported** | Future | |

---

## DevOps & Infrastructure

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| PEM Private Key | **Supported** | Future | TruffleHog verifies by testing against GitHub/GitLab/Driftwood |
| Age Secret Key | **Supported** | Future | AGE-SECRET-KEY-1 prefix |
| Kubernetes Secret Manifest | **Supported** | Future | YAML with base64 data |
| HashiCorp Vault Token | **Supported** | Future | hvs./hvb./s. prefixes |
| HashiCorp Terraform Token | **Supported** | Future | |
| Ansible Vault Password | **Supported** | Future | |
| Docker Registry Token | **Supported** | Future | |
| Harbor Token | **Supported** | Future | |
| Nexus Token | **Supported** | Future | |
| Confluent Access Token | **Supported** | Future | |
| Confluent Secret Key | **Supported** | Future | |
| Databricks Token | **Supported** | Future | dapi prefix |
| Snowflake Token | **Supported** | Future | |
| Dynatrace API Token | **Supported** | Future | dt0c01 prefix |
| LaunchDarkly Key | **Supported** | Future | |
| ConfigCat Key | **Supported** | Future | |
| Flagsmith Key | **Supported** | Future | |

---

## Security & API Services

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Shodan API Key | **Supported** | Future | |
| AbuseIPDB Key | **Supported** | Future | |
| AlienVault OTX Key | **Supported** | Future | |
| VirusTotal API Key | **Supported** | Future | |
| Hunter.io API Key | **Supported** | Future | |
| IPStack Key | **Supported** | Future | |
| MaxMind License Key | **Supported** | Future | |
| CloudSight Key | **Supported** | Future | |
| Snyk API Key | **Supported** | Future | Already supported in CI/CD section |
| RapidAPI Key | **Supported** | Future | |
| ScrapingBee Key | **Supported** | Future | |
| ipinfo.io Token | **Supported** | Future | |

---

## Maps & Location

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Google Maps API Key | **Supported** | Future | AIza prefix (subset of Google API Key) |
| MapBox Token | **Supported** | Future | pk. prefix |
| MapQuest Key | **Supported** | Future | |
| Here Maps Key | **Supported** | Future | |
| OpenCage Key | **Supported** | Future | |

---

## CRM & Business

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| HubSpot API Key | **Supported** | Future | |
| HubSpot OAuth Token | **Supported** | Future | |
| Salesforce OAuth2 Token | **Supported** | Future | |
| Zendesk API Token | **Supported** | Future | |
| Intercom Token | **Supported** | Future | Already supported in Communication section |
| HelpScout Token | **Supported** | Future | Already supported in Communication section |
| Pipedrive Token | **Supported** | Future | Already supported in Communication section |
| Elastic Path Token | **Supported** | Future | |
| ButterCMS Token | **Supported** | Future | |
| Contentful Delivery Token | **Supported** | Future | |
| Contentful Personal Access Token | **Supported** | Future | CFPAT- prefix |
| Sanity API Token | **Supported** | Future | |
| Storyblok Token | **Supported** | Future | |
| Strapi API Token | **Supported** | Future | |
| Airtable API Key | **Supported** | Future | Deprecated, key prefix |
| Airtable Personal Access Token | **Supported** | Future | pat prefix |
| Airtable OAuth Token | **Supported** | Future | |
| Algolia Admin Key | **Supported** | Future | |
| Lokalise Token | **Supported** | Future | |

---

## Crypto & Web3

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Bitcoin Private Key (WIF) | **Supported** | Future | 5K/L prefix |
| Ethereum Private Key | **Supported** | Future | 0x + 64 hex |
| Solana Private Key | **Supported** | Future | base58 88-char |
| Infura API Key | **Supported** | Future | |
| Alchemy API Key | **Supported** | Future | |
| Moralis API Key | **Supported** | Future | |
| QuickNode Token | **Supported** | Future | |
| Bitfinex API Key | **Supported** | Future | |
| Bittrex Access Key | **Supported** | Future | |
| Bittrex Secret Key | **Supported** | Future | |
| Coinbase Access Token | **Supported** | Future | Already supported in Payments section |

---

## Generic & Framework-Specific

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Generic Bearer Token | **Supported** | Future | |
| Generic API Key Assignment | **Supported** | Future | |
| Generic High-Entropy String | **Supported** | N/A | Shannon entropy based |
| JWT | **Supported** | Future | Could verify signature against JWKS |
| Curl Authentication String | Future | Future | Gitleaks detects `curl -u` patterns |
| URI with Embedded Credentials | Future | Future | TruffleHog supports |
| Generic OAuth Client Secret | Future | Future | |
| .env File Secrets | Future | Future | Pattern: KEY=VALUE in .env files |
| Firebase Config (web) | Future | Future | Not secret but worth flagging |

---

## Scanning Sources (Future)

Beyond the current scanning sources (working tree, stdin, git history, Docker, GitHub/GitLab API, S3, GCS, archives), the following sources are supported by competitors:

| Source | Competitor | Priority | Notes |
|---|---|---|---|
| **Azure Blob Storage** | TruffleHog | High | Similar to S3/GCS scanning |
| **Alibaba OSS** | — | Medium | Growing cloud provider |
| **Confluence** | TruffleHog | Medium | Wiki/documentation scanning |
| **Slack (as source)** | TruffleHog | Medium | Scan Slack messages for secrets |
| **Jira** | TruffleHog | Medium | Scan Jira issues/comments |
| **Syslog streams** | TruffleHog | Low | Real-time log scanning |
| **Postman** | TruffleHog | Low | Scan Postman collections |
| **Gerrit** | TruffleHog | Low | Code review platform |
| **Buildkite** | TruffleHog | Low | CI/CD artifact scanning |
| **Artifactory** | TruffleHog | Low | Repository scanning |
| **Helm Charts** | — | Low | Kubernetes manifest scanning |
| **Terraform State Files** | — | Medium | Often contain plaintext secrets |
| **Kubernetes Secrets** | Gitleaks | Medium | YAML manifests with base64 data |
| **AWS Secrets Manager** | — | Low | Could scan for exposed secrets |
| **Vault Tokens in Logs** | — | Low | Detect leaked Vault tokens |

---

## Verification Features (Future)

| Feature | Competitor | Priority | Notes |
|---|---|---|---|
| **AWS STS verification** | TruffleHog | High | SigV4 signed GetCallerIdentity |
| **Azure AD verification** | TruffleHog | High | OAuth2 client_credentials flow |
| **GCP IAM verification** | TruffleHog | High | Exchange service account key for token |
| **Private key verification** | TruffleHog | Medium | Test against GitHub/GitLab/Driftwood |
| **Database connection verification** | TruffleHog | Medium | Attempt connect + ping |
| **Slack webhook verification** | TruffleHog | Low | Send malformed JSON, check for `invalid_payload` |
| **`--verify-detectors` flag** | TruffleHog | Medium | Per-detector verification override |
| **`--no-verify-detectors` flag** | TruffleHog | Medium | Disable verification per detector |
| **Verification caching** | — | Medium | Cache results to avoid repeated API calls |
| **Rate-limit aware verification** | — | Medium | Backoff on 429 responses |

---

## Summary Statistics

| Metric | Current | Future (Total Potential) |
|---|---|---|
| **Detectors** | 325 | 350+ |
| **Verification providers** | 34 | 150+ |
| **Scanning sources** | 10 | 25+ |
| **Output formats** | 6 | 6 (competitive) |

---

## Priority Recommendations

### High Priority (Close gap with competitors)
1. **AWS STS verification** — most requested cloud provider
2. **Azure AD verification** — second largest cloud provider
3. **GCP IAM verification** — third largest cloud provider
4. **PostHog detector + verifier** — popular product analytics
5. **Sentry detector + verifier** — widely used error tracking
6. **HubSpot detector + verifier** — major CRM
7. **Algolia detector + verifier** — popular search service
8. **Databricks detector + verifier** — data platform
9. **Terraform Cloud token** — IaC platform
10. **HashiCorp Vault token** — secrets management irony
11. **Alibaba Cloud Secret Key** — detector only, needs verifier
12. **Tencent Cloud Secret Key** — detector only, needs verifier
13. **IBM Cloud User Key** — major enterprise cloud
14. **Oracle Cloud (OCI)** — growing enterprise cloud
15. **Snowflake token** — data warehouse
16. **Dynatrace token** — APM
17. **Asana token** — project management
18. **Airtable token** — no-code database
19. **Contentful token** — headless CMS
20. **Fastly API key** — CDN/edge
21. **Scaleway key** — European cloud
22. **Vultr API key** — cloud provider
23. **Snyk API key** — security scanning
24. **Postman API key** — API development
25. **Segment API key** — analytics pipeline

### Low Priority (Long tail)
- All remaining providers from the lists above
- These can be added incrementally via TOML config rules without code changes
