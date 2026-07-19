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
| Alibaba Cloud Secret Key | Future | Future | Gitleaks detects this |
| Tencent Cloud Secret ID | **Supported** | Future | |
| Tencent Cloud Secret Key | Future | Future | |
| DigitalOcean PAT | **Supported** | **Supported** | |
| DigitalOcean Spaces Key | **Supported** | Future | |
| IBM Cloud User Key | Future | Future | TruffleHog supports |
| Oracle Cloud (OCI) | Future | Future | |
| Scaleway Key | Future | Future | TruffleHog supports |
| Vultr API Key | Future | Future | TruffleHog supports |
| Linode/Akamai Token | Future | Future | |
| Cloudflare API Key | **Supported** | Future | |
| Cloudflare API Token | **Supported** | **Supported** | |
| Cloudflare CA Key | Future | Future | |
| Cloudflare Global API Key | Future | Future | |

---

## Version Control & CI/CD

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| GitHub PAT (ghp_) | **Supported** | **Supported** | |
| GitHub Fine-Grained PAT | **Supported** | **Supported** | |
| GitHub OAuth Token (gho_) | Future | Future | |
| GitHub App Token (ghu_/ghs_) | Future | Future | |
| GitHub Refresh Token (ghr_) | Future | Future | |
| GitHub Old PAT | Future | Future | Legacy format |
| GitLab PAT (glpat-) | **Supported** | **Supported** | |
| GitLab Pipeline Trigger Token | **Supported** | Future | |
| GitLab Runner Registration Token | **Supported** | Future | |
| Bitbucket App Password | **Supported** | Future | |
| Bitbucket Client ID | Future | Future | Gitleaks detects |
| Bitbucket Client Secret | Future | Future | Gitleaks detects |
| Bitbucket Data Center Token | Future | Future | TruffleHog supports |
| CircleCI API Token | **Supported** | **Supported** | |
| Travis CI Token | Future | Future | TruffleHog supports |
| DroneCI Access Token | Future | Future | TruffleHog + Gitleaks |
| Buildkite Token | Future | Future | TruffleHog supports |
| TeamCity Token | Future | Future | |
| Jenkins API Token | Future | Future | |
| GoCD Token | Future | Future | |
| ArgoCD Token | Future | Future | |
| Spinnaker Token | Future | Future | |
| Harness API Key | Future | Future | |
| Codecov Access Token | Future | Future | Gitleaks detects |
| SonarQube Token | Future | Future | |
| Snyk API Key | Future | Future | TruffleHog supports |
| Artifactory API Key | Future | Future | Gitleaks + TruffleHog |
| Artifactory Reference Token | Future | Future | Gitleaks + TruffleHog |
| Terraform Cloud Token | Future | Future | TruffleHog supports |
| Pivotal Tracker Token | Future | Future | TruffleHog supports |
| Clojars API Token | Future | Future | Gitleaks detects |

---

## Communication & Collaboration

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Slack Token (xox) | **Supported** | **Supported** | |
| Slack Webhook URL | **Supported** | Future | TruffleHog verifies by sending malformed JSON |
| Discord Bot Token | **Supported** | **Supported** | |
| Discord Webhook URL | **Supported** | Future | |
| Discord Client ID | Future | Future | Gitleaks detects |
| Discord Client Secret | Future | Future | Gitleaks detects |
| Telegram Bot Token | **Supported** | **Supported** | |
| Microsoft Teams Webhook | Future | Future | TruffleHog supports |
| Atlassian API Token | **Supported** | **Supported** | |
| Atlassian (Jira) Token | Future | Future | TruffleHog has Jira-specific detector |
| Notion Integration Token | **Supported** | **Supported** | |
| Gitter Access Token | Future | Future | Gitleaks detects |
| Webex Token | Future | Future | TruffleHog supports |
| Intercom Token | Future | Future | TruffleHog supports |
| HelpScout Token | Future | Future | TruffleHog supports |
| HelpCrunch Token | Future | Future | TruffleHog supports |
| Canny.io Token | Future | Future | TruffleHog supports |
| Pipedrive Token | Future | Future | TruffleHog supports |
| Beamer API Token | Future | Future | Gitleaks detects |
| Frame.io API Token | Future | Future | Gitleaks detects |
| Zeplin Token | Future | Future | TruffleHog supports |
| Trello API Key | Future | Future | TruffleHog supports |
| Asana Client ID | Future | Future | Gitleaks detects |
| Asana Client Secret | Future | Future | Gitleaks detects |
| Asana Personal Access Token | Future | Future | TruffleHog supports |

---

## Payments & E-Commerce

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Stripe Secret Key | **Supported** | **Supported** | |
| Stripe Publishable Key | **Supported** | Future | Publishable keys are not secret |
| Stripe Restricted Key (rk_) | **Supported** | **Supported** | |
| Shopify Access Token (shpat_) | **Supported** | **Supported** | |
| Shopify Shared Secret (shpss_) | Future | Future | Gitleaks detects |
| Shopify Custom App Token (shpca_) | Future | Future | Gitleaks detects |
| Shopify Private App Token (shppa_) | Future | Future | Gitleaks detects |
| PayPal OAuth Token | Future | Future | TruffleHog supports |
| PayPal Client Secret | Future | Future | |
| Square Token | Future | Future | TruffleHog supports |
| Square App Token | Future | Future | TruffleHog supports |
| Coinbase Access Token | Future | Future | TruffleHog + Gitleaks |
| RazorPay Key | Future | Future | TruffleHog supports |
| Paystack Token | Future | Future | TruffleHog supports |
| Plaid Token | Future | Future | TruffleHog supports |
| Plaid Key | Future | Future | TruffleHog supports |
| Flutterwave Secret Key | Future | Future | Gitleaks detects |
| Flutterwave Encryption Key | Future | Future | Gitleaks detects |
| Paddle Token | Future | Future | TruffleHog supports |
| FastSpring Token | Future | Future | TruffleHog supports |
| Sellfy Token | Future | Future | TruffleHog supports |
| Duffel API Token | Future | Future | Gitleaks detects |
| EasyPost API Token | Future | Future | Gitleaks detects |
| EasyPost Test API Token | Future | Future | Gitleaks detects |
| Finicity API Token | Future | Future | Gitleaks detects |
| Finicity Client Secret | Future | Future | Gitleaks detects |
| Freshbooks Access Token | Future | Future | Gitleaks detects |
| GoCardless API Token | Future | Future | Gitleaks detects |
| Taxjar API Key | Future | Future | TruffleHog supports |
| Etsy API Key | Future | Future | TruffleHog supports (deprecated) |
| Amazon MWS Token | Future | Future | TruffleHog + Gitleaks |

---

## AI/ML Providers

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| OpenAI API Key (sk-) | **Supported** | **Supported** | |
| Anthropic API Key (sk-ant-) | **Supported** | **Supported** | |
| Anthropic Admin API Key | Future | Future | Gitleaks detects admin variant |
| HuggingFace Token (hf_) | **Supported** | **Supported** | |
| Google Gemini / PaLM Key | Future | Future | |
| Cohere API Key | Future | Future | |
| Replicate API Token | Future | Future | |
| Stability AI Key | Future | Future | |
| AssemblyAI Key | Future | Future | TruffleHog supports |
| Clarifai Key | Future | Future | TruffleHog supports |
| OpenRouter Key | Future | Future | |
| Together AI Key | Future | Future | |
| Perplexity API Key | Future | Future | |
| Mistral API Key | Future | Future | |
| Groq API Key | Future | Future | |
| DeepSeek API Key | Future | Future | |
| ElevenLabs API Key | Future | Future | |

---

## Email & Messaging

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| SendGrid API Key (SG.) | **Supported** | **Supported** | |
| Mailgun API Key (key-) | **Supported** | **Supported** | |
| Mailchimp API Key | **Supported** | **Supported** | |
| Postmark Token | Future | Future | TruffleHog supports |
| MailJet Basic Auth | Future | Future | TruffleHog supports |
| MailJet SMS | Future | Future | TruffleHog supports |
| SendinBlue / Brevo Token | Future | Future | TruffleHog supports |
| Elastic Email Key | Future | Future | TruffleHog supports |
| Pepipost Token | Future | Future | TruffleHog supports |
| Mailmodo Token | Future | Future | TruffleHog supports |
| Verimail Token | Future | Future | TruffleHog supports |
| ZeroBounce Token | Future | Future | TruffleHog supports |
| Mailboxlayer Token | Future | Future | TruffleHog supports |
| D7Network Token | Future | Future | TruffleHog supports |
| Sinch Message Token | Future | Future | TruffleHog supports |
| MessageBird Token | Future | Future | TruffleHog supports |
| Vonage/Nexmo API Key | Future | Future | TruffleHog supports |
| Plivo Token | Future | Future | TruffleHog supports |
| Postman API Key | Future | Future | TruffleHog supports |
| PubNub Publish/Subscription Key | Future | Future | TruffleHog supports |
| Pusher Channel Key | Future | Future | TruffleHog supports |
| PushBullet API Key | Future | Future | TruffleHog supports |
| Doppler API Token | Future | Future | Gitleaks detects |

---

## Monitoring & Observability

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Datadog API Key | **Supported** | **Supported** | |
| Datadog Access Token (dt0) | Future | Future | Gitleaks detects different format |
| New Relic License Key | **Supported** | **Supported** | |
| New Relic Personal API Key | Future | Future | TruffleHog supports |
| PagerDuty API Key | **Supported** | **Supported** | |
| Opsgenie API Key | **Supported** | **Supported** | |
| Sentry Token | Future | Future | TruffleHog supports |
| SumoLogic Key | Future | Future | TruffleHog supports |
| Splunk Observability Token | Future | Future | TruffleHog supports |
| AppOptics Token | Future | Future | TruffleHog supports |
| Airbrake Project/User Key | Future | Future | TruffleHog supports |
| LogDNA Key | Future | Future | |
| Loggly Token | Future | Future | |
| Better Stack / Better Uptime Key | Future | Future | |
| Statuspage API Key | Future | Future | |
| UptimeRobot API Key | Future | Future | |
| Pingdom Token | Future | Future | |

---

## Analytics & Product

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| PostHog API Key | Future | Future | TruffleHog supports (PosthogApp) |
| Amplitude API Key | Future | Future | TruffleHog supports |
| Segment API Key | Future | Future | TruffleHog supports |
| Mixpanel Token | Future | Future | |
| Heap API Key | Future | Future | |
| Pendo Integration Key | Future | Future | TruffleHog supports |
| Keen.io Key | Future | Future | TruffleHog supports |
| Fathom Analytics Key | Future | Future | |
| Plausible Analytics Key | Future | Future | |
| Hotjar Token | Future | Future | |
| FullStory Token | Future | Future | |
| Amplitude Key | Future | Future | TruffleHog supports |
| Bitly Access Token | Future | Future | TruffleHog supports |
| Calendly API Key | Future | Future | TruffleHog supports |
| Calendarific Token | Future | Future | TruffleHog supports |
| AppFollow Token | Future | Future | TruffleHog supports |
| Appcues Token | Future | Future | TruffleHog supports |

---

## Auth & Identity

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Auth0 API Token | **Supported** | **Supported** | |
| Auth0 Management API Token | Future | Future | TruffleHog has separate detector |
| Auth0 OAuth Token | Future | Future | TruffleHog supports |
| Okta API Token | **Supported** | **Supported** | |
| OneLogin Token | Future | Future | TruffleHog supports |
| JumpCloud Token | Future | Future | TruffleHog supports |
| Authress Service Client Key | Future | Future | Gitleaks detects |
| Keycloak Token | Future | Future | |
| FusionAuth Token | Future | Future | |
| Stytch Token | Future | Future | |
| Clerk Token | Future | Future | |
| WorkOS Token | Future | Future | |
| Supabase Service Key | **Supported** | **Supported** | |
| Supabase Anon Key | Future | Future | Not truly secret but worth detecting |
| Firebase Token | Future | Future | TruffleHog supports |
| Firebase Cloud Messaging Key | Future | Future | TruffleHog supports |
| KubeConfig | Future | Future | TruffleHog supports |
| HashiCorp Vault Token | Future | Future | Gitleaks detects (hvs./hvb./s. prefixes) |
| 1Password Secret Key | Future | Future | Gitleaks detects |
| 1Password Service Account Token | Future | Future | Gitleaks detects |
| Doppler Token | Future | Future | Gitleaks detects |

---

## Hosting & Backend

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Vercel Token | **Supported** | **Supported** | |
| Netlify Token | **Supported** | Future | |
| Heroku API Key | **Supported** | **Supported** | |
| Supabase Service Key | **Supported** | **Supported** | |
| WP Engine Token | Future | Future | TruffleHog supports |
| Fastly API Key | Future | Future | Gitleaks + TruffleHog |
| Akamai Token | Future | Future | TruffleHog supports |
| Equinix OAuth Token | Future | Future | TruffleHog supports |
| Fly.io Token | Future | Future | |
| Railway Token | Future | Future | |
| Render Token | Future | Future | |
| Koyeb Token | Future | Future | |
| Edge Token | Future | Future | |

---

## Social & Developer Platforms

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Twitch Client Secret | **Supported** | Future | |
| Twitter/X Bearer Token | **Supported** | Future | |
| Facebook App Secret | **Supported** | Future | |
| Facebook Access Token | Future | Future | TruffleHog supports (FacebookOAuth) |
| Facebook OAuth Token | Future | Future | |
| LinkedIn Client Secret | **Supported** | Future | |
| Linear API Key | **Supported** | **Supported** | |
| Figma Token | **Supported** | Future | |
| Figma Personal Access Token | Future | Future | TruffleHog has specific detector |
| npm Token (npm_) | **Supported** | **Supported** | |
| PyPI Token (pypi-AgEI...) | Future | Future | Gitleaks detects newer format |
| Docker Hub Token | **Supported** | **Supported** | |
| Spotify Key | Future | Future | TruffleHog supports |
| YouTube API Key | Future | Future | TruffleHog supports |
| Twitch Access Token | Future | Future | |
| Flickr Access Token | Future | Future | Gitleaks detects |
| Dropbox API Secret | Future | Future | Gitleaks detects |
| Dropbox Long-Lived Token | Future | Future | Gitleaks detects |
| Dropbox Short-Lived Token | Future | Future | Gitleaks detects |
| Reddit Client Secret | Future | Future | |
| Reddit Access Token | Future | Future | |
| Instagram Access Token | Future | Future | |
| Pinterest Token | Future | Future | |
| TikTok Access Token | Future | Future | |
| Zoom API Key/Secret | Future | Future | |
| Calendly Webhook | Future | Future | |
| Zapier Webhook URL | Future | Future | TruffleHog supports |

---

## Database & Data

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| PostgreSQL Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| MySQL Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| MongoDB Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| Redis Connection String | **Supported** | Future | TruffleHog verifies by connecting |
| JDBC Connection String | Future | Future | TruffleHog supports (MySQL/PostgreSQL/SQL Server) |
| SQL Server Connection String | Future | Future | |
| Elasticsearch Connection | Future | Future | |
| InfluxDB Token | Future | Future | |
| Couchbase Connection String | Future | Future | |
| Cassandra Connection | Future | Future | |
| Neo4j Connection String | Future | Future | |
| Supabase DB Connection | Future | Future | |
| PlanetScale Token | Future | Future | |
| Neon Database Token | Future | Future | |
| Turso Token | Future | Future | |
| Convex Token | Future | Future | |

---

## DevOps & Infrastructure

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| PEM Private Key | **Supported** | Future | TruffleHog verifies by testing against GitHub/GitLab/Driftwood |
| Age Secret Key | Future | Future | Gitleaks detects (age encryption tool) |
| Kubernetes Secret Manifest | Future | Future | Gitleaks detects YAML with base64 data |
| HashiCorp Vault Token | Future | Future | Gitleaks detects (hvs./hvb./s. prefixes) |
| HashiCorp Terraform Token | Future | Future | Gitleaks + TruffleHog |
| Ansible Vault Password | Future | Future | |
| Docker Registry Token | Future | Future | |
| Harbor Token | Future | Future | |
| Nexus Token | Future | Future | |
| Confluent Access Token | Future | Future | Gitleaks detects |
| Confluent Secret Key | Future | Future | Gitleaks detects |
| Databricks Token | Future | Future | Gitleaks + TruffleHog |
| Snowflake Token | Future | Future | TruffleHog supports |
| Dynatrace API Token | Future | Future | Gitleaks detects |
| LaunchDarkly Key | Future | Future | |
| ConfigCat Key | Future | Future | |
| Flagsmith Key | Future | Future | |

---

## Security & API Services

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Shodan API Key | Future | Future | TruffleHog supports |
| AbuseIPDB Key | Future | Future | TruffleHog supports |
| AlienVault OTX Key | Future | Future | TruffleHog supports |
| VirusTotal API Key | Future | Future | |
| Hunter.io API Key | Future | Future | TruffleHog supports |
| IPStack Key | Future | Future | TruffleHog supports |
| MaxMind License Key | Future | Future | TruffleHog supports |
| CloudSight Key | Future | Future | TruffleHog supports |
| Snyk API Key | Future | Future | TruffleHog supports |
| RapidAPI Key | Future | Future | TruffleHog supports |
| ScrapingBee Key | Future | Future | TruffleHog supports |
| ipinfo.io Token | Future | Future | |

---

## Maps & Location

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Google Maps API Key | Future | Future | Subset of Google API Key |
| MapBox Token | Future | Future | TruffleHog supports |
| MapQuest Key | Future | Future | |
| Here Maps Key | Future | Future | |
| OpenCage Key | Future | Future | |

---

## CRM & Business

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| HubSpot API Key | Future | Future | TruffleHog supports |
| HubSpot OAuth Token | Future | Future | TruffleHog supports |
| Salesforce OAuth2 Token | Future | Future | TruffleHog supports |
| Zendesk API Token | Future | Future | TruffleHog supports |
| Intercom Token | Future | Future | TruffleHog supports |
| HelpScout Token | Future | Future | TruffleHog supports |
| Pipedrive Token | Future | Future | TruffleHog supports |
| Elastic Path Token | Future | Future | TruffleHog supports |
| ButterCMS Token | Future | Future | TruffleHog supports |
| Contentful Delivery Token | Future | Future | Gitleaks + TruffleHog |
| Contentful Personal Access Token | Future | Future | TruffleHog supports |
| Sanity API Token | Future | Future | |
| Storyblok Token | Future | Future | |
| Strapi API Token | Future | Future | |
| Airtable API Key | Future | Future | Gitleaks detects (deprecated) |
| Airtable Personal Access Token | Future | Future | TruffleHog supports |
| Airtable OAuth Token | Future | Future | TruffleHog supports |
| Algolia Admin Key | Future | Future | Gitleaks detects |
| Lokalise Token | Future | Future | TruffleHog supports |

---

## Crypto & Web3

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Bitcoin Private Key (WIF) | Future | Future | |
| Ethereum Private Key | Future | Future | |
| Solana Private Key | Future | Future | |
| Infura API Key | Future | Future | |
| Alchemy API Key | Future | Future | TruffleHog supports |
| Moralis API Key | Future | Future | |
| QuickNode Token | Future | Future | |
| Bitfinex API Key | Future | Future | TruffleHog supports |
| Bittrex Access Key | Future | Future | Gitleaks detects |
| Bittrex Secret Key | Future | Future | Gitleaks detects |
| Coinbase Access Token | Future | Future | TruffleHog + Gitleaks |

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
| **Detectors** | 76 | 300+ |
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
