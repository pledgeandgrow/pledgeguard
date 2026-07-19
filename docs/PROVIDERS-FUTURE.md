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
| Curl Authentication String | **Supported** | Future | curl -u user:pass |
| URI with Embedded Credentials | **Supported** | Future | https://user:pass@host |
| Generic OAuth Client Secret | **Supported** | Future | |
| .env File Secrets | **Supported** | Future | KEY=VALUE pattern |
| Firebase Config (web) | **Supported** | Future | apiKey in firebaseConfig |

---

## Additional Communication & Messaging (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Twilio API Key | **Supported** | Future | TruffleHog supports |
| Line Messaging API Token | **Supported** | Future | TruffleHog supports |
| Line Notify Token | **Supported** | Future | TruffleHog supports |
| Mattermost Personal Token | **Supported** | Future | TruffleHog supports |
| WeChat App Key | **Supported** | Future | TruffleHog (not yet implemented) |
| KakaoTalk API Key | **Supported** | Future | TruffleHog (not yet implemented) |
| LiveAgent API Key | **Supported** | Future | TruffleHog supports |
| Front API Key | **Supported** | Future | TruffleHog supports |
| RingCentral API Key | **Supported** | Future | TruffleHog supports |
| TeleSign API Key | **Supported** | Future | TruffleHog (not yet implemented) |
| TeamViewer API Key | **Supported** | Future | TruffleHog (not yet implemented) |
| CometChat API Key | **Supported** | Future | TruffleHog (not yet implemented) |
| Mesibo API Key | **Supported** | Future | TruffleHog supports |
| Bulbul API Key | **Supported** | Future | TruffleHog supports |
| Tyntec API Key | **Supported** | Future | TruffleHog supports |
| Kaleyra API Key | **Supported** | Future | TruffleHog (not yet implemented) |
| Onbuka API Key | **Supported** | Future | TruffleHog (not yet implemented) |
| ClickSend SMS API Key | **Supported** | Future | TruffleHog supports |
| Clockwork SMS API Key | **Supported** | Future | TruffleHog supports |
| SMS API Key | **Supported** | Future | TruffleHog (not yet implemented) |
| BombBomb API Key | **Supported** | Future | TruffleHog supports |
| DFuse API Key | **Supported** | Future | TruffleHog supports |
| ApiFonica API Key | **Supported** | Future | TruffleHog supports |
| Mandrill API Key | **Supported** | Future | TruffleHog supports (Mailchimp transactional) |
| SparkPost API Key | **Supported** | Future | TruffleHog supports |
| MailerLite API Key | **Supported** | Future | TruffleHog supports |
| ConvertKit API Key | **Supported** | Future | TruffleHog supports |
| Omnisend API Key | **Supported** | Future | TruffleHog supports |
| Customer.io API Key | **Supported** | Future | TruffleHog supports |
| Moosend API Key | **Supported** | Future | TruffleHog supports |
| Dotdigital API Key | **Supported** | Future | TruffleHog supports |
| Dyspatch API Key | **Supported** | Future | TruffleHog supports |
| PostageApp API Key | **Supported** | Future | TruffleHog supports |
| Nicereply API Key | **Supported** | Future | TruffleHog supports |
| AutoPilot API Key | **Supported** | Future | TruffleHog supports |
| Airship API Key | **Supported** | Future | TruffleHog supports |

---

## Additional CRM & Sales (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Freshworks API Key | **Supported** | Future | TruffleHog supports |
| Close CRM API Key | **Supported** | Future | TruffleHog supports |
| Copper CRM API Key | **Supported** | Future | TruffleHog supports |
| Streak CRM API Key | **Supported** | Future | TruffleHog supports |
| GrooveHQ API Key | **Supported** | Future | TruffleHog supports |
| GetGist API Key | **Supported** | Future | TruffleHog supports |
| Autoklose API Key | **Supported** | Future | TruffleHog supports |
| Salesflare API Key | **Supported** | Future | TruffleHog supports |
| SalesBlink API Key | **Supported** | Future | TruffleHog supports |
| Salescookie API Key | **Supported** | Future | TruffleHog supports |
| Metrilo API Key | **Supported** | Future | TruffleHog supports |
| RevampCRM API Key | **Supported** | Future | TruffleHog supports |
| KarmaCRM API Key | **Supported** | Future | TruffleHog supports |
| Less Annoying CRM API Key | **Supported** | Future | TruffleHog supports |
| NetHunt CRM API Key | **Supported** | Future | TruffleHog supports |
| Nimble CRM API Key | **Supported** | Future | TruffleHog supports |
| Apptivo CRM API Key | **Supported** | Future | TruffleHog supports |
| Capsule CRM API Key | **Supported** | Future | TruffleHog supports |
| Insightly CRM API Key | **Supported** | Future | TruffleHog supports |
| Kylas CRM API Key | **Supported** | Future | TruffleHog supports |
| OnePageCRM API Key | **Supported** | Future | TruffleHog supports |
| Prospect CRM API Key | **Supported** | Future | TruffleHog supports |
| Really Simple Systems CRM API Key | **Supported** | Future | TruffleHog supports |
| Central Station CRM API Key | **Supported** | Future | TruffleHog supports |
| Teamgate CRM API Key | **Supported** | Future | TruffleHog supports |
| Axonaut API Key | **Supported** | Future | TruffleHog supports |
| FlowFlu API Key | **Supported** | Future | TruffleHog supports |
| Clientary API Key | **Supported** | Future | TruffleHog supports |
| Clinchpad API Key | **Supported** | Future | TruffleHog supports |
| CompanyHub API Key | **Supported** | Future | TruffleHog supports |
| Campayn API Key | **Supported** | Future | TruffleHog supports |
| Hiveage API Key | **Supported** | Future | TruffleHog supports |
| Billomat API Key | **Supported** | Future | TruffleHog supports |
| Alegra API Key | **Supported** | Future | TruffleHog supports |
| Loyverse API Key | **Supported** | Future | TruffleHog supports |
| CommerceJS API Key | **Supported** | Future | TruffleHog supports |
| Snipcart API Key | **Supported** | Future | TruffleHog supports |
| PartnerStack API Key | **Supported** | Future | TruffleHog supports |
| Vouchery API Key | **Supported** | Future | TruffleHog supports |
| Monday.com API Key | **Supported** | Future | TruffleHog supports |
| Smartsheets API Key | **Supported** | Future | TruffleHog supports |
| Wrike API Key | **Supported** | Future | TruffleHog supports |
| Apollo.io API Key | **Supported** | Future | TruffleHog supports |
| UpLead API Key | **Supported** | Future | TruffleHog supports |
| RocketReach API Key | **Supported** | Future | TruffleHog supports |
| Clearbit API Key | **Supported** | Future | TruffleHog supports |
| Brandfetch API Key | **Supported** | Future | TruffleHog supports |
| Leadfeeder API Key | **Supported** | Future | TruffleHog supports |
| GetEmail API Key | **Supported** | Future | TruffleHog supports |
| GetEmails API Key | **Supported** | Future | TruffleHog supports |
| Skrappio API Key | **Supported** | Future | TruffleHog supports |
| Prospect.io API Key | Future | Future | TruffleHog supports (deprecated) |
| Powrbot API Key | **Supported** | Future | TruffleHog supports |

---

## Project Management & Productivity (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| ClickUp Personal Token | Future | Future | TruffleHog supports |
| Todoist API Token | Future | Future | TruffleHog supports |
| Shortcut API Key | Future | Future | TruffleHog supports (formerly Clubhouse) |
| Tmetric API Key | Future | Future | TruffleHog supports |
| Clockify API Key | Future | Future | TruffleHog supports |
| Everhour API Key | Future | Future | TruffleHog supports |
| Harvest API Key | Future | Future | TruffleHog supports |
| Humanity API Key | Future | Future | TruffleHog supports |
| Toggl Track API Key | Future | Future | TruffleHog supports |
| RunRunIt API Key | Future | Future | TruffleHog supports |
| Workstack API Key | Future | Future | TruffleHog supports |
| EasyInsight API Key | Future | Future | TruffleHog supports |
| Dovico API Key | Future | Future | TruffleHog supports |
| Mavenlink API Key | Future | Future | TruffleHog supports |
| Float API Key | Future | Future | TruffleHog supports |
| Daily.co API Key | Future | Future | TruffleHog supports |
| T.ly API Key | Future | Future | TruffleHog supports (URL shortener) |
| Rebrandly API Key | Future | Future | TruffleHog supports |
| Timezone API Key | Future | Future | TruffleHog supports |
| Jotform API Key | Future | Future | TruffleHog supports |

---

## Forms & Survey Platforms (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Typeform API Key | Future | Future | TruffleHog supports |
| SurveySparrow API Key | Future | Future | TruffleHog supports |
| Survicate API Key | Future | Future | TruffleHog supports |
| Delighted API Key | Future | Future | TruffleHog supports |
| Feedier API Key | Future | Future | TruffleHog supports |
| Zonka Feedback API Key | Future | Future | TruffleHog supports |
| Satismeter Project Key | Future | Future | TruffleHog supports |
| Satismeter Write Key | Future | Future | TruffleHog supports |
| Simplesat API Key | Future | Future | TruffleHog supports |
| SurveyAnyplace API Key | Future | Future | TruffleHog supports |
| SurveyBot API Key | Future | Future | TruffleHog supports |
| Qualaroo API Key | Future | Future | TruffleHog supports |
| CustomerGuru API Key | Future | Future | TruffleHog supports |
| Abyssale API Key | Future | Future | TruffleHog supports |
| Magnetic API Key | Future | Future | TruffleHog supports |
| Refiner API Key | Future | Future | TruffleHog supports |
| Simvoly API Key | Future | Future | TruffleHog supports |
| Checkmarket API Key | Future | Future | TruffleHog (not yet implemented) |
| Webengage API Key | Future | Future | TruffleHog (not yet implemented) |

---

## Financial & Trading APIs (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Twelve Data API Key | Future | Future | TruffleHog supports |
| Fixer.io API Key | Future | Future | TruffleHog supports |
| Alpha Vantage API Key | Future | Future | TruffleHog (not yet implemented) |
| Tradier API Key | Future | Future | TruffleHog supports |
| Finnhub API Key | Future | Future | TruffleHog supports |
| Tiingo API Key | Future | Future | TruffleHog supports |
| Finage API Key | Future | Future | TruffleHog supports |
| IEX Cloud API Key | Future | Future | TruffleHog supports |
| Intrinio API Key | Future | Future | TruffleHog supports |
| Financial Modeling Prep API Key | Future | Future | TruffleHog supports |
| Nasdaq Data Link API Key | Future | Future | TruffleHog supports |
| Qubole API Key | Future | Future | TruffleHog supports |
| Enigma API Key | Future | Future | TruffleHog supports |
| Data.gov API Key | Future | Future | TruffleHog supports |
| Stockdata API Key | Future | Future | TruffleHog supports |
| Marketstack API Key | Future | Future | TruffleHog supports |
| Commodities API Key | Future | Future | TruffleHog supports |
| Baremetrics API Key | Future | Future | TruffleHog supports |
| Dwolla API Key | Future | Future | TruffleHog supports |
| WePay API Key | Future | Future | TruffleHog supports |
| Checkout.com API Key | Future | Future | TruffleHog supports |
| Paymongo API Key | Future | Future | TruffleHog supports |
| Avalara API Key | Future | Future | TruffleHog (not yet implemented) |
| Carbon Interface API Key | Future | Future | TruffleHog supports |
| Currency Layer API Key | Future | Future | TruffleHog supports |
| Exchange Rates API Key | Future | Future | TruffleHog supports |
| CurrencyScoop API Key | Future | Future | TruffleHog supports |
| Currency Freaks API Key | Future | Future | TruffleHog supports |
| Country Layer API Key | Future | Future | TruffleHog supports |
| FX Market API Key | Future | Future | TruffleHog supports |
| Currency Cloud API Key | Future | Future | TruffleHog supports |

---

## Crypto & Blockchain (Additional TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Kraken API Key | Future | Future | TruffleHog supports |
| Poloniex API Key | Future | Future | TruffleHog supports |
| BitMEX API Key | Future | Future | TruffleHog supports |
| CoinAPI Key | Future | Future | TruffleHog supports |
| Coinlayer API Key | Future | Future | TruffleHog supports |
| Coinlib API Key | Future | Future | TruffleHog supports |
| CryptoCompare API Key | Future | Future | TruffleHog supports |
| Bitcoin Average API Key | Future | Future | TruffleHog supports |
| World Coin Index API Key | Future | Future | TruffleHog supports |
| Glassnode API Key | Future | Future | TruffleHog supports |
| Tatum.io API Key | Future | Future | TruffleHog supports |
| Ethplorer API Key | Future | Future | TruffleHog supports |
| NFTPort API Key | Future | Future | TruffleHog supports |
| Messari API Key | Future | Future | TruffleHog (not yet implemented) |
| CoinGecko API Key | Future | Future | TruffleHog (not yet implemented) |

---

## Weather & Environment APIs (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| OpenWeather API Key | Future | Future | TruffleHog supports |
| WeatherStack API Key | Future | Future | TruffleHog supports |
| AccuWeather API Key | Future | Future | TruffleHog supports |
| World Weather API Key | Future | Future | TruffleHog supports |
| Tomorrow.io API Key | Future | Future | TruffleHog supports |
| AirVisual API Key | Future | Future | TruffleHog supports |
| Visual Crossing API Key | Future | Future | TruffleHog supports |
| Stormglass API Key | Future | Future | TruffleHog supports |
| Aeris Weather API Key | Future | Future | TruffleHog (not yet implemented) |
| Ambee API Key | Future | Future | TruffleHog supports |
| OpenUV API Key | Future | Future | TruffleHog supports |

---

## Geocoding & Location (Additional TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| TomTom API Key | Future | Future | TruffleHog supports |
| Geoapify API Key | Future | Future | TruffleHog supports |
| Geocodify API Key | Future | Future | TruffleHog supports |
| Geocode API Key | Future | Future | TruffleHog supports |
| Geocodio API Key | Future | Future | TruffleHog supports |
| PositionStack API Key | Future | Future | TruffleHog supports |
| LocationIQ API Key | Future | Future | TruffleHog supports |
| Graphhopper API Key | Future | Future | TruffleHog supports |
| SmartyStreets API Key | Future | Future | TruffleHog supports |
| Route4me API Key | Future | Future | TruffleHog supports |
| ZipCode API Key | Future | Future | TruffleHog supports |
| OnWater.io API Key | Future | Future | TruffleHog supports |
| GeoIPify API Key | Future | Future | TruffleHog supports |
| IPGeolocation API Key | Future | Future | TruffleHog supports |
| IPinfoDB API Key | Future | Future | TruffleHog supports |
| ipify API Key | Future | Future | TruffleHog supports |
| ipapi API Key | Future | Future | TruffleHog supports |
| VPN API Key | Future | Future | TruffleHog supports |
| DNS Check API Key | Future | Future | TruffleHog supports |
| Walk Score API Key | Future | Future | TruffleHog supports |
| Besttime API Key | Future | Future | TruffleHog supports |
| Hypertrack API Key | Future | Future | TruffleHog supports |
| Fulcrum API Key | Future | Future | TruffleHog supports |
| Samsara API Key | Future | Future | TruffleHog (not yet implemented) |

---

## Media & Image APIs (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Unsplash API Key | Future | Future | TruffleHog supports |
| Pixabay API Key | Future | Future | TruffleHog supports |
| Gyazo API Key | Future | Future | TruffleHog supports |
| Imgur API Key | Future | Future | TruffleHog (not yet implemented) |
| Shutterstock API Key | Future | Future | TruffleHog supports |
| Shutterstock OAuth Token | Future | Future | TruffleHog supports |
| IconFinder API Key | Future | Future | TruffleHog supports |
| ImageKit API Key | Future | Future | TruffleHog supports |
| Bannerbear API Key | Future | Future | TruffleHog supports |
| Imagga API Key | Future | Future | TruffleHog supports |
| Face++ API Key | Future | Future | TruffleHog supports |
| SkyBiometry API Key | Future | Future | TruffleHog supports |
| Cloudmersive API Key | Future | Future | TruffleHog supports |
| ScreenshotAPI API Key | Future | Future | TruffleHog supports |
| ScreenshotLayer API Key | Future | Future | TruffleHog supports |
| Browshot API Key | Future | Future | TruffleHog supports |
| LinkPreview API Key | Future | Future | TruffleHog supports |
| Last.fm API Key | Future | Future | TruffleHog supports (deprecated) |
| Mixcloud API Key | Future | Future | TruffleHog (not yet implemented) |
| Rawg API Key | Future | Future | TruffleHog supports |
| Strava API Key | Future | Future | TruffleHog supports |
| FourSquare API Key | Future | Future | TruffleHog supports |
| TicketMaster API Key | Future | Future | TruffleHog supports |
| Riot Games API Key | Future | Future | TruffleHog (not yet implemented) |
| Cricket API Key | Future | Future | TruffleHog (not yet implemented) |
| All Sports API Key | Future | Future | TruffleHog supports |
| SportsMonk API Key | Future | Future | TruffleHog supports |
| Edamam API Key | Future | Future | TruffleHog supports |
| Nutritionix API Key | Future | Future | TruffleHog supports |
| Spoonacular API Key | Future | Future | TruffleHog supports |
| Calorie Ninja API Key | Future | Future | TruffleHog supports |
| Protocols.io API Key | Future | Future | TruffleHog supports |
| HypeAuditor API Key | Future | Future | TruffleHog (not yet implemented) |

---

## News & Content APIs (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| NewsAPI Key | Future | Future | TruffleHog supports |
| Newscatcher API Key | Future | Future | TruffleHog supports |
| Currents API Key | Future | Future | TruffleHog supports |
| Guardian API Key | Future | Future | TruffleHog supports |
| Aylien API Key | Future | Future | TruffleHog supports |
| Cicero API Key | Future | Future | TruffleHog supports |
| Lexigram API Key | Future | Future | TruffleHog supports |
| Blogger API Key | Future | Future | TruffleHog supports |
| NYT API Key | Future | Future | TruffleHog supports (deprecated) |
| Open Graph API Key | Future | Future | TruffleHog supports (deprecated) |
| MediaStack API Key | Future | Future | TruffleHog supports |
| ClickHelp API Key | Future | Future | TruffleHog supports |
| Storychief API Key | Future | Future | TruffleHog supports |
| Noticeable API Key | Future | Future | TruffleHog supports |
| ReadMe API Key | Future | Future | TruffleHog supports |
| Pastebin API Key | Future | Future | TruffleHog supports |
| Crowdin API Key | Future | Future | TruffleHog supports |
| Alconost API Key | Future | Future | TruffleHog supports |
| Gengo API Key | Future | Future | TruffleHog supports |
| HappyScribe API Key | Future | Future | TruffleHog supports |
| RiteKit API Key | Future | Future | TruffleHog supports |

---

## Developer & Code Tools (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| RubyGems API Token | Future | Future | TruffleHog supports |
| Codacy API Token | Future | Future | TruffleHog supports |
| Coveralls API Token | Future | Future | TruffleHog supports |
| SauceLabs API Key | Future | Future | TruffleHog supports |
| Bitbar API Key | Future | Future | TruffleHog supports |
| Bugsnag API Key | Future | Future | TruffleHog supports |
| Adafruit IO Key | Future | Future | TruffleHog supports |
| Apify API Key | Future | Future | TruffleHog supports |
| Keygen API Key | Future | Future | TruffleHog (not yet implemented) |
| Aiven API Key | Future | Future | TruffleHog supports |
| File.io API Key | Future | Future | TruffleHog supports |
| Flat.io API Key | Future | Future | TruffleHog supports |
| Dynalist API Key | Future | Future | TruffleHog supports |
| Sheety API Key | Future | Future | TruffleHog supports |
| Swell API Key | Future | Future | TruffleHog supports |
| M3o API Key | Future | Future | TruffleHog supports |
| JSONbin API Key | Future | Future | TruffleHog (not yet implemented) |
| UserStack API Key | Future | Future | TruffleHog supports |
| PureStake API Key | Future | Future | TruffleHog supports |
| Host API Key | Future | Future | TruffleHog supports |
| BaseAPI.io API Key | Future | Future | TruffleHog (not yet implemented) |
| SslMate API Key | Future | Future | TruffleHog supports |
| Adobe IO API Key | Future | Future | TruffleHog supports |
| EdenAI API Key | Future | Future | TruffleHog supports |
| Deepgram API Key | Future | Future | TruffleHog supports |
| Voicegain API Key | Future | Future | TruffleHog supports |
| Audd.io API Key | Future | Future | TruffleHog supports |
| OwlBot API Key | Future | Future | TruffleHog supports |
| DetectLanguage API Key | Future | Future | TruffleHog supports |
| LanguageLayer API Key | Future | Future | TruffleHog supports |
| ParallelDots API Key | Future | Future | TruffleHog supports |
| Text2Data API Key | Future | Future | TruffleHog supports (deprecated) |
| Veriphone API Key | Future | Future | TruffleHog supports |
| Verifier API Key | Future | Future | TruffleHog supports |
| API2Cart API Key | Future | Future | TruffleHog supports |
| APIDeck API Key | Future | Future | TruffleHog supports |
| APIFlash API Key | Future | Future | TruffleHog supports |
| Fleetbase API Key | Future | Future | TruffleHog supports |
| Agora API Key | Future | Future | TruffleHog supports |
| Yandex API Key | Future | Future | TruffleHog supports |
| Artsy API Key | Future | Future | TruffleHog supports |
| Blit.app API Key | Future | Future | TruffleHog supports |
| Censys API Key | Future | Future | TruffleHog supports |
| SecurityTrails API Key | Future | Future | TruffleHog supports |
| URLScan API Key | Future | Future | TruffleHog supports |
| Aletheia API Key | Future | Future | TruffleHog supports |
| Whoxy API Key | Future | Future | TruffleHog supports |
| Mailsac API Key | Future | Future | TruffleHog supports |
| LoginRadius API Key | Future | Future | TruffleHog supports |
| Passbase API Key | Future | Future | TruffleHog supports (deprecated) |
| Nitro API Key | Future | Future | TruffleHog supports (deprecated) |
| Rev API Key | Future | Future | TruffleHog supports |
| YouNeedABudget API Key | Future | Future | TruffleHog supports |
| Filestack API Key | Future | Future | TruffleHog (not yet implemented) |
| Bubble API Key | Future | Future | TruffleHog (not yet implemented) |
| Shopee Open Platform API Key | Future | Future | TruffleHog (not yet implemented) |
| Kite Connect API Key | Future | Future | TruffleHog (not yet implemented) |
| Veeva Vault API Key | Future | Future | TruffleHog (not yet implemented) |
| Cloudways API Key | Future | Future | TruffleHog (not yet implemented) |
| Duda API Key | Future | Future | TruffleHog (not yet implemented) |
| Yext API Key | Future | Future | TruffleHog (not yet implemented) |
| ContentStack API Key | Future | Future | TruffleHog (not yet implemented) |
| Surge API Key | Future | Future | TruffleHog (not yet implemented) |
| Kairos API Key | Future | Future | TruffleHog (not yet implemented) |
| FullContact API Key | Future | Future | TruffleHog (not yet implemented) |
| Eversign API Key | Future | Future | TruffleHog (not yet implemented) |
| NetCore API Key | Future | Future | TruffleHog (not yet implemented) |
| Bored API Key | Future | Future | TruffleHog (not yet implemented) |

---

## Document & PDF APIs (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| HTML2PDF API Key | Future | Future | TruffleHog supports |
| PDF Layer API Key | Future | Future | TruffleHog supports |
| PDF Shift API Key | Future | Future | TruffleHog supports |
| Restpack HTML-to-PDF API Key | Future | Future | TruffleHog supports |
| Restpack Screenshot API Key | Future | Future | TruffleHog supports |
| Restpack API Key | Future | Future | TruffleHog supports (deprecated) |
| Documo API Key | Future | Future | TruffleHog supports |
| ClustDoc API Key | Future | Future | TruffleHog supports |
| PandaDoc API Key | Future | Future | TruffleHog supports |
| HelloSign API Key | Future | Future | TruffleHog supports |
| Juro API Key | Future | Future | TruffleHog supports |
| Eversign API Key | Future | Future | TruffleHog (not yet implemented) |
| YouSign API Key | Future | Future | TruffleHog supports |
| PDFShift API Key | Future | Future | TruffleHog supports |
| VatLayer API Key | Future | Future | TruffleHog supports |
| UPC Database API Key | Future | Future | TruffleHog supports |

---

## Scraping & Web Automation (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| ScraperAPI Key | Future | Future | TruffleHog supports |
| ScrapingDog API Key | Future | Future | TruffleHog (not yet implemented) |
| ScrapeOwl API Key | Future | Future | TruffleHog supports |
| WebScraping API Key | Future | Future | TruffleHog supports |
| ZenScrape API Key | Future | Future | TruffleHog supports |
| ZenSerp API Key | Future | Future | TruffleHog supports |
| SerpStack API Key | Future | Future | TruffleHog supports |
| ScraperBox API Key | Future | Future | TruffleHog supports |
| ScrapingAnt API Key | Future | Future | TruffleHog supports |
| ScrapeStack API Key | Future | Future | TruffleHog supports |
| ProxyCrawl API Key | Future | Future | TruffleHog supports |
| ScrapingBee (additional) | Future | Future | Already supported in Security section |

---

## Email Verification (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Debounce API Key | Future | Future | TruffleHog supports |
| Kickbox API Key | Future | Future | TruffleHog supports |
| IPQuality API Key | Future | Future | TruffleHog supports |
| Roaring API Key | Future | Future | TruffleHog supports |
| OOPSpam API Key | Future | Future | TruffleHog supports |
| Numverify API Key | Future | Future | TruffleHog supports |

---

## CMS & Web Builders (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Webflow API Key | Future | Future | TruffleHog supports |
| Squarespace API Key | Future | Future | TruffleHog supports |
| Siteleaf API Key | Future | Future | TruffleHog supports |
| GraphCMS API Key | Future | Future | TruffleHog supports |
| Kontent API Key | Future | Future | TruffleHog supports |
| Swell API Key | Future | Future | TruffleHog supports |
| Sheety API Key | Future | Future | TruffleHog supports |
| Daily.co API Key | Future | Future | TruffleHog supports |
| ClickHelp API Key | Future | Future | TruffleHog supports |
| ReadMe API Key | Future | Future | TruffleHog supports |
| Noticeable API Key | Future | Future | TruffleHog supports |
| Storychief API Key | Future | Future | TruffleHog supports |

---

## Miscellaneous APIs (TruffleHog)

| Provider / Token Type | Detector | Verifier | Notes |
|---|---|---|---|
| Wakatime API Key | Future | Future | TruffleHog (not yet implemented) |
| Ubidots API Key | Future | Future | TruffleHog supports |
| Tmetric API Key | Future | Future | TruffleHog supports |
| Raven API Key | Future | Future | TruffleHog supports |
| Guru API Key | Future | Future | TruffleHog supports |
| Hive API Key | Future | Future | TruffleHog supports |
| QuickMetrics API Key | Future | Future | TruffleHog supports (deprecated) |
| Technical Analysis API Key | Future | Future | TruffleHog supports |
| Impala API Key | Future | Future | TruffleHog supports |
| Unplugg API Key | Future | Future | TruffleHog supports |
| M3o API Key | Future | Future | TruffleHog supports |
| Cloverly API Key | Future | Future | TruffleHog supports |
| Flight API Key | Future | Future | TruffleHog supports |
| AviationStack API Key | Future | Future | TruffleHog supports |
| Distribusion API Key | Future | Future | TruffleHog (not yet implemented) |
| Blablabus API Key | Future | Future | TruffleHog supports (deprecated) |
| Words API Key | Future | Future | TruffleHog (not yet implemented) |
| FakeJSON API Key | Future | Future | TruffleHog supports (deprecated) |
| OpenGraphr API Key | Future | Future | TruffleHog supports (deprecated) |
| Holiday API Key | Future | Future | TruffleHog supports |
| Calendarific (additional) | Future | Future | Already supported in Analytics section |
| Spoonacular API Key | Future | Future | TruffleHog supports |
| Nutritionix API Key | Future | Future | TruffleHog supports |
| Edamam API Key | Future | Future | TruffleHog supports |
| Calorie Ninja API Key | Future | Future | TruffleHog supports |
| Protocols.io API Key | Future | Future | TruffleHog supports |
| Amadeus API Key | Future | Future | TruffleHog supports |
| Twelve Data API Key | Future | Future | TruffleHog supports |
| Exchange Rate API Key | Future | Future | TruffleHog supports |
| Holiday API Key | Future | Future | TruffleHog supports |
| Abstract API Key | Future | Future | TruffleHog supports |
| Integromat API Key | Future | Future | TruffleHog supports (deprecated, now Make) |
| Unsplash API Key | Future | Future | TruffleHog supports |

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
| **Detectors** | 416 | 700+ |
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
