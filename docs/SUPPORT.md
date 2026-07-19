# PledgeGuard — Supported Platforms & Capabilities

This document lists all detectors, verification providers, output formats, scanning sources, and configuration options currently supported by PledgeGuard.

---

## Built-in Detectors

PledgeGuard ships with **512 regex-based detectors** covering major cloud providers, SaaS platforms, CI/CD systems, and generic secret patterns. Each detector has a prefilter (Aho-Corasick) for fast scanning and a regex for precise matching.

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
| `tencent-secret-key` | Tencent Cloud Secret Key (36-char assignment) | Critical |
| `alibaba-secret-key` | Alibaba Cloud Secret Key (30-char base64) | Critical |
| `digitalocean-pat` | DigitalOcean Personal Access Token (dop_v1_ prefix) | High |
| `digitalocean-spaces-key` | DigitalOcean Spaces Access Key | High |
| `ibm-cloud-key` | IBM Cloud API Key (44-char assignment) | High |
| `oracle-cloud-token` | Oracle Cloud (OCI) Token | High |
| `scaleway-key` | Scaleway API Key (UUID format) | High |
| `vultr-api-key` | Vultr API Key (36-char hex) | High |
| `linode-token` | Linode/Akamai API Token (64-char hex) | High |
| `cloudflare-ca-key` | Cloudflare Origin CA Key (v1.0- prefix) | High |
| `cloudflare-global-api-key` | Cloudflare Global API Key (37-char hex) | High |

### Version Control & CI/CD

| Rule ID | Description | Severity |
|---|---|---|
| `github-pat` | GitHub Personal Access Token (ghp_/gho_/ghu_/ghs_/ghr_ prefixes) | Critical |
| `github-fine-grained-pat` | GitHub Fine-Grained PAT (github_pat_ prefix) | Critical |
| `github-old-pat` | GitHub Legacy PAT (40-char hex assignment) | High |
| `gitlab-pat` | GitLab Personal Access Token (glpat- prefix) | Critical |
| `gitlab-pipeline-trigger-token` | GitLab Pipeline Trigger Token (glptt- prefix) | High |
| `gitlab-runner-registration-token` | GitLab Runner Registration Token (GR1348921 prefix) | High |
| `bitbucket-app-password` | Bitbucket App Password | High |
| `bitbucket-client-id` | Bitbucket OAuth Client ID | Medium |
| `bitbucket-client-secret` | Bitbucket OAuth Client Secret | High |
| `bitbucket-datacenter-token` | Bitbucket Data Center Token | High |
| `circleci-api-token` | CircleCI API Token (CCIPVJ_ prefix) | High |
| `heroku-api-key` | Heroku API Key | High |
| `travis-ci-token` | Travis CI Token | High |
| `droneci-token` | DroneCI Access Token | High |
| `buildkite-token` | Buildkite API Token (bk[cuor]_ prefix) | High |
| `teamcity-token` | TeamCity API Token | High |
| `jenkins-token` | Jenkins API Token | High |
| `gocd-token` | GoCD Access Token | High |
| `argocd-token` | ArgoCD API Token | High |
| `spinnaker-token` | Spinnaker Token | High |
| `harness-api-key` | Harness API Key | High |
| `codecov-token` | Codecov Access Token | High |
| `sonarqube-token` | SonarQube Token (squ_ prefix) | High |
| `snyk-api-key` | Snyk API Key | High |
| `artifactory-api-key` | Artifactory API Key (AKC prefix, 70 chars) | High |
| `artifactory-reference-token` | Artifactory Reference Token (cmV prefix, 60 chars) | High |
| `terraform-cloud-token` | Terraform Cloud / HCP API Token (atlasv1. suffix) | High |
| `pivotal-tracker-token` | Pivotal Tracker API Token | High |
| `clojars-token` | Clojars API Token (CLOJARS_ prefix) | High |

### Communication & Collaboration

| Rule ID | Description | Severity |
|---|---|---|
| `slack-token` | Slack Token (xoxb-/xoxa-/xoxp-/xoxr-/xoxs- prefixes) | High |
| `slack-webhook` | Slack Incoming Webhook URL | High |
| `discord-bot-token` | Discord Bot Token | High |
| `discord-webhook` | Discord Webhook URL | Medium |
| `discord-client-id` | Discord Client ID (18-digit assignment) | Medium |
| `discord-client-secret` | Discord Client Secret (32-char assignment) | High |
| `telegram-bot-token` | Telegram Bot Token | High |
| `microsoft-teams-webhook` | Microsoft Teams Webhook URL | High |
| `atlassian-api-token` | Atlassian API Token (Jira/Confluence) | High |
| `atlassian-jira-token` | Atlassian (Jira) API Token | High |
| `notion-integration-token` | Notion Integration Token | Medium |
| `gitter-token` | Gitter Access Token | High |
| `webex-token` | Webex Access Token | High |
| `intercom-token` | Intercom Access Token | High |
| `helpscout-token` | HelpScout API Key | High |
| `helpcrunch-token` | HelpCrunch Secret Key | High |
| `canny-token` | Canny.io API Key | High |
| `pipedrive-token` | Pipedrive API Token | High |
| `beamer-token` | Beamer API Token | High |
| `frameio-token` | Frame.io API Token (fio- prefix) | High |
| `zeplin-token` | Zeplin API Token | High |
| `trello-api-key` | Trello API Key | High |
| `asana-client-id` | Asana Client ID | Medium |
| `asana-client-secret` | Asana Client Secret | High |
| `asana-pat` | Asana Personal Access Token | High |

### Payments & E-Commerce

| Rule ID | Description | Severity |
|---|---|---|
| `stripe-secret-key` | Stripe Secret Key (sk_live_/sk_test_/rk_live_/rk_test_ prefixes) | Critical |
| `stripe-publishable-key` | Stripe Publishable Key (pk_live_/pk_test_ prefixes) | Low |
| `shopify-access-token` | Shopify Access Token (shpat_ prefix) | High |
| `shopify-shared-secret` | Shopify Shared Secret (shpss_ prefix) | High |
| `shopify-custom-app-token` | Shopify Custom App Token (shpca_ prefix) | High |
| `shopify-private-app-token` | Shopify Private App Token (shppa_ prefix) | High |
| `paypal-oauth-token` | PayPal OAuth Token | High |
| `paypal-client-secret` | PayPal Client Secret (80-char assignment) | High |
| `square-token` | Square Access Token (sq0atp- prefix) | High |
| `square-app-token` | Square Application Secret (sq0csp- prefix) | High |
| `coinbase-access-token` | Coinbase Access Token | High |
| `razorpay-key` | RazorPay API Key (rzp_ prefix) | High |
| `paystack-token` | Paystack Secret Key (sk_live_/sk_test_ prefix) | High |
| `plaid-token` | Plaid Access Token (access-sandbox/production/development- prefix) | High |
| `plaid-key` | Plaid API Key / Client ID | Medium |
| `flutterwave-secret-key` | Flutterwave Secret Key (FLWSECK- prefix) | High |
| `flutterwave-encryption-key` | Flutterwave Encryption Key (FLWSECK_TEST- prefix) | High |
| `paddle-token` | Paddle API Key | High |
| `fastspring-token` | FastSpring API Key | High |
| `sellfy-token` | Sellfy API Key | High |
| `duffel-token` | Duffel API Token (duffel_ prefix) | High |
| `easypost-api-token` | EasyPost API Token (EZ prefix) | High |
| `easypost-test-api-token` | EasyPost Test API Token (EZTK prefix) | Medium |
| `finicity-api-token` | Finicity API Token | High |
| `finicity-client-secret` | Finicity Client Secret | High |
| `freshbooks-token` | Freshbooks Access Token | High |
| `gocardless-token` | GoCardless API Token | High |
| `taxjar-api-key` | Taxjar API Key | High |
| `etsy-api-key` | Etsy API Key | Medium |

### AI/ML Providers

| Rule ID | Description | Severity |
|---|---|---|
| `openai-api-key` | OpenAI API Key (sk- prefix, 48 chars) | Critical |
| `anthropic-api-key` | Anthropic API Key (sk-ant- prefix) | Critical |
| `anthropic-admin-key` | Anthropic Admin API Key (sk-ant-admin prefix) | Critical |
| `huggingface-token` | HuggingFace Access Token (hf_ prefix) | High |
| `google-gemini-key` | Google Gemini / PaLM API Key (AIza prefix) | High |
| `cohere-api-key` | Cohere API Key | High |
| `replicate-api-token` | Replicate API Token (r8_ prefix) | High |
| `stability-ai-key` | Stability AI API Key | High |
| `assemblyai-key` | AssemblyAI API Key | High |
| `clarifai-key` | Clarifai API Key | High |
| `openrouter-key` | OpenRouter API Key (sk-or- prefix) | High |
| `together-ai-key` | Together AI API Key | High |
| `perplexity-api-key` | Perplexity API Key (pplx- prefix) | High |
| `mistral-api-key` | Mistral API Key | High |
| `groq-api-key` | Groq API Key (gsk_ prefix) | High |
| `deepseek-api-key` | DeepSeek API Key | High |
| `elevenlabs-api-key` | ElevenLabs API Key | High |

### Email & Messaging

| Rule ID | Description | Severity |
|---|---|---|
| `sendgrid-api-key` | SendGrid API Key (SG. prefix) | High |
| `mailgun-api-key` | Mailgun API Key (key- prefix) | High |
| `mailchimp-api-key` | Mailchimp API Key (hex-us## format) | High |
| `postmark-token` | Postmark Server Token (po_ prefix) | High |
| `mailjet-basic-auth` | Mailjet Basic Auth Token (MJ prefix) | High |
| `mailjet-sms-token` | Mailjet SMS Token | High |
| `brevo-token` | SendinBlue / Brevo API Key (xkeysib- prefix) | High |
| `elastic-email-key` | Elastic Email API Key | High |
| `pepipost-token` | Pepipost API Token | High |
| `mailmodo-token` | Mailmodo API Key | High |
| `verimail-token` | Verimail API Token | High |
| `zerobounce-token` | ZeroBounce API Key | High |
| `mailboxlayer-token` | Mailboxlayer Access Key | High |
| `d7network-token` | D7Networks API Token | High |
| `sinch-message-token` | Sinch Message Token | High |
| `messagebird-token` | MessageBird API Key | High |
| `vonage-api-key` | Vonage / Nexmo API Key | High |
| `plivo-token` | Plivo Auth Token | High |
| `postman-api-key` | Postman API Key (PMAK- prefix) | High |
| `pubnub-key` | PubNub Publish/Subscription Key | High |
| `pusher-key` | Pusher Channel Key | High |
| `pushbullet-api-key` | PushBullet API Key | High |
| `doppler-token` | Doppler API Token (dp.pt. prefix) | High |

### Monitoring & Observability

| Rule ID | Description | Severity |
|---|---|---|
| `datadog-api-key` | Datadog API Key | High |
| `datadog-access-token` | Datadog Access Token (dt0 format) | High |
| `new-relic-license-key` | New Relic License Key | High |
| `new-relic-personal-api-key` | New Relic Personal API Key (NRAK prefix) | High |
| `pagerduty-api-key` | PagerDuty API Key | High |
| `opsgenie-api-key` | Opsgenie API Key | High |
| `sentry-token` | Sentry Auth Token (sntrys_ prefix) | High |
| `sumologic-key` | SumoLogic Access Key | High |
| `splunk-observability-token` | Splunk Observability Access Token (SPL prefix) | High |
| `appoptics-token` | AppOptics / SolarWinds Token | High |
| `airbrake-key` | Airbrake Project / User Key | High |
| `logdna-key` | LogDNA Ingestion Key | High |
| `loggly-token` | Loggly Customer Token | High |
| `better-stack-key` | Better Stack / Better Uptime API Key | High |
| `statuspage-api-key` | Statuspage API Key | High |
| `uptimerobot-api-key` | UptimeRobot API Key | High |
| `pingdom-token` | Pingdom API Token | High |

### Analytics & Product

| Rule ID | Description | Severity |
|---|---|---|
| `posthog-api-key` | PostHog API Key (phc_ prefix) | High |
| `amplitude-api-key` | Amplitude API Key | High |
| `segment-api-key` | Segment API Key | High |
| `mixpanel-token` | Mixpanel Project Token | High |
| `heap-api-key` | Heap Analytics API Key | High |
| `pendo-integration-key` | Pendo Integration Key | High |
| `keenio-key` | Keen.io API Key | High |
| `fathom-analytics-key` | Fathom Analytics API Key | High |
| `plausible-analytics-key` | Plausible Analytics API Key | High |
| `hotjar-token` | Hotjar API Token | High |
| `fullstory-token` | FullStory API Token | High |
| `bitly-access-token` | Bitly Access Token | High |
| `calendly-api-key` | Calendly API Key | High |
| `calendarific-token` | Calendarific API Token | High |
| `appfollow-token` | AppFollow API Token | High |
| `appcues-token` | Appcues API Token | High |

### Auth & Identity

| Rule ID | Description | Severity |
|---|---|---|
| `auth0-api-token` | Auth0 API Token | High |
| `auth0-management-token` | Auth0 Management API Token | High |
| `auth0-oauth-token` | Auth0 OAuth Token | High |
| `okta-api-token` | Okta API Token | High |
| `onelogin-token` | OneLogin API Token | High |
| `jumpcloud-token` | JumpCloud API Token | High |
| `authress-service-client-key` | Authress Service Client Key (sc_ prefix) | High |
| `keycloak-token` | Keycloak Token | High |
| `fusionauth-token` | FusionAuth API Token | High |
| `stytch-token` | Stytch API Token | High |
| `clerk-token` | Clerk API Token (sk_ prefix) | High |
| `workos-token` | WorkOS API Token | High |
| `supabase-service-key` | Supabase Service Key (sbp_ prefix) | High |
| `supabase-anon-key` | Supabase Anon Key (eyJ JWT format) | Medium |
| `firebase-token` | Firebase Auth Token | High |
| `firebase-fcm-key` | Firebase Cloud Messaging Server Key (AAAA prefix) | High |
| `kubeconfig` | KubeConfig with Client Key Data | High |
| `hashicorp-vault-token` | HashiCorp Vault Token (hvs./hvb./s. prefix) | High |
| `onepassword-secret-key` | 1Password Secret Key (a3- format) | High |
| `onepassword-service-account-token` | 1Password Service Account Token (ops_ prefix) | High |

### Hosting & Backend

| Rule ID | Description | Severity |
|---|---|---|
| `vercel-token` | Vercel Access Token | High |
| `netlify-token` | Netlify Access Token | High |
| `supabase-service-key` | Supabase Service Key (sbp_ prefix) | High |
| `cloudflare-api-key` | Cloudflare API Key | High |
| `cloudflare-api-token` | Cloudflare API Token | High |
| `wpengine-token` | WP Engine API Token | High |
| `fastly-api-key` | Fastly API Key | High |
| `akamai-token` | Akamai API Token | High |
| `equinix-oauth-token` | Equinix OAuth Token | High |
| `flyio-token` | Fly.io API Token | High |
| `railway-token` | Railway API Token | High |
| `render-token` | Render API Token (rnd_ prefix) | High |
| `koyeb-token` | Koyeb API Token | High |

### Social & Developer Platforms

| Rule ID | Description | Severity |
|---|---|---|
| `twitch-client-secret` | Twitch Client Secret | High |
| `twitch-access-token` | Twitch Access Token | High |
| `twitter-bearer-token` | Twitter/X Bearer Token | High |
| `facebook-app-secret` | Facebook App Secret | High |
| `facebook-access-token` | Facebook Access Token (EAAD prefix) | High |
| `facebook-oauth-token` | Facebook OAuth Token | High |
| `linkedin-client-secret` | LinkedIn Client Secret | High |
| `linear-api-key` | Linear API Key (lin_api_ prefix) | High |
| `figma-token` | Figma Access Token | Medium |
| `figma-personal-access-token` | Figma Personal Access Token (figd_ prefix) | High |
| `npm-token` | npm Access Token (npm_ prefix) | High |
| `pypi-token` | PyPI Token (pypi-AgEI prefix) | High |
| `spotify-key` | Spotify API Key | High |
| `youtube-api-key` | YouTube API Key (AIza prefix) | High |
| `flickr-access-token` | Flickr Access Token | High |
| `dropbox-api-secret` | Dropbox API Secret | High |
| `dropbox-long-lived-token` | Dropbox Long-Lived Token (sl. prefix) | High |
| `dropbox-short-lived-token` | Dropbox Short-Lived Token (sl. prefix) | High |
| `reddit-client-secret` | Reddit Client Secret | High |
| `reddit-access-token` | Reddit Access Token | High |
| `instagram-access-token` | Instagram Access Token (IG prefix) | High |
| `pinterest-token` | Pinterest API Token | High |
| `tiktok-access-token` | TikTok Access Token | High |
| `zoom-api-secret` | Zoom API Key/Secret | High |
| `zapier-webhook-url` | Zapier Webhook URL | High |

### Database Connection Strings

| Rule ID | Description | Severity |
|---|---|---|
| `postgres-connection-string` | PostgreSQL connection string with embedded credentials | High |
| `mysql-connection-string` | MySQL connection string with embedded credentials | High |
| `mongodb-connection-string` | MongoDB connection string with embedded credentials | High |
| `redis-connection-string` | Redis connection string with embedded credentials | High |
| `jdbc-connection-string` | JDBC connection string (MySQL/PostgreSQL/SQL Server) | High |
| `sqlserver-connection-string` | SQL Server connection string with password | High |
| `elasticsearch-connection` | Elasticsearch connection with credentials | High |
| `influxdb-token` | InfluxDB API Token | High |
| `couchbase-connection-string` | Couchbase connection string with credentials | High |
| `cassandra-connection` | Cassandra connection with credentials | High |
| `neo4j-connection-string` | Neo4j connection string with credentials | High |
| `supabase-db-connection` | Supabase DB connection string | High |
| `planetscale-token` | PlanetScale API Token (pscale_ prefix) | High |
| `neon-database-token` | Neon Database API Token | High |
| `turso-token` | Turso Database API Token | High |
| `convex-token` | Convex Database Token | High |

### DevOps & Infrastructure

| Rule ID | Description | Severity |
|---|---|---|
| `age-secret-key` | Age Encryption Secret Key (AGE-SECRET-KEY-1 prefix) | High |
| `kubernetes-secret-manifest` | Kubernetes Secret Manifest with base64 data | High |
| `hashicorp-terraform-token` | HashiCorp Terraform Cloud Token | High |
| `ansible-vault-password` | Ansible Vault Password | High |
| `docker-registry-token` | Docker Registry Token | High |
| `harbor-token` | Harbor Registry API Token | High |
| `nexus-token` | Nexus Repository Token | High |
| `confluent-access-token` | Confluent Cloud Access Token | High |
| `confluent-secret-key` | Confluent Cloud Secret Key | High |
| `databricks-token` | Databricks API Token (dapi prefix) | High |
| `snowflake-token` | Snowflake API Token | High |
| `dynatrace-api-token` | Dynatrace API Token (dt0c01 prefix) | High |
| `launchdarkly-key` | LaunchDarkly API Key | High |
| `configcat-key` | ConfigCat API Key | High |
| `flagsmith-key` | Flagsmith API Key | High |

### Security & API Services

| Rule ID | Description | Severity |
|---|---|---|
| `shodan-api-key` | Shodan API Key | High |
| `abuseipdb-key` | AbuseIPDB API Key | High |
| `alienvault-otx-key` | AlienVault OTX API Key | High |
| `virustotal-api-key` | VirusTotal API Key | High |
| `hunterio-api-key` | Hunter.io API Key | High |
| `ipstack-key` | IPStack API Key | High |
| `maxmind-license-key` | MaxMind License Key | High |
| `cloudsight-key` | CloudSight API Key | High |
| `rapidapi-key` | RapidAPI Key | High |
| `scrapingbee-key` | ScrapingBee API Key | High |
| `ipinfo-token` | ipinfo.io API Token | High |

### Maps & Location

| Rule ID | Description | Severity |
|---|---|---|
| `google-maps-api-key` | Google Maps API Key (AIza prefix) | High |
| `mapbox-token` | MapBox Access Token (pk. prefix) | High |
| `mapquest-key` | MapQuest API Key | High |
| `here-maps-key` | Here Maps API Key | High |
| `opencage-key` | OpenCage Geocoder API Key | High |

### CRM & Business

| Rule ID | Description | Severity |
|---|---|---|
| `hubspot-api-key` | HubSpot API Key | High |
| `hubspot-oauth-token` | HubSpot OAuth Token | High |
| `salesforce-oauth2-token` | Salesforce OAuth2 Token | High |
| `zendesk-api-token` | Zendesk API Token | High |
| `elastic-path-token` | Elastic Path API Token | High |
| `buttercms-token` | ButterCMS API Token | High |
| `contentful-delivery-token` | Contentful Delivery API Token | High |
| `contentful-personal-access-token` | Contentful Personal Access Token (CFPAT- prefix) | High |
| `sanity-api-token` | Sanity API Token | High |
| `storyblok-token` | Storyblok API Token | High |
| `strapi-api-token` | Strapi API Token | High |
| `airtable-api-key` | Airtable API Key (deprecated, key prefix) | High |
| `airtable-personal-access-token` | Airtable Personal Access Token (pat prefix) | High |
| `airtable-oauth-token` | Airtable OAuth Token | High |
| `algolia-admin-key` | Algolia Admin API Key | High |
| `lokalise-token` | Lokalise API Token | High |

### Crypto & Web3

| Rule ID | Description | Severity |
|---|---|---|
| `bitcoin-private-key-wif` | Bitcoin Private Key (WIF format) | Critical |
| `ethereum-private-key` | Ethereum Private Key (0x + 64 hex) | Critical |
| `solana-private-key` | Solana Private Key (base58 88-char) | Critical |
| `infura-api-key` | Infura API Key | High |
| `alchemy-api-key` | Alchemy API Key | High |
| `moralis-api-key` | Moralis API Key | High |
| `quicknode-token` | QuickNode API Token | High |
| `bitfinex-api-key` | Bitfinex API Key | High |
| `bittrex-access-key` | Bittrex Access Key | High |
| `bittrex-secret-key` | Bittrex Secret Key | High |

### Communication & Messaging (TruffleHog)

| Rule ID | Description | Severity |
|---|---|---|
| `twilio-api-key` | Twilio API Key (SK prefix) | High |
| `line-messaging-api-token` | Line Messaging API Token | High |
| `line-notify-token` | Line Notify Token | High |
| `mattermost-personal-token` | Mattermost Personal Token | High |
| `wechat-app-key` | WeChat App Key/Secret | High |
| `kakaotalk-api-key` | KakaoTalk API Key | Medium |
| `liveagent-api-key` | LiveAgent API Key | Medium |
| `front-api-key` | Front API Key (front_ prefix) | High |
| `ringcentral-api-key` | RingCentral API Key | High |
| `telesign-api-key` | TeleSign API Key | High |
| `teamviewer-api-token` | TeamViewer API Token | High |
| `cometchat-api-key` | CometChat API Key | Medium |
| `mesibo-api-key` | Mesibo API Key | High |
| `bulbul-api-key` | Bulbul API Key | Medium |
| `tyntec-api-key` | Tyntec API Key | Medium |
| `kaleyra-api-key` | Kaleyra API Key | Medium |
| `onbuka-api-key` | Onbuka API Key | Medium |
| `clicksend-api-key` | ClickSend SMS API Key | High |
| `clockwork-sms-api-key` | Clockwork SMS API Key | High |
| `sms-api-key` | Generic SMS API Key | Medium |
| `bombbomb-api-key` | BombBomb API Key | Medium |
| `dfuse-api-key` | DFuse API Key (server_ prefix) | Medium |
| `apifonica-api-key` | ApiFonica API Key | Medium |
| `mandrill-api-key` | Mandrill API Key (Mailchimp transactional) | High |
| `sparkpost-api-key` | SparkPost API Key | High |
| `mailerlite-api-key` | MailerLite API Key | High |
| `convertkit-api-key` | ConvertKit API Key/Secret | High |
| `omnisend-api-key` | Omnisend API Key | Medium |
| `customerio-api-key` | Customer.io API Key | High |
| `moosend-api-key` | Moosend API Key | Medium |
| `dotdigital-api-key` | Dotdigital API Key | Medium |
| `dyspatch-api-key` | Dyspatch API Key | Medium |
| `postageapp-api-key` | PostageApp API Key | Medium |
| `nicereply-api-key` | Nicereply API Key | Medium |
| `autopilot-api-key` | AutoPilot API Key | Medium |
| `airship-api-key` | Airship (Urban Airship) API Key | High |

### CRM & Sales (TruffleHog)

| Rule ID | Description | Severity |
|---|---|---|
| `freshworks-api-key` | Freshworks/Freshdesk API Key | High |
| `close-crm-api-key` | Close CRM API Key | High |
| `copper-crm-api-key` | Copper CRM API Key | Medium |
| `streak-crm-api-key` | Streak CRM API Key | Medium |
| `groovehq-api-key` | GrooveHQ API Key | Medium |
| `getgist-api-key` | GetGist API Key | Medium |
| `autoklose-api-key` | Autoklose API Key | Medium |
| `salesflare-api-key` | Salesflare API Key | Medium |
| `salesblink-api-key` | SalesBlink API Key | Medium |
| `salescookie-api-key` | Salescookie API Key | Medium |
| `metrilo-api-key` | Metrilo API Key | Medium |
| `revampcrm-api-key` | RevampCRM API Key | Medium |
| `karmacrm-api-key` | KarmaCRM API Key | Medium |
| `lessannoyingcrm-api-key` | Less Annoying CRM API Key | Medium |
| `nethunt-crm-api-key` | NetHunt CRM API Key | Medium |
| `nimble-crm-api-key` | Nimble CRM API Key | Medium |
| `apptivo-crm-api-key` | Apptivo CRM API Key | Medium |
| `capsule-crm-api-key` | Capsule CRM API Key | Medium |
| `insightly-crm-api-key` | Insightly CRM API Key | Medium |
| `kylas-crm-api-key` | Kylas CRM API Key | Medium |
| `onepagecrm-api-key` | OnePageCRM API Key | Medium |
| `prospectcrm-api-key` | Prospect CRM API Key | Medium |
| `reallysimplesystems-crm-api-key` | Really Simple Systems CRM API Key | Medium |
| `centralstation-crm-api-key` | Central Station CRM API Key | Medium |
| `teamgate-crm-api-key` | Teamgate CRM API Key | Medium |
| `axonaut-api-key` | Axonaut API Key | Medium |
| `flowflu-api-key` | FlowFlu API Key | Medium |
| `clientary-api-key` | Clientary API Key | Medium |
| `clinchpad-api-key` | Clinchpad API Key | Medium |
| `companyhub-api-key` | CompanyHub API Key | Medium |
| `campayn-api-key` | Campayn API Key | Medium |
| `hiveage-api-key` | Hiveage API Key | Medium |
| `billomat-api-key` | Billomat API Key | Medium |
| `alegra-api-key` | Alegra API Key | Medium |
| `loyverse-api-key` | Loyverse API Key | Medium |
| `commercejs-api-key` | CommerceJS API Key (pk_ prefix) | Medium |
| `snipcart-api-key` | Snipcart API Key (SNIP_ prefix) | High |
| `partnerstack-api-key` | PartnerStack API Key | Medium |
| `vouchery-api-key` | Vouchery API Key | Medium |
| `monday-api-key` | Monday.com API Key | High |
| `smartsheets-api-key` | Smartsheets API Key | High |
| `wrike-api-key` | Wrike API Key | High |
| `apollo-io-api-key` | Apollo.io API Key | High |
| `uplead-api-key` | UpLead API Key | Medium |
| `rocketreach-api-key` | RocketReach API Key | Medium |
| `clearbit-api-key` | Clearbit API Key (cb_ prefix) | High |
| `brandfetch-api-key` | Brandfetch API Key | Medium |
| `leadfeeder-api-key` | Leadfeeder API Key | Medium |
| `getemail-api-key` | GetEmail API Key | Medium |
| `getemails-api-key` | GetEmails API Key | Medium |
| `skrappio-api-key` | Skrappio API Key | Medium |
| `powrbot-api-key` | Powrbot API Key | Medium |

### Project Management & Productivity (TruffleHog)

| Rule ID | Description | Severity |
|---|---|---|
| `clickup-personal-token` | ClickUp Personal Token | High |
| `todoist-api-token` | Todoist API Token | High |
| `shortcut-api-key` | Shortcut API Key | Medium |
| `tmetric-api-key` | TMetric API Key | Medium |
| `clockify-api-key` | Clockify API Key | High |
| `everhour-api-key` | Everhour API Key | Medium |
| `harvest-api-key` | Harvest API Key | High |
| `humanity-api-key` | Humanity API Key | Medium |
| `toggl-track-api-key` | Toggl Track API Key | Medium |
| `runrunit-api-key` | RunRunIt API Key | Medium |
| `workstack-api-key` | Workstack API Key | Medium |
| `easyinsight-api-key` | EasyInsight API Key | Medium |
| `dovico-api-key` | Dovico API Key | Medium |
| `mavenlink-api-key` | Mavenlink API Key | Medium |
| `float-api-key` | Float API Key | Medium |
| `daily-co-api-key` | Daily.co API Key | High |
| `tly-api-key` | T.ly API Key | Medium |
| `rebrandly-api-key` | Rebrandly API Key | Medium |
| `timezone-api-key` | Timezone API Key | Low |
| `jotform-api-key` | Jotform API Key | High |

### Forms & Survey Platforms (TruffleHog)

| Rule ID | Description | Severity |
|---|---|---|
| `typeform-api-key` | Typeform API Key | High |
| `surveysparrow-api-key` | SurveySparrow API Key | Medium |
| `survicate-api-key` | Survicate API Key | Medium |
| `delighted-api-key` | Delighted API Key | Medium |
| `feedier-api-key` | Feedier API Key | Medium |
| `zonka-feedback-api-key` | Zonka Feedback API Key | Medium |
| `satismeter-project-key` | Satismeter Project Key | Medium |
| `satismeter-write-key` | Satismeter Write Key | Medium |
| `simplesat-api-key` | Simplesat API Key | Medium |
| `surveyanyplace-api-key` | SurveyAnyplace API Key | Medium |
| `surveybot-api-key` | SurveyBot API Key | Medium |
| `qualaroo-api-key` | Qualaroo API Key | Medium |
| `customerguru-api-key` | CustomerGuru API Key | Medium |
| `abyssale-api-key` | Abyssale API Key | Medium |
| `magnetic-api-key` | Magnetic API Key | Medium |
| `refiner-api-key` | Refiner API Key | Medium |
| `simvoly-api-key` | Simvoly API Key | Medium |
| `checkmarket-api-key` | Checkmarket API Key | Medium |
| `webengage-api-key` | Webengage API Key | Medium |

### Financial & Trading APIs (TruffleHog)

| Rule ID | Description | Severity |
|---|---|---|
| `twelve-data-api-key` | Twelve Data API Key | Medium |
| `fixer-io-api-key` | Fixer.io API Key | Medium |
| `alpha-vantage-api-key` | Alpha Vantage API Key | Medium |
| `tradier-api-key` | Tradier API Key | High |
| `finnhub-api-key` | Finnhub API Key | Medium |
| `tiingo-api-key` | Tiingo API Key | Medium |
| `finage-api-key` | Finage API Key | Medium |
| `iex-cloud-api-key` | IEX Cloud API Key | Medium |
| `intrinio-api-key` | Intrinio API Key | Medium |
| `financial-modeling-prep-api-key` | Financial Modeling Prep API Key | Medium |
| `nasdaq-data-link-api-key` | Nasdaq Data Link API Key | High |
| `qubole-api-key` | Qubole API Key | Medium |
| `enigma-api-key` | Enigma API Key | Medium |
| `datagov-api-key` | Data.gov API Key | Low |
| `stockdata-api-key` | Stockdata API Key | Medium |
| `marketstack-api-key` | Marketstack API Key | Medium |
| `commodities-api-key` | Commodities API Key | Medium |
| `baremetrics-api-key` | Baremetrics API Key | Medium |
| `dwolla-api-key` | Dwolla API Key | High |
| `wepay-api-key` | WePay API Key | High |
| `checkout-com-api-key` | Checkout.com API Key | High |
| `paymongo-api-key` | Paymongo API Key | High |
| `avalara-api-key` | Avalara API Key | High |
| `carbon-interface-api-key` | Carbon Interface API Key | Medium |
| `currency-layer-api-key` | Currency Layer API Key | Medium |
| `exchange-rates-api-key` | Exchange Rates API Key | Low |
| `currencyscoop-api-key` | CurrencyScoop API Key | Medium |
| `currencyfreaks-api-key` | Currency Freaks API Key | Medium |
| `country-layer-api-key` | Country Layer API Key | Low |
| `fxmarket-api-key` | FX Market API Key | Medium |
| `currencycloud-api-key` | Currency Cloud API Key | High |

### Crypto & Blockchain Additional (TruffleHog)

| Rule ID | Description | Severity |
|---|---|---|
| `kraken-api-key` | Kraken API Key | High |
| `poloniex-api-key` | Poloniex API Key | High |
| `bitmex-api-key` | BitMEX API Key | High |
| `coinapi-key` | CoinAPI Key | Medium |
| `coinlayer-api-key` | Coinlayer API Key | Medium |
| `coinlib-api-key` | Coinlib API Key | Low |
| `cryptocompare-api-key` | CryptoCompare API Key | Medium |
| `bitcoinaverage-api-key` | Bitcoin Average API Key | Medium |
| `worldcoinindex-api-key` | World Coin Index API Key | Medium |
| `glassnode-api-key` | Glassnode API Key | High |
| `tatum-api-key` | Tatum.io API Key | High |
| `ethplorer-api-key` | Ethplorer API Key | Medium |
| `nftport-api-key` | NFTPort API Key | High |
| `messari-api-key` | Messari API Key | Medium |
| `coingecko-api-key` | CoinGecko API Key | Medium |

### Weather & Environment APIs (TruffleHog)

| Rule ID | Description | Severity |
|---|---|---|
| `openweather-api-key` | OpenWeather API Key | Medium |
| `weatherstack-api-key` | WeatherStack API Key | Medium |
| `accuweather-api-key` | AccuWeather API Key | Medium |
| `worldweather-api-key` | World Weather API Key | Medium |
| `tomorrow-io-api-key` | Tomorrow.io API Key | Medium |
| `airvisual-api-key` | AirVisual API Key | Medium |
| `visualcrossing-api-key` | Visual Crossing API Key | Medium |
| `stormglass-api-key` | Stormglass API Key | Medium |
| `aeris-weather-api-key` | Aeris Weather API Key | Medium |
| `ambee-api-key` | Ambee API Key | Medium |
| `openuv-api-key` | OpenUV API Key | Medium |

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
| `curl-auth-string` | Curl Authentication String (curl -u user:pass) | High |
| `uri-embedded-credentials` | URI with Embedded Credentials (https://user:pass@host) | High |
| `generic-oauth-client-secret` | Generic OAuth Client Secret assignment | High |
| `env-file-secret` | .env File Secret (KEY=VALUE pattern) | Medium |
| `firebase-config-web` | Firebase Web Config (apiKey in firebaseConfig) | Low |

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
