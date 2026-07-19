//! Built-in detector registry — well-known secret formats from popular providers.

use crate::detector::{Detector, RegexDetector};
use crate::entropy::EntropyDetector;
use crate::finding::Severity;

/// Returns the full set of built-in detectors (provider-specific regexes + generic entropy).
pub fn builtin_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        // ── AWS ──────────────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "aws-access-key-id",
            "AWS Access Key ID",
            Severity::Critical,
            r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b",
            &["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-secret-access-key",
            "AWS Secret Access Key",
            Severity::Critical,
            r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
            &["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-session-token",
            "AWS Session Token",
            Severity::Critical,
            r#"(?i)aws_session_token\s*[:=]\s*['"]?([A-Za-z0-9/+=]{16,})['"]?"#,
            &["aws_session_token", "AWS_SESSION_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-mws-auth-token",
            "Amazon MWS Auth Token",
            Severity::High,
            r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            &["amzn.mws."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-bedrock-api-key-long-lived",
            "Amazon Bedrock API Key (long-lived)",
            Severity::Critical,
            r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}\b",
            &["ABSK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-bedrock-api-key-short-lived",
            "Amazon Bedrock API Key (short-lived)",
            Severity::High,
            r"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
            &["bedrock-api-key-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-account-id",
            "AWS Account ID",
            Severity::Low,
            r#"(?i)aws_account_id\s*[:=]\s*['"]?(\d{12})['"]?"#,
            &["aws_account_id", "AWS_ACCOUNT_ID"],
        )),
        // ── GitHub ───────────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "github-pat",
            "GitHub Personal Access Token",
            Severity::Critical,
            r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
            &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "github-fine-grained-pat",
            "GitHub Fine-Grained Personal Access Token",
            Severity::Critical,
            r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
            &["github_pat_"],
        )),
        // ── Slack ────────────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "slack-token",
            "Slack Token",
            Severity::High,
            r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b",
            &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "slack-webhook",
            "Slack Incoming Webhook URL",
            Severity::High,
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{24,}",
            &["hooks.slack.com"],
        )),
        // ── Stripe ───────────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "stripe-secret-key",
            "Stripe Secret Key",
            Severity::Critical,
            r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,247}\b",
            &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stripe-publishable-key",
            "Stripe Publishable Key",
            Severity::Low,
            r"\bpk_(live|test)_[A-Za-z0-9]{16,247}\b",
            &["pk_live_", "pk_test_"],
        )),
        // ── Google / GCP ─────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "google-api-key",
            "Google API Key",
            Severity::High,
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            &["AIza"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "google-oauth-access-token",
            "Google OAuth Access Token",
            Severity::High,
            r"\bya29\.[A-Za-z0-9\-_]{16,}\b",
            &["ya29."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "google-service-account-json",
            "Google Service Account Private Key",
            Severity::Critical,
            r#"(?i)"type"\s*:\s*"service_account""#,
            &["\"type\"", "service_account"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gcp-service-account-private-key",
            "GCP Service Account Private Key",
            Severity::Critical,
            r#"(?i)"private_key"\s*:\s*"-----BEGIN (RSA |EC )?PRIVATE KEY-----"#,
            &["private_key", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gcp-oauth-client-id",
            "GCP OAuth Client ID",
            Severity::Medium,
            r#"[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com"#,
            &["googleusercontent.com"],
        )),
        // ── Azure ────────────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "azure-connection-string",
            "Azure Storage Connection String",
            Severity::Critical,
            r"(?i)(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{50,})",
            &["AccountKey=", "accountkey=", "DefaultEndpointsProtocol"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-sas-token",
            "Azure Shared Access Signature Token",
            Severity::High,
            r"\bsig=[A-Za-z0-9%]{20,}",
            &["sig=", "sv=", "st=", "se="],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-client-secret",
            "Azure Client Secret",
            Severity::High,
            r#"(?i)(azure|client)_secret\s*[:=]\s*['"]?([A-Za-z0-9\-_.~]{20,})['"]?"#,
            &["azure_secret", "client_secret", "AZURE_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-ad-client-secret",
            "Azure AD (Entra ID) Client Secret",
            Severity::High,
            r"[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}",
            &["Q~"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-batch-key",
            "Azure Batch Account Key",
            Severity::High,
            r#"(?i)batchaccountkey\s*[:=]\s*['"]?([A-Za-z0-9+/=]{50,})['"]?"#,
            &["BatchAccountKey", "batchaccountkey", "BATCHACCOUNTKEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-function-key",
            "Azure Function Key",
            Severity::High,
            r#"(?i)(functions_key|function_key|code)\s*[:=]\s*['"]?([A-Za-z0-9_\-=/+]{20,})['"]?"#,
            &["FUNCTIONS_KEY", "functions_key", "function_key", "code="],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-devops-pat",
            "Azure DevOps Personal Access Token",
            Severity::High,
            r"\b[A-Za-z0-9]{52}\b",
            &["devops", "azure-devops", "vsts"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-cosmos-key",
            "Azure Cosmos DB Key",
            Severity::Critical,
            r#"(?i)accountkey\s*[:=]\s*['"]?([A-Za-z0-9+/=]{88})['"]?"#,
            &["AccountKey", "accountkey", "ACCOUNTKEY"],
        )),
        // ── GitLab ───────────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "gitlab-pat",
            "GitLab Personal Access Token",
            Severity::Critical,
            r"\bglpat-[A-Za-z0-9_-]{20}\b",
            &["glpat-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gitlab-pipeline-trigger-token",
            "GitLab Pipeline Trigger Token",
            Severity::High,
            r"\bglptt-[A-Za-z0-9_-]{40,}\b",
            &["glptt-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gitlab-runner-registration-token",
            "GitLab Runner Registration Token",
            Severity::High,
            r"\bGR1348921[A-Za-z0-9_-]{20}\b",
            &["GR1348921"],
        )),
        // ── Discord / Telegram ───────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "discord-bot-token",
            "Discord Bot Token",
            Severity::High,
            r"\b[A-Za-z0-9]{24}\.[A-Za-z0-9]{6}\.[A-Za-z0-9_-]{27}\b",
            &["discord", "DISCORD", "bot_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "discord-webhook",
            "Discord Webhook URL",
            Severity::Medium,
            r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{40,}",
            &["discord.com/api/webhooks", "discordapp.com/api/webhooks"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "telegram-bot-token",
            "Telegram Bot Token",
            Severity::High,
            r"\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33,}\b",
            &["telegram", "TELEGRAM", "bot_token", ":AA"],
        )),
        // ── Cloudflare ───────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "cloudflare-api-key",
            "Cloudflare API Key",
            Severity::High,
            r#"(?i)cloudflare[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{37})['"]?"#,
            &["cloudflare_api_key", "CLOUDFLARE_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudflare-api-token",
            "Cloudflare API Token",
            Severity::High,
            r#"(?i)cloudflare[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{40})['"]?"#,
            &["cloudflare_api_token", "CLOUDFLARE_API_TOKEN"],
        )),
        // ── Twilio / SendGrid / Mailgun ──────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "twilio-account-sid",
            "Twilio Account SID",
            Severity::High,
            r"\bAC[a-f0-9]{32}\b",
            &["AC"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "twilio-auth-token",
            "Twilio Auth Token",
            Severity::High,
            r#"(?i)twilio[_-]?auth[_-]?token\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"#,
            &["twilio_auth_token", "TWILIO_AUTH_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sendgrid-api-key",
            "SendGrid API Key",
            Severity::High,
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
            &["SG."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailgun-api-key",
            "Mailgun API Key",
            Severity::High,
            r"\bkey-[a-zA-Z0-9]{32}\b",
            &["key-"],
        )),
        // ── AI Providers ─────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "openai-api-key",
            "OpenAI API Key",
            Severity::Critical,
            r"\bsk-[A-Za-z0-9]{48}\b",
            &["sk-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "anthropic-api-key",
            "Anthropic API Key",
            Severity::Critical,
            r"\bsk-ant-[A-Za-z0-9_-]{86,}\b",
            &["sk-ant-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "huggingface-token",
            "HuggingFace Access Token",
            Severity::High,
            r"\bhf_[A-Za-z0-9]{34}\b",
            &["hf_"],
        )),
        // ── CI/CD Providers ──────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "circleci-api-token",
            "CircleCI API Token",
            Severity::High,
            r"\bCCIPVJ_[A-Za-z0-9_-]{22,}\b",
            &["CCIPVJ_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "heroku-api-key",
            "Heroku API Key",
            Severity::High,
            r#"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Fa-f0-9]{32})['"]?"#,
            &["heroku_api_key", "HEROKU_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "github-old-pat",
            "GitHub Legacy Personal Access Token",
            Severity::High,
            r#"(?i)github[_-]?(?:token|pat)\s*[:=]\s*['"]?([0-9a-f]{40})['"]?"#,
            &["github_token", "GITHUB_TOKEN", "github_pat", "GITHUB_PAT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitbucket-client-id",
            "Bitbucket OAuth Client ID",
            Severity::Medium,
            r#"(?i)bitbucket[_-]?client[_-]?id\s*[:=]\s*['"]?([A-Za-z0-9]{32,})['"]?"#,
            &["bitbucket_client_id", "BITBUCKET_CLIENT_ID"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitbucket-client-secret",
            "Bitbucket OAuth Client Secret",
            Severity::High,
            r#"(?i)bitbucket[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9_\-]{32,})['"]?"#,
            &["bitbucket_client_secret", "BITBUCKET_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitbucket-datacenter-token",
            "Bitbucket Data Center Token",
            Severity::High,
            r#"(?i)bitbucket[_-]?(?:dc|datacenter)[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bitbucket_dc_token", "BITBUCKET_DC_TOKEN", "bitbucket_datacenter"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "travis-ci-token",
            "Travis CI Token",
            Severity::High,
            r#"(?i)travis[_-]?ci[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["travis_ci_token", "TRAVIS_CI_TOKEN", "travis_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "droneci-token",
            "DroneCI Access Token",
            Severity::High,
            r#"(?i)drone(?:ci)?[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["drone_token", "DRONE_TOKEN", "droneci_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "buildkite-token",
            "Buildkite API Token",
            Severity::High,
            r"\bbk[a-z]_[A-Za-z0-9]{40}\b",
            &["bkc_", "bku_", "bkr_", "bko_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "teamcity-token",
            "TeamCity API Token",
            Severity::High,
            r#"(?i)teamcity[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["teamcity_token", "TEAMCITY_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "jenkins-token",
            "Jenkins API Token",
            Severity::High,
            r#"(?i)jenkins[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{32,})['"]?"#,
            &["jenkins_token", "JENKINS_TOKEN", "jenkins_api_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gocd-token",
            "GoCD Access Token",
            Severity::High,
            r#"(?i)gocd[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["gocd_token", "GOCD_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "argocd-token",
            "ArgoCD API Token",
            Severity::High,
            r#"(?i)argocd[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["argocd_token", "ARGOCD_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "spinnaker-token",
            "Spinnaker Token",
            Severity::High,
            r#"(?i)spinnaker[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["spinnaker_token", "SPINNAKER_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "harness-api-key",
            "Harness API Key",
            Severity::High,
            r#"(?i)harness[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["harness_api_key", "HARNESS_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "codecov-token",
            "Codecov Access Token",
            Severity::High,
            r#"(?i)codecov[_-]?token\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"#,
            &["codecov_token", "CODECOV_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sonarqube-token",
            "SonarQube Token",
            Severity::High,
            r"\bsqu_[A-Za-z0-9]{40}\b",
            &["squ_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "snyk-api-key",
            "Snyk API Key",
            Severity::High,
            r#"(?i)snyk[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Fa-f0-9\-]{36,})['"]?"#,
            &["snyk_api_key", "SNYK_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "artifactory-api-key",
            "Artifactory API Key",
            Severity::High,
            r"\bAKC[A-Za-z0-9]{70}\b",
            &["AKC"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "artifactory-reference-token",
            "Artifactory Reference Token",
            Severity::High,
            r"\bcmV[A-Za-z0-9]{60}\b",
            &["cmV"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "terraform-cloud-token",
            "Terraform Cloud / HCP API Token",
            Severity::High,
            r"\b[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.atlasv1\.[A-Za-z0-9]{70,}\b",
            &["atlasv1."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pivotal-tracker-token",
            "Pivotal Tracker API Token",
            Severity::High,
            r#"(?i)pivotal[_-]?tracker[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["pivotal_tracker_token", "PIVOTAL_TRACKER_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clojars-token",
            "Clojars API Token",
            Severity::High,
            r"\bCLOJARS_[A-Za-z0-9]{60}\b",
            &["CLOJARS_"],
        )),
        // ── Monitoring / Observability ───────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "datadog-api-key",
            "Datadog API Key",
            Severity::High,
            r#"(?i)datadog[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["datadog_api_key", "DATADOG_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "new-relic-license-key",
            "New Relic License Key",
            Severity::High,
            r#"(?i)new[_-]?relic[_-]?license[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?"#,
            &["new_relic_license_key", "NEW_RELIC_LICENSE_KEY"],
        )),
        // ── Atlassian / Bitbucket ────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "atlassian-api-token",
            "Atlassian API Token",
            Severity::High,
            r#"(?i)atlassian[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{24,})['"]?"#,
            &["atlassian_api_token", "ATLASSIAN_API_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitbucket-app-password",
            "Bitbucket App Password",
            Severity::High,
            r#"(?i)bitbucket[_-]?app[_-]?password\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})['"]?"#,
            &["bitbucket_app_password", "BITBUCKET_APP_PASSWORD"],
        )),
        // ── Cloud Providers ──────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "digitalocean-pat",
            "DigitalOcean Personal Access Token",
            Severity::High,
            r"\bdop_v1_[A-Za-z0-9]{64}\b",
            &["dop_v1_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "digitalocean-spaces-key",
            "DigitalOcean Spaces Access Key",
            Severity::High,
            r"\bDO[A-Za-z0-9]{16,}\b",
            &["DO"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "alibaba-access-key-id",
            "Alibaba Cloud Access Key ID",
            Severity::Critical,
            r"\bLTAI[A-Za-z0-9]{12,20}\b",
            &["LTAI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tencent-secret-id",
            "Tencent Cloud Secret ID",
            Severity::Critical,
            r#"(?i)tencent[_-]?secret[_-]?id\s*[:=]\s*['"]?(AKID[A-Za-z0-9]{13,40})['"]?"#,
            &["tencent_secret_id", "TENCENT_SECRET_ID", "AKID"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "alibaba-secret-key",
            "Alibaba Cloud Secret Key",
            Severity::Critical,
            r#"(?i)(alibaba|aliyun)[_\-./\s]{0,20}(secret[_-]?key|secretkey)\s*[:=]\s*['"]?([A-Za-z0-9+/]{30})['"]?"#,
            &["alibaba_secret_key", "ALIBABA_SECRET_KEY", "aliyun_secret_key", "ALIYUN_SECRET_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tencent-secret-key",
            "Tencent Cloud Secret Key",
            Severity::Critical,
            r#"(?i)tencent[_-]?secret[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{36})['"]?"#,
            &["tencent_secret_key", "TENCENT_SECRET_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ibm-cloud-key",
            "IBM Cloud API Key",
            Severity::High,
            r#"(?i)ibm[_-]?cloud[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_-]{44})['"]?"#,
            &["ibm_cloud_key", "IBM_CLOUD_KEY", "ibmcloud", "bluemix"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "oracle-cloud-token",
            "Oracle Cloud (OCI) Token",
            Severity::High,
            r#"(?i)oracle[_-]?cloud[_-]?(?:token|key)\s*[:=]\s*['"]?([A-Za-z0-9_\-=/+]{40,})['"]?"#,
            &["oracle_cloud", "ORACLE_CLOUD", "oci_token", "OCI_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scaleway-key",
            "Scaleway API Key",
            Severity::High,
            r#"(?i)scaleway[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"#,
            &["scaleway", "SCALEWAY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "vultr-api-key",
            "Vultr API Key",
            Severity::High,
            r#"(?i)vultr[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Fa-f0-9]{36})['"]?"#,
            &["vultr_api_key", "VULTR_API_KEY", "vultr"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "linode-token",
            "Linode/Akamai API Token",
            Severity::High,
            r#"(?i)linode[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([0-9a-f]{64})['"]?"#,
            &["linode_token", "LINODE_TOKEN", "linode"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudflare-ca-key",
            "Cloudflare Origin CA Key",
            Severity::High,
            r"\bv1\.0-[0-9a-f]{24}-[0-9a-f]{146}\b",
            &["v1.0-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudflare-global-api-key",
            "Cloudflare Global API Key",
            Severity::High,
            r#"(?i)cloudflare[_-]?global[_-]?api[_-]?key\s*[:=]\s*['"]?([0-9a-f]{37})['"]?"#,
            &["cloudflare_global_api_key", "CLOUDFLARE_GLOBAL_API_KEY"],
        )),
        // ── Vercel / Netlify / Supabase ──────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "vercel-token",
            "Vercel Access Token",
            Severity::High,
            r#"(?i)vercel[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{24,})['"]?"#,
            &["vercel_token", "VERCEL_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "netlify-token",
            "Netlify Access Token",
            Severity::High,
            r#"(?i)netlify[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"#,
            &["netlify_token", "NETLIFY_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "supabase-service-key",
            "Supabase Service Key",
            Severity::High,
            r"\bsbp_[a-z]+\.[A-Za-z0-9]{40,}\b",
            &["sbp_"],
        )),
        // ── Auth / Identity ──────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "auth0-api-token",
            "Auth0 API Token",
            Severity::High,
            r#"(?i)auth0[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"#,
            &["auth0_api_token", "AUTH0_API_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "okta-api-token",
            "Okta API Token",
            Severity::High,
            r#"(?i)okta[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})['"]?"#,
            &["okta_api_token", "OKTA_API_TOKEN"],
        )),
        // ── SaaS / Productivity ──────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "pagerduty-api-key",
            "PagerDuty API Key",
            Severity::High,
            r#"(?i)pagerduty[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_-]{20})['"]?"#,
            &["pagerduty_api_key", "PAGERDUTY_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailchimp-api-key",
            "Mailchimp API Key",
            Severity::High,
            r"\b[A-Fa-f0-9]{32}-us[0-9]{1,2}\b",
            &["-us"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shopify-access-token",
            "Shopify Access Token",
            Severity::High,
            r"\bshpat_[A-Za-z0-9]{32}\b",
            &["shpat_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "linear-api-key",
            "Linear API Key",
            Severity::High,
            r"\blin_api_[A-Za-z0-9]{40}\b",
            &["lin_api_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "notion-integration-token",
            "Notion Integration Token",
            Severity::Medium,
            r"\bsecret_[A-Za-z0-9]{43}\b",
            &["secret_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "figma-token",
            "Figma Access Token",
            Severity::Medium,
            r#"(?i)figma[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"#,
            &["figma_token", "FIGMA_TOKEN"],
        )),
        // ── Social / Communication ───────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "twitch-client-secret",
            "Twitch Client Secret",
            Severity::High,
            r#"(?i)twitch[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9]{30})['"]?"#,
            &["twitch_client_secret", "TWITCH_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "twitter-bearer-token",
            "Twitter/X Bearer Token",
            Severity::High,
            r#"(?i)twitter[_-]?bearer\s*[:=]\s*['"]?(AAAA[A-Za-z0-9%-]{40,})['"]?"#,
            &["twitter_bearer", "TWITTER_BEARER"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "facebook-app-secret",
            "Facebook App Secret",
            Severity::High,
            r#"(?i)facebook[_-]?app[_-]?secret\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"#,
            &["facebook_app_secret", "FACEBOOK_APP_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "linkedin-client-secret",
            "LinkedIn Client Secret",
            Severity::High,
            r#"(?i)linkedin[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9]{16})['"]?"#,
            &["linkedin_client_secret", "LINKEDIN_CLIENT_SECRET"],
        )),
        // ── Misc / Generic ───────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "private-key-pem",
            "PEM-Encoded Private Key",
            Severity::Critical,
            r"-----BEGIN ((RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY-----",
            &["-----BEGIN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "jwt",
            "JSON Web Token",
            Severity::Medium,
            r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b",
            &["eyJ"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "npm-token",
            "npm Access Token",
            Severity::High,
            r"\bnpm_[A-Za-z0-9]{36}\b",
            &["npm_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "postgres-connection-string",
            "PostgreSQL Connection String with Credentials",
            Severity::High,
            r"postgres(?:ql)?://[^:\s]+:[^@\s]+@[^\s/]+",
            &["postgres://", "postgresql://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mysql-connection-string",
            "MySQL Connection String with Credentials",
            Severity::High,
            r"mysql://[^:\s]+:[^@\s]+@[^\s/]+",
            &["mysql://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mongodb-connection-string",
            "MongoDB Connection String with Credentials",
            Severity::High,
            r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s/]+",
            &["mongodb://", "mongodb+srv://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "redis-connection-string",
            "Redis Connection String with Credentials",
            Severity::High,
            r"redis://[^:\s]+:[^@\s]+@[^\s/]+",
            &["redis://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "generic-bearer-token",
            "Generic Bearer Token",
            Severity::Low,
            r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}",
            &["bearer ", "Bearer "],
        )),
        Box::new(RegexDetector::with_prefilter(
            "generic-api-key-assignment",
            "Generic API Key Assignment",
            Severity::Low,
            r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([A-Za-z0-9]{32,})['"]?"#,
            &["api_key", "apikey", "API_KEY"],
        )),
        Box::new(EntropyDetector::default()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_detectors_nonempty() {
        assert!(!builtin_detectors().is_empty());
    }

    #[test]
    fn test_aws_key_detected() {
        let detectors = builtin_detectors();
        let aws = detectors
            .iter()
            .find(|d| d.id() == "aws-access-key-id")
            .unwrap();
        let matches = aws.scan_line("aws_key = AKIAIOSFODNN7EXAMPLE");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].text, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn test_github_pat_detected() {
        let detectors = builtin_detectors();
        let gh = detectors.iter().find(|d| d.id() == "github-pat").unwrap();
        let matches = gh.scan_line("token: ghp_1234567890abcdef1234567890abcdef1234");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_private_key_detected() {
        let detectors = builtin_detectors();
        let pk = detectors
            .iter()
            .find(|d| d.id() == "private-key-pem")
            .unwrap();
        let matches = pk.scan_line("-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_no_false_positive_on_plain_text() {
        let detectors = builtin_detectors();
        for d in &detectors {
            if d.id() == "generic-high-entropy" {
                continue; // entropy detector needs its own targeted tests
            }
            let matches = d.scan_line("this is just a plain sentence with no secrets in it");
            assert!(
                matches.is_empty(),
                "detector {} produced false positive",
                d.id()
            );
        }
    }

    #[test]
    fn test_aws_mws_token_detected() {
        let detectors = builtin_detectors();
        let mws = detectors
            .iter()
            .find(|d| d.id() == "aws-mws-auth-token")
            .unwrap();
        let matches = mws.scan_line("amzn.mws.12345678-1234-1234-1234-123456789012");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_aws_bedrock_key_detected() {
        let detectors = builtin_detectors();
        let bedrock = detectors
            .iter()
            .find(|d| d.id() == "aws-bedrock-api-key-long-lived")
            .unwrap();
        let key = format!("ABSK{}", "A".repeat(110));
        let matches = bedrock.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_azure_ad_client_secret_detected() {
        let detectors = builtin_detectors();
        let azure = detectors
            .iter()
            .find(|d| d.id() == "azure-ad-client-secret")
            .unwrap();
        let matches = azure.scan_line("abc1Q~abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_azure_batch_key_detected() {
        let detectors = builtin_detectors();
        let batch = detectors
            .iter()
            .find(|d| d.id() == "azure-batch-key")
            .unwrap();
        let matches = batch.scan_line("BatchAccountKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_azure_function_key_detected() {
        let detectors = builtin_detectors();
        let func = detectors
            .iter()
            .find(|d| d.id() == "azure-function-key")
            .unwrap();
        let matches = func.scan_line("FUNCTIONS_KEY=abc123def456ghi789jkl012mno345pqr678");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gcp_service_account_private_key_detected() {
        let detectors = builtin_detectors();
        let gcp = detectors
            .iter()
            .find(|d| d.id() == "gcp-service-account-private-key")
            .unwrap();
        let matches = gcp.scan_line(r#""private_key": "-----BEGIN PRIVATE KEY-----""#);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gcp_oauth_client_id_detected() {
        let detectors = builtin_detectors();
        let gcp = detectors
            .iter()
            .find(|d| d.id() == "gcp-oauth-client-id")
            .unwrap();
        let matches = gcp.scan_line("123456789-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_alibaba_secret_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "alibaba-secret-key").unwrap();
        let matches = d.scan_line("alibaba_secret_key = ABCDEF1234567890ABCDEFGHIJKLMN12");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tencent_secret_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tencent-secret-key").unwrap();
        let matches = d.scan_line("tencent_secret_key = ABCDEF1234567890ABCDEFGHIJKLMN1234567890");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ibm_cloud_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ibm-cloud-key").unwrap();
        let matches = d.scan_line("ibm_cloud_key = ABCDEfghIJklMNopQRstUVwxYZ1234567890123456-_");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_oracle_cloud_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "oracle-cloud-token").unwrap();
        let matches = d.scan_line("oracle_cloud_token = ABCDEfghIJklMNopQRstUVwxYZ1234567890abcd");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scaleway_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scaleway-key").unwrap();
        let matches = d.scan_line("scaleway_key = 12345678-1234-1234-1234-123456789012");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_vultr_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "vultr-api-key").unwrap();
        let matches = d.scan_line("vultr_api_key = ABCDEF1234567890ABCDEF1234567890ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_linode_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "linode-token").unwrap();
        let matches = d.scan_line("linode_token = abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cloudflare_global_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cloudflare-global-api-key").unwrap();
        let matches = d.scan_line("cloudflare_global_api_key = 1234567890abcdef1234567890abcdef1234567");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_github_old_pat_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "github-old-pat").unwrap();
        let matches = d.scan_line("github_token = abc123def4567890abc123def4567890abc123de");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bitbucket_client_id_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitbucket-client-id").unwrap();
        let matches = d.scan_line("bitbucket_client_id = ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bitbucket_client_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitbucket-client-secret").unwrap();
        let matches = d.scan_line("bitbucket_client_secret = ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_travis_ci_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "travis-ci-token").unwrap();
        let matches = d.scan_line("travis_ci_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_droneci_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "droneci-token").unwrap();
        let matches = d.scan_line("drone_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_buildkite_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "buildkite-token").unwrap();
        let matches = d.scan_line("bkc_1234567890abcdef1234567890abcdef12345678");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_teamcity_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "teamcity-token").unwrap();
        let matches = d.scan_line("teamcity_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_jenkins_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "jenkins-token").unwrap();
        let matches = d.scan_line("jenkins_token = abcdefghijklmnopqrstuvwxyz123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gocd_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "gocd-token").unwrap();
        let matches = d.scan_line("gocd_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_argocd_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "argocd-token").unwrap();
        let matches = d.scan_line("argocd_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_spinnaker_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "spinnaker-token").unwrap();
        let matches = d.scan_line("spinnaker_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_harness_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "harness-api-key").unwrap();
        let matches = d.scan_line("harness_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_codecov_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "codecov-token").unwrap();
        let matches = d.scan_line("codecov_token = abcdef1234567890abcdef1234567890");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sonarqube_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sonarqube-token").unwrap();
        let matches = d.scan_line("squ_1234567890abcdef1234567890abcdef12345678");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_snyk_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "snyk-api-key").unwrap();
        let matches = d.scan_line("snyk_api_key = abcdef12-3456-7890-abcd-ef1234567890");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_artifactory_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "artifactory-api-key").unwrap();
        let key = format!("AKC{}", "A".repeat(70));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_artifactory_reference_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "artifactory-reference-token").unwrap();
        let key = format!("cmV{}", "A".repeat(60));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_terraform_cloud_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "terraform-cloud-token").unwrap();
        let token = format!("app.abc123.def456.ghi789.jkl012.atlasv1.{}", "A".repeat(70));
        let matches = d.scan_line(&token);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pivotal_tracker_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pivotal-tracker-token").unwrap();
        let matches = d.scan_line("pivotal_tracker_token = abcdefghijklmnopqrstuvwxyz123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clojars_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clojars-token").unwrap();
        let key = format!("CLOJARS_{}", "A".repeat(60));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }
}
