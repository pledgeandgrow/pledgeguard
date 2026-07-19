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
            &[concat!("sk", "_live_"), concat!("sk", "_test_"), concat!("rk", "_live_"), concat!("rk", "_test_")],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stripe-publishable-key",
            "Stripe Publishable Key",
            Severity::Low,
            r"\bpk_(live|test)_[A-Za-z0-9]{16,247}\b",
            &[concat!("pk", "_live_"), concat!("pk", "_test_")],
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
            "discord-client-id",
            "Discord Client ID",
            Severity::Medium,
            r#"(?i)discord[_-]?client[_-]?id\s*[:=]\s*['"]?(\d{18})['"]?"#,
            &["discord_client_id", "DISCORD_CLIENT_ID"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "discord-client-secret",
            "Discord Client Secret",
            Severity::High,
            r#"(?i)discord[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9_\-]{32})['"]?"#,
            &["discord_client_secret", "DISCORD_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "microsoft-teams-webhook",
            "Microsoft Teams Webhook URL",
            Severity::High,
            r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]{36}/@[a-f0-9\-]{36}/IncomingWebhook/[A-Za-z0-9_\-]+/[a-f0-9\-]{36}",
            &["webhook.office.com", "office.com/webhookb2"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "atlassian-jira-token",
            "Atlassian (Jira) API Token",
            Severity::High,
            r#"(?i)(jira|atlassian)[_\-./\s]{0,20}(api[_-]?token|pat)\s*[:=]\s*['"]?([A-Za-z0-9]{24,})['"]?"#,
            &["jira_api_token", "JIRA_API_TOKEN", "jira_token", "JIRA_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gitter-token",
            "Gitter Access Token",
            Severity::High,
            r#"(?i)gitter[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["gitter_token", "GITTER_TOKEN", "gitter_access_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "webex-token",
            "Webex Access Token",
            Severity::High,
            r#"(?i)webex[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["webex_token", "WEBEX_TOKEN", "webex_access_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "intercom-token",
            "Intercom Access Token",
            Severity::High,
            r#"(?i)intercom[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["intercom_token", "INTERCOM_TOKEN", "intercom_access_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "helpscout-token",
            "HelpScout API Key",
            Severity::High,
            r#"(?i)helpscout[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["helpscout", "HELPSCOUT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "helpcrunch-token",
            "HelpCrunch Secret Key",
            Severity::High,
            r#"(?i)helpcrunch[_-]?secret[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["helpcrunch", "HELPCRUNCH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "canny-token",
            "Canny.io API Key",
            Severity::High,
            r#"(?i)canny[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["canny", "CANNY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pipedrive-token",
            "Pipedrive API Token",
            Severity::High,
            r#"(?i)pipedrive[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?"#,
            &["pipedrive", "PIPEDRIVE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "beamer-token",
            "Beamer API Token",
            Severity::High,
            r#"(?i)beamer[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["beamer", "BEAMER"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "frameio-token",
            "Frame.io API Token",
            Severity::High,
            r"\bfio-[A-Za-z0-9_\-]{64}\b",
            &["fio-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zeplin-token",
            "Zeplin API Token",
            Severity::High,
            r#"(?i)zeplin[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zeplin", "ZEPLIN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "trello-api-key",
            "Trello API Key",
            Severity::High,
            r#"(?i)trello[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["trello", "TRELLO"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "asana-client-id",
            "Asana Client ID",
            Severity::Medium,
            r#"(?i)asana[_-]?client[_-]?id\s*[:=]\s*['"]?([0-9]{16,})['"]?"#,
            &["asana_client_id", "ASANA_CLIENT_ID"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "asana-client-secret",
            "Asana Client Secret",
            Severity::High,
            r#"(?i)asana[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["asana_client_secret", "ASANA_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "asana-pat",
            "Asana Personal Access Token",
            Severity::High,
            r#"(?i)asana[_-]?(?:personal[_-]?access[_-]?)?token\s*[:=]\s*['"]?([0-9]/[A-Za-z0-9]{30,})['"]?"#,
            &["asana_token", "ASANA_TOKEN", "asana_pat", "ASANA_PAT"],
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
        Box::new(RegexDetector::with_prefilter(
            "postmark-token",
            "Postmark Server Token",
            Severity::High,
            r"\bpo_[-_][A-Za-z0-9]{36}\b",
            &["po_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailjet-basic-auth",
            "Mailjet Basic Auth Token",
            Severity::High,
            r"\bMJ[A-Za-z0-9]{30}\b",
            &["MJ"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailjet-sms-token",
            "Mailjet SMS Token",
            Severity::High,
            r#"(?i)mailjet[_-]?sms[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["mailjet_sms", "MAILJET_SMS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "brevo-token",
            "SendinBlue / Brevo API Key",
            Severity::High,
            r"\bxkeysib-[A-Za-z0-9_\-]{64,}\b",
            &["xkeysib-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "elastic-email-key",
            "Elastic Email API Key",
            Severity::High,
            r#"(?i)elastic[_-]?email[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["elastic_email", "ELASTIC_EMAIL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pepipost-token",
            "Pepipost API Token",
            Severity::High,
            r#"(?i)pepipost[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pepipost", "PEPIPOST"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailmodo-token",
            "Mailmodo API Key",
            Severity::High,
            r#"(?i)mailmodo[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["mailmodo", "MAILMODO"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "verimail-token",
            "Verimail API Token",
            Severity::High,
            r#"(?i)verimail[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["verimail", "VERIMAIL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zerobounce-token",
            "ZeroBounce API Key",
            Severity::High,
            r#"(?i)zerobounce[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zerobounce", "ZEROBOUNCE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailboxlayer-token",
            "Mailboxlayer Access Key",
            Severity::High,
            r#"(?i)mailboxlayer[_-]?(?:access[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["mailboxlayer", "MAILBOXLAYER"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "d7network-token",
            "D7Networks API Token",
            Severity::High,
            r#"(?i)d7[_-]?networks?[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["d7network", "D7NETWORK", "d7_networks"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sinch-message-token",
            "Sinch Message Token",
            Severity::High,
            r#"(?i)sinch[_-]?(?:message[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sinch", "SINCH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "messagebird-token",
            "MessageBird API Key",
            Severity::High,
            r#"(?i)messagebird[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{25})['"]?"#,
            &["messagebird", "MESSAGEBIRD"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "vonage-api-key",
            "Vonage / Nexmo API Key",
            Severity::High,
            r#"(?i)(vonage|nexmo)[_\-./\s]{0,20}(api[_-]?key|secret)\s*[:=]\s*['"]?([A-Za-z0-9]{8,})['"]?"#,
            &["vonage", "VONAGE", "nexmo", "NEXMO"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "plivo-token",
            "Plivo Auth Token",
            Severity::High,
            r#"(?i)plivo[_-]?(?:auth[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{40,})['"]?"#,
            &["plivo", "PLIVO"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "postman-api-key",
            "Postman API Key",
            Severity::High,
            r"\bPMAK-[A-Za-z0-9_\-]{59}\b",
            &["PMAK-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pubnub-key",
            "PubNub Publish/Subscribe Key",
            Severity::High,
            r#"(?i)pub[_-]?nub[_-]?(?:sub[_-]?)?key\s*[:=]\s*['"]?(sub-c-[A-Za-z0-9_\-]{20,})['"]?"#,
            &["pubnub", "PUBNUB", "sub-c-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pusher-key",
            "Pusher Channel Key",
            Severity::High,
            r#"(?i)pusher[_-]?(?:channel[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["pusher", "PUSHER"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pushbullet-api-key",
            "PushBullet API Key",
            Severity::High,
            r#"(?i)pushbullet[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["pushbullet", "PUSHBULLET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "doppler-token",
            "Doppler API Token",
            Severity::High,
            r"\bdp\.pt\.[A-Za-z0-9_\-]{40,}\b",
            &["dp.pt."],
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
        Box::new(RegexDetector::with_prefilter(
            "anthropic-admin-key",
            "Anthropic Admin API Key",
            Severity::Critical,
            r"\bsk-ant-admin[A-Za-z0-9_-]{80,}\b",
            &["sk-ant-admin"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "google-gemini-key",
            "Google Gemini / PaLM API Key",
            Severity::High,
            r"\bAIza[A-Za-z0-9_\-]{35}\b",
            &["AIza"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cohere-api-key",
            "Cohere API Key",
            Severity::High,
            r#"(?i)cohere[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?"#,
            &["cohere", "COHERE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "replicate-api-token",
            "Replicate API Token",
            Severity::High,
            r"\br8_[A-Za-z0-9]{37}\b",
            &["r8_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stability-ai-key",
            "Stability AI API Key",
            Severity::High,
            r#"(?i)stability[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?(sk-[A-Za-z0-9]{40,})['"]?"#,
            &["stability", "STABILITY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "assemblyai-key",
            "AssemblyAI API Key",
            Severity::High,
            r#"(?i)assemblyai[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["assemblyai", "ASSEMBLYAI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clarifai-key",
            "Clarifai API Key",
            Severity::High,
            r#"(?i)clarifai[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clarifai", "CLARIFAI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "openrouter-key",
            "OpenRouter API Key",
            Severity::High,
            r"\bsk-or-[A-Za-z0-9_\-]{40,}\b",
            &["sk-or-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "together-ai-key",
            "Together AI API Key",
            Severity::High,
            r#"(?i)together[_-]?(?:ai[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{40,})['"]?"#,
            &["together_ai", "TOGETHER_AI", "together_ai_api_key"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "perplexity-api-key",
            "Perplexity API Key",
            Severity::High,
            r"\bpplx-[A-Za-z0-9]{48,56}\b",
            &["pplx-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mistral-api-key",
            "Mistral API Key",
            Severity::High,
            r#"(?i)mistral[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["mistral", "MISTRAL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "groq-api-key",
            "Groq API Key",
            Severity::High,
            r"\bgsk_[A-Za-z0-9]{52}\b",
            &["gsk_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "deepseek-api-key",
            "DeepSeek API Key",
            Severity::High,
            r"\bsk-[A-Za-z0-9]{32}\b",
            &["deepseek", "DEEPSEEK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "elevenlabs-api-key",
            "ElevenLabs API Key",
            Severity::High,
            r#"(?i)elevenlabs[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["elevenlabs", "ELEVENLABS"],
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
        Box::new(RegexDetector::with_prefilter(
            "datadog-access-token",
            "Datadog Access Token (dt0 format)",
            Severity::High,
            r"\bdt0[a-zA-Z0-9_\-]{23}\.[A-Za-z0-9_\-]{64}\b",
            &["dt0"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "new-relic-personal-api-key",
            "New Relic Personal API Key (NRAK prefix)",
            Severity::High,
            r"\bNRAK[A-Za-z0-9_\-]{22,}\b",
            &["NRAK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sentry-token",
            "Sentry Auth Token (sntrys_ prefix)",
            Severity::High,
            r"\bsntrys_[A-Za-z0-9_\-]{64,}\b",
            &["sntrys_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sumologic-key",
            "SumoLogic Access Key ID / Secret",
            Severity::High,
            r#"(?i)sumo[_-]?(?:logic[_-]?)?(?:access[_-]?)?(?:key|secret)\s*[:=]\s*['"]?([A-Za-z0-9]{40,})['"]?"#,
            &["sumologic", "SUMOLOGIC", "sumo_logic"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "splunk-observability-token",
            "Splunk Observability Access Token",
            Severity::High,
            r"\bSPL[A-Za-z0-9_\-]{40,}\b",
            &["SPL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "appoptics-token",
            "AppOptics / SolarWinds Token",
            Severity::High,
            r#"(?i)appoptics[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40,})['"]?"#,
            &["appoptics", "APPOPTICS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "airbrake-key",
            "Airbrake Project / User Key",
            Severity::High,
            r#"(?i)airbrake[_-]?(?:project|user)[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["airbrake", "AIRBRAKE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "logdna-key",
            "LogDNA Ingestion Key",
            Severity::High,
            r#"(?i)logdna[_-]?(?:ingestion[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["logdna", "LOGDNA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "loggly-token",
            "Loggly Customer Token",
            Severity::High,
            r#"(?i)loggly[_-]?(?:customer[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["loggly", "LOGGLY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "better-stack-key",
            "Better Stack / Better Uptime API Key",
            Severity::High,
            r#"(?i)better[_-]?(?:stack|uptime)[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["better_stack", "BETTER_STACK", "better_uptime"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "statuspage-api-key",
            " Statuspage API Key",
            Severity::High,
            r#"(?i)statuspage[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["statuspage", "STATUSPAGE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "uptimerobot-api-key",
            "UptimeRobot API Key",
            Severity::High,
            r"\bu[A-Za-z0-9_\-]{40,}\b",
            &["uptimerobot", "UPTIMEROBOT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pingdom-token",
            "Pingdom API Token",
            Severity::High,
            r#"(?i)pingdom[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pingdom", "PINGDOM"],
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
        Box::new(RegexDetector::with_prefilter(
            "wpengine-token",
            "WP Engine API Token",
            Severity::High,
            r#"(?i)wp[_-]?engine[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["wpengine", "WPENGINE", "wp_engine"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fastly-api-key",
            "Fastly API Key",
            Severity::High,
            r#"(?i)fastly[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fastly", "FASTLY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "akamai-token",
            "Akamai API Token",
            Severity::High,
            r#"(?i)akamai[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["akamai", "AKAMAI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "equinix-oauth-token",
            "Equinix OAuth Token",
            Severity::High,
            r#"(?i)equinix[_-]?(?:oauth[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["equinix", "EQUINIX"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flyio-token",
            "Fly.io API Token (fly_ prefix)",
            Severity::High,
            r"\bfly[A-Za-z0-9_\-]{20,}\b",
            &["fly"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "railway-token",
            "Railway API Token",
            Severity::High,
            r#"(?i)railway[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["railway", "RAILWAY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "render-token",
            "Render API Token (rnd_ prefix)",
            Severity::High,
            r"\brnd_[A-Za-z0-9_\-]{20,}\b",
            &["rnd_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "koyeb-token",
            "Koyeb API Token",
            Severity::High,
            r#"(?i)koyeb[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["koyeb", "KOYEB"],
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
        Box::new(RegexDetector::with_prefilter(
            "auth0-management-token",
            "Auth0 Management API Token",
            Severity::High,
            r#"(?i)auth0[_-]?management[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_.-]{40,})['"]?"#,
            &["auth0_management", "AUTH0_MANAGEMENT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "auth0-oauth-token",
            "Auth0 OAuth Token",
            Severity::High,
            r#"(?i)auth0[_-]?oauth[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"#,
            &["auth0_oauth", "AUTH0_OAUTH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "onelogin-token",
            "OneLogin API Token",
            Severity::High,
            r#"(?i)onelogin[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{40,})['"]?"#,
            &["onelogin", "ONELOGIN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "jumpcloud-token",
            "JumpCloud API Token",
            Severity::High,
            r#"(?i)jumpcloud[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{40,})['"]?"#,
            &["jumpcloud", "JUMPCLOUD"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "authress-service-client-key",
            "Authress Service Client Key",
            Severity::High,
            r"\bsc_[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b",
            &["sc_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "keycloak-token",
            "Keycloak Token",
            Severity::High,
            r#"(?i)keycloak[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})['"]?"#,
            &["keycloak", "KEYCLOAK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fusionauth-token",
            "FusionAuth API Token",
            Severity::High,
            r#"(?i)fusion[_-]?auth[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})['"]?"#,
            &["fusionauth", "FUSIONAUTH", "fusion_auth"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stytch-token",
            "Stytch API Token",
            Severity::High,
            r#"(?i)stytch[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["stytch", "STYTCH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clerk-token",
            "Clerk API Token",
            Severity::High,
            r#"(?i)clerk[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?(sk_[A-Za-z0-9_\-]{40,})['"]?"#,
            &["clerk", "CLERK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "workos-token",
            "WorkOS API Token",
            Severity::High,
            r#"(?i)work[_-]?os[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["workos", "WORKOS", "work_os"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "supabase-anon-key",
            "Supabase Anon Key (eyJ prefix)",
            Severity::Medium,
            r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
            &["eyJ"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "firebase-token",
            "Firebase Auth Token",
            Severity::High,
            r#"(?i)firebase[_-]?(?:auth[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["firebase", "FIREBASE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "firebase-fcm-key",
            "Firebase Cloud Messaging Server Key (AAAA prefix)",
            Severity::High,
            r"\bAAAA[A-Za-z0-9_\-]{60,}\b",
            &["AAAA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kubeconfig",
            "KubeConfig with Client Key Data",
            Severity::High,
            r"(?i)client[_-]?key[_-]?data\s*:\s*[A-Za-z0-9+/=]{100,}",
            &["client_key_data", "client-key-data"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hashicorp-vault-token",
            "HashiCorp Vault Token (hvs./hvb./s. prefix)",
            Severity::High,
            r"\b(?:hvs\.|hvb\.|s\.)[A-Za-z0-9_\-]{20,}\b",
            &["hvs.", "hvb.", "s."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "onepassword-secret-key",
            "1Password Secret Key",
            Severity::High,
            r"\ba3-[A-Za-z0-9]{6}-[A-Za-z0-9]{6}-[A-Za-z0-9]{6}-[A-Za-z0-9]{6}-[A-Za-z0-9]{6}\b",
            &["a3-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "onepassword-service-account-token",
            "1Password Service Account Token (ops_ prefix)",
            Severity::High,
            r"\bops_[A-Za-z0-9_\-]{20,}\b",
            &["ops_"],
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
            "shopify-shared-secret",
            "Shopify Shared Secret",
            Severity::High,
            r"\bshpss_[A-Za-z0-9]{32}\b",
            &["shpss_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shopify-custom-app-token",
            "Shopify Custom App Token",
            Severity::High,
            r"\bshpca_[A-Za-z0-9]{32}\b",
            &["shpca_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shopify-private-app-token",
            "Shopify Private App Token",
            Severity::High,
            r"\bshppa_[A-Za-z0-9]{32}\b",
            &["shppa_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "paypal-oauth-token",
            "PayPal OAuth Token",
            Severity::High,
            r#"(?i)paypal[_-]?(?:oauth[_-]?)?token\s*[:=]\s*['"]?(A[A-Za-z0-9]{20,})['"]?"#,
            &["paypal_token", "PAYPAL_TOKEN", "paypal_oauth"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "paypal-client-secret",
            "PayPal Client Secret",
            Severity::High,
            r#"(?i)paypal[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9]{80})['"]?"#,
            &["paypal_client_secret", "PAYPAL_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "square-token",
            "Square Access Token",
            Severity::High,
            r"\bsq0atp-[A-Za-z0-9_\-]{22}\b",
            &[concat!("sq0", "atp-")],
        )),
        Box::new(RegexDetector::with_prefilter(
            "square-app-token",
            "Square Application Secret",
            Severity::High,
            r"\bsq0csp-[A-Za-z0-9_\-]{43}\b",
            &["sq0csp-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "coinbase-access-token",
            "Coinbase Access Token",
            Severity::High,
            r#"(?i)coinbase[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coinbase", "COINBASE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "razorpay-key",
            "RazorPay API Key",
            Severity::High,
            r#"(?i)razorpay[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?(rzp_[A-Za-z0-9]{20,})['"]?"#,
            &["rzp_", "razorpay", "RAZORPAY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "paystack-token",
            "Paystack Secret Key",
            Severity::High,
            r"\bsk_(?:live|test)_[A-Za-z0-9]{40}\b",
            &["paystack", "PAYSTACK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "plaid-token",
            "Plaid Access Token",
            Severity::High,
            r"\baccess-(?:sandbox|production|development)-[A-Za-z0-9_\-]{20,}\b",
            &["access-sandbox-", "access-production-", "access-development-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "plaid-key",
            "Plaid API Key (Client ID)",
            Severity::Medium,
            r#"(?i)plaid[_-]?client[_-]?id\s*[:=]\s*['"]?([A-Za-z0-9]{24})['"]?"#,
            &["plaid_client_id", "PLAID_CLIENT_ID"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flutterwave-secret-key",
            "Flutterwave Secret Key",
            Severity::High,
            r"\bFLWSECK-[A-Za-z0-9_\-]{32,}\b",
            &["FLWSECK-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flutterwave-encryption-key",
            "Flutterwave Encryption Key",
            Severity::High,
            r"\bFLWSECK_TEST-[A-Za-z0-9]{12}\b",
            &["FLWSECK_TEST-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "paddle-token",
            "Paddle API Key",
            Severity::High,
            r#"(?i)paddle[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["paddle", "PADDLE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fastspring-token",
            "FastSpring API Key",
            Severity::High,
            r#"(?i)fastspring[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fastspring", "FASTSPRING"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sellfy-token",
            "Sellfy API Key",
            Severity::High,
            r#"(?i)sellfy[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sellfy", "SELLFY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "duffel-token",
            "Duffel API Token",
            Severity::High,
            r"\bduffel_[A-Za-z0-9]{43}\b",
            &["duffel_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "easypost-api-token",
            "EasyPost API Token",
            Severity::High,
            r"\bEZ[A-Za-z0-9]{54}\b",
            &["EZ"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "easypost-test-api-token",
            "EasyPost Test API Token",
            Severity::Medium,
            r"\bEZTK[A-Za-z0-9]{52}\b",
            &["EZTK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "finicity-api-token",
            "Finicity API Token",
            Severity::High,
            r#"(?i)finicity[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["finicity", "FINICITY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "finicity-client-secret",
            "Finicity Client Secret",
            Severity::High,
            r#"(?i)finicity[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["finicity_client_secret", "FINICITY_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "freshbooks-token",
            "Freshbooks Access Token",
            Severity::High,
            r#"(?i)freshbooks[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["freshbooks", "FRESHBOOKS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gocardless-token",
            "GoCardless API Token",
            Severity::High,
            r#"(?i)gocardless[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["gocardless", "GOCARDLESS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "taxjar-api-key",
            "Taxjar API Key",
            Severity::High,
            r#"(?i)taxjar[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["taxjar", "TAXJAR"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "etsy-api-key",
            "Etsy API Key",
            Severity::Medium,
            r#"(?i)etsy[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{24,})['"]?"#,
            &["etsy", "ETSY"],
        )),
        // ── Analytics & Product ──────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "posthog-api-key",
            "PostHog API Key (phc_ prefix)",
            Severity::High,
            r"\bphc_[A-Za-z0-9_\-]{43,}\b",
            &["phc_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "amplitude-api-key",
            "Amplitude API Key",
            Severity::High,
            r#"(?i)amplitude[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["amplitude", "AMPLITUDE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "segment-api-key",
            "Segment API Key",
            Severity::High,
            r#"(?i)segment[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["segment", "SEGMENT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mixpanel-token",
            "Mixpanel Project Token",
            Severity::High,
            r#"(?i)mixpanel[_-]?(?:project[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["mixpanel", "MIXPANEL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "heap-api-key",
            "Heap Analytics API Key",
            Severity::High,
            r#"(?i)heap[_-]?(?:analytics[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["heap", "HEAP"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pendo-integration-key",
            "Pendo Integration Key",
            Severity::High,
            r#"(?i)pendo[_-]?integration[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pendo", "PENDO"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "keenio-key",
            "Keen.io API Key",
            Severity::High,
            r#"(?i)keen[_-]?(?:io[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{64})['"]?"#,
            &["keen", "KEEN", "keen_io"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fathom-analytics-key",
            "Fathom Analytics API Key",
            Severity::High,
            r#"(?i)fathom[_-]?(?:analytics[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fathom", "FATHOM"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "plausible-analytics-key",
            "Plausible Analytics API Key",
            Severity::High,
            r#"(?i)plausible[_-]?(?:analytics[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["plausible", "PLAUSIBLE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hotjar-token",
            "Hotjar API Token",
            Severity::High,
            r#"(?i)hotjar[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["hotjar", "HOTJAR"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fullstory-token",
            "FullStory API Token",
            Severity::High,
            r#"(?i)full[_-]?story[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fullstory", "FULLSTORY", "full_story"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitly-access-token",
            "Bitly Access Token",
            Severity::High,
            r#"(?i)bitly[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{30,})['"]?"#,
            &["bitly", "BITLY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "calendly-api-key",
            "Calendly API Key",
            Severity::High,
            r#"(?i)calendly[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["calendly", "CALENDLY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "calendarific-token",
            "Calendarific API Token",
            Severity::High,
            r#"(?i)calendarific[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["calendarific", "CALENDARIFIC"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "appfollow-token",
            "AppFollow API Token",
            Severity::High,
            r#"(?i)appfollow[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["appfollow", "APPFOLLOW"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "appcues-token",
            "Appcues API Token",
            Severity::High,
            r#"(?i)appcues[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["appcues", "APPCUES"],
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
        Box::new(RegexDetector::with_prefilter(
            "facebook-access-token",
            "Facebook Access Token (EAAD prefix)",
            Severity::High,
            r"\bEAAD[A-Za-z0-9]{20,}\b",
            &["EAAD"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "facebook-oauth-token",
            "Facebook OAuth Token",
            Severity::High,
            r#"(?i)facebook[_-]?oauth[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40,})['"]?"#,
            &["facebook_oauth", "FACEBOOK_OAUTH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "figma-personal-access-token",
            "Figma Personal Access Token (figd_ prefix)",
            Severity::High,
            r"\bfigd_[A-Za-z0-9_\-]{20,}\b",
            &["figd_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pypi-token",
            "PyPI Token (pypi-AgEI prefix)",
            Severity::High,
            r"\bpypi-AgEI[A-Za-z0-9_\-]{20,}\b",
            &["pypi-AgEI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "spotify-key",
            "Spotify API Key",
            Severity::High,
            r#"(?i)spotify[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["spotify", "SPOTIFY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "youtube-api-key",
            "YouTube API Key (AIza prefix)",
            Severity::High,
            r"\bAIza[A-Za-z0-9_\-]{35}\b",
            &["AIza"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "twitch-access-token",
            "Twitch Access Token",
            Severity::High,
            r#"(?i)twitch[_-]?access[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{30,})['"]?"#,
            &["twitch_access_token", "TWITCH_ACCESS_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flickr-access-token",
            "Flickr Access Token",
            Severity::High,
            r#"(?i)flickr[_-]?access[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["flickr", "FLICKR"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dropbox-api-secret",
            "Dropbox API Secret",
            Severity::High,
            r#"(?i)dropbox[_-]?api[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9]{15,})['"]?"#,
            &["dropbox_api_secret", "DROPBOX_API_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dropbox-long-lived-token",
            "Dropbox Long-Lived Token (sl. prefix)",
            Severity::High,
            r"\bsl\.[A-Za-z0-9_\-]{20,}\b",
            &["sl."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dropbox-short-lived-token",
            "Dropbox Short-Lived Token (sl. prefix with t1.)",
            Severity::High,
            r"\bsl\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b",
            &["sl."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "reddit-client-secret",
            "Reddit Client Secret",
            Severity::High,
            r#"(?i)reddit[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["reddit_client_secret", "REDDIT_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "reddit-access-token",
            "Reddit Access Token",
            Severity::High,
            r#"(?i)reddit[_-]?access[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["reddit_access_token", "REDDIT_ACCESS_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "instagram-access-token",
            "Instagram Access Token",
            Severity::High,
            r#"(?i)instagram[_-]?access[_-]?token\s*[:=]\s*['"]?(IG[A-Za-z0-9_\-]{30,})['"]?"#,
            &["instagram", "INSTAGRAM"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pinterest-token",
            "Pinterest API Token",
            Severity::High,
            r#"(?i)pinterest[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pinterest", "PINTEREST"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tiktok-access-token",
            "TikTok Access Token",
            Severity::High,
            r#"(?i)tiktok[_-]?access[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tiktok", "TIKTOK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zoom-api-secret",
            "Zoom API Key/Secret",
            Severity::High,
            r#"(?i)zoom[_-]?(?:api[_-]?)?(?:key|secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zoom", "ZOOM"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zapier-webhook-url",
            "Zapier Webhook URL",
            Severity::High,
            r"https://hooks\.zapier\.com/hooks/catch/[A-Za-z0-9_\-]+/[A-Za-z0-9_\-]+",
            &["hooks.zapier.com"],
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
            "jdbc-connection-string",
            "JDBC Connection String with Credentials",
            Severity::High,
            r"jdbc:(?:mysql|postgresql|sqlserver)://[^:\s]+:[^@\s]+@[^\s/]+",
            &["jdbc:mysql://", "jdbc:postgresql://", "jdbc:sqlserver://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sqlserver-connection-string",
            "SQL Server Connection String with Password",
            Severity::High,
            r#"(?i)(?:server|data[_\s-]?source)=[^;]+;\s*(?:user[_\s-]?id|uid)=[^;]+;\s*password=[^;]+"#,
            &["server=", "SERVER=", "data source=", "Data Source="],
        )),
        Box::new(RegexDetector::with_prefilter(
            "elasticsearch-connection",
            "Elasticsearch Connection with Credentials",
            Severity::High,
            r"https?://[^:\s]+:[^@\s]+@[^\s]*elastic[a-z]*\.[^\s/]+",
            &["elastic", "ELASTIC"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "influxdb-token",
            "InfluxDB API Token",
            Severity::High,
            r#"(?i)influx[_-]?db[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["influxdb", "INFLUXDB", "influx_db"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "couchbase-connection-string",
            "Couchbase Connection String with Credentials",
            Severity::High,
            r"couchbase://[^:\s]+:[^@\s]+@[^\s/]+",
            &["couchbase://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cassandra-connection",
            "Cassandra Connection with Credentials",
            Severity::High,
            r#"(?i)cassandra[_-]?(?:username|password)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{8,})['"]?"#,
            &["cassandra", "CASSANDRA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "neo4j-connection-string",
            "Neo4j Connection String with Credentials",
            Severity::High,
            r"neo4j(?:\+s)?://[^:\s]+:[^@\s]+@[^\s/]+",
            &["neo4j://", "neo4j+s://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "supabase-db-connection",
            "Supabase DB Connection String",
            Severity::High,
            r"postgresql://[^:\s]+:[^@\s]+@db\.[a-z0-9]+\.supabase\.co",
            &["supabase.co"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "planetscale-token",
            "PlanetScale API Token (pscale_ prefix)",
            Severity::High,
            r"\bpscale_[A-Za-z0-9_\-]{20,}\b",
            &["pscale_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "neon-database-token",
            "Neon Database API Token",
            Severity::High,
            r#"(?i)neon[_-]?(?:database[_-]?)?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["neon", "NEON"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "turso-token",
            "Turso Database API Token",
            Severity::High,
            r#"(?i)turso[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["turso", "TURSO"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "convex-token",
            "Convex Database Token",
            Severity::High,
            r#"(?i)convex[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["convex", "CONVEX"],
        )),
        // ── DevOps & Infrastructure ──────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "age-secret-key",
            "Age Encryption Secret Key",
            Severity::High,
            r"AGE-SECRET-KEY-1[A-Za-z0-9]{58}",
            &["AGE-SECRET-KEY-1"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kubernetes-secret-manifest",
            "Kubernetes Secret Manifest (base64 data)",
            Severity::High,
            r#"(?i)kind:\s*Secret[^}]*?\bdata:\s*\n\s+[A-Za-z0-9_-]+:\s*[A-Za-z0-9+/=]{20,}"#,
            &["kind: Secret", "kind:Secret"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hashicorp-terraform-token",
            "HashiCorp Terraform Cloud Token",
            Severity::High,
            r#"(?i)terraform[_-]?cloud[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["terraform_cloud_token", "TERRAFORM_CLOUD_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ansible-vault-password",
            "Ansible Vault Password",
            Severity::High,
            r#"(?i)ansible[_-]?vault[_-]?password\s*[:=]\s*['"]?([A-Za-z0-9_\-]{8,})['"]?"#,
            &["ansible_vault_password", "ANSIBLE_VAULT_PASSWORD"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "docker-registry-token",
            "Docker Registry Token",
            Severity::High,
            r#"(?i)docker[_-]?registry[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["docker_registry_token", "DOCKER_REGISTRY_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "harbor-token",
            "Harbor Registry API Token",
            Severity::High,
            r#"(?i)harbor[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["harbor", "HARBOR"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nexus-token",
            "Nexus Repository Token",
            Severity::High,
            r#"(?i)nexus[_-]?(?:repo[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["nexus", "NEXUS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "confluent-access-token",
            "Confluent Cloud Access Token",
            Severity::High,
            r#"(?i)confluent[_-]?(?:cloud[_-]?)?access[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["confluent", "CONFLUENT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "confluent-secret-key",
            "Confluent Cloud Secret Key",
            Severity::High,
            r#"(?i)confluent[_-]?(?:cloud[_-]?)?secret[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["confluent", "CONFLUENT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "databricks-token",
            "Databricks API Token",
            Severity::High,
            r"\bdapi[A-Za-z0-9]{20,}\b",
            &["dapi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "snowflake-token",
            "Snowflake API Token",
            Severity::High,
            r#"(?i)snowflake[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["snowflake", "SNOWFLAKE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dynatrace-api-token",
            "Dynatrace API Token",
            Severity::High,
            r"\bdt0c01[A-Za-z0-9]{20,}\b",
            &["dt0c01"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "launchdarkly-key",
            "LaunchDarkly API Key",
            Severity::High,
            r#"(?i)launchdarkly[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["launchdarkly", "LAUNCHDARKLY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "configcat-key",
            "ConfigCat API Key",
            Severity::High,
            r#"(?i)configcat[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["configcat", "CONFIGCAT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flagsmith-key",
            "Flagsmith API Key",
            Severity::High,
            r#"(?i)flagsmith[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["flagsmith", "FLAGSMITH"],
        )),
        // ── Security & API Services ──────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "shodan-api-key",
            "Shodan API Key",
            Severity::High,
            r#"(?i)shodan[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["shodan_api_key", "SHODAN_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "abuseipdb-key",
            "AbuseIPDB API Key",
            Severity::High,
            r#"(?i)abuseipdb[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{80})['"]?"#,
            &["abuseipdb", "ABUSEIPDB"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "alienvault-otx-key",
            "AlienVault OTX API Key",
            Severity::High,
            r#"(?i)alienvault[_-]?otx[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?"#,
            &["alienvault", "ALIENVAULT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "virustotal-api-key",
            "VirusTotal API Key",
            Severity::High,
            r#"(?i)virustotal[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{64})['"]?"#,
            &["virustotal", "VIRUSTOTAL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hunterio-api-key",
            "Hunter.io API Key",
            Severity::High,
            r#"(?i)hunter[_-]?io[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["hunter", "HUNTER"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ipstack-key",
            "IPStack API Key",
            Severity::High,
            r#"(?i)ipstack[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["ipstack", "IPSTACK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "maxmind-license-key",
            "MaxMind License Key",
            Severity::High,
            r#"(?i)maxmind[_-]?license[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["maxmind", "MAXMIND"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudsight-key",
            "CloudSight API Key",
            Severity::High,
            r#"(?i)cloudsight[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["cloudsight", "CLOUDSIGHT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "rapidapi-key",
            "RapidAPI Key",
            Severity::High,
            r#"(?i)rapidapi[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{50})['"]?"#,
            &["rapidapi", "RAPIDAPI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scrapingbee-key",
            "ScrapingBee API Key",
            Severity::High,
            r#"(?i)scrapingbee[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["scrapingbee", "SCRAPINGBEE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ipinfo-token",
            "ipinfo.io API Token",
            Severity::High,
            r#"(?i)ipinfo[_-]?io[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["ipinfo", "IPINFO"],
        )),
        // ── Maps & Location ──────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "google-maps-api-key",
            "Google Maps API Key",
            Severity::High,
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            &["AIza"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mapbox-token",
            "MapBox Access Token",
            Severity::High,
            r"\bpk\.[A-Za-z0-9]{60,}\b",
            &["pk."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mapquest-key",
            "MapQuest API Key",
            Severity::High,
            r#"(?i)mapquest[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["mapquest", "MAPQUEST"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "here-maps-key",
            "Here Maps API Key",
            Severity::High,
            r#"(?i)here[_-]?maps[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{43})['"]?"#,
            &["here_maps", "HERE_MAPS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "opencage-key",
            "OpenCage Geocoder API Key",
            Severity::High,
            r#"(?i)opencage[_-]?(?:geocoder[_-]?)?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["opencage", "OPENCAGE"],
        )),
        // ── CRM & Business ───────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "hubspot-api-key",
            "HubSpot API Key",
            Severity::High,
            r#"(?i)hubspot[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{36})['"]?"#,
            &["hubspot", "HUBSPOT"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hubspot-oauth-token",
            "HubSpot OAuth Token",
            Severity::High,
            r#"(?i)hubspot[_-]?oauth[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{30,})['"]?"#,
            &["hubspot_oauth", "HUBSPOT_OAUTH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "salesforce-oauth2-token",
            "Salesforce OAuth2 Token",
            Severity::High,
            r#"(?i)salesforce[_-]?oauth[_-]?(?:2[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?"#,
            &["salesforce", "SALESFORCE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zendesk-api-token",
            "Zendesk API Token",
            Severity::High,
            r#"(?i)zendesk[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?"#,
            &["zendesk", "ZENDESK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "elastic-path-token",
            "Elastic Path API Token",
            Severity::High,
            r#"(?i)elastic[_-]?path[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["elastic_path", "ELASTIC_PATH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "buttercms-token",
            "ButterCMS API Token",
            Severity::High,
            r#"(?i)buttercms[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{20})['"]?"#,
            &["buttercms", "BUTTERCMS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "contentful-delivery-token",
            "Contentful Delivery API Token",
            Severity::High,
            r#"(?i)contentful[_-]?delivery[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{43})['"]?"#,
            &["contentful", "CONTENTFUL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "contentful-personal-access-token",
            "Contentful Personal Access Token",
            Severity::High,
            r"\bCFPAT-[A-Za-z0-9]{43}\b",
            &["CFPAT-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sanity-api-token",
            "Sanity API Token",
            Severity::High,
            r#"(?i)sanity[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["sanity", "SANITY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "storyblok-token",
            "Storyblok API Token",
            Severity::High,
            r#"(?i)storyblok[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["storyblok", "STORYBLOK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "strapi-api-token",
            "Strapi API Token",
            Severity::High,
            r#"(?i)strapi[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["strapi", "STRAPI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "airtable-api-key",
            "Airtable API Key (deprecated)",
            Severity::High,
            r"\bkey[A-Za-z0-9]{16}\b",
            &["keyA", "keyB", "keyC", "keyD"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "airtable-personal-access-token",
            "Airtable Personal Access Token",
            Severity::High,
            r"\bpat[A-Za-z0-9]{16,}\b",
            &["pat"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "airtable-oauth-token",
            "Airtable OAuth Token",
            Severity::High,
            r#"(?i)airtable[_-]?oauth[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["airtable", "AIRTABLE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "algolia-admin-key",
            "Algolia Admin API Key",
            Severity::High,
            r#"(?i)algolia[_-]?admin[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["algolia", "ALGOLIA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "lokalise-token",
            "Lokalise API Token",
            Severity::High,
            r#"(?i)lokalise[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["lokalise", "LOKALISE"],
        )),
        // ── Crypto & Web3 ────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "bitcoin-private-key-wif",
            "Bitcoin Private Key (WIF format)",
            Severity::Critical,
            r"\b[5KL][A-Za-z0-9]{50,51}\b",
            &["5K", "5L", "Kw", "Ky", "L1", "L2"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ethereum-private-key",
            "Ethereum Private Key",
            Severity::Critical,
            r"\b0x[0-9a-fA-F]{64}\b",
            &["0x"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "solana-private-key",
            "Solana Private Key (base58 88-char)",
            Severity::Critical,
            r"\b[1-9A-HJ-NP-Za-km-z]{88}\b",
            &["solana", "SOLANA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "infura-api-key",
            "Infura API Key",
            Severity::High,
            r#"(?i)infura[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["infura", "INFURA"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "alchemy-api-key",
            "Alchemy API Key",
            Severity::High,
            r#"(?i)alchemy[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{32})['"]?"#,
            &["alchemy", "ALCHEMY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "moralis-api-key",
            "Moralis API Key",
            Severity::High,
            r#"(?i)moralis[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{32})['"]?"#,
            &["moralis", "MORALIS"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "quicknode-token",
            "QuickNode API Token",
            Severity::High,
            r#"(?i)quicknode[_-]?api[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["quicknode", "QUICKNODE"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitfinex-api-key",
            "Bitfinex API Key",
            Severity::High,
            r#"(?i)bitfinex[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bitfinex", "BITFINEX"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bittrex-access-key",
            "Bittrex Access Key",
            Severity::High,
            r#"(?i)bittrex[_-]?access[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bittrex", "BITTREX"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bittrex-secret-key",
            "Bittrex Secret Key",
            Severity::High,
            r#"(?i)bittrex[_-]?secret[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bittrex", "BITTREX"],
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
        Box::new(RegexDetector::with_prefilter(
            "curl-auth-string",
            "Curl Authentication String",
            Severity::High,
            r#"(?i)curl\s+(?:[^ ]+\s+)*-u\s+([A-Za-z0-9_\-]+):([A-Za-z0-9_\-]+)"#,
            &["curl ", "curl\t"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "uri-embedded-credentials",
            "URI with Embedded Credentials",
            Severity::High,
            r#"(?i)\b(https?|ftp|wss?)://[^:\s]+:[^@\s]+@[^\s/]+"#,
            &["http://", "https://", "ftp://", "wss://"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "generic-oauth-client-secret",
            "Generic OAuth Client Secret",
            Severity::High,
            r#"(?i)oauth[_-]?client[_-]?secret\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["oauth_client_secret", "OAUTH_CLIENT_SECRET"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "env-file-secret",
            ".env File Secret (KEY=VALUE)",
            Severity::Medium,
            r#"(?i)^(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*['"]?([A-Za-z0-9_\-]{20,})['"]?$"#,
            &["SECRET=", "PASSWORD=", "TOKEN=", "API_KEY=", "PRIVATE_KEY="],
        )),
        Box::new(RegexDetector::with_prefilter(
            "firebase-config-web",
            "Firebase Web Config",
            Severity::Low,
            r#"(?i)firebase[_-]?config\s*[:=]\s*\{[^}]*?apiKey\s*:\s*['"]?(AIza[A-Za-z0-9\-_]{35})['"]?"#,
            &["firebaseConfig", "firebase_config", "FIREBASE_CONFIG"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "twilio-api-key",
            "Twilio API Key",
            Severity::High,
            r#"(?i)twilio[_-]?(?:api[_-]?key|apikey)\s*[:=]\s*['"]?(SK[A-Za-z0-9]{32})['"]?"#,
            &["twilio_api_key", "twilio_apikey", "TWILIO_API_KEY", "TWILIO_APIKEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "line-messaging-api-token",
            "Line Messaging API Token",
            Severity::High,
            r#"(?i)line[_-]?messaging[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["line_messaging", "LINE_MESSAGING", "lineMessaging"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "line-notify-token",
            "Line Notify Token",
            Severity::High,
            r#"(?i)line[_-]?notify[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{43})['"]?"#,
            &["line_notify", "LINE_NOTIFY", "lineNotify"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mattermost-personal-token",
            "Mattermost Personal Token",
            Severity::High,
            r#"(?i)mattermost[_-]?(?:personal[_-]?)?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{26})['"]?"#,
            &["mattermost_token", "MATTERMOST_TOKEN", "mattermostToken"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "wechat-app-key",
            "WeChat App Key",
            Severity::High,
            r#"(?i)wechat[_-]?(?:app[_-]?)?(?:key|secret)\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["wechat_app", "WECHAT_APP", "wechatApp"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kakaotalk-api-key",
            "KakaoTalk API Key",
            Severity::Medium,
            r#"(?i)kakao[_-]?(?:talk[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["kakao_api", "KAKAO_API", "kakaoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "liveagent-api-key",
            "LiveAgent API Key",
            Severity::Medium,
            r#"(?i)liveagent[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["liveagent_api", "LIVEAGENT_API", "liveAgent"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "front-api-key",
            "Front API Key",
            Severity::High,
            r#"(?i)front[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?(front_[A-Za-z0-9_\-]{20,})['"]?"#,
            &["front_api", "FRONT_API", "frontApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ringcentral-api-key",
            "RingCentral API Key",
            Severity::High,
            r#"(?i)ringcentral[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ringcentral_api", "RINGCENTRAL_API", "ringCentral"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "telesign-api-key",
            "TeleSign API Key",
            Severity::High,
            r#"(?i)telesign[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["telesign_api", "TELESIGN_API", "teleSign"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "teamviewer-api-token",
            "TeamViewer API Token",
            Severity::High,
            r#"(?i)teamviewer[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["teamviewer_api", "TEAMVIEWER_API", "teamViewer"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cometchat-api-key",
            "CometChat API Key",
            Severity::Medium,
            r#"(?i)cometchat[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cometchat_api", "COMETCHAT_API", "cometChat"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mesibo-api-key",
            "Mesibo API Key",
            Severity::High,
            r#"(?i)mesibo[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["mesibo_api", "MESIBO_API", "mesiboApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bulbul-api-key",
            "Bulbul API Key",
            Severity::Medium,
            r#"(?i)bulbul[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bulbul_api", "BULBUL_API", "bulbulApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tyntec-api-key",
            "Tyntec API Key",
            Severity::Medium,
            r#"(?i)tyntec[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tyntec_api", "TYNTEC_API", "tyntecApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kaleyra-api-key",
            "Kaleyra API Key",
            Severity::Medium,
            r#"(?i)kaleyra[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["kaleyra_api", "KALEYRA_API", "kaleyraApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "onbuka-api-key",
            "Onbuka API Key",
            Severity::Medium,
            r#"(?i)onbuka[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["onbuka_api", "ONBUKA_API", "onbukaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clicksend-api-key",
            "ClickSend SMS API Key",
            Severity::High,
            r#"(?i)clicksend[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clicksend_api", "CLICKSEND_API", "clickSend"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clockwork-sms-api-key",
            "Clockwork SMS API Key",
            Severity::High,
            r#"(?i)clockwork[_-]?(?:sms[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clockwork_api", "CLOCKWORK_API", "clockworkApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sms-api-key",
            "SMS API Key",
            Severity::Medium,
            r#"(?i)sms[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sms_api_key", "SMS_API_KEY", "smsApiKey"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bombbomb-api-key",
            "BombBomb API Key",
            Severity::Medium,
            r#"(?i)bombbomb[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bombbomb_api", "BOMBBOMB_API", "bombBomb"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dfuse-api-key",
            "DFuse API Key",
            Severity::Medium,
            r#"(?i)dfuse[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?(server_[A-Za-z0-9_\-]{20,})['"]?"#,
            &["dfuse_api", "DFUSE_API", "dfuseApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "apifonica-api-key",
            "ApiFonica API Key",
            Severity::Medium,
            r#"(?i)apifonica[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["apifonica_api", "APIFONICA_API", "apiFonica"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mandrill-api-key",
            "Mandrill API Key",
            Severity::High,
            r#"(?i)mandrill[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{22})['"]?"#,
            &["mandrill_api", "MANDRILL_API", "mandrillApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sparkpost-api-key",
            "SparkPost API Key",
            Severity::High,
            r#"(?i)sparkpost[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{64})['"]?"#,
            &["sparkpost_api", "SPARKPOST_API", "sparkPost"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailerlite-api-key",
            "MailerLite API Key",
            Severity::High,
            r#"(?i)mailerlite[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["mailerlite_api", "MAILERLITE_API", "mailerLite"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "convertkit-api-key",
            "ConvertKit API Key",
            Severity::High,
            r#"(?i)convertkit[_-]?(?:api[_-]?)?(?:key|secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["convertkit_api", "CONVERTKIT_API", "convertKit"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "omnisend-api-key",
            "Omnisend API Key",
            Severity::Medium,
            r#"(?i)omnisend[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["omnisend_api", "OMNISEND_API", "omniSend"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "customerio-api-key",
            "Customer.io API Key",
            Severity::High,
            r#"(?i)customer[_-]?\.?io[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["customerio_api", "CUSTOMERIO_API", "customerIo"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "moosend-api-key",
            "Moosend API Key",
            Severity::Medium,
            r#"(?i)moosend[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["moosend_api", "MOOSEND_API", "mooSend"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dotdigital-api-key",
            "Dotdigital API Key",
            Severity::Medium,
            r#"(?i)dotdigital[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["dotdigital_api", "DOTDIGITAL_API", "dotDigital"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dyspatch-api-key",
            "Dyspatch API Key",
            Severity::Medium,
            r#"(?i)dyspatch[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["dyspatch_api", "DYSPATCH_API", "dyspatchApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "postageapp-api-key",
            "PostageApp API Key",
            Severity::Medium,
            r#"(?i)postageapp[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["postageapp_api", "POSTAGEAPP_API", "postageApp"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nicereply-api-key",
            "Nicereply API Key",
            Severity::Medium,
            r#"(?i)nicereply[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["nicereply_api", "NICEREPLY_API", "niceReply"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "autopilot-api-key",
            "AutoPilot API Key",
            Severity::Medium,
            r#"(?i)autopilot[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["autopilot_api", "AUTOPILOT_API", "autoPilot"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "airship-api-key",
            "Airship API Key",
            Severity::High,
            r#"(?i)(?:urban[_-]?)?airship[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["airship_api", "AIRSHIP_API", "airshipApi"],
        )),
        // ── CRM & Sales ────────────────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "freshworks-api-key",
            "Freshworks API Key",
            Severity::High,
            r#"(?i)fresh(?:works|desk)[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["freshworks_api", "FRESHWORKS_API", "freshdesk_api", "FRESHDESK_API"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "close-crm-api-key",
            "Close CRM API Key",
            Severity::High,
            r#"(?i)close[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["close_crm_api", "CLOSE_CRM_API", "closeCrm"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "copper-crm-api-key",
            "Copper CRM API Key",
            Severity::Medium,
            r#"(?i)copper[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["copper_crm_api", "COPPER_CRM_API", "copperCrm"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "streak-crm-api-key",
            "Streak CRM API Key",
            Severity::Medium,
            r#"(?i)streak[_\-]?(?:crm[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["streak_api", "STREAK_API", "streakApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "groovehq-api-key",
            "GrooveHQ API Key",
            Severity::Medium,
            r#"(?i)groove(?:hq)?[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["groovehq_api", "GROOVEHQ_API", "grooveApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "getgist-api-key",
            "GetGist API Key",
            Severity::Medium,
            r#"(?i)(?:get)?gist[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["getgist_api", "GETGIST_API", "gistApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "autoklose-api-key",
            "Autoklose API Key",
            Severity::Medium,
            r#"(?i)autoklose[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["autoklose_api", "AUTOKLOSE_API", "autoKlose"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "salesflare-api-key",
            "Salesflare API Key",
            Severity::Medium,
            r#"(?i)salesflare[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["salesflare_api", "SALESFLARE_API", "salesFlare"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "salesblink-api-key",
            "SalesBlink API Key",
            Severity::Medium,
            r#"(?i)salesblink[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["salesblink_api", "SALESBLINK_API", "salesBlink"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "salescookie-api-key",
            "Salescookie API Key",
            Severity::Medium,
            r#"(?i)salescookie[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["salescookie_api", "SALESCOOKIE_API", "salesCookie"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "metrilo-api-key",
            "Metrilo API Key",
            Severity::Medium,
            r#"(?i)metrilo[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["metrilo_api", "METRILO_API", "metriloApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "revampcrm-api-key",
            "RevampCRM API Key",
            Severity::Medium,
            r#"(?i)revampcrm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["revampcrm_api", "REVAMPCRM_API", "revampCrm"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "karmacrm-api-key",
            "KarmaCRM API Key",
            Severity::Medium,
            r#"(?i)karma[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["karmacrm_api", "KARMACRM_API", "karmaCrm"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "lessannoyingcrm-api-key",
            "Less Annoying CRM API Key",
            Severity::Medium,
            r#"(?i)less[_\-]?annoying[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["lessannoyingcrm", "LESSANNOYINGCRM", "lessAnnoying"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nethunt-crm-api-key",
            "NetHunt CRM API Key",
            Severity::Medium,
            r#"(?i)nethunt[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["nethunt_crm", "NETHUNT_CRM", "netHunt"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nimble-crm-api-key",
            "Nimble CRM API Key",
            Severity::Medium,
            r#"(?i)nimble[_\-]?(?:crm[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["nimble_api", "NIMBLE_API", "nimbleApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "apptivo-crm-api-key",
            "Apptivo CRM API Key",
            Severity::Medium,
            r#"(?i)apptivo[_\-]?(?:crm[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["apptivo_api", "APPTIVO_API", "apptivoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "capsule-crm-api-key",
            "Capsule CRM API Key",
            Severity::Medium,
            r#"(?i)capsule[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["capsule_crm", "CAPSULE_CRM", "capsuleCrm"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "insightly-crm-api-key",
            "Insightly CRM API Key",
            Severity::Medium,
            r#"(?i)insightly[_\-]?(?:crm[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["insightly_api", "INSIGHTLY_API", "insightlyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kylas-crm-api-key",
            "Kylas CRM API Key",
            Severity::Medium,
            r#"(?i)kylas[_\-]?(?:crm[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["kylas_api", "KYLAS_API", "kylasApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "onepagecrm-api-key",
            "OnePageCRM API Key",
            Severity::Medium,
            r#"(?i)onepage[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["onepagecrm_api", "ONEPAGECRM_API", "onePageCrm"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "prospectcrm-api-key",
            "Prospect CRM API Key",
            Severity::Medium,
            r#"(?i)prospect[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["prospectcrm_api", "PROSPECTCRM_API", "prospectCrm"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "reallysimplesystems-crm-api-key",
            "Really Simple Systems CRM API Key",
            Severity::Medium,
            r#"(?i)really[_\-]?simple[_\-]?systems[_\-]?(?:crm[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["reallysimple", "REALLYSIMPLE", "reallySimple"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "centralstation-crm-api-key",
            "Central Station CRM API Key",
            Severity::Medium,
            r#"(?i)central[_\-]?station[_\-]?crm[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["centralstation_api", "CENTRALSTATION_API", "centralStation"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "teamgate-crm-api-key",
            "Teamgate CRM API Key",
            Severity::Medium,
            r#"(?i)teamgate[_\-]?(?:crm[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["teamgate_api", "TEAMGATE_API", "teamgateApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "axonaut-api-key",
            "Axonaut API Key",
            Severity::Medium,
            r#"(?i)axonaut[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["axonaut_api", "AXONAUT_API", "axonautApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flowflu-api-key",
            "FlowFlu API Key",
            Severity::Medium,
            r#"(?i)flowflu[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["flowflu_api", "FLOWFLU_API", "flowFlu"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clientary-api-key",
            "Clientary API Key",
            Severity::Medium,
            r#"(?i)clientary[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clientary_api", "CLIENTARY_API", "clientaryApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clinchpad-api-key",
            "Clinchpad API Key",
            Severity::Medium,
            r#"(?i)clinchpad[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clinchpad_api", "CLINCHPAD_API", "clinchpadApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "companyhub-api-key",
            "CompanyHub API Key",
            Severity::Medium,
            r#"(?i)companyhub[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["companyhub_api", "COMPANYHUB_API", "companyHub"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "campayn-api-key",
            "Campayn API Key",
            Severity::Medium,
            r#"(?i)campayn[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["campayn_api", "CAMPAYN_API", "campaynApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hiveage-api-key",
            "Hiveage API Key",
            Severity::Medium,
            r#"(?i)hiveage[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["hiveage_api", "HIVEAGE_API", "hiveageApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "billomat-api-key",
            "Billomat API Key",
            Severity::Medium,
            r#"(?i)billomat[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["billomat_api", "BILLOMAT_API", "billomatApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "alegra-api-key",
            "Alegra API Key",
            Severity::Medium,
            r#"(?i)alegra[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["alegra_api", "ALEGRA_API", "alegraApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "loyverse-api-key",
            "Loyverse API Key",
            Severity::Medium,
            r#"(?i)loyverse[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["loyverse_api", "LOYVERSE_API", "loyverseApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "commercejs-api-key",
            "CommerceJS API Key",
            Severity::Medium,
            r#"(?i)commerce[_\-]?js[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?(pk_[A-Za-z0-9_\-]{20,})['"]?"#,
            &["commercejs_api", "COMMERCEJS_API", "commerceJs"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "snipcart-api-key",
            "Snipcart API Key",
            Severity::High,
            r#"(?i)snipcart[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?(SNIP_[A-Za-z0-9_\-]{20,})['"]?"#,
            &["snipcart_api", "SNIPCART_API", "snipcartApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "partnerstack-api-key",
            "PartnerStack API Key",
            Severity::Medium,
            r#"(?i)partner[_\-]?stack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["partnerstack_api", "PARTNERSTACK_API", "partnerStack"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "vouchery-api-key",
            "Vouchery API Key",
            Severity::Medium,
            r#"(?i)vouchery[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["vouchery_api", "VOUCHERY_API", "voucheryApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "monday-api-key",
            "Monday.com API Key",
            Severity::High,
            r#"(?i)monday[_\-]?(?:\.com[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["monday_api", "MONDAY_API", "mondayApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "smartsheets-api-key",
            "Smartsheets API Key",
            Severity::High,
            r#"(?i)smartsheets?[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["smartsheets_api", "SMARTSHEETS_API", "smartsheetApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "wrike-api-key",
            "Wrike API Key",
            Severity::High,
            r#"(?i)wrike[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["wrike_api", "WRIKE_API", "wrikeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "apollo-io-api-key",
            "Apollo.io API Key",
            Severity::High,
            r#"(?i)apollo[_\-]?(?:\.io[_\-]?)?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["apollo_api", "APOLLO_API", "apolloApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "uplead-api-key",
            "UpLead API Key",
            Severity::Medium,
            r#"(?i)uplead[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["uplead_api", "UPLEAD_API", "upLead"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "rocketreach-api-key",
            "RocketReach API Key",
            Severity::Medium,
            r#"(?i)rocket[_\-]?reach[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["rocketreach_api", "ROCKETREACH_API", "rocketReach"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clearbit-api-key",
            "Clearbit API Key",
            Severity::High,
            r#"(?i)clearbit[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?(cb_[A-Za-z0-9_\-]{20,})['"]?"#,
            &["clearbit_api", "CLEARBIT_API", "clearbitApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "brandfetch-api-key",
            "Brandfetch API Key",
            Severity::Medium,
            r#"(?i)brandfetch[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["brandfetch_api", "BRANDFETCH_API", "brandfetchApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "leadfeeder-api-key",
            "Leadfeeder API Key",
            Severity::Medium,
            r#"(?i)leadfeeder[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["leadfeeder_api", "LEADFEEDER_API", "leadfeederApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "getemail-api-key",
            "GetEmail API Key",
            Severity::Medium,
            r#"(?i)get[_\-]?email[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["getemail_api", "GETEMAIL_API", "getEmail"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "getemails-api-key",
            "GetEmails API Key",
            Severity::Medium,
            r#"(?i)get[_\-]?emails[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["getemails_api", "GETEMAILS_API", "getEmails"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "skrappio-api-key",
            "Skrappio API Key",
            Severity::Medium,
            r#"(?i)skrappio[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["skrappio_api", "SKRAPPIO_API", "skrappioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "powrbot-api-key",
            "Powrbot API Key",
            Severity::Medium,
            r#"(?i)powrbot[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["powrbot_api", "POWRBOT_API", "powrbotApi"],
        )),
        // ── Project Management & Productivity (TruffleHog) ───────────────

        Box::new(RegexDetector::with_prefilter(
            "clickup-personal-token",
            "ClickUp Personal Token",
            Severity::High,
            r#"(?i)clickup[_\-]?(?:personal[_\-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clickup_token", "CLICKUP_TOKEN", "clickupToken"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "todoist-api-token",
            "Todoist API Token",
            Severity::High,
            r#"(?i)todoist[_\-]?(?:api[_\-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["todoist_token", "TODOIST_TOKEN", "todoistToken"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shortcut-api-key",
            "Shortcut API Key",
            Severity::Medium,
            r#"(?i)shortcut[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["shortcut_api", "SHORTCUT_API", "shortcutApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tmetric-api-key",
            "TMetric API Key",
            Severity::Medium,
            r#"(?i)tmetric[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tmetric_api", "TMETRIC_API", "tmetricApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clockify-api-key",
            "Clockify API Key",
            Severity::High,
            r#"(?i)clockify[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clockify_api", "CLOCKIFY_API", "clockifyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "everhour-api-key",
            "Everhour API Key",
            Severity::Medium,
            r#"(?i)everhour[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["everhour_api", "EVERHOUR_API", "everhourApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "harvest-api-key",
            "Harvest API Key",
            Severity::High,
            r#"(?i)harvest[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["harvest_api", "HARVEST_API", "harvestApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "humanity-api-key",
            "Humanity API Key",
            Severity::Medium,
            r#"(?i)humanity[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["humanity_api", "HUMANITY_API", "humanityApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "toggl-track-api-key",
            "Toggl Track API Key",
            Severity::Medium,
            r#"(?i)toggl[_\-]?track[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["toggl_track", "TOGGL_TRACK", "togglTrack"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "runrunit-api-key",
            "RunRunIt API Key",
            Severity::Medium,
            r#"(?i)runrunit[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["runrunit_api", "RUNRUNIT_API", "runRunIt"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "workstack-api-key",
            "Workstack API Key",
            Severity::Medium,
            r#"(?i)workstack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["workstack_api", "WORKSTACK_API", "workstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "easyinsight-api-key",
            "EasyInsight API Key",
            Severity::Medium,
            r#"(?i)easyinsight[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["easyinsight_api", "EASYINSIGHT_API", "easyInsight"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dovico-api-key",
            "Dovico API Key",
            Severity::Medium,
            r#"(?i)dovico[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["dovico_api", "DOVICO_API", "dovicoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mavenlink-api-key",
            "Mavenlink API Key",
            Severity::Medium,
            r#"(?i)mavenlink[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["mavenlink_api", "MAVENLINK_API", "mavenlinkApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "float-api-key",
            "Float API Key",
            Severity::Medium,
            r#"(?i)float[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["float_api", "FLOAT_API", "floatApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "daily-co-api-key",
            "Daily.co API Key",
            Severity::High,
            r#"(?i)daily[_\-]?co[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["daily_co_api", "DAILY_CO_API", "dailyCoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tly-api-key",
            "T.ly API Key",
            Severity::Medium,
            r#"(?i)t[_\-]?\.?ly[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["t.ly_api", "T.LY_API", "tlyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "rebrandly-api-key",
            "Rebrandly API Key",
            Severity::Medium,
            r#"(?i)rebrandly[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["rebrandly_api", "REBRANDLY_API", "rebrandlyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "timezone-api-key",
            "Timezone API Key",
            Severity::Low,
            r#"(?i)timezone[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["timezone_api", "TIMEZONE_API", "timezoneApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "jotform-api-key",
            "Jotform API Key",
            Severity::High,
            r#"(?i)jotform[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["jotform_api", "JOTFORM_API", "jotformApi"],
        )),

        // ── Forms & Survey Platforms (TruffleHog) ────────────────────────

        Box::new(RegexDetector::with_prefilter(
            "typeform-api-key",
            "Typeform API Key",
            Severity::High,
            r#"(?i)typeform[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["typeform_api", "TYPEFORM_API", "typeformApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "surveysparrow-api-key",
            "SurveySparrow API Key",
            Severity::Medium,
            r#"(?i)surveysparrow[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["surveysparrow_api", "SURVEYSPARROW_API", "surveySparrow"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "survicate-api-key",
            "Survicate API Key",
            Severity::Medium,
            r#"(?i)survicate[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["survicate_api", "SURVICATE_API", "survicateApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "delighted-api-key",
            "Delighted API Key",
            Severity::Medium,
            r#"(?i)delighted[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["delighted_api", "DELIGHTED_API", "delightedApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "feedier-api-key",
            "Feedier API Key",
            Severity::Medium,
            r#"(?i)feedier[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["feedier_api", "FEEDIER_API", "feedierApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zonka-feedback-api-key",
            "Zonka Feedback API Key",
            Severity::Medium,
            r#"(?i)zonka[_\-]?feedback[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zonka_feedback", "ZONKA_FEEDBACK", "zonkaFeedback"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "satismeter-project-key",
            "Satismeter Project Key",
            Severity::Medium,
            r#"(?i)satismeter[_\-]?project[_\-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["satismeter_project", "SATISMETER_PROJECT", "satismeterProject"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "satismeter-write-key",
            "Satismeter Write Key",
            Severity::Medium,
            r#"(?i)satismeter[_\-]?write[_\-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["satismeter_write", "SATISMETER_WRITE", "satismeterWrite"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "simplesat-api-key",
            "Simplesat API Key",
            Severity::Medium,
            r#"(?i)simplesat[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["simplesat_api", "SIMPLESAT_API", "simplesatApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "surveyanyplace-api-key",
            "SurveyAnyplace API Key",
            Severity::Medium,
            r#"(?i)surveyanyplace[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["surveyanyplace_api", "SURVEYANYPLACE_API", "surveyAnyplace"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "surveybot-api-key",
            "SurveyBot API Key",
            Severity::Medium,
            r#"(?i)surveybot[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["surveybot_api", "SURVEYBOT_API", "surveyBotApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "qualaroo-api-key",
            "Qualaroo API Key",
            Severity::Medium,
            r#"(?i)qualaroo[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["qualaroo_api", "QUALAROO_API", "qualarooApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "customerguru-api-key",
            "CustomerGuru API Key",
            Severity::Medium,
            r#"(?i)customerguru[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["customerguru_api", "CUSTOMERGURU_API", "customerGuru"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "abyssale-api-key",
            "Abyssale API Key",
            Severity::Medium,
            r#"(?i)abyssale[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["abyssale_api", "ABYSSALE_API", "abyssaleApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "magnetic-api-key",
            "Magnetic API Key",
            Severity::Medium,
            r#"(?i)magnetic[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["magnetic_api", "MAGNETIC_API", "magneticApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "refiner-api-key",
            "Refiner API Key",
            Severity::Medium,
            r#"(?i)refiner[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["refiner_api", "REFINER_API", "refinerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "simvoly-api-key",
            "Simvoly API Key",
            Severity::Medium,
            r#"(?i)simvoly[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["simvoly_api", "SIMVOLY_API", "simvolyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "checkmarket-api-key",
            "Checkmarket API Key",
            Severity::Medium,
            r#"(?i)checkmarket[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["checkmarket_api", "CHECKMARKET_API", "checkmarketApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "webengage-api-key",
            "Webengage API Key",
            Severity::Medium,
            r#"(?i)webengage[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["webengage_api", "WEBENGAGE_API", "webengageApi"],
        )),

        // ── Financial & Trading APIs (TruffleHog) ────────────────────────

        Box::new(RegexDetector::with_prefilter(
            "twelve-data-api-key",
            "Twelve Data API Key",
            Severity::Medium,
            r#"(?i)twelve[_\-]?data[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["twelve_data_api", "TWELVE_DATA_API", "twelveDataApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fixer-io-api-key",
            "Fixer.io API Key",
            Severity::Medium,
            r#"(?i)fixer[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fixer_io_api", "FIXER_IO_API", "fixerIoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "alpha-vantage-api-key",
            "Alpha Vantage API Key",
            Severity::Medium,
            r#"(?i)alpha[_\-]?vantage[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["alpha_vantage_api", "ALPHA_VANTAGE_API", "alphaVantageApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tradier-api-key",
            "Tradier API Key",
            Severity::High,
            r#"(?i)tradier[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tradier_api", "TRADIER_API", "tradierApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "finnhub-api-key",
            "Finnhub API Key",
            Severity::Medium,
            r#"(?i)finnhub[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["finnhub_api", "FINNHUB_API", "finnhubApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tiingo-api-key",
            "Tiingo API Key",
            Severity::Medium,
            r#"(?i)tiingo[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tiingo_api", "TIINGO_API", "tiingoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "finage-api-key",
            "Finage API Key",
            Severity::Medium,
            r#"(?i)finage[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["finage_api", "FINAGE_API", "finageApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "iex-cloud-api-key",
            "IEX Cloud API Key",
            Severity::Medium,
            r#"(?i)iex[_\-]?cloud[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["iex_cloud_api", "IEX_CLOUD_API", "iexCloudApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "intrinio-api-key",
            "Intrinio API Key",
            Severity::Medium,
            r#"(?i)intrinio[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["intrinio_api", "INTRINIO_API", "intrinioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "financial-modeling-prep-api-key",
            "Financial Modeling Prep API Key",
            Severity::Medium,
            r#"(?i)financial[_\-]?modeling[_\-]?prep[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["financial_modeling_prep", "FINANCIAL_MODELING_PREP", "financialModelingPrep"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nasdaq-data-link-api-key",
            "Nasdaq Data Link API Key",
            Severity::High,
            r#"(?i)nasdaq[_\-]?data[_\-]?link[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["nasdaq_data_link", "NASDAQ_DATA_LINK", "nasdaqDataLink"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "qubole-api-key",
            "Qubole API Key",
            Severity::Medium,
            r#"(?i)qubole[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["qubole_api", "QUBOLE_API", "quboleApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "enigma-api-key",
            "Enigma API Key",
            Severity::Medium,
            r#"(?i)enigma[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["enigma_api", "ENIGMA_API", "enigmaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "datagov-api-key",
            "Data.gov API Key",
            Severity::Low,
            r#"(?i)data[_\-]?gov[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["data_gov_api", "DATA_GOV_API", "dataGovApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stockdata-api-key",
            "Stockdata API Key",
            Severity::Medium,
            r#"(?i)stockdata[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["stockdata_api", "STOCKDATA_API", "stockdataApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "marketstack-api-key",
            "Marketstack API Key",
            Severity::Medium,
            r#"(?i)marketstack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["marketstack_api", "MARKETSTACK_API", "marketstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "commodities-api-key",
            "Commodities API Key",
            Severity::Medium,
            r#"(?i)commodities[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["commodities_api", "COMMODITIES_API", "commoditiesApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "baremetrics-api-key",
            "Baremetrics API Key",
            Severity::Medium,
            r#"(?i)baremetrics[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["baremetrics_api", "BAREMETRICS_API", "baremetricsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dwolla-api-key",
            "Dwolla API Key",
            Severity::High,
            r#"(?i)dwolla[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["dwolla_api", "DWOLLA_API", "dwollaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "wepay-api-key",
            "WePay API Key",
            Severity::High,
            r#"(?i)wepay[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["wepay_api", "WEPAY_API", "wepayApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "checkout-com-api-key",
            "Checkout.com API Key",
            Severity::High,
            r#"(?i)checkout[_\-]?com[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["checkout_com_api", "CHECKOUT_COM_API", "checkoutComApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "paymongo-api-key",
            "Paymongo API Key",
            Severity::High,
            r#"(?i)paymongo[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["paymongo_api", "PAYMONGO_API", "paymongoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "avalara-api-key",
            "Avalara API Key",
            Severity::High,
            r#"(?i)avalara[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["avalara_api", "AVALARA_API", "avalaraApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "carbon-interface-api-key",
            "Carbon Interface API Key",
            Severity::Medium,
            r#"(?i)carbon[_\-]?interface[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["carbon_interface_api", "CARBON_INTERFACE_API", "carbonInterfaceApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "currency-layer-api-key",
            "Currency Layer API Key",
            Severity::Medium,
            r#"(?i)currency[_\-]?layer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["currency_layer_api", "CURRENCY_LAYER_API", "currencyLayerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "exchange-rates-api-key",
            "Exchange Rates API Key",
            Severity::Low,
            r#"(?i)exchange[_\-]?rates[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["exchange_rates_api", "EXCHANGE_RATES_API", "exchangeRatesApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "currencyscoop-api-key",
            "CurrencyScoop API Key",
            Severity::Medium,
            r#"(?i)currencyscoop[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["currencyscoop_api", "CURRENCYSCOOP_API", "currencyScoopApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "currencyfreaks-api-key",
            "Currency Freaks API Key",
            Severity::Medium,
            r#"(?i)currencyfreaks[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["currencyfreaks_api", "CURRENCYFREAKS_API", "currencyFreaksApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "country-layer-api-key",
            "Country Layer API Key",
            Severity::Low,
            r#"(?i)country[_\-]?layer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["country_layer_api", "COUNTRY_LAYER_API", "countryLayerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fxmarket-api-key",
            "FX Market API Key",
            Severity::Medium,
            r#"(?i)fx[_\-]?market[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fx_market_api", "FX_MARKET_API", "fxMarketApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "currencycloud-api-key",
            "Currency Cloud API Key",
            Severity::High,
            r#"(?i)currency[_\-]?cloud[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["currency_cloud_api", "CURRENCY_CLOUD_API", "currencyCloudApi"],
        )),

        // ── Crypto & Blockchain Additional (TruffleHog) ──────────────────

        Box::new(RegexDetector::with_prefilter(
            "kraken-api-key",
            "Kraken API Key",
            Severity::High,
            r#"(?i)kraken[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-/]{20,})['"]?"#,
            &["kraken_api", "KRAKEN_API", "krakenApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "poloniex-api-key",
            "Poloniex API Key",
            Severity::High,
            r#"(?i)poloniex[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["poloniex_api", "POLONIEX_API", "poloniexApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitmex-api-key",
            "BitMEX API Key",
            Severity::High,
            r#"(?i)bitmex[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bitmex_api", "BITMEX_API", "bitmexApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "coinapi-key",
            "CoinAPI Key",
            Severity::Medium,
            r#"(?i)coinapi[_\-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coinapi_key", "COINAPI_KEY", "coinApiKey"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "coinlayer-api-key",
            "Coinlayer API Key",
            Severity::Medium,
            r#"(?i)coinlayer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coinlayer_api", "COINLAYER_API", "coinlayerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "coinlib-api-key",
            "Coinlib API Key",
            Severity::Low,
            r#"(?i)coinlib[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coinlib_api", "COINLIB_API", "coinlibApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cryptocompare-api-key",
            "CryptoCompare API Key",
            Severity::Medium,
            r#"(?i)cryptocompare[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cryptocompare_api", "CRYPTOCOMPARE_API", "cryptoCompareApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitcoinaverage-api-key",
            "Bitcoin Average API Key",
            Severity::Medium,
            r#"(?i)bitcoin[_\-]?average[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bitcoin_average_api", "BITCOIN_AVERAGE_API", "bitcoinAverageApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "worldcoinindex-api-key",
            "World Coin Index API Key",
            Severity::Medium,
            r#"(?i)world[_\-]?coin[_\-]?index[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["world_coin_index_api", "WORLD_COIN_INDEX_API", "worldCoinIndexApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "glassnode-api-key",
            "Glassnode API Key",
            Severity::High,
            r#"(?i)glassnode[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["glassnode_api", "GLASSNODE_API", "glassnodeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tatum-api-key",
            "Tatum.io API Key",
            Severity::High,
            r#"(?i)tatum[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tatum_api", "TATUM_API", "tatumApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ethplorer-api-key",
            "Ethplorer API Key",
            Severity::Medium,
            r#"(?i)ethplorer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ethplorer_api", "ETHPLORER_API", "ethplorerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nftport-api-key",
            "NFTPort API Key",
            Severity::High,
            r#"(?i)nftport[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["nftport_api", "NFTPORT_API", "nftportApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "messari-api-key",
            "Messari API Key",
            Severity::Medium,
            r#"(?i)messari[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["messari_api", "MESSARI_API", "messariApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "coingecko-api-key",
            "CoinGecko API Key",
            Severity::Medium,
            r#"(?i)coingecko[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coingecko_api", "COINGECKO_API", "coingeckoApi"],
        )),

        // ── Weather & Environment APIs (TruffleHog) ──────────────────────

        Box::new(RegexDetector::with_prefilter(
            "openweather-api-key",
            "OpenWeather API Key",
            Severity::Medium,
            r#"(?i)openweather[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["openweather_api", "OPENWEATHER_API", "openweatherApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "weatherstack-api-key",
            "WeatherStack API Key",
            Severity::Medium,
            r#"(?i)weatherstack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["weatherstack_api", "WEATHERSTACK_API", "weatherstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "accuweather-api-key",
            "AccuWeather API Key",
            Severity::Medium,
            r#"(?i)accuweather[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["accuweather_api", "ACCUWEATHER_API", "accuweatherApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "worldweather-api-key",
            "World Weather API Key",
            Severity::Medium,
            r#"(?i)world[_\-]?weather[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["world_weather_api", "WORLD_WEATHER_API", "worldWeatherApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tomorrow-io-api-key",
            "Tomorrow.io API Key",
            Severity::Medium,
            r#"(?i)tomorrow[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tomorrow_io_api", "TOMORROW_IO_API", "tomorrowIoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "airvisual-api-key",
            "AirVisual API Key",
            Severity::Medium,
            r#"(?i)airvisual[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["airvisual_api", "AIRVISUAL_API", "airvisualApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "visualcrossing-api-key",
            "Visual Crossing API Key",
            Severity::Medium,
            r#"(?i)visual[_\-]?crossing[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["visual_crossing_api", "VISUAL_CROSSING_API", "visualCrossingApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stormglass-api-key",
            "Stormglass API Key",
            Severity::Medium,
            r#"(?i)stormglass[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["stormglass_api", "STORMGLASS_API", "stormglassApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aeris-weather-api-key",
            "Aeris Weather API Key",
            Severity::Medium,
            r#"(?i)aeris[_\-]?weather[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["aeris_weather_api", "AERIS_WEATHER_API", "aerisWeatherApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ambee-api-key",
            "Ambee API Key",
            Severity::Medium,
            r#"(?i)ambee[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ambee_api", "AMBEE_API", "ambeeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "openuv-api-key",
            "OpenUV API Key",
            Severity::Medium,
            r#"(?i)openuv[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["openuv_api", "OPENUV_API", "openuvApi"],
        )),

        // ── Edge Token (TruffleHog) ───────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "edge-token",
            "Edge Token",
            Severity::Medium,
            r#"(?i)edge[_\-]?(?:api[_\-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["edge_token", "EDGE_TOKEN", "edgeToken"],
        )),
        // ── Calendly Webhook (TruffleHog) ────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "calendly-webhook",
            "Calendly Webhook",
            Severity::Medium,
            r#"(?i)calendly[_\-]?webhook[_\-]?(?:url|secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["calendly_webhook", "CALENDLY_WEBHOOK", "calendlyWebhook"],
        )),

        // ── Geocoding & Location (TruffleHog) ────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "tomtom-api-key",
            "TomTom API Key",
            Severity::Medium,
            r#"(?i)tomtom[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tomtom_api", "TOMTOM_API", "tomtomApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "geoapify-api-key",
            "Geoapify API Key",
            Severity::Medium,
            r#"(?i)geoapify[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["geoapify_api", "GEOAPIFY_API", "geoapifyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "geocodify-api-key",
            "Geocodify API Key",
            Severity::Medium,
            r#"(?i)geocodify[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["geocodify_api", "GEOCODIFY_API", "geocodifyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "geocode-api-key",
            "Geocode API Key",
            Severity::Medium,
            r#"(?i)geocode[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["geocode_api", "GEOCODE_API", "geocodeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "geocodio-api-key",
            "Geocodio API Key",
            Severity::Medium,
            r#"(?i)geocodio[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["geocodio_api", "GEOCODIO_API", "geocodioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "positionstack-api-key",
            "PositionStack API Key",
            Severity::Medium,
            r#"(?i)position[_\-]?stack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["positionstack_api", "POSITIONSTACK_API", "positionstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "locationiq-api-key",
            "LocationIQ API Key",
            Severity::Medium,
            r#"(?i)locationiq[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["locationiq_api", "LOCATIONIQ_API", "locationiqApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "graphhopper-api-key",
            "Graphhopper API Key",
            Severity::Medium,
            r#"(?i)graphhopper[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["graphhopper_api", "GRAPHHOPPER_API", "graphhopperApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "smartystreets-api-key",
            "SmartyStreets API Key",
            Severity::Medium,
            r#"(?i)smartystreets[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["smartystreets_api", "SMARTYSTREETS_API", "smartystreetsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "route4me-api-key",
            "Route4me API Key",
            Severity::Medium,
            r#"(?i)route4me[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["route4me_api", "ROUTE4ME_API", "route4meApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zipcode-api-key",
            "ZipCode API Key",
            Severity::Medium,
            r#"(?i)zipcode[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zipcode_api", "ZIPCODE_API", "zipcodeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "onwater-api-key",
            "OnWater.io API Key",
            Severity::Low,
            r#"(?i)onwater[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["onwater_api", "ONWATER_API", "onwaterApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "geoipify-api-key",
            "GeoIPify API Key",
            Severity::Medium,
            r#"(?i)geoipify[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["geoipify_api", "GEOIPIFY_API", "geoipifyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ipgeolocation-api-key",
            "IPGeolocation API Key",
            Severity::Medium,
            r#"(?i)ipgeolocation[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ipgeolocation_api", "IPGEOLOCATION_API", "ipgeolocationApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ipinfodb-api-key",
            "IPinfoDB API Key",
            Severity::Medium,
            r#"(?i)ipinfodb[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ipinfodb_api", "IPINFODB_API", "ipinfodbApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ipify-api-key",
            "ipify API Key",
            Severity::Medium,
            r#"(?i)ipify[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ipify_api", "IPIFY_API", "ipifyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ipapi-api-key",
            "ipapi API Key",
            Severity::Medium,
            r#"(?i)ipapi[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ipapi_api", "IPAPI_API", "ipapiApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "vpn-api-key",
            "VPN API Key",
            Severity::Medium,
            r#"(?i)vpn[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["vpn_api", "VPN_API", "vpnApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dnscheck-api-key",
            "DNS Check API Key",
            Severity::Medium,
            r#"(?i)dns[_\-]?check[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["dnscheck_api", "DNSCHECK_API", "dnscheckApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "walkscore-api-key",
            "Walk Score API Key",
            Severity::Low,
            r#"(?i)walk[_\-]?score[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["walkscore_api", "WALKSCORE_API", "walkscoreApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "besttime-api-key",
            "Besttime API Key",
            Severity::Medium,
            r#"(?i)besttime[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["besttime_api", "BESTTIME_API", "besttimeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hypertrack-api-key",
            "Hypertrack API Key",
            Severity::Medium,
            r#"(?i)hypertrack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["hypertrack_api", "HYPERTRACK_API", "hypertrackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fulcrum-api-key",
            "Fulcrum API Key",
            Severity::Medium,
            r#"(?i)fulcrum[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fulcrum_api", "FULCRUM_API", "fulcrumApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "samsara-api-key",
            "Samsara API Key",
            Severity::High,
            r#"(?i)samsara[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["samsara_api", "SAMSARA_API", "samsaraApi"],
        )),

        // ── Media & Image APIs (TruffleHog) ──────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "unsplash-api-key",
            "Unsplash API Key",
            Severity::Medium,
            r#"(?i)unsplash[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["unsplash_api", "UNSPLASH_API", "unsplashApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pixabay-api-key",
            "Pixabay API Key",
            Severity::Medium,
            r#"(?i)pixabay[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pixabay_api", "PIXABAY_API", "pixabayApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gyazo-api-key",
            "Gyazo API Key",
            Severity::Medium,
            r#"(?i)gyazo[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["gyazo_api", "GYAZO_API", "gyazoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "imgur-api-key",
            "Imgur API Key",
            Severity::Medium,
            r#"(?i)imgur[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["imgur_api", "IMGUR_API", "imgurApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shutterstock-api-key",
            "Shutterstock API Key",
            Severity::High,
            r#"(?i)shutterstock[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["shutterstock_api", "SHUTTERSTOCK_API", "shutterstockApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shutterstock-oauth-token",
            "Shutterstock OAuth Token",
            Severity::High,
            r#"(?i)shutterstock[_\-]?oauth[_\-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["shutterstock_oauth", "SHUTTERSTOCK_OAUTH", "shutterstockOauth"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "iconfinder-api-key",
            "IconFinder API Key",
            Severity::Medium,
            r#"(?i)iconfinder[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["iconfinder_api", "ICONFINDER_API", "iconfinderApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "imagekit-api-key",
            "ImageKit API Key",
            Severity::Medium,
            r#"(?i)imagekit[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["imagekit_api", "IMAGEKIT_API", "imagekitApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bannerbear-api-key",
            "Bannerbear API Key",
            Severity::Medium,
            r#"(?i)bannerbear[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bannerbear_api", "BANNERBEAR_API", "bannerbearApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "imagga-api-key",
            "Imagga API Key",
            Severity::Medium,
            r#"(?i)imagga[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["imagga_api", "IMAGGA_API", "imaggaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "faceplusplus-api-key",
            "Face++ API Key",
            Severity::Medium,
            r#"(?i)face[_\-]?plusplus[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["faceplusplus_api", "FACEPLUSPLUS_API", "faceplusplusApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "skybiometry-api-key",
            "SkyBiometry API Key",
            Severity::Medium,
            r#"(?i)skybiometry[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["skybiometry_api", "SKYBIOMETRY_API", "skybiometryApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudmersive-api-key",
            "Cloudmersive API Key",
            Severity::Medium,
            r#"(?i)cloudmersive[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cloudmersive_api", "CLOUDMERSIVE_API", "cloudmersiveApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "screenshotapi-api-key",
            "ScreenshotAPI API Key",
            Severity::Medium,
            r#"(?i)screenshotapi[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["screenshotapi_api", "SCREENSHOTAPI_API", "screenshotapiApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "screenshotlayer-api-key",
            "ScreenshotLayer API Key",
            Severity::Medium,
            r#"(?i)screenshotlayer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["screenshotlayer_api", "SCREENSHOTLAYER_API", "screenshotlayerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "browshot-api-key",
            "Browshot API Key",
            Severity::Medium,
            r#"(?i)browshot[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["browshot_api", "BROWSHOT_API", "browshotApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "linkpreview-api-key",
            "LinkPreview API Key",
            Severity::Medium,
            r#"(?i)linkpreview[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["linkpreview_api", "LINKPREVIEW_API", "linkpreviewApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mixcloud-api-key",
            "Mixcloud API Key",
            Severity::Low,
            r#"(?i)mixcloud[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["mixcloud_api", "MIXCLOUD_API", "mixcloudApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "rawg-api-key",
            "Rawg API Key",
            Severity::Medium,
            r#"(?i)rawg[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["rawg_api", "RAWG_API", "rawgApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "strava-api-key",
            "Strava API Key",
            Severity::Medium,
            r#"(?i)strava[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["strava_api", "STRAVA_API", "stravaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "foursquare-api-key",
            "FourSquare API Key",
            Severity::Medium,
            r#"(?i)foursquare[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["foursquare_api", "FOURSQUARE_API", "foursquareApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ticketmaster-api-key",
            "TicketMaster API Key",
            Severity::Medium,
            r#"(?i)ticketmaster[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ticketmaster_api", "TICKETMASTER_API", "ticketmasterApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "riotgames-api-key",
            "Riot Games API Key",
            Severity::Medium,
            r#"(?i)riot[_\-]?games[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["riotgames_api", "RIOTGAMES_API", "riotgamesApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cricket-api-key",
            "Cricket API Key",
            Severity::Low,
            r#"(?i)cricket[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cricket_api", "CRICKET_API", "cricketApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "allsports-api-key",
            "All Sports API Key",
            Severity::Medium,
            r#"(?i)all[_\-]?sports[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["allsports_api", "ALLSPORTS_API", "allsportsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sportsmonk-api-key",
            "SportsMonk API Key",
            Severity::Medium,
            r#"(?i)sportsmonk[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sportsmonk_api", "SPORTSMONK_API", "sportsmonkApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "edamam-api-key",
            "Edamam API Key",
            Severity::Medium,
            r#"(?i)edamam[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["edamam_api", "EDAMAM_API", "edamamApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nutritionix-api-key",
            "Nutritionix API Key",
            Severity::Medium,
            r#"(?i)nutritionix[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["nutritionix_api", "NUTRITIONIX_API", "nutritionixApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "spoonacular-api-key",
            "Spoonacular API Key",
            Severity::Medium,
            r#"(?i)spoonacular[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["spoonacular_api", "SPOONACULAR_API", "spoonacularApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "calorieninja-api-key",
            "Calorie Ninja API Key",
            Severity::Low,
            r#"(?i)calorie[_\-]?ninja[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["calorieninja_api", "CALORIENINJA_API", "calorieninjaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "protocolsio-api-key",
            "Protocols.io API Key",
            Severity::Medium,
            r#"(?i)protocols[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["protocolsio_api", "PROTOCOLSIO_API", "protocolsioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hypeauditor-api-key",
            "HypeAuditor API Key",
            Severity::Medium,
            r#"(?i)hypeauditor[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["hypeauditor_api", "HYPEAUDITOR_API", "hypeauditorApi"],
        )),

        // ── News & Content APIs (TruffleHog) ─────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "newsapi-key",
            "NewsAPI Key",
            Severity::Medium,
            r#"(?i)news[_\-]?api[_\-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["newsapi_key", "NEWSAPI_KEY", "newsapiKey"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "newscatcher-api-key",
            "Newscatcher API Key",
            Severity::Medium,
            r#"(?i)newscatcher[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["newscatcher_api", "NEWSCATCHER_API", "newscatcherApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "currents-api-key",
            "Currents API Key",
            Severity::Medium,
            r#"(?i)currents[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["currents_api", "CURRENTS_API", "currentsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "guardian-api-key",
            "Guardian API Key",
            Severity::Medium,
            r#"(?i)guardian[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["guardian_api", "GUARDIAN_API", "guardianApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aylien-api-key",
            "Aylien API Key",
            Severity::Medium,
            r#"(?i)aylien[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["aylien_api", "AYLIEN_API", "aylienApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cicero-api-key",
            "Cicero API Key",
            Severity::Medium,
            r#"(?i)cicero[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cicero_api", "CICERO_API", "ciceroApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "lexigram-api-key",
            "Lexigram API Key",
            Severity::Medium,
            r#"(?i)lexigram[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["lexigram_api", "LEXIGRAM_API", "lexigramApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "blogger-api-key",
            "Blogger API Key",
            Severity::Low,
            r#"(?i)blogger[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["blogger_api", "BLOGGER_API", "bloggerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mediastack-api-key",
            "MediaStack API Key",
            Severity::Medium,
            r#"(?i)mediastack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["mediastack_api", "MEDIASTACK_API", "mediastackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clickhelp-api-key",
            "ClickHelp API Key",
            Severity::Medium,
            r#"(?i)clickhelp[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clickhelp_api", "CLICKHELP_API", "clickhelpApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "storychief-api-key",
            "Storychief API Key",
            Severity::Medium,
            r#"(?i)storychief[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["storychief_api", "STORYCHIEF_API", "storychiefApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "noticeable-api-key",
            "Noticeable API Key",
            Severity::Medium,
            r#"(?i)noticeable[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["noticeable_api", "NOTICEABLE_API", "noticeableApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "readme-api-key",
            "ReadMe API Key",
            Severity::Medium,
            r#"(?i)readme[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["readme_api", "README_API", "readmeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pastebin-api-key",
            "Pastebin API Key",
            Severity::Medium,
            r#"(?i)pastebin[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pastebin_api", "PASTEBIN_API", "pastebinApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "crowdin-api-key",
            "Crowdin API Key",
            Severity::Medium,
            r#"(?i)crowdin[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["crowdin_api", "CROWDIN_API", "crowdinApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "alconost-api-key",
            "Alconost API Key",
            Severity::Medium,
            r#"(?i)alconost[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["alconost_api", "ALCONOST_API", "alconostApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gengo-api-key",
            "Gengo API Key",
            Severity::Medium,
            r#"(?i)gengo[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["gengo_api", "GENGO_API", "gengoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "happyscribe-api-key",
            "HappyScribe API Key",
            Severity::Medium,
            r#"(?i)happyscribe[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["happyscribe_api", "HAPPYSCRIBE_API", "happyscribeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ritekit-api-key",
            "RiteKit API Key",
            Severity::Medium,
            r#"(?i)ritekit[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ritekit_api", "RITEKIT_API", "ritekitApi"],
        )),

        // ── Developer & Code Tools (TruffleHog) ──────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "rubygems-api-token",
            "RubyGems API Token",
            Severity::High,
            r#"(?i)rubygems[_\-]?(?:api[_\-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["rubygems_api", "RUBYGEMS_API", "rubygemsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "codacy-api-token",
            "Codacy API Token",
            Severity::High,
            r#"(?i)codacy[_\-]?(?:api[_\-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["codacy_api", "CODACY_API", "codacyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "coveralls-api-token",
            "Coveralls API Token",
            Severity::Medium,
            r#"(?i)coveralls[_\-]?(?:api[_\-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coveralls_api", "COVERALLS_API", "coverallsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "saucelabs-api-key",
            "SauceLabs API Key",
            Severity::High,
            r#"(?i)saucelabs[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["saucelabs_api", "SAUCELABS_API", "saucelabsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bitbar-api-key",
            "Bitbar API Key",
            Severity::Medium,
            r#"(?i)bitbar[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bitbar_api", "BITBAR_API", "bitbarApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bugsnag-api-key",
            "Bugsnag API Key",
            Severity::High,
            r#"(?i)bugsnag[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bugsnag_api", "BUGSNAG_API", "bugsnagApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "adafruit-io-key",
            "Adafruit IO Key",
            Severity::Medium,
            r#"(?i)adafruit[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["adafruit_io", "ADAFRUIT_IO", "adafruitIo"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "apify-api-key",
            "Apify API Key",
            Severity::Medium,
            r#"(?i)apify[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["apify_api", "APIFY_API", "apifyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "keygen-api-key",
            "Keygen API Key",
            Severity::High,
            r#"(?i)keygen[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["keygen_api", "KEYGEN_API", "keygenApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aiven-api-key",
            "Aiven API Key",
            Severity::Medium,
            r#"(?i)aiven[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["aiven_api", "AIVEN_API", "aivenApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fileio-api-key",
            "File.io API Key",
            Severity::Medium,
            r#"(?i)file[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fileio_api", "FILEIO_API", "fileioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flatio-api-key",
            "Flat.io API Key",
            Severity::Medium,
            r#"(?i)flat[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["flatio_api", "FLATIO_API", "flatioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dynalist-api-key",
            "Dynalist API Key",
            Severity::Medium,
            r#"(?i)dynalist[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["dynalist_api", "DYNALIST_API", "dynalistApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sheety-api-key",
            "Sheety API Key",
            Severity::Medium,
            r#"(?i)sheety[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sheety_api", "SHEETY_API", "sheetyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "swell-api-key",
            "Swell API Key",
            Severity::Medium,
            r#"(?i)swell[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["swell_api", "SWELL_API", "swellApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "m3o-api-key",
            "M3o API Key",
            Severity::Medium,
            r#"(?i)m3o[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["m3o_api", "M3O_API", "m3oApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "jsonbin-api-key",
            "JSONbin API Key",
            Severity::Medium,
            r#"(?i)jsonbin[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["jsonbin_api", "JSONBIN_API", "jsonbinApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "userstack-api-key",
            "UserStack API Key",
            Severity::Medium,
            r#"(?i)userstack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["userstack_api", "USERSTACK_API", "userstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "purestake-api-key",
            "PureStake API Key",
            Severity::Medium,
            r#"(?i)purestake[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["purestake_api", "PURESTAKE_API", "purestakeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "host-api-key",
            "Host API Key",
            Severity::Medium,
            r#"(?i)host[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["host_api", "HOST_API", "hostApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "baseapi-api-key",
            "BaseAPI.io API Key",
            Severity::Medium,
            r#"(?i)baseapi[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["baseapi_api", "BASEAPI_API", "baseapiApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sslmate-api-key",
            "SslMate API Key",
            Severity::Medium,
            r#"(?i)sslmate[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sslmate_api", "SSLMATE_API", "sslmateApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "adobeio-api-key",
            "Adobe IO API Key",
            Severity::High,
            r#"(?i)adobe[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["adobeio_api", "ADOBEIO_API", "adobeioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "edenai-api-key",
            "EdenAI API Key",
            Severity::Medium,
            r#"(?i)edenai[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["edenai_api", "EDENAI_API", "edenaiApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "deepgram-api-key",
            "Deepgram API Key",
            Severity::High,
            r#"(?i)deepgram[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["deepgram_api", "DEEPGRAM_API", "deepgramApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "voicegain-api-key",
            "Voicegain API Key",
            Severity::Medium,
            r#"(?i)voicegain[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["voicegain_api", "VOICEGAIN_API", "voicegainApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "auddio-api-key",
            "Audd.io API Key",
            Severity::Medium,
            r#"(?i)audd[_\-]?io[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["auddio_api", "AUDDIO_API", "auddioApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "owlbot-api-key",
            "OwlBot API Key",
            Severity::Low,
            r#"(?i)owlbot[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["owlbot_api", "OWLBOT_API", "owlbotApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "detectlanguage-api-key",
            "DetectLanguage API Key",
            Severity::Medium,
            r#"(?i)detectlanguage[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["detectlanguage_api", "DETECTLANGUAGE_API", "detectlanguageApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "languagelayer-api-key",
            "LanguageLayer API Key",
            Severity::Medium,
            r#"(?i)languagelayer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["languagelayer_api", "LANGUAGELAYER_API", "languagelayerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "paralleldots-api-key",
            "ParallelDots API Key",
            Severity::Medium,
            r#"(?i)paralleldots[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["paralleldots_api", "PARALLELDOTS_API", "paralleldotsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "veriphone-api-key",
            "Veriphone API Key",
            Severity::Medium,
            r#"(?i)veriphone[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["veriphone_api", "VERIPHONE_API", "veriphoneApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "verifier-api-key",
            "Verifier API Key",
            Severity::Medium,
            r#"(?i)verifier[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["verifier_api", "VERIFIER_API", "verifierApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "api2cart-api-key",
            "API2Cart API Key",
            Severity::Medium,
            r#"(?i)api2cart[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["api2cart_api", "API2CART_API", "api2cartApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "apideck-api-key",
            "APIDeck API Key",
            Severity::Medium,
            r#"(?i)apideck[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["apideck_api", "APIDECK_API", "apideckApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "apiflash-api-key",
            "APIFlash API Key",
            Severity::Medium,
            r#"(?i)apiflash[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["apiflash_api", "APIFLASH_API", "apiflashApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fleetbase-api-key",
            "Fleetbase API Key",
            Severity::Medium,
            r#"(?i)fleetbase[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fleetbase_api", "FLEETBASE_API", "fleetbaseApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "agora-api-key",
            "Agora API Key",
            Severity::High,
            r#"(?i)agora[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["agora_api", "AGORA_API", "agoraApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "yandex-api-key",
            "Yandex API Key",
            Severity::Medium,
            r#"(?i)yandex[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["yandex_api", "YANDEX_API", "yandexApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "artsy-api-key",
            "Artsy API Key",
            Severity::Low,
            r#"(?i)artsy[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["artsy_api", "ARTSY_API", "artsyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "blitapp-api-key",
            "Blit.app API Key",
            Severity::Medium,
            r#"(?i)blit[_\-]?app[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["blitapp_api", "BLITAPP_API", "blitappApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "censys-api-key",
            "Censys API Key",
            Severity::High,
            r#"(?i)censys[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["censys_api", "CENSYS_API", "censysApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "securitytrails-api-key",
            "SecurityTrails API Key",
            Severity::High,
            r#"(?i)securitytrails[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["securitytrails_api", "SECURITYTRAILS_API", "securitytrailsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "urlscan-api-key",
            "URLScan API Key",
            Severity::Medium,
            r#"(?i)urlscan[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["urlscan_api", "URLSCAN_API", "urlscanApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aletheia-api-key",
            "Aletheia API Key",
            Severity::Medium,
            r#"(?i)aletheia[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["aletheia_api", "ALETHEIA_API", "aletheiaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "whoxy-api-key",
            "Whoxy API Key",
            Severity::Medium,
            r#"(?i)whoxy[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["whoxy_api", "WHOXY_API", "whoxyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "mailsac-api-key",
            "Mailsac API Key",
            Severity::Medium,
            r#"(?i)mailsac[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["mailsac_api", "MAILSAC_API", "mailsacApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "loginradius-api-key",
            "LoginRadius API Key",
            Severity::High,
            r#"(?i)loginradius[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["loginradius_api", "LOGINRADIUS_API", "loginradiusApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "rev-api-key",
            "Rev API Key",
            Severity::Medium,
            r#"(?i)rev[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["rev_api", "REV_API", "revApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "youneedabudget-api-key",
            "YouNeedABudget API Key",
            Severity::Medium,
            r#"(?i)youneedabudget[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["youneedabudget_api", "YOUNEEDABUDGET_API", "youneedabudgetApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "filestack-api-key",
            "Filestack API Key",
            Severity::Medium,
            r#"(?i)filestack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["filestack_api", "FILESTACK_API", "filestackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bubble-api-key",
            "Bubble API Key",
            Severity::Medium,
            r#"(?i)bubble[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bubble_api", "BUBBLE_API", "bubbleApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shopee-api-key",
            "Shopee Open Platform API Key",
            Severity::Medium,
            r#"(?i)shopee[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["shopee_api", "SHOPEE_API", "shopeeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kiteconnect-api-key",
            "Kite Connect API Key",
            Severity::High,
            r#"(?i)kite[_\-]?connect[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["kiteconnect_api", "KITECONNECT_API", "kiteconnectApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "veevavault-api-key",
            "Veeva Vault API Key",
            Severity::High,
            r#"(?i)veeva[_\-]?vault[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["veevavault_api", "VEEVAVAULT_API", "veevavaultApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudways-api-key",
            "Cloudways API Key",
            Severity::High,
            r#"(?i)cloudways[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cloudways_api", "CLOUDWAYS_API", "cloudwaysApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "duda-api-key",
            "Duda API Key",
            Severity::Medium,
            r#"(?i)duda[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["duda_api", "DUDA_API", "dudaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "yext-api-key",
            "Yext API Key",
            Severity::Medium,
            r#"(?i)yext[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["yext_api", "YEXT_API", "yextApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "contentstack-api-key",
            "ContentStack API Key",
            Severity::Medium,
            r#"(?i)contentstack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["contentstack_api", "CONTENTSTACK_API", "contentstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "surge-api-key",
            "Surge API Key",
            Severity::Medium,
            r#"(?i)surge[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["surge_api", "SURGE_API", "surgeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kairos-api-key",
            "Kairos API Key",
            Severity::Medium,
            r#"(?i)kairos[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["kairos_api", "KAIROS_API", "kairosApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fullcontact-api-key",
            "FullContact API Key",
            Severity::Medium,
            r#"(?i)fullcontact[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fullcontact_api", "FULLCONTACT_API", "fullcontactApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "eversign-api-key",
            "Eversign API Key",
            Severity::Medium,
            r#"(?i)eversign[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["eversign_api", "EVERSIGN_API", "eversignApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "netcore-api-key",
            "NetCore API Key",
            Severity::Medium,
            r#"(?i)netcore[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["netcore_api", "NETCORE_API", "netcoreApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bored-api-key",
            "Bored API Key",
            Severity::Low,
            r#"(?i)bored[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["bored_api", "BORED_API", "boredApi"],
        )),

        // ── Document & PDF APIs (TruffleHog) ─────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "html2pdf-api-key",
            "HTML2PDF API Key",
            Severity::Medium,
            r#"(?i)html2pdf[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["html2pdf_api", "HTML2PDF_API", "html2pdfApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pdflayer-api-key",
            "PDF Layer API Key",
            Severity::Medium,
            r#"(?i)pdf[_\-]?layer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pdflayer_api", "PDFLAYER_API", "pdflayerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pdfshift-api-key",
            "PDF Shift API Key",
            Severity::Medium,
            r#"(?i)pdf[_\-]?shift[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pdfshift_api", "PDFSHIFT_API", "pdfshiftApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "restpack-html-to-pdf-api-key",
            "Restpack HTML-to-PDF API Key",
            Severity::Medium,
            r#"(?i)restpack[_\-]?html[_\-]?to[_\-]?pdf[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["restpack_html", "RESTPACK_HTML", "restpackHtml"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "restpack-screenshot-api-key",
            "Restpack Screenshot API Key",
            Severity::Medium,
            r#"(?i)restpack[_\-]?screenshot[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["restpack_screenshot", "RESTPACK_SCREENSHOT", "restpackScreenshot"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "documo-api-key",
            "Documo API Key",
            Severity::Medium,
            r#"(?i)documo[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["documo_api", "DOCUMO_API", "documoApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "clustdoc-api-key",
            "ClustDoc API Key",
            Severity::Medium,
            r#"(?i)clustdoc[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["clustdoc_api", "CLUSTDOC_API", "clustdocApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pandadoc-api-key",
            "PandaDoc API Key",
            Severity::High,
            r#"(?i)pandadoc[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["pandadoc_api", "PANDADOC_API", "pandadocApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hellosign-api-key",
            "HelloSign API Key",
            Severity::High,
            r#"(?i)hellosign[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["hellosign_api", "HELLOSIGN_API", "hellosignApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "juro-api-key",
            "Juro API Key",
            Severity::Medium,
            r#"(?i)juro[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["juro_api", "JURO_API", "juroApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "yousign-api-key",
            "YouSign API Key",
            Severity::Medium,
            r#"(?i)yousign[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["yousign_api", "YOUSIGN_API", "yousignApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "vatlayer-api-key",
            "VatLayer API Key",
            Severity::Medium,
            r#"(?i)vatlayer[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["vatlayer_api", "VATLAYER_API", "vatlayerApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "upcdatabase-api-key",
            "UPC Database API Key",
            Severity::Low,
            r#"(?i)upc[_\-]?database[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["upcdatabase_api", "UPCDATABASE_API", "upcdatabaseApi"],
        )),

        // ── Scraping & Web Automation (TruffleHog) ───────────────────────
        Box::new(RegexDetector::with_prefilter(
            "scraperapi-key",
            "ScraperAPI Key",
            Severity::Medium,
            r#"(?i)scraperapi[_\-]?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["scraperapi_key", "SCRAPERAPI_KEY", "scraperapiKey"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scrapingdog-api-key",
            "ScrapingDog API Key",
            Severity::Medium,
            r#"(?i)scrapingdog[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["scrapingdog_api", "SCRAPINGDOG_API", "scrapingdogApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scrapeowl-api-key",
            "ScrapeOwl API Key",
            Severity::Medium,
            r#"(?i)scrapeowl[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["scrapeowl_api", "SCRAPEOWL_API", "scrapeowlApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "webscraping-api-key",
            "WebScraping API Key",
            Severity::Medium,
            r#"(?i)webscraping[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["webscraping_api", "WEBSCRAPING_API", "webscrapingApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zenscrape-api-key",
            "ZenScrape API Key",
            Severity::Medium,
            r#"(?i)zenscrape[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zenscrape_api", "ZENSCRAPE_API", "zenscrapeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zenserp-api-key",
            "ZenSerp API Key",
            Severity::Medium,
            r#"(?i)zenserp[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zenserp_api", "ZENSERP_API", "zenserpApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "serpstack-api-key",
            "SerpStack API Key",
            Severity::Medium,
            r#"(?i)serpstack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["serpstack_api", "SERPSTACK_API", "serpstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scraperbox-api-key",
            "ScraperBox API Key",
            Severity::Medium,
            r#"(?i)scraperbox[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["scraperbox_api", "SCRAPERBOX_API", "scraperboxApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scrapingant-api-key",
            "ScrapingAnt API Key",
            Severity::Medium,
            r#"(?i)scrapingant[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["scrapingant_api", "SCRAPINGANT_API", "scrapingantApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scrapestack-api-key",
            "ScrapeStack API Key",
            Severity::Medium,
            r#"(?i)scrapestack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["scrapestack_api", "SCRAPESTACK_API", "scrapestackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "proxycrawl-api-key",
            "ProxyCrawl API Key",
            Severity::Medium,
            r#"(?i)proxycrawl[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["proxycrawl_api", "PROXYCRAWL_API", "proxycrawlApi"],
        )),

        // ── Email Verification (TruffleHog) ──────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "debounce-api-key",
            "Debounce API Key",
            Severity::Medium,
            r#"(?i)debounce[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["debounce_api", "DEBOUNCE_API", "debounceApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kickbox-api-key",
            "Kickbox API Key",
            Severity::Medium,
            r#"(?i)kickbox[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["kickbox_api", "KICKBOX_API", "kickboxApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ipquality-api-key",
            "IPQuality API Key",
            Severity::Medium,
            r#"(?i)ipquality[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ipquality_api", "IPQUALITY_API", "ipqualityApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "roaring-api-key",
            "Roaring API Key",
            Severity::Medium,
            r#"(?i)roaring[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["roaring_api", "ROARING_API", "roaringApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "oopspam-api-key",
            "OOPSpam API Key",
            Severity::Medium,
            r#"(?i)oopspam[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["oopspam_api", "OOPSPAM_API", "oopspamApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "numverify-api-key",
            "Numverify API Key",
            Severity::Medium,
            r#"(?i)numverify[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["numverify_api", "NUMVERIFY_API", "numverifyApi"],
        )),

        // ── CMS & Web Builders (TruffleHog) ──────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "webflow-api-key",
            "Webflow API Key",
            Severity::High,
            r#"(?i)webflow[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["webflow_api", "WEBFLOW_API", "webflowApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "squarespace-api-key",
            "Squarespace API Key",
            Severity::Medium,
            r#"(?i)squarespace[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["squarespace_api", "SQUARESPACE_API", "squarespaceApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "siteleaf-api-key",
            "Siteleaf API Key",
            Severity::Medium,
            r#"(?i)siteleaf[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["siteleaf_api", "SITELEAF_API", "siteleafApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "graphcms-api-key",
            "GraphCMS API Key",
            Severity::Medium,
            r#"(?i)graphcms[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["graphcms_api", "GRAPHCMS_API", "graphcmsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kontent-api-key",
            "Kontent API Key",
            Severity::Medium,
            r#"(?i)kontent[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["kontent_api", "KONTENT_API", "kontentApi"],
        )),

        // ── Miscellaneous APIs (TruffleHog) ──────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "wakatime-api-key",
            "Wakatime API Key",
            Severity::Medium,
            r#"(?i)wakatime[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["wakatime_api", "WAKATIME_API", "wakatimeApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ubidots-api-key",
            "Ubidots API Key",
            Severity::Medium,
            r#"(?i)ubidots[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["ubidots_api", "UBIDOTS_API", "ubidotsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "raven-api-key",
            "Raven API Key",
            Severity::Medium,
            r#"(?i)raven[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["raven_api", "RAVEN_API", "ravenApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "guru-api-key",
            "Guru API Key",
            Severity::Medium,
            r#"(?i)guru[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["guru_api", "GURU_API", "guruApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "hive-api-key",
            "Hive API Key",
            Severity::Medium,
            r#"(?i)hive[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["hive_api", "HIVE_API", "hiveApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "technicalanalysis-api-key",
            "Technical Analysis API Key",
            Severity::Medium,
            r#"(?i)technical[_\-]?analysis[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["technicalanalysis_api", "TECHNICALANALYSIS_API", "technicalanalysisApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "impala-api-key",
            "Impala API Key",
            Severity::Medium,
            r#"(?i)impala[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["impala_api", "IMPALA_API", "impalaApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "unplugg-api-key",
            "Unplugg API Key",
            Severity::Medium,
            r#"(?i)unplugg[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["unplugg_api", "UNPLUGG_API", "unpluggApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloverly-api-key",
            "Cloverly API Key",
            Severity::Medium,
            r#"(?i)cloverly[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cloverly_api", "CLOVERLY_API", "cloverlyApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "flight-api-key",
            "Flight API Key",
            Severity::Medium,
            r#"(?i)flight[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["flight_api", "FLIGHT_API", "flightApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aviationstack-api-key",
            "AviationStack API Key",
            Severity::Medium,
            r#"(?i)aviationstack[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["aviationstack_api", "AVIATIONSTACK_API", "aviationstackApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "distribusion-api-key",
            "Distribusion API Key",
            Severity::Medium,
            r#"(?i)distribusion[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["distribusion_api", "DISTRIBUSION_API", "distribusionApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "words-api-key",
            "Words API Key",
            Severity::Low,
            r#"(?i)words[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["words_api", "WORDS_API", "wordsApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "holiday-api-key",
            "Holiday API Key",
            Severity::Low,
            r#"(?i)holiday[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["holiday_api", "HOLIDAY_API", "holidayApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "amadeus-api-key",
            "Amadeus API Key",
            Severity::High,
            r#"(?i)amadeus[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["amadeus_api", "AMADEUS_API", "amadeusApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "exchangerate-api-key",
            "Exchange Rate API Key",
            Severity::Low,
            r#"(?i)exchange[_\-]?rate[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["exchangerate_api", "EXCHANGERATE_API", "exchangerateApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "abstract-api-key",
            "Abstract API Key",
            Severity::Medium,
            r#"(?i)abstract[_\-]?(?:api[_\-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["abstract_api", "ABSTRACT_API", "abstractApi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pulumi-api-token",
            "Pulumi API Token",
            Severity::High,
            r"\bpul-[A-Za-z0-9]{40}\b",
            &["pul-"],
        )),

        // ── Phase 1: Additional Cloud Providers ──────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "huawei-cloud-access-key",
            "Huawei Cloud Access Key ID",
            Severity::High,
            r#"(?i)huawei[_-]?(?:cloud[_-]?)?(?:access[_-]?)?key[_-]?id\s*[:=]\s*['"]?(AK[A-Za-z0-9]{16,})['"]?"#,
            &["huawei_access_key", "HUAWEI_ACCESS_KEY", "huawei_cloud_key"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "huawei-cloud-secret-key",
            "Huawei Cloud Secret Access Key",
            Severity::Critical,
            r#"(?i)huawei[_-]?(?:cloud[_-]?)?secret[_-]?access[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
            &["huawei_secret", "HUAWEI_SECRET", "huawei_cloud_secret"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ovhcloud-api-key",
            "OVHcloud API Key",
            Severity::High,
            r#"(?i)ovh[_-]?(?:cloud[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["ovh_api_key", "OVH_API_KEY", "ovhcloud"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "ovhcloud-app-secret",
            "OVHcloud Application Secret",
            Severity::Critical,
            r#"(?i)ovh[_-]?(?:app[_-]?)?secret\s*[:=]\s*['"]?([A-Za-z0-9]{40,})['"]?"#,
            &["ovh_app_secret", "OVH_APP_SECRET", "ovhcloud_secret"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "backblaze-b2-key-id",
            "Backblaze B2 Key ID",
            Severity::High,
            r#"(?i)b2[_-]?(?:key[_-]?)?id\s*[:=]\s*['"]?([A-Za-z0-9]{20,})['"]?"#,
            &["b2_key_id", "B2_KEY_ID", "backblaze"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "backblaze-b2-application-key",
            "Backblaze B2 Application Key",
            Severity::Critical,
            r#"(?i)b2[_-]?(?:application[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40,})['"]?"#,
            &["b2_application_key", "B2_APPLICATION_KEY", "backblaze_app_key"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "wasabi-api-key",
            "Wasabi API Key",
            Severity::High,
            r#"(?i)wasabi[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["wasabi_api_key", "WASABI_API_KEY", "wasabi"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "minio-access-key",
            "MinIO Access Key",
            Severity::High,
            r#"(?i)minio[_-]?(?:access[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{16,})['"]?"#,
            &["minio_access_key", "MINIO_ACCESS_KEY", "minio"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "minio-secret-key",
            "MinIO Secret Key",
            Severity::Critical,
            r#"(?i)minio[_-]?secret[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{32,})['"]?"#,
            &["minio_secret_key", "MINIO_SECRET_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudflare-r2-token",
            "Cloudflare R2 API Token",
            Severity::High,
            r#"(?i)(?:cloudflare[_-]?)?r2[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["r2_token", "R2_TOKEN", "cloudflare_r2"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudflare-workers-ai-token",
            "Cloudflare Workers AI API Token",
            Severity::High,
            r#"(?i)cloudflare[_-]?workers[_-]?ai[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["workers_ai_token", "WORKERS_AI_TOKEN", "cf_workers_ai"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cloudflare-d1-token",
            "Cloudflare D1 API Token",
            Severity::High,
            r#"(?i)(?:cloudflare[_-]?)?d1[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["d1_token", "D1_TOKEN", "cloudflare_d1"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-sso-token",
            "AWS SSO (Identity Center) Token",
            Severity::High,
            r#"(?i)aws[_-]?sso[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["aws_sso_token", "AWS_SSO_TOKEN", "sso_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-rds-iam-auth-token",
            "AWS RDS IAM Authentication Token",
            Severity::High,
            r"amzn-rds-token://[A-Za-z0-9_\-./]+",
            &["amzn-rds-token://", "rds_iam_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "azure-arc-token",
            "Azure Arc Token",
            Severity::High,
            r#"(?i)azure[_-]?arc[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["azure_arc_token", "AZURE_ARC_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gcp-firebase-admin-key",
            "Firebase Admin SDK Private Key",
            Severity::Critical,
            r#"(?i)"type"\s*:\s*"service_account".*firebase"#,
            &["firebase", "FIREBASE", "firebase_admin"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gcp-cloud-run-invoker-token",
            "GCP Cloud Run Invoker Token",
            Severity::Medium,
            r#"(?i)cloud[_-]?run[_-]?(?:invoker[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?"#,
            &["cloud_run_token", "CLOUD_RUN_TOKEN", "cloud_run_invoker"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gcp-workload-identity-token",
            "GCP Workload Identity Token",
            Severity::Medium,
            r#"(?i)workload[_-]?identity[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?"#,
            &["workload_identity_token", "WORKLOAD_IDENTITY_TOKEN"],
        )),
        // ── Phase 1: SaaS & API Platforms ────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "cal-com-api-key",
            "Cal.com API Key",
            Severity::Medium,
            r#"(?i)cal[_-]?(?:com[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["cal_api_key", "CAL_API_KEY", "cal_com"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "resend-api-key",
            "Resend API Key",
            Severity::High,
            r"\bre_[A-Za-z0-9]{8,}\b",
            &["re_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "loops-api-key",
            "Loops.so API Key",
            Severity::Medium,
            r#"(?i)loops[_-]?(?:so[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["loops_api_key", "LOOPS_API_KEY", "loops"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "orb-api-key",
            "Orb API Key",
            Severity::Medium,
            r#"(?i)orb[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["orb_api_key", "ORB_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "metabase-session-token",
            "Metabase Session Token",
            Severity::High,
            r#"(?i)metabase[_-]?session[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["metabase_session", "METABASE_SESSION", "metabase"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "retool-token",
            "Retool API Token",
            Severity::High,
            r#"(?i)retool[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["retool_token", "RETOOL_TOKEN", "retool"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tooljet-token",
            "ToolJet API Token",
            Severity::Medium,
            r#"(?i)tooljet[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tooljet_token", "TOOLJET_TOKEN", "tooljet"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "appsmith-token",
            "Appsmith API Token",
            Severity::Medium,
            r#"(?i)appsmith[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["appsmith_token", "APPSSMITH_TOKEN", "appsmith"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "budibase-token",
            "Budibase API Token",
            Severity::Medium,
            r#"(?i)budibase[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["budibase_token", "BUDIBASE_TOKEN", "budibase"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "supabase-edge-function-key",
            "Supabase Edge Function Key",
            Severity::High,
            r#"(?i)supabase[_-]?edge[_-]?function[_-]?key\s*[:=]\s*['"]?(sb[_-]?[A-Za-z0-9_\-]{20,})['"]?"#,
            &["supabase_edge", "SUPABASE_EDGE", "sb_edge"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sst-console-token",
            "SST Console API Token",
            Severity::Medium,
            r#"(?i)sst[_-]?console[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sst_console", "SST_CONSOLE", "sst_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "wundergraph-token",
            "WunderGraph API Token",
            Severity::Medium,
            r#"(?i)wundergraph[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["wundergraph", "WUNDERGRAPH"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zuplo-api-key",
            "Zuplo API Key",
            Severity::Medium,
            r#"(?i)zuplo[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zuplo_api_key", "ZUPLO_API_KEY", "zuplo"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "kong-konnect-token",
            "Kong Konnect API Token",
            Severity::High,
            r#"(?i)kong[_-]?konnect[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["kong_konnect", "KONG_KONNECT", "konnect_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tyk-token",
            "Tyk API Token",
            Severity::Medium,
            r#"(?i)tyk[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tyk_token", "TYK_TOKEN", "tyk"],
        )),
        // ── Phase 1: AI/ML Providers ─────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "fireworks-ai-key",
            "Fireworks AI API Key",
            Severity::High,
            r#"(?i)fireworks[_-]?(?:ai[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fireworks_api_key", "FIREWORKS_API_KEY", "fireworks_ai"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "anyscale-api-key",
            "Anyscale API Key",
            Severity::High,
            r#"(?i)anyscale[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["anyscale_api_key", "ANYSCALE_API_KEY", "anyscale"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "modal-api-key",
            "Modal API Key",
            Severity::High,
            r#"(?i)modal[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["modal_api_key", "MODAL_API_KEY", "modal"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "runwayml-api-key",
            "RunwayML API Key",
            Severity::High,
            r#"(?i)runway[_-]?(?:ml[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["runwayml_api_key", "RUNWAYML_API_KEY", "runway"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "langsmith-api-key",
            "LangSmith (LangChain) API Key",
            Severity::High,
            r"\blsk_[A-Za-z0-9]{32,}\b",
            &["lsk_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "langfuse-public-key",
            "Langfuse Public Key",
            Severity::Medium,
            r"\bpk-lf-[A-Za-z0-9]{20,}\b",
            &["pk-lf-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "langfuse-secret-key",
            "Langfuse Secret Key",
            Severity::High,
            r"\bsk-lf-[A-Za-z0-9]{20,}\b",
            &["sk-lf-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "helicone-api-key",
            "Helicone API Key",
            Severity::Medium,
            r"\bsk-helicone-[A-Za-z0-9_\-]{20,}\b",
            &["sk-helicone-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "portkey-api-key",
            "Portkey API Key",
            Severity::Medium,
            r#"(?i)portkey[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["portkey_api_key", "PORTKEY_API_KEY", "portkey"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "braintrust-api-key",
            "Braintrust API Key",
            Severity::Medium,
            r#"(?i)braintrust[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["braintrust_api_key", "BRAINTRUST_API_KEY", "braintrust"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "weights-biases-api-key",
            "Weights & Biases API Key",
            Severity::High,
            r#"(?i)(?:wandb|weights[_-]?biases)[_\-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{40})['"]?"#,
            &["wandb_api_key", "WANDB_API_KEY", "weights_biases"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "comet-ml-api-key",
            "Comet ML API Key",
            Severity::High,
            r#"(?i)comet[_-]?(?:ml[_-]?)?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32,})['"]?"#,
            &["comet_ml_api_key", "COMET_ML_API_KEY", "comet_ml"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pinecone-api-key",
            "Pinecone API Key",
            Severity::High,
            r"\bpcsk_[A-Za-z0-9_\-]{40,}\b",
            &["pcsk_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "weaviate-api-key",
            "Weaviate API Key",
            Severity::High,
            r#"(?i)weaviate[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["weaviate_api_key", "WEAVIATE_API_KEY", "weaviate"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "qdrant-api-key",
            "Qdrant API Key",
            Severity::High,
            r#"(?i)qdrant[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["qdrant_api_key", "QDRANT_API_KEY", "qdrant"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "chroma-api-key",
            "Chroma API Key",
            Severity::Medium,
            r#"(?i)chroma[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["chroma_api_key", "CHROMA_API_KEY", "chroma"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "milvus-token",
            "Milvus API Token",
            Severity::Medium,
            r#"(?i)milvus[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["milvus_token", "MILVUS_TOKEN", "milvus"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pgvector-connection-string",
            "pgvector Connection String",
            Severity::High,
            r"(?i)postgres(?:ql)?://[^\s]+/[^\s]*pgvector",
            &["pgvector", "PGVECTOR"],
        )),
        // ── Phase 1: Security & DevOps ───────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "sonarcloud-token",
            "SonarCloud API Token",
            Severity::High,
            r"\bsca_[A-Za-z0-9]{40,}\b",
            &["sca_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "code-climate-token",
            "Code Climate API Token",
            Severity::Medium,
            r#"(?i)code[_-]?climate[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["code_climate", "CODE_CLIMATE", "codeclimate"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "deepsource-token",
            "DeepSource API Token",
            Severity::Medium,
            r#"(?i)deepsource[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["deepsource", "DEEPSOURCE", "deepsource_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "semgrep-api-token",
            "Semgrep API Token",
            Severity::Medium,
            r#"(?i)semgrep[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["semgrep_api_token", "SEMGREP_API_TOKEN", "semgrep"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "codeium-api-key",
            "Codeium API Key",
            Severity::Medium,
            r#"(?i)codeium[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["codeium_api_key", "CODEIUM_API_KEY", "codeium"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tabnine-api-key",
            "Tabnine API Key",
            Severity::Medium,
            r#"(?i)tabnine[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["tabnine_api_key", "TABNINE_API_KEY", "tabnine"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "sourcegraph-cody-token",
            "Sourcegraph Cody API Token",
            Severity::Medium,
            r#"(?i)sourcegraph[_-]?cody[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["sourcegraph_cody", "SOURCEGRAPH_CODY", "cody_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "greptile-api-key",
            "Greptile API Key",
            Severity::Medium,
            r#"(?i)greptile[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?(grpt_[A-Za-z0-9_\-]{20,})['"]?"#,
            &["greptile_api_key", "GREPTILE_API_KEY", "grpt_"],
        )),
        // ── Phase 1: Generic & Framework ─────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "npmrc-auth-token",
            ".npmrc Auth Token",
            Severity::High,
            r#"(?i)_authToken\s*=\s*['"]?(npm_[A-Za-z0-9]{36,})['"]?"#,
            &["_authToken", "npm_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pypirc-token",
            ".pypirc Token",
            Severity::High,
            r#"(?i)pypi[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?(pypi-[A-Za-z0-9]{60,})['"]?"#,
            &["pypirc", "pypi_token", ".pypirc"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "netrc-credentials",
            ".netrc Machine Credentials",
            Severity::High,
            r"(?i)machine\s+\S+\s+login\s+\S+\s+password\s+(\S+)",
            &["machine", "login", "password"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "aws-credentials-file",
            "AWS Credentials File Entry",
            Severity::Critical,
            r#"(?i)aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})"#,
            &["aws_secret_access_key ="],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fluxcd-notification-token",
            "FluxCD Notification Token",
            Severity::Medium,
            r#"(?i)flux(?:cd)?[_-]?(?:notification[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["fluxcd_token", "FLUXCD_TOKEN", "flux_notification"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "terraform-cloud-workspace-token",
            "Terraform Cloud Workspace Token",
            Severity::High,
            r#"(?i)terraform[_-]?cloud[_-]?workspace[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["terraform_cloud_workspace", "TERRAFORM_CLOUD_WORKSPACE"],
        )),
        // ── Phase 1: Crypto & Web3 ───────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "etherscan-api-key",
            "Etherscan API Key",
            Severity::Medium,
            r#"(?i)etherscan[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{34})['"]?"#,
            &["etherscan_api_key", "ETHERSCAN_API_KEY", "etherscan"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "bscscan-api-key",
            "BscScan API Key",
            Severity::Medium,
            r#"(?i)bscscan[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{34})['"]?"#,
            &["bscscan_api_key", "BSCSCAN_API_KEY", "bscscan"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "polygonscan-api-key",
            "Polygonscan API Key",
            Severity::Medium,
            r#"(?i)polygonscan[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{34})['"]?"#,
            &["polygonscan_api_key", "POLYGONSCAN_API_KEY", "polygonscan"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "arbiscan-api-key",
            "Arbiscan API Key",
            Severity::Medium,
            r#"(?i)arbiscan[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{34})['"]?"#,
            &["arbiscan_api_key", "ARBISCAN_API_KEY", "arbiscan"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "optimism-api-key",
            "Optimism (Optimistic Ethereum) API Key",
            Severity::Medium,
            r#"(?i)optimism[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{34})['"]?"#,
            &["optimism_api_key", "OPTIMISM_API_KEY", "optimism"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "covalent-api-key",
            "Covalent API Key",
            Severity::Medium,
            r"\bckt_[A-Za-z0-9]{30,}\b",
            &["ckt_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "chainlink-node-token",
            "Chainlink Node Token",
            Severity::High,
            r#"(?i)chainlink[_-]?node[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["chainlink_node_token", "CHAINLINK_NODE_TOKEN", "chainlink"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "thegraph-api-key",
            "The Graph API Key",
            Severity::Medium,
            r#"(?i)the[_-]?graph[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["the_graph_api_key", "THE_GRAPH_API_KEY", "thegraph"],
        )),
        // ── Phase 1: Database & Data ─────────────────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "clickhouse-connection-string",
            "ClickHouse Connection String",
            Severity::High,
            r"(?i)clickhouse://[^\s]+:[^\s]+@",
            &["clickhouse://", "CLICKHOUSE_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "duckdb-connection-string",
            "DuckDB Connection String",
            Severity::Medium,
            r"(?i)duckdb://[^\s]+:[^\s]+@",
            &["duckdb://", "DUCKDB_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "surrealdb-connection-string",
            "SurrealDB Connection String",
            Severity::Medium,
            r"(?i)surrealdb://[^\s]+:[^\s]+@",
            &["surrealdb://", "SURREALDB_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "tigergraph-connection-string",
            "TigerGraph Connection String",
            Severity::High,
            r"(?i)tigergraph://[^\s]+:[^\s]+@",
            &["tigergraph://", "TIGERGRAPH_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dremio-connection-string",
            "Dremio Connection String",
            Severity::Medium,
            r"(?i)dremio://[^\s]+:[^\s]+@",
            &["dremio://", "DREMIO_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "starrocks-connection-string",
            "StarRocks Connection String",
            Severity::Medium,
            r"(?i)starrocks://[^\s]+:[^\s]+@",
            &["starrocks://", "STARROCKS_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "doris-connection-string",
            "Apache Doris Connection String",
            Severity::Medium,
            r"(?i)doris://[^\s]+:[^\s]+@",
            &["doris://", "DORIS_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "questdb-connection-string",
            "QuestDB Connection String",
            Severity::Medium,
            r"(?i)questdb://[^\s]+:[^\s]+@",
            &["questdb://", "QUESTDB_URL"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "timescaledb-connection-string",
            "TimescaleDB Connection String",
            Severity::High,
            r"(?i)postgres(?:ql)?://[^\s]+:[^\s]+@.*timescale",
            &["timescaledb", "TIMESCALEDB", "timescale"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "materialize-connection-string",
            "Materialize Connection String",
            Severity::Medium,
            r"(?i)materialize://[^\s]+:[^\s]+@",
            &["materialize://", "MATERIALIZE_URL"],
        )),
        // ── Phase 1: Additional SaaS detectors ───────────────────────────
        Box::new(RegexDetector::with_prefilter(
            "contentful-token",
            "Contentful API Token",
            Severity::Medium,
            r#"(?i)contentful[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?(CFPAT-[A-Za-z0-9_\-]{40,})['"]?"#,
            &["CFPAT-", "contentful_token", "CONTENTFUL_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "asana-pat-v2",
            "Asana Personal Access Token (v2)",
            Severity::High,
            r#"(?i)asana[_-]?(?:personal[_-]?access[_-]?)?token\s*[:=]\s*['"]?([0-9]/[A-Za-z0-9]{30,})['"]?"#,
            &["asana_pat", "ASANA_PAT", "asana_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "algolia-api-key",
            "Algolia API Key",
            Severity::High,
            r#"(?i)algolia[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?"#,
            &["algolia_api_key", "ALGOLIA_API_KEY", "algolia"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "posthog-api-key-v2",
            "PostHog Project API Key",
            Severity::Medium,
            r"\bphc_[A-Za-z0-9]{43}\b",
            &["phc_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "launchdarkly-sdk-key",
            "LaunchDarkly SDK Key",
            Severity::High,
            r#"(?i)launchdarkly[_-]?(?:sdk[_-]?)?key\s*[:=]\s*['"]?(sdk-[A-Za-z0-9_\-]{20,})['"]?"#,
            &["sdk-", "launchdarkly", "LAUNCHDARKLY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "launchdarkly-api-key",
            "LaunchDarkly API Key",
            Severity::High,
            r#"(?i)launchdarkly[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?(api-[A-Za-z0-9_\-]{20,})['"]?"#,
            &["api-", "launchdarkly_api", "LAUNCHDARKLY_API"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "confluent-api-token",
            "Confluent Cloud API Token",
            Severity::High,
            r#"(?i)confluent[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9]{32,})['"]?"#,
            &["confluent_api_token", "CONFLUENT_API_TOKEN", "confluent"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "doppler-api-token",
            "Doppler API Token",
            Severity::High,
            r"\bdp\.pt\.[A-Za-z0-9]{40,}\b",
            &["dp.pt."],
        )),
        Box::new(RegexDetector::with_prefilter(
            "reddit-access-token-v2",
            "Reddit Access Token",
            Severity::Medium,
            r#"(?i)reddit[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["reddit_access_token", "REDDIT_ACCESS_TOKEN", "reddit_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "spotify-key-v2",
            "Spotify Web API Token",
            Severity::Medium,
            r"\bBQ[A-Za-z0-9_\-]{20,}\b",
            &["BQ"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "youtube-api-key-v2",
            "YouTube Data API Key",
            Severity::Medium,
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            &["AIza", "youtube_api_key", "YOUTUBE_API_KEY"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "razorpay-key-v2",
            "RazorPay Key ID",
            Severity::High,
            r"\brzp_[A-Za-z0-9]{20,}\b",
            &["rzp_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shopify-custom-app-token-v2",
            "Shopify Custom App Access Token (shpca_)",
            Severity::High,
            r"\bshpca_[A-Za-z0-9]{32}\b",
            &["shpca_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "shopify-private-app-token-v2",
            "Shopify Private App Access Token (shppa_)",
            Severity::High,
            r"\bshppa_[A-Za-z0-9]{32}\b",
            &["shppa_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "wepay-token",
            "WePay Access Token",
            Severity::High,
            r#"(?i)wepay[_-]?(?:access[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["wepay_access_token", "WEPAY_ACCESS_TOKEN", "wepay"],
        )),

        // ── Phase 1: More SaaS, DevOps, and Infrastructure ──────────────
        Box::new(RegexDetector::with_prefilter(
            "coda-api-key",
            "Coda API Key",
            Severity::Medium,
            r#"(?i)coda[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coda_api_key", "CODA_API_KEY", "coda"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gitbook-api-token",
            "GitBook API Token",
            Severity::Medium,
            r#"(?i)gitbook[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["gitbook_api_token", "GITBOOK_API_TOKEN", "gitbook"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "readme-api-token-v2",
            "ReadMe API Token (rdme_)",
            Severity::Medium,
            r"\brdme_[A-Za-z0-9]{30,}\b",
            &["rdme_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "stoplight-token",
            "Stoplight API Token",
            Severity::Medium,
            r#"(?i)stoplight[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["stoplight_api_token", "STOPLIGHT_API_TOKEN", "stoplight"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "postman-api-key-v2",
            "Postman API Key (PMAK)",
            Severity::High,
            r"\bPMAK[A-Za-z0-9_\-]{20,}\b",
            &["PMAK"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "insomnia-api-key",
            "Insomnia API Key",
            Severity::Medium,
            r#"(?i)insomnia[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["insomnia_api_key", "INSOMNIA_API_KEY", "insomnia"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "apidog-api-key",
            "Apidog API Key",
            Severity::Medium,
            r#"(?i)apidog[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["apidog_api_key", "APIDOG_API_KEY", "apidog"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "swaggerhub-api-key",
            "SwaggerHub API Key",
            Severity::Medium,
            r#"(?i)swaggerhub[_-]?(?:api[_-]?)?key\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["swaggerhub_api_key", "SWAGGERHUB_API_KEY", "swaggerhub"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "buildkite-api-token",
            "Buildkite API Token",
            Severity::High,
            r"\bbkua_[A-Za-z0-9_\-]{30,}\b",
            &["bkua_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "buildkite-agent-token",
            "Buildkite Agent Registration Token",
            Severity::Critical,
            r#"(?i)buildkite[_-]?agent[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["buildkite_agent_token", "BUILDKITE_AGENT_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "drone-ci-token",
            "Drone CI Token",
            Severity::Medium,
            r#"(?i)drone[_-]?ci[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["drone_ci_token", "DRONE_CI_TOKEN", "drone_token"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "woodpecker-ci-token",
            "Woodpecker CI Token",
            Severity::Medium,
            r#"(?i)woodpecker[_-]?ci[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["woodpecker_ci_token", "WOODPECKER_CI_TOKEN", "woodpecker"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "agola-ci-token",
            "Agola CI Token",
            Severity::Medium,
            r#"(?i)agola[_-]?ci[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["agola_ci_token", "AGOLA_CI_TOKEN", "agola"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gitea-token",
            "Gitea API Token",
            Severity::High,
            r#"(?i)gitea[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["gitea_token", "GITEA_TOKEN", "gitea"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gogs-token",
            "Gogs API Token",
            Severity::High,
            r#"(?i)gogs[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["gogs_token", "GOGS_TOKEN", "gogs"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "codeberg-token",
            "Codeberg API Token",
            Severity::Medium,
            r#"(?i)codeberg[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{40})['"]?"#,
            &["codeberg_token", "CODEBERG_TOKEN", "codeberg"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "jira-api-token",
            "Jira API Token",
            Severity::High,
            r#"(?i)jira[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["jira_api_token", "JIRA_API_TOKEN", "jira"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "confluence-api-token",
            "Confluence API Token",
            Severity::High,
            r#"(?i)confluence[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["confluence_api_token", "CONFLUENCE_API_TOKEN", "confluence"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "linear-webhook",
            "Linear Webhook URL",
            Severity::Medium,
            r"https://api\.linear\.app/[A-Za-z0-9_\-]{20,}",
            &["api.linear.app/", "linear_webhook"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "vercel-blob-token",
            "Vercel Blob Read/Write Token",
            Severity::Medium,
            r"\bvercel_blob_rw_[A-Za-z0-9_\-]{30,}\b",
            &["vercel_blob_rw_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "netlify-api-token",
            "Netlify API Token",
            Severity::High,
            r#"(?i)netlify[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?(nfp_[A-Za-z0-9]{40})['"]?"#,
            &["nfp_", "netlify_api_token", "NETLIFY_API_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "render-deploy-token",
            "Render Deploy Token",
            Severity::High,
            r"\brnd_[A-Za-z0-9_\-]{30,}\b",
            &["rnd_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "fly-io-token",
            "Fly.io API Token",
            Severity::High,
            r"\bFlyV1_[A-Za-z0-9_\-]{20,}\b",
            &["FlyV1_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "railway-token-v2",
            "Railway Project Token (rw_)",
            Severity::High,
            r"\brw_[A-Za-z0-9_\-]{30,}\b",
            &["rw_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "glitch-project-token",
            "Glitch Project Token",
            Severity::Medium,
            r#"(?i)glitch[_-]?project[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["glitch_project_token", "GLITCH_PROJECT_TOKEN", "glitch"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "deno-deploy-token",
            "Deno Deploy Access Token",
            Severity::Medium,
            r"\bddp_[A-Za-z0-9_\-]{30,}\b",
            &["ddp_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "scalingo-api-token",
            "Scalingo API Token",
            Severity::Medium,
            r#"(?i)scalingo[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["scalingo_api_token", "SCALINGO_API_TOKEN", "scalingo"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "northflank-api-token",
            "Northflank API Token",
            Severity::Medium,
            r#"(?i)northflank[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["northflank_api_token", "NORTHFLANK_API_TOKEN", "northflank"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "zeabur-token",
            "Zeabur API Token",
            Severity::Medium,
            r#"(?i)zeabur[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["zeabur_api_token", "ZAEBUR_API_TOKEN", "zeabur"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "coolify-api-token",
            "Coolify API Token",
            Severity::Medium,
            r#"(?i)coolify[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["coolify_api_token", "COOLIFY_API_TOKEN", "coolify"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "dokploy-api-token",
            "Dokploy API Token",
            Severity::Medium,
            r#"(?i)dokploy[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["dokploy_api_token", "DOKPLOY_API_TOKEN", "dokploy"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "easypanel-api-token",
            "Easypanel API Token",
            Severity::Medium,
            r#"(?i)easypanel[_-]?(?:api[_-]?)?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["easypanel_api_token", "EASYPANEL_API_TOKEN", "easypanel"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "openai-project-key",
            "OpenAI Project API Key (sk-proj-)",
            Severity::Critical,
            r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b",
            &["sk-proj-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "openai-organization-key",
            "OpenAI Organization API Key (sk-org-)",
            Severity::Critical,
            r"\bsk-org-[A-Za-z0-9_\-]{40,}\b",
            &["sk-org-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "openai-admin-key",
            "OpenAI Admin API Key (sk-admin-)",
            Severity::Critical,
            r"\bsk-admin-[A-Za-z0-9_\-]{40,}\b",
            &["sk-admin-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "anthropic-cli-key",
            "Anthropic CLI API Key (sk-ant-cli)",
            Severity::Critical,
            r"\bsk-ant-cli[A-Za-z0-9_\-]{40,}\b",
            &["sk-ant-cli"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "huggingface-write-token",
            "Hugging Face Write Token (hf_w)",
            Severity::High,
            r"\bhf_[A-Za-z0-9]{34}\b",
            &["hf_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "huggingface-org-token",
            "Hugging Face Organization Token",
            Severity::High,
            r#"(?i)hugging[_-]?face[_-]?org[_-]?token\s*[:=]\s*['"]?(hf_[A-Za-z0-9]{34})['"]?"#,
            &["huggingface_org_token", "HUGGINGFACE_ORG_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "github-codespaces-token",
            "GitHub Codespaces Token",
            Severity::High,
            r"\bghc_[A-Za-z0-9]{36,}\b",
            &["ghc_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "github-copilot-token",
            "GitHub Copilot Token",
            Severity::Medium,
            r"\bghc_copilot_[A-Za-z0-9_\-]{20,}\b",
            &["ghc_copilot_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gitlab-ci-job-token",
            "GitLab CI Job Token",
            Severity::Medium,
            r"\bglcbt-[A-Za-z0-9_\-]{20,}\b",
            &["glcbt-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "gitlab-deploy-token",
            "GitLab Deploy Token",
            Severity::High,
            r"\bgldt-[A-Za-z0-9_\-]{20,}\b",
            &["gldt-"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "npm-publish-token",
            "npm Publish Token (npm_pub_)",
            Severity::High,
            r"\bnpm_pub_[A-Za-z0-9]{36,}\b",
            &["npm_pub_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "pypi-upload-token",
            "PyPI Upload Token",
            Severity::High,
            r"\bpypi-AgEI[A-Za-z0-9_\-]{50,}\b",
            &["pypi-AgEI"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "crates-io-token",
            "crates.io API Token",
            Severity::High,
            r"\bcio_[A-Za-z0-9]{32,}\b",
            &["cio_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "go-proxy-token",
            "Go Proxy (Athens) Token",
            Severity::Medium,
            r#"(?i)go[_-]?proxy[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["go_proxy_token", "GO_PROXY_TOKEN", "athens"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "maven-central-token",
            "Maven Central Deploy Token",
            Severity::High,
            r#"(?i)maven[_-]?central[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#,
            &["maven_central_token", "MAVEN_CENTRAL_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "nuget-api-key",
            "NuGet API Key",
            Severity::High,
            r"\boy2[a-z0-9]{43,}\b",
            &["oy2"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "packagist-token",
            "Packagist API Token",
            Severity::Medium,
            r"\bpackagist_[A-Za-z0-9]{20,}\b",
            &["packagist_token", "PACKAGIST_TOKEN"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "composer-token",
            "Composer/Packagist Token (token_)",
            Severity::Medium,
            r"\btoken_[A-Za-z0-9]{20,}\b",
            &["token_"],
        )),
        Box::new(RegexDetector::with_prefilter(
            "cargo-registry-token",
            "Cargo Registry Token",
            Severity::High,
            r#"(?i)cargo[_-]?registry[_-]?token\s*[:=]\s*['"]?([A-Za-z0-9]{36,})['"]?"#,
            &["cargo_registry_token", "CARGO_REGISTRY_TOKEN"],
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

    // ── Communication & Collaboration ─────────────────────────────────

    #[test]
    fn test_discord_client_id_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "discord-client-id").unwrap();
        let matches = d.scan_line("discord_client_id = 123456789012345678");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_discord_client_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "discord-client-secret").unwrap();
        let matches = d.scan_line("discord_client_secret = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ms_teams_webhook_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "microsoft-teams-webhook").unwrap();
        let matches = d.scan_line("https://test.webhook.office.com/webhookb2/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/@aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/IncomingWebhook/abcdefghijklmnop/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_atlassian_jira_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "atlassian-jira-token").unwrap();
        let matches = d.scan_line("jira_api_token = abcdefghijklmnopqrstuvwxyz1234");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gitter_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "gitter-token").unwrap();
        let matches = d.scan_line("gitter_token = abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_webex_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "webex-token").unwrap();
        let matches = d.scan_line("webex_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_intercom_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "intercom-token").unwrap();
        let matches = d.scan_line("intercom_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_helpscout_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "helpscout-token").unwrap();
        let matches = d.scan_line("helpscout_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_helpcrunch_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "helpcrunch-token").unwrap();
        let matches = d.scan_line("helpcrunch_secret_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_canny_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "canny-token").unwrap();
        let matches = d.scan_line("canny_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pipedrive_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pipedrive-token").unwrap();
        let matches = d.scan_line("pipedrive_api_token = abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_beamer_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "beamer-token").unwrap();
        let matches = d.scan_line("beamer_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_frameio_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "frameio-token").unwrap();
        let key = format!("fio-{}", "A".repeat(64));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zeplin_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zeplin-token").unwrap();
        let matches = d.scan_line("zeplin_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_trello_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "trello-api-key").unwrap();
        let matches = d.scan_line("trello_api_key = abcdefghijklmnopqrstuvwxyz123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_asana_client_id_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "asana-client-id").unwrap();
        let matches = d.scan_line("asana_client_id = 1234567890123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_asana_client_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "asana-client-secret").unwrap();
        let matches = d.scan_line("asana_client_secret = abcdefghijklmnopqrstuvwxyz123456");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_asana_pat_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "asana-pat").unwrap();
        let matches = d.scan_line("asana_token = 1/abcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(matches.len(), 1);
    }

    // ── Payments & E-Commerce ──────────────────────────────────────────

    #[test]
    fn test_shopify_shared_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shopify-shared-secret").unwrap();
        let matches = d.scan_line("shpss_abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_shopify_custom_app_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shopify-custom-app-token").unwrap();
        let matches = d.scan_line("shpca_abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_shopify_private_app_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shopify-private-app-token").unwrap();
        let matches = d.scan_line("shppa_abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_paypal_oauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "paypal-oauth-token").unwrap();
        let matches = d.scan_line("paypal_token = Aabcdefghijklmnopqrstuvwxyz0123");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_paypal_client_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "paypal-client-secret").unwrap();
        let key = format!("paypal_client_secret = {}", "A".repeat(80));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_square_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "square-token").unwrap();
        let key = format!("sq{}atp-{}", "0", "a".repeat(22));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_square_app_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "square-app-token").unwrap();
        let key = format!("sq0csp-{}", "A".repeat(43));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_coinbase_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "coinbase-access-token").unwrap();
        let matches = d.scan_line("coinbase_access_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_razorpay_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "razorpay-key").unwrap();
        let matches = d.scan_line("razorpay_api_key = rzp_abcdefghijklmnopqrstuvwxyz0123");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_paystack_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "paystack-token").unwrap();
        let key = format!("sk_{}_{}", "live", "a".repeat(40));
        let line = format!("paystack {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_plaid_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "plaid-token").unwrap();
        let matches = d.scan_line("access-sandbox-abcdefghijklmnopqrstuvwxyz0123");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_plaid_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "plaid-key").unwrap();
        let matches = d.scan_line("plaid_client_id = abcdefghijklmnopqrstuvwxyz12");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flutterwave_secret_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flutterwave-secret-key").unwrap();
        let matches = d.scan_line("FLWSECK-abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flutterwave_encryption_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flutterwave-encryption-key").unwrap();
        let matches = d.scan_line("FLWSECK_TEST-abcdefghijkl");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_paddle_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "paddle-token").unwrap();
        let matches = d.scan_line("paddle_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fastspring_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fastspring-token").unwrap();
        let matches = d.scan_line("fastspring_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sellfy_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sellfy-token").unwrap();
        let matches = d.scan_line("sellfy_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_duffel_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "duffel-token").unwrap();
        let key = format!("duffel_{}", "A".repeat(43));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_easypost_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "easypost-api-token").unwrap();
        let key = format!("EZ{}", "A".repeat(54));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_easypost_test_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "easypost-test-api-token").unwrap();
        let key = format!("EZTK{}", "A".repeat(52));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_finicity_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "finicity-api-token").unwrap();
        let matches = d.scan_line("finicity_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_finicity_client_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "finicity-client-secret").unwrap();
        let matches = d.scan_line("finicity_client_secret = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_freshbooks_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "freshbooks-token").unwrap();
        let matches = d.scan_line("freshbooks_access_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gocardless_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "gocardless-token").unwrap();
        let matches = d.scan_line("gocardless_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_taxjar_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "taxjar-api-key").unwrap();
        let matches = d.scan_line("taxjar_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_etsy_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "etsy-api-key").unwrap();
        let matches = d.scan_line("etsy_api_key = abcdefghijklmnopqrstuvwxyz12");
        assert_eq!(matches.len(), 1);
    }

    // ── AI/ML Providers ────────────────────────────────────────────────

    #[test]
    fn test_anthropic_admin_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "anthropic-admin-key").unwrap();
        let key = format!("sk-ant-admin{}", "A".repeat(80));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_google_gemini_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "google-gemini-key").unwrap();
        let key = format!("AIza{}", "A".repeat(35));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cohere_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cohere-api-key").unwrap();
        let key = format!("cohere_api_key = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_replicate_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "replicate-api-token").unwrap();
        let key = format!("r8_{}", "A".repeat(37));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_stability_ai_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "stability-ai-key").unwrap();
        let key = format!("stability_api_key = sk-{}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_assemblyai_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "assemblyai-key").unwrap();
        let matches = d.scan_line("assemblyai_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clarifai_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clarifai-key").unwrap();
        let matches = d.scan_line("clarifai_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_openrouter_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "openrouter-key").unwrap();
        let key = format!("sk-or-{}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_together_ai_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "together-ai-key").unwrap();
        let matches = d.scan_line("together_ai_api_key = abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_perplexity_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "perplexity-api-key").unwrap();
        let key = format!("pplx-{}", "A".repeat(48));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mistral_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mistral-api-key").unwrap();
        let matches = d.scan_line("mistral_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_groq_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "groq-api-key").unwrap();
        let key = format!("gsk_{}", "A".repeat(52));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_deepseek_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "deepseek-api-key").unwrap();
        let key = format!("deepseek_api_key = sk-{}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_elevenlabs_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "elevenlabs-api-key").unwrap();
        let matches = d.scan_line("elevenlabs_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    // ── Email & Messaging ──────────────────────────────────────────────

    #[test]
    fn test_postmark_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "postmark-token").unwrap();
        let key = format!("po_-{}", "A".repeat(36));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mailjet_basic_auth_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mailjet-basic-auth").unwrap();
        let key = format!("MJ{}", "A".repeat(30));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mailjet_sms_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mailjet-sms-token").unwrap();
        let matches = d.scan_line("mailjet_sms_token = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_brevo_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "brevo-token").unwrap();
        let key = format!("xkeysib-{}", "A".repeat(64));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_elastic_email_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "elastic-email-key").unwrap();
        let matches = d.scan_line("elastic_email_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pepipost_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pepipost-token").unwrap();
        let matches = d.scan_line("pepipost_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mailmodo_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mailmodo-token").unwrap();
        let matches = d.scan_line("mailmodo_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_verimail_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "verimail-token").unwrap();
        let matches = d.scan_line("verimail_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zerobounce_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zerobounce-token").unwrap();
        let matches = d.scan_line("zerobounce_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mailboxlayer_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mailboxlayer-token").unwrap();
        let matches = d.scan_line("mailboxlayer_access_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_d7network_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "d7network-token").unwrap();
        let matches = d.scan_line("d7network_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sinch_message_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sinch-message-token").unwrap();
        let matches = d.scan_line("sinch_message_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_messagebird_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "messagebird-token").unwrap();
        let matches = d.scan_line("messagebird_api_key = abcdefghijklmnopqrstuvwxy");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_vonage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "vonage-api-key").unwrap();
        let matches = d.scan_line("vonage_api_key = abcdefgh");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_plivo_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "plivo-token").unwrap();
        let matches = d.scan_line("plivo_auth_token = abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_postman_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "postman-api-key").unwrap();
        let key = format!("PMAK-{}", "A".repeat(59));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pubnub_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pubnub-key").unwrap();
        let matches = d.scan_line("pubnub_sub_key = sub-c-abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pusher_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pusher-key").unwrap();
        let matches = d.scan_line("pusher_channel_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pushbullet_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pushbullet-api-key").unwrap();
        let matches = d.scan_line("pushbullet_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_doppler_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "doppler-token").unwrap();
        let key = format!("dp.pt.{}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    // ── Monitoring & Observability ─────────────────────────────────────

    #[test]
    fn test_datadog_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "datadog-access-token").unwrap();
        let key = format!("dt0{}.{}", "A".repeat(23), "B".repeat(64));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_new_relic_personal_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "new-relic-personal-api-key").unwrap();
        let key = format!("NRAK{}", "A".repeat(22));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sentry_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sentry-token").unwrap();
        let key = format!("sntrys_{}", "A".repeat(64));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sumologic_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sumologic-key").unwrap();
        let matches = d.scan_line("sumologic_access_key = abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_splunk_observability_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "splunk-observability-token").unwrap();
        let key = format!("SPL{}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_appoptics_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "appoptics-token").unwrap();
        let matches = d.scan_line("appoptics_api_token = abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_airbrake_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "airbrake-key").unwrap();
        let matches = d.scan_line("airbrake_project_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_logdna_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "logdna-key").unwrap();
        let matches = d.scan_line("logdna_ingestion_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_loggly_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "loggly-token").unwrap();
        let matches = d.scan_line("loggly_customer_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_better_stack_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "better-stack-key").unwrap();
        let matches = d.scan_line("better_stack_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_statuspage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "statuspage-api-key").unwrap();
        let matches = d.scan_line("statuspage_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_uptimerobot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "uptimerobot-api-key").unwrap();
        let key = format!("u{}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pingdom_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pingdom-token").unwrap();
        let matches = d.scan_line("pingdom_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    // ── Analytics & Product ────────────────────────────────────────────

    #[test]
    fn test_posthog_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "posthog-api-key").unwrap();
        let key = format!("phc_{}", "A".repeat(43));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_amplitude_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "amplitude-api-key").unwrap();
        let matches = d.scan_line("amplitude_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_segment_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "segment-api-key").unwrap();
        let matches = d.scan_line("segment_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mixpanel_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mixpanel-token").unwrap();
        let matches = d.scan_line("mixpanel_project_token = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_heap_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "heap-api-key").unwrap();
        let matches = d.scan_line("heap_analytics_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pendo_integration_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pendo-integration-key").unwrap();
        let matches = d.scan_line("pendo_integration_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_keenio_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "keenio-key").unwrap();
        let key = format!("keen_io_api_key = {}", "A".repeat(64));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fathom_analytics_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fathom-analytics-key").unwrap();
        let matches = d.scan_line("fathom_analytics_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_plausible_analytics_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "plausible-analytics-key").unwrap();
        let matches = d.scan_line("plausible_analytics_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hotjar_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hotjar-token").unwrap();
        let matches = d.scan_line("hotjar_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fullstory_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fullstory-token").unwrap();
        let matches = d.scan_line("full_story_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bitly_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitly-access-token").unwrap();
        let matches = d.scan_line("bitly_access_token = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_calendly_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "calendly-api-key").unwrap();
        let matches = d.scan_line("calendly_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_calendarific_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "calendarific-token").unwrap();
        let matches = d.scan_line("calendarific_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_appfollow_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "appfollow-token").unwrap();
        let matches = d.scan_line("appfollow_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_appcues_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "appcues-token").unwrap();
        let matches = d.scan_line("appcues_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    // ── Auth & Identity ────────────────────────────────────────────────

    #[test]
    fn test_auth0_management_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "auth0-management-token").unwrap();
        let key = format!("auth0_management_api_token = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_auth0_oauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "auth0-oauth-token").unwrap();
        let key = format!("auth0_oauth_token = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_onelogin_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "onelogin-token").unwrap();
        let key = format!("onelogin_api_token = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_jumpcloud_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "jumpcloud-token").unwrap();
        let key = format!("jumpcloud_api_token = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_authress_service_client_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "authress-service-client-key").unwrap();
        let key = format!("sc_{}.{}", "A".repeat(20), "B".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_keycloak_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "keycloak-token").unwrap();
        let matches = d.scan_line("keycloak_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fusionauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fusionauth-token").unwrap();
        let matches = d.scan_line("fusion_auth_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_stytch_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "stytch-token").unwrap();
        let matches = d.scan_line("stytch_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clerk_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clerk-token").unwrap();
        let key = format!("clerk_api_token = sk_{}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_workos_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "workos-token").unwrap();
        let matches = d.scan_line("work_os_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_supabase_anon_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "supabase-anon-key").unwrap();
        let key = format!("eyJ{}.eyJ{}.{}", "A".repeat(20), "B".repeat(20), "C".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_firebase_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "firebase-token").unwrap();
        let matches = d.scan_line("firebase_auth_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_firebase_fcm_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "firebase-fcm-key").unwrap();
        let key = format!("AAAA{}", "A".repeat(60));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kubeconfig_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kubeconfig").unwrap();
        let key = format!("client_key_data: {}", "A".repeat(100));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hashicorp_vault_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hashicorp-vault-token").unwrap();
        let key = format!("hvs.{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_onepassword_secret_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "onepassword-secret-key").unwrap();
        let matches = d.scan_line("a3-ABC123-ABC123-ABC123-ABC123-ABC123");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_onepassword_service_account_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "onepassword-service-account-token").unwrap();
        let key = format!("ops_{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    // ── Hosting & Backend ──────────────────────────────────────────────

    #[test]
    fn test_wpengine_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "wpengine-token").unwrap();
        let matches = d.scan_line("wp_engine_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fastly_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fastly-api-key").unwrap();
        let matches = d.scan_line("fastly_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_akamai_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "akamai-token").unwrap();
        let matches = d.scan_line("akamai_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_equinix_oauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "equinix-oauth-token").unwrap();
        let matches = d.scan_line("equinix_oauth_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flyio_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flyio-token").unwrap();
        let key = format!("fly{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_railway_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "railway-token").unwrap();
        let matches = d.scan_line("railway_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_render_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "render-token").unwrap();
        let key = format!("rnd_{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_koyeb_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "koyeb-token").unwrap();
        let matches = d.scan_line("koyeb_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    // ── Social & Developer Platforms ───────────────────────────────────

    #[test]
    fn test_facebook_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "facebook-access-token").unwrap();
        let key = format!("EAAD{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_facebook_oauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "facebook-oauth-token").unwrap();
        let key = format!("facebook_oauth_token = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_figma_personal_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "figma-personal-access-token").unwrap();
        let key = format!("figd_{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pypi_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pypi-token").unwrap();
        let key = format!("pypi-AgEI{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_spotify_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "spotify-key").unwrap();
        let matches = d.scan_line("spotify_api_key = abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_youtube_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "youtube-api-key").unwrap();
        let key = format!("AIza{}", "A".repeat(35));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_twitch_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "twitch-access-token").unwrap();
        let key = format!("twitch_access_token = {}", "A".repeat(30));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flickr_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flickr-access-token").unwrap();
        let matches = d.scan_line("flickr_access_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dropbox_api_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dropbox-api-secret").unwrap();
        let matches = d.scan_line("dropbox_api_secret = abcdefghijklmno");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dropbox_long_lived_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dropbox-long-lived-token").unwrap();
        let key = format!("sl.{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dropbox_short_lived_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dropbox-short-lived-token").unwrap();
        let key = format!("sl.{}.{}", "A".repeat(20), "B".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_reddit_client_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "reddit-client-secret").unwrap();
        let matches = d.scan_line("reddit_client_secret = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_reddit_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "reddit-access-token").unwrap();
        let matches = d.scan_line("reddit_access_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_instagram_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "instagram-access-token").unwrap();
        let key = format!("instagram_access_token = IG{}", "A".repeat(30));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pinterest_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pinterest-token").unwrap();
        let matches = d.scan_line("pinterest_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tiktok_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tiktok-access-token").unwrap();
        let matches = d.scan_line("tiktok_access_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zoom_api_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zoom-api-secret").unwrap();
        let matches = d.scan_line("zoom_api_secret = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zapier_webhook_url_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zapier-webhook-url").unwrap();
        let matches = d.scan_line("https://hooks.zapier.com/hooks/catch/123456/abc123");
        assert_eq!(matches.len(), 1);
    }

    // ── Database & Data ────────────────────────────────────────────────

    #[test]
    fn test_jdbc_connection_string_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "jdbc-connection-string").unwrap();
        let matches = d.scan_line("jdbc:postgresql://user:pass@localhost:5432/db");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sqlserver_connection_string_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sqlserver-connection-string").unwrap();
        let matches = d.scan_line("server=localhost;user id=admin;password=secretpass123");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_elasticsearch_connection_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "elasticsearch-connection").unwrap();
        let matches = d.scan_line("https://user:pass@elastic.example.com:9200");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_influxdb_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "influxdb-token").unwrap();
        let matches = d.scan_line("influx_db_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_couchbase_connection_string_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "couchbase-connection-string").unwrap();
        let matches = d.scan_line("couchbase://user:pass@localhost:8091");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cassandra_connection_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cassandra-connection").unwrap();
        let matches = d.scan_line("cassandra_password = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_neo4j_connection_string_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "neo4j-connection-string").unwrap();
        let matches = d.scan_line("neo4j://user:pass@localhost:7687");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_supabase_db_connection_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "supabase-db-connection").unwrap();
        let matches = d.scan_line("postgresql://user:pass@db.abcdefgh.supabase.co:5432/postgres");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_planetscale_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "planetscale-token").unwrap();
        let key = format!("pscale_{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_neon_database_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "neon-database-token").unwrap();
        let matches = d.scan_line("neon_database_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_turso_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "turso-token").unwrap();
        let matches = d.scan_line("turso_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_convex_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "convex-token").unwrap();
        let matches = d.scan_line("convex_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    // ── DevOps & Infrastructure ────────────────────────────────────────

    #[test]
    fn test_age_secret_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "age-secret-key").unwrap();
        let key = format!("AGE-SECRET-KEY-1{}", "A".repeat(58));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kubernetes_secret_manifest_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kubernetes-secret-manifest").unwrap();
        let manifest = "kind: Secret\nmetadata:\n  name: my-secret\ndata:\n  password: c2VjcmV0cGFzc3dvcmQxMjM=";
        let matches = d.scan_line(manifest);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hashicorp_terraform_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hashicorp-terraform-token").unwrap();
        let key = format!("terraform_cloud_token = {}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ansible_vault_password_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ansible-vault-password").unwrap();
        let matches = d.scan_line("ansible_vault_password = mypassword123");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_docker_registry_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "docker-registry-token").unwrap();
        let key = format!("docker_registry_token = {}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_harbor_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "harbor-token").unwrap();
        let matches = d.scan_line("harbor_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nexus_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "nexus-token").unwrap();
        let matches = d.scan_line("nexus_repo_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_confluent_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "confluent-access-token").unwrap();
        let matches = d.scan_line("confluent_cloud_access_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_confluent_secret_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "confluent-secret-key").unwrap();
        let matches = d.scan_line("confluent_cloud_secret_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_databricks_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "databricks-token").unwrap();
        let key = format!("dapi{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_snowflake_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "snowflake-token").unwrap();
        let matches = d.scan_line("snowflake_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dynatrace_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dynatrace-api-token").unwrap();
        let key = format!("dt0c01{}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_launchdarkly_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "launchdarkly-key").unwrap();
        let matches = d.scan_line("launchdarkly_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_configcat_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "configcat-key").unwrap();
        let matches = d.scan_line("configcat_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flagsmith_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flagsmith-key").unwrap();
        let matches = d.scan_line("flagsmith_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    // ── Security & API Services ────────────────────────────────────────

    #[test]
    fn test_shodan_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shodan-api-key").unwrap();
        let key = format!("shodan_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_abuseipdb_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "abuseipdb-key").unwrap();
        let key = format!("abuseipdb_api_key = {}", "A".repeat(80));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_alienvault_otx_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "alienvault-otx-key").unwrap();
        let key = format!("alienvault_otx_api_key = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_virustotal_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "virustotal-api-key").unwrap();
        let key = format!("virustotal_api_key = {}", "A".repeat(64));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hunterio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hunterio-api-key").unwrap();
        let key = format!("hunter_io_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ipstack_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ipstack-key").unwrap();
        let key = format!("ipstack_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_maxmind_license_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "maxmind-license-key").unwrap();
        let matches = d.scan_line("maxmind_license_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cloudsight_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cloudsight-key").unwrap();
        let key = format!("cloudsight_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rapidapi_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "rapidapi-key").unwrap();
        let key = format!("rapidapi_key = {}", "A".repeat(50));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scrapingbee_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scrapingbee-key").unwrap();
        let key = format!("scrapingbee_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ipinfo_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ipinfo-token").unwrap();
        let key = format!("ipinfo_io_token = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    // ── Maps & Location ────────────────────────────────────────────────

    #[test]
    fn test_google_maps_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "google-maps-api-key").unwrap();
        let key = format!("AIza{}", "A".repeat(35));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mapbox_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mapbox-token").unwrap();
        let key = format!("pk.{}", "A".repeat(60));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mapquest_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mapquest-key").unwrap();
        let key = format!("mapquest_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_here_maps_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "here-maps-key").unwrap();
        let key = format!("here_maps_api_key = {}", "A".repeat(43));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_opencage_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "opencage-key").unwrap();
        let key = format!("opencage_geocoder_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    // ── CRM & Business ─────────────────────────────────────────────────

    #[test]
    fn test_hubspot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hubspot-api-key").unwrap();
        let key = format!("hubspot_api_key = {}", "A".repeat(36));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hubspot_oauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hubspot-oauth-token").unwrap();
        let key = format!("hubspot_oauth_token = {}", "A".repeat(30));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_salesforce_oauth2_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "salesforce-oauth2-token").unwrap();
        let matches = d.scan_line("salesforce_oauth2_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zendesk_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zendesk-api-token").unwrap();
        let key = format!("zendesk_api_token = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_elastic_path_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "elastic-path-token").unwrap();
        let matches = d.scan_line("elastic_path_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_buttercms_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "buttercms-token").unwrap();
        let key = format!("buttercms_api_token = {}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_contentful_delivery_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "contentful-delivery-token").unwrap();
        let key = format!("contentful_delivery_api_token = {}", "A".repeat(43));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_contentful_personal_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "contentful-personal-access-token").unwrap();
        let key = format!("CFPAT-{}", "A".repeat(43));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sanity_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sanity-api-token").unwrap();
        let key = format!("sanity_api_token = {}", "A".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_storyblok_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "storyblok-token").unwrap();
        let matches = d.scan_line("storyblok_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_strapi_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "strapi-api-token").unwrap();
        let matches = d.scan_line("strapi_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_airtable_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "airtable-api-key").unwrap();
        let key = format!("key{}", "A".repeat(16));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_airtable_personal_access_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "airtable-personal-access-token").unwrap();
        let key = format!("pat{}", "A".repeat(16));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_airtable_oauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "airtable-oauth-token").unwrap();
        let matches = d.scan_line("airtable_oauth_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_algolia_admin_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "algolia-admin-key").unwrap();
        let key = format!("algolia_admin_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_lokalise_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "lokalise-token").unwrap();
        let matches = d.scan_line("lokalise_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    // ── Crypto & Web3 ──────────────────────────────────────────────────

    #[test]
    fn test_bitcoin_private_key_wif_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitcoin-private-key-wif").unwrap();
        let key = format!("5K{}", "A".repeat(50));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ethereum_private_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ethereum-private-key").unwrap();
        let key = format!("0x{}", "a".repeat(64));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_solana_private_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "solana-private-key").unwrap();
        let key = "1".repeat(88);
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_infura_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "infura-api-key").unwrap();
        let key = format!("infura_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_alchemy_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "alchemy-api-key").unwrap();
        let key = format!("alchemy_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_moralis_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "moralis-api-key").unwrap();
        let key = format!("moralis_api_key = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_quicknode_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "quicknode-token").unwrap();
        let matches = d.scan_line("quicknode_api_token = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bitfinex_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitfinex-api-key").unwrap();
        let matches = d.scan_line("bitfinex_api_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bittrex_access_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bittrex-access-key").unwrap();
        let matches = d.scan_line("bittrex_access_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bittrex_secret_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bittrex-secret-key").unwrap();
        let matches = d.scan_line("bittrex_secret_key = abcdefghijklmnopqrst");
        assert_eq!(matches.len(), 1);
    }

    // ── Generic & Framework-Specific ───────────────────────────────────

    #[test]
    fn test_curl_auth_string_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "curl-auth-string").unwrap();
        let matches = d.scan_line("curl -u myuser:mypassword123 https://example.com");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_uri_embedded_credentials_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "uri-embedded-credentials").unwrap();
        let matches = d.scan_line("https://user:password123@internal.example.com");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_generic_oauth_client_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "generic-oauth-client-secret").unwrap();
        let key = format!("oauth_client_secret = {}", "A".repeat(20));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_env_file_secret_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "env-file-secret").unwrap();
        let key = format!("API_KEY = {}", "A".repeat(32));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_firebase_config_web_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "firebase-config-web").unwrap();
        let api_key = format!("AIza{}", "A".repeat(35));
        let line = format!("firebaseConfig = {{ apiKey: \"{}\" }}", api_key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Communication & Messaging (TruffleHog) ─────────────────────────

    #[test]
    fn test_twilio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "twilio-api-key").unwrap();
        let key = format!("SK{}", "a".repeat(32));
        let line = format!("twilio_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_line_messaging_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "line-messaging-api-token").unwrap();
        let token = "a".repeat(30);
        let line = format!("line_messaging_api_token = {}", token);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_line_notify_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "line-notify-token").unwrap();
        let token = "a".repeat(43);
        let line = format!("line_notify_token = {}", token);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mattermost_personal_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mattermost-personal-token").unwrap();
        let token = "a".repeat(26);
        let line = format!("mattermost_personal_token = {}", token);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_wechat_app_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "wechat-app-key").unwrap();
        let key = "a".repeat(32);
        let line = format!("wechat_app_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kakaotalk_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kakaotalk-api-key").unwrap();
        let key = "a".repeat(32);
        let line = format!("kakao_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_liveagent_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "liveagent-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("liveagent_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_front_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "front-api-key").unwrap();
        let key = format!("front_{}", "a".repeat(25));
        let line = format!("front_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ringcentral_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ringcentral-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ringcentral_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_telesign_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "telesign-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("telesign_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_teamviewer_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "teamviewer-api-token").unwrap();
        let token = "a".repeat(25);
        let line = format!("teamviewer_api_token = {}", token);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cometchat_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cometchat-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("cometchat_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mesibo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mesibo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("mesibo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bulbul_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bulbul-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bulbul_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tyntec_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tyntec-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("tyntec_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kaleyra_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kaleyra-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("kaleyra_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_onbuka_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "onbuka-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("onbuka_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clicksend_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clicksend-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("clicksend_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clockwork_sms_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clockwork-sms-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("clockwork_sms_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sms_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sms-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("sms_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bombbomb_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bombbomb-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bombbomb_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dfuse_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dfuse-api-key").unwrap();
        let key = format!("server_{}", "a".repeat(25));
        let line = format!("dfuse_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_apifonica_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "apifonica-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("apifonica_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mandrill_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mandrill-api-key").unwrap();
        let key = "a".repeat(22);
        let line = format!("mandrill_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sparkpost_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sparkpost-api-key").unwrap();
        let key = "a".repeat(64);
        let line = format!("sparkpost_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mailerlite_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mailerlite-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("mailerlite_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_convertkit_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "convertkit-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("convertkit_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_omnisend_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "omnisend-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("omnisend_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_customerio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "customerio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("customer.io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_moosend_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "moosend-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("moosend_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dotdigital_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dotdigital-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("dotdigital_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dyspatch_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dyspatch-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("dyspatch_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_postageapp_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "postageapp-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("postageapp_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nicereply_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "nicereply-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("nicereply_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_autopilot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "autopilot-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("autopilot_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_airship_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "airship-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("airship_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── CRM & Sales (TruffleHog) ───────────────────────────────────────

    #[test]
    fn test_freshworks_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "freshworks-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("freshworks_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_close_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "close-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("close_crm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_copper_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "copper-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("copper_crm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_streak_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "streak-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("streak_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_groovehq_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "groovehq-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("groovehq_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_getgist_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "getgist-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("getgist_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_autoklose_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "autoklose-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("autoklose_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_salesflare_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "salesflare-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("salesflare_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_salesblink_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "salesblink-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("salesblink_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_salescookie_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "salescookie-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("salescookie_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_metrilo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "metrilo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("metrilo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_revampcrm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "revampcrm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("revampcrm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_karmacrm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "karmacrm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("karma_crm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_lessannoyingcrm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "lessannoyingcrm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("less_annoying_crm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nethunt_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "nethunt-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("nethunt_crm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nimble_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "nimble-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("nimble_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_apptivo_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "apptivo-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("apptivo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_capsule_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "capsule-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("capsule_crm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_insightly_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "insightly-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("insightly_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kylas_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kylas-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("kylas_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_onepagecrm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "onepagecrm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("onepagecrm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_prospectcrm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "prospectcrm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("prospectcrm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_reallysimplesystems_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "reallysimplesystems-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("really_simple_systems_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_centralstation_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "centralstation-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("central_station_crm_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_teamgate_crm_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "teamgate-crm-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("teamgate_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_axonaut_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "axonaut-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("axonaut_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flowflu_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flowflu-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("flowflu_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clientary_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clientary-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("clientary_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clinchpad_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clinchpad-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("clinchpad_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_companyhub_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "companyhub-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("companyhub_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_campayn_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "campayn-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("campayn_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hiveage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hiveage-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("hiveage_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_billomat_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "billomat-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("billomat_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_alegra_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "alegra-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("alegra_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_loyverse_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "loyverse-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("loyverse_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_commercejs_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "commercejs-api-key").unwrap();
        let key = format!("pk_{}", "a".repeat(25));
        let line = format!("commercejs_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_snipcart_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "snipcart-api-key").unwrap();
        let key = format!("SNIP_{}", "a".repeat(25));
        let line = format!("snipcart_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_partnerstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "partnerstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("partnerstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_vouchery_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "vouchery-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("vouchery_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_monday_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "monday-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("monday_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_smartsheets_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "smartsheets-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("smartsheets_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_wrike_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "wrike-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("wrike_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_apollo_io_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "apollo-io-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("apollo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_uplead_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "uplead-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("uplead_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rocketreach_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "rocketreach-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("rocketreach_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clearbit_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clearbit-api-key").unwrap();
        let key = format!("cb_{}", "a".repeat(25));
        let line = format!("clearbit_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_brandfetch_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "brandfetch-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("brandfetch_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_leadfeeder_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "leadfeeder-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("leadfeeder_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_getemail_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "getemail-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("getemail_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_getemails_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "getemails-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("getemails_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_skrappio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "skrappio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("skrappio_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_powrbot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "powrbot-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("powrbot_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Project Management & Productivity (TruffleHog) ─────────────────

    #[test]
    fn test_clickup_personal_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clickup-personal-token").unwrap();
        let token = "a".repeat(25);
        let line = format!("clickup_token = {}", token);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_todoist_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "todoist-api-token").unwrap();
        let token = "a".repeat(25);
        let line = format!("todoist_token = {}", token);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_shortcut_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shortcut-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("shortcut_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tmetric_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tmetric-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("tmetric_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clockify_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clockify-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("clockify_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_everhour_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "everhour-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("everhour_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_harvest_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "harvest-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("harvest_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_humanity_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "humanity-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("humanity_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_toggl_track_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "toggl-track-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("toggl_track_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_runrunit_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "runrunit-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("runrunit_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_workstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "workstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("workstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_easyinsight_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "easyinsight-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("easyinsight_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dovico_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dovico-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("dovico_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mavenlink_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mavenlink-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("mavenlink_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_float_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "float-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("float_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_daily_co_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "daily-co-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("daily_co_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tly_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tly-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("t.ly_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rebrandly_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "rebrandly-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("rebrandly_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_timezone_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "timezone-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("timezone_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_jotform_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "jotform-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("jotform_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Forms & Survey Platforms (TruffleHog) ──────────────────────────

    #[test]
    fn test_typeform_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "typeform-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("typeform_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_surveysparrow_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "surveysparrow-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("surveysparrow_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_survicate_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "survicate-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("survicate_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_delighted_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "delighted-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("delighted_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_feedier_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "feedier-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("feedier_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zonka_feedback_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zonka-feedback-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("zonka_feedback_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_satismeter_project_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "satismeter-project-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("satismeter_project_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_satismeter_write_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "satismeter-write-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("satismeter_write_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_simplesat_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "simplesat-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("simplesat_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_surveyanyplace_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "surveyanyplace-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("surveyanyplace_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_surveybot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "surveybot-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("surveybot_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_qualaroo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "qualaroo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("qualaroo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_customerguru_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "customerguru-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("customerguru_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_abyssale_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "abyssale-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("abyssale_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_magnetic_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "magnetic-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("magnetic_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_refiner_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "refiner-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("refiner_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_simvoly_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "simvoly-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("simvoly_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_checkmarket_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "checkmarket-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("checkmarket_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_webengage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "webengage-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("webengage_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Financial & Trading APIs (TruffleHog) ──────────────────────────

    #[test]
    fn test_twelve_data_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "twelve-data-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("twelve_data_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fixer_io_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fixer-io-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("fixer_io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_alpha_vantage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "alpha-vantage-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("alpha_vantage_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tradier_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tradier-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("tradier_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_finnhub_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "finnhub-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("finnhub_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tiingo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tiingo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("tiingo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_finage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "finage-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("finage_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_iex_cloud_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "iex-cloud-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("iex_cloud_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_intrinio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "intrinio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("intrinio_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_financial_modeling_prep_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "financial-modeling-prep-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("financial_modeling_prep_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nasdaq_data_link_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "nasdaq-data-link-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("nasdaq_data_link_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_qubole_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "qubole-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("qubole_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_enigma_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "enigma-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("enigma_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_datagov_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "datagov-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("data_gov_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_stockdata_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "stockdata-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("stockdata_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_marketstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "marketstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("marketstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_commodities_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "commodities-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("commodities_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_baremetrics_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "baremetrics-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("baremetrics_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dwolla_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dwolla-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("dwolla_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_wepay_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "wepay-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("wepay_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_checkout_com_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "checkout-com-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("checkout_com_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_paymongo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "paymongo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("paymongo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_avalara_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "avalara-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("avalara_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_carbon_interface_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "carbon-interface-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("carbon_interface_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_currency_layer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "currency-layer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("currency_layer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_exchange_rates_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "exchange-rates-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("exchange_rates_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_currencyscoop_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "currencyscoop-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("currencyscoop_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_currencyfreaks_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "currencyfreaks-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("currencyfreaks_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_country_layer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "country-layer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("country_layer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fxmarket_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fxmarket-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("fx_market_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_currencycloud_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "currencycloud-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("currency_cloud_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Crypto & Blockchain Additional (TruffleHog) ────────────────────

    #[test]
    fn test_kraken_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kraken-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("kraken_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_poloniex_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "poloniex-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("poloniex_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bitmex_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitmex-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bitmex_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_coinapi_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "coinapi-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("coinapi_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_coinlayer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "coinlayer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("coinlayer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_coinlib_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "coinlib-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("coinlib_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cryptocompare_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cryptocompare-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("cryptocompare_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bitcoinaverage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitcoinaverage-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bitcoin_average_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_worldcoinindex_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "worldcoinindex-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("world_coin_index_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_glassnode_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "glassnode-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("glassnode_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tatum_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tatum-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("tatum_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ethplorer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ethplorer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ethplorer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nftport_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "nftport-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("nftport_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_messari_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "messari-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("messari_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_coingecko_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "coingecko-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("coingecko_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Weather & Environment APIs (TruffleHog) ────────────────────────

    #[test]
    fn test_openweather_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "openweather-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("openweather_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_weatherstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "weatherstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("weatherstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_accuweather_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "accuweather-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("accuweather_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_worldweather_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "worldweather-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("world_weather_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tomorrow_io_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tomorrow-io-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("tomorrow_io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_airvisual_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "airvisual-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("airvisual_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_visualcrossing_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "visualcrossing-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("visual_crossing_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_stormglass_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "stormglass-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("stormglass_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_aeris_weather_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "aeris-weather-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("aeris_weather_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ambee_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ambee-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ambee_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_openuv_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "openuv-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("openuv_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: Edge Token, Calendly Webhook, Geocoding & Location ────────

    #[test]
    fn test_edge_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "edge-token").unwrap();
        let key = "a".repeat(25);
        let line = format!("edge_token = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_calendly_webhook_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "calendly-webhook").unwrap();
        let key = "a".repeat(25);
        let line = format!("calendly_webhook_secret = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_tomtom_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "tomtom-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("tomtom_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_geoapify_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "geoapify-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("geoapify_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_geocodify_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "geocodify-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("geocodify_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_geocode_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "geocode-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("geocode_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_geocodio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "geocodio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("geocodio_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_positionstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "positionstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("positionstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_locationiq_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "locationiq-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("locationiq_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_graphhopper_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "graphhopper-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("graphhopper_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_smartystreets_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "smartystreets-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("smartystreets_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_route4me_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "route4me-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("route4me_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zipcode_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zipcode-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("zipcode_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_onwater_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "onwater-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("onwater_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_geoipify_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "geoipify-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("geoipify_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ipgeolocation_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ipgeolocation-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ipgeolocation_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ipinfodb_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ipinfodb-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ipinfodb_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ipify_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ipify-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ipify_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ipapi_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ipapi-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ipapi_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_vpn_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "vpn-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("vpn_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dnscheck_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dnscheck-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("dnscheck_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_walkscore_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "walkscore-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("walkscore_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_besttime_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "besttime-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("besttime_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hypertrack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hypertrack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("hypertrack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fulcrum_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fulcrum-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("fulcrum_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_samsara_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "samsara-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("samsara_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: Media & Image APIs ────────────────────────────────────────

    #[test]
    fn test_unsplash_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "unsplash-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("unsplash_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pixabay_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pixabay-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("pixabay_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gyazo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "gyazo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("gyazo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_imgur_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "imgur-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("imgur_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_shutterstock_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shutterstock-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("shutterstock_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_shutterstock_oauth_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shutterstock-oauth-token").unwrap();
        let key = "a".repeat(25);
        let line = format!("shutterstock_oauth_token = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_iconfinder_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "iconfinder-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("iconfinder_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_imagekit_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "imagekit-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("imagekit_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bannerbear_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bannerbear-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bannerbear_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_imagga_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "imagga-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("imagga_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_faceplusplus_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "faceplusplus-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("faceplusplus_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_skybiometry_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "skybiometry-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("skybiometry_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cloudmersive_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cloudmersive-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("cloudmersive_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_screenshotapi_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "screenshotapi-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("screenshotapi_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_screenshotlayer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "screenshotlayer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("screenshotlayer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_browshot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "browshot-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("browshot_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_linkpreview_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "linkpreview-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("linkpreview_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mixcloud_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mixcloud-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("mixcloud_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rawg_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "rawg-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("rawg_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_strava_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "strava-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("strava_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_foursquare_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "foursquare-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("foursquare_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ticketmaster_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ticketmaster-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ticketmaster_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_riotgames_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "riotgames-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("riotgames_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cricket_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cricket-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("cricket_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_allsports_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "allsports-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("allsports_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sportsmonk_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sportsmonk-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("sportsmonk_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_edamam_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "edamam-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("edamam_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_nutritionix_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "nutritionix-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("nutritionix_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_spoonacular_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "spoonacular-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("spoonacular_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_calorieninja_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "calorieninja-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("calorieninja_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_protocolsio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "protocolsio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("protocolsio_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hypeauditor_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hypeauditor-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("hypeauditor_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: News & Content APIs ───────────────────────────────────────

    #[test]
    fn test_newsapi_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "newsapi-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("newsapi_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_newscatcher_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "newscatcher-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("newscatcher_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_currents_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "currents-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("currents_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_guardian_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "guardian-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("guardian_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_aylien_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "aylien-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("aylien_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cicero_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cicero-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("cicero_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_lexigram_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "lexigram-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("lexigram_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_blogger_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "blogger-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("blogger_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mediastack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mediastack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("mediastack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clickhelp_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clickhelp-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("clickhelp_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_storychief_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "storychief-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("storychief_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_noticeable_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "noticeable-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("noticeable_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_readme_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "readme-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("readme_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pastebin_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pastebin-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("pastebin_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_crowdin_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "crowdin-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("crowdin_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_alconost_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "alconost-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("alconost_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_gengo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "gengo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("gengo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_happyscribe_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "happyscribe-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("happyscribe_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ritekit_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ritekit-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ritekit_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: Developer & Code Tools ────────────────────────────────────

    #[test]
    fn test_rubygems_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "rubygems-api-token").unwrap();
        let key = "a".repeat(25);
        let line = format!("rubygems_api_token = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_codacy_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "codacy-api-token").unwrap();
        let key = "a".repeat(25);
        let line = format!("codacy_api_token = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_coveralls_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "coveralls-api-token").unwrap();
        let key = "a".repeat(25);
        let line = format!("coveralls_api_token = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_saucelabs_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "saucelabs-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("saucelabs_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bitbar_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bitbar-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bitbar_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bugsnag_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bugsnag-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bugsnag_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_adafruit_io_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "adafruit-io-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("adafruit_io_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_apify_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "apify-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("apify_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_keygen_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "keygen-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("keygen_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_aiven_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "aiven-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("aiven_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fileio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fileio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("file_io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flatio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flatio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("flat_io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_dynalist_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "dynalist-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("dynalist_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sheety_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sheety-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("sheety_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_swell_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "swell-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("swell_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_m3o_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "m3o-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("m3o_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_jsonbin_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "jsonbin-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("jsonbin_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_userstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "userstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("userstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_purestake_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "purestake-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("purestake_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_host_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "host-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("host_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_baseapi_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "baseapi-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("baseapi_io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_sslmate_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "sslmate-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("sslmate_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_adobeio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "adobeio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("adobe_io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_edenai_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "edenai-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("edenai_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_deepgram_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "deepgram-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("deepgram_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_voicegain_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "voicegain-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("voicegain_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_auddio_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "auddio-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("audd_io_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_owlbot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "owlbot-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("owlbot_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_detectlanguage_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "detectlanguage-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("detectlanguage_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_languagelayer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "languagelayer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("languagelayer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_paralleldots_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "paralleldots-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("paralleldots_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_veriphone_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "veriphone-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("veriphone_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_verifier_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "verifier-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("verifier_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_api2cart_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "api2cart-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("api2cart_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_apideck_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "apideck-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("apideck_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_apiflash_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "apiflash-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("apiflash_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fleetbase_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fleetbase-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("fleetbase_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_agora_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "agora-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("agora_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_yandex_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "yandex-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("yandex_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_artsy_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "artsy-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("artsy_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_blitapp_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "blitapp-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("blit_app_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_censys_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "censys-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("censys_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_securitytrails_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "securitytrails-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("securitytrails_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_urlscan_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "urlscan-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("urlscan_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_aletheia_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "aletheia-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("aletheia_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_whoxy_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "whoxy-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("whoxy_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_mailsac_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "mailsac-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("mailsac_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_loginradius_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "loginradius-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("loginradius_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_rev_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "rev-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("rev_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_youneedabudget_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "youneedabudget-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("youneedabudget_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_filestack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "filestack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("filestack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bubble_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bubble-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bubble_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_shopee_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "shopee-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("shopee_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kiteconnect_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kiteconnect-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("kiteconnect_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_veevavault_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "veevavault-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("veevavault_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cloudways_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cloudways-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("cloudways_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_duda_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "duda-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("duda_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_yext_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "yext-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("yext_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_contentstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "contentstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("contentstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_surge_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "surge-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("surge_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kairos_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kairos-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("kairos_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_fullcontact_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "fullcontact-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("fullcontact_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_eversign_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "eversign-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("eversign_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_netcore_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "netcore-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("netcore_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_bored_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "bored-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("bored_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: Document & PDF APIs ───────────────────────────────────────

    #[test]
    fn test_html2pdf_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "html2pdf-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("html2pdf_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pdflayer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pdflayer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("pdf_layer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pdfshift_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pdfshift-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("pdf_shift_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_restpack_html_to_pdf_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "restpack-html-to-pdf-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("restpack_html_to_pdf_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_restpack_screenshot_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "restpack-screenshot-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("restpack_screenshot_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_documo_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "documo-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("documo_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_clustdoc_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "clustdoc-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("clustdoc_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pandadoc_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pandadoc-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("pandadoc_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hellosign_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hellosign-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("hellosign_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_juro_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "juro-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("juro_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_yousign_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "yousign-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("yousign_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_vatlayer_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "vatlayer-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("vatlayer_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_upcdatabase_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "upcdatabase-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("upc_database_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: Scraping & Web Automation ─────────────────────────────────

    #[test]
    fn test_scraperapi_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scraperapi-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("scraperapi_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scrapingdog_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scrapingdog-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("scrapingdog_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scrapeowl_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scrapeowl-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("scrapeowl_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_webscraping_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "webscraping-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("webscraping_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zenscrape_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zenscrape-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("zenscrape_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_zenserp_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "zenserp-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("zenserp_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_serpstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "serpstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("serpstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scraperbox_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scraperbox-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("scraperbox_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scrapingant_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scrapingant-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("scrapingant_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_scrapestack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "scrapestack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("scrapestack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_proxycrawl_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "proxycrawl-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("proxycrawl_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: Email Verification ────────────────────────────────────────

    #[test]
    fn test_debounce_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "debounce-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("debounce_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kickbox_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kickbox-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("kickbox_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ipquality_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ipquality-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ipquality_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_roaring_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "roaring-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("roaring_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_oopspam_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "oopspam-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("oopspam_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_numverify_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "numverify-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("numverify_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: CMS & Web Builders ────────────────────────────────────────

    #[test]
    fn test_webflow_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "webflow-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("webflow_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_squarespace_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "squarespace-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("squarespace_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_siteleaf_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "siteleaf-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("siteleaf_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_graphcms_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "graphcms-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("graphcms_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_kontent_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "kontent-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("kontent_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    // ── Tests: Miscellaneous APIs ────────────────────────────────────────

    #[test]
    fn test_wakatime_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "wakatime-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("wakatime_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ubidots_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "ubidots-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("ubidots_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_raven_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "raven-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("raven_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_guru_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "guru-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("guru_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_hive_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "hive-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("hive_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_technicalanalysis_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "technicalanalysis-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("technicalanalysis_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_impala_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "impala-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("impala_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_unplugg_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "unplugg-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("unplugg_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_cloverly_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "cloverly-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("cloverly_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_flight_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "flight-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("flight_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_aviationstack_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "aviationstack-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("aviationstack_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_distribusion_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "distribusion-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("distribusion_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_words_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "words-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("words_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_holiday_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "holiday-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("holiday_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_amadeus_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "amadeus-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("amadeus_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_exchangerate_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "exchangerate-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("exchange_rate_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_abstract_api_key_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "abstract-api-key").unwrap();
        let key = "a".repeat(25);
        let line = format!("abstract_api_key = {}", key);
        let matches = d.scan_line(&line);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_pulumi_api_token_detected() {
        let detectors = builtin_detectors();
        let d = detectors.iter().find(|d| d.id() == "pulumi-api-token").unwrap();
        let key = format!("pul-{}", "a".repeat(40));
        let matches = d.scan_line(&key);
        assert_eq!(matches.len(), 1);
    }
}
