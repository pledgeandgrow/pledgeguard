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
}
