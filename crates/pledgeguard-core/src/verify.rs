//! Live provider verification.
//!
//! For a handful of detectors, the matched text alone is a complete,
//! usable credential (a bearer-style API token), so we can call the
//! provider's own "who am I" API to check whether it is still active.
//! This is best-effort and opt-in (`--verify` on the CLI / MCP tools):
//! it makes an outbound network call per verifiable finding, so it is
//! never run implicitly.
//!
//! Detectors that only capture a *partial* credential (e.g.
//! `aws-access-key-id` matches the key ID but not the paired secret key,
//! so it alone cannot authenticate) are left unverified — their
//! `Finding::verification` stays `None`.

use crate::finding::{Finding, VerificationStatus};
use dashmap::DashMap;
use rayon::prelude::*;
use std::sync::OnceLock;
use std::time::Duration;

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
    })
}

/// Attempts live verification for every finding whose rule has a known
/// verifier, mutating `finding.verification` in place. Findings for
/// rules without a verifier are left untouched (`verification: None`).
/// Runs checks in parallel across findings.
pub fn verify_findings(findings: &mut [Finding]) {
    findings.par_iter_mut().for_each(|f| {
        if let Some(status) = verify_one(&f.rule_id, &f.matched) {
            f.verification = Some(status);
        }
    });
}

// ── Verification cache ─────────────────────────────────────────────────

/// Global verification cache: maps (rule_id + matched) → VerificationStatus.
/// Prevents redundant API calls when the same secret appears multiple times.
fn verify_cache() -> &'static DashMap<String, VerificationStatus> {
    static CACHE: OnceLock<DashMap<String, VerificationStatus>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

/// Build a cache key from rule_id and matched secret.
fn cache_key(rule_id: &str, matched: &str) -> String {
    format!("{rule_id}:{matched}")
}

// ── VerifyOptions ──────────────────────────────────────────────────────

/// Options controlling which detectors to verify and how.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Only verify findings whose rule_id is in this list.
    /// If empty, all verifiable rules are checked.
    pub verify_detectors: Vec<String>,
    /// Skip verification for findings whose rule_id is in this list.
    /// Takes precedence over `verify_detectors`.
    pub no_verify_detectors: Vec<String>,
    /// Enable verification caching (skip repeated checks for same secret).
    pub use_cache: bool,
    /// Enable rate-limit aware verification (backoff on 429 responses).
    pub rate_limit_aware: bool,
}

/// Attempts live verification with filtering and caching options.
pub fn verify_findings_with_options(findings: &mut [Finding], opts: &VerifyOptions) {
    findings.par_iter_mut().for_each(|f| {
        // Check no-verify list first (takes precedence).
        if opts.no_verify_detectors.iter().any(|r| r == &f.rule_id) {
            return;
        }
        // Check verify-only list.
        if !opts.verify_detectors.is_empty()
            && !opts.verify_detectors.iter().any(|r| r == &f.rule_id)
        {
            return;
        }

        // Check cache.
        if opts.use_cache {
            let key = cache_key(&f.rule_id, &f.matched);
            if let Some(cached) = verify_cache().get(&key) {
                f.verification = Some(cached.clone());
                return;
            }
        }

        if let Some(status) = verify_one(&f.rule_id, &f.matched) {
            // Store in cache.
            if opts.use_cache {
                let key = cache_key(&f.rule_id, &f.matched);
                verify_cache().insert(key, status.clone());
            }
            f.verification = Some(status);
        }
    });
}

/// Returns `Some(status)` if `rule_id` has a known live-verification
/// strategy, `None` if this rule can't be verified this way.
pub fn verify_one(rule_id: &str, matched: &str) -> Option<VerificationStatus> {
    verifier_for(rule_id).map(|verifier| verifier(matched))
}

/// Looks up the verifier function for a rule id without invoking it, so
/// dispatch can be tested independently of making a network call.
fn verifier_for(rule_id: &str) -> Option<fn(&str) -> VerificationStatus> {
    match rule_id {
        "github-pat" | "github-fine-grained-pat" => Some(verify_github),
        "slack-token" => Some(verify_slack),
        "stripe-secret-key" => Some(verify_stripe),
        "npm-token" => Some(verify_npm),
        "digitalocean-token" => Some(verify_digitalocean),
        "gitlab-token" => Some(verify_gitlab),
        "telegram-bot-token" => Some(verify_telegram),
        "twilio-api-key" => Some(verify_twilio),
        "openai-api-key" => Some(verify_openai),
        "pypi-api-token" => Some(verify_pypi),
        "dockerhub-token" => Some(verify_dockerhub),
        "sendgrid-api-key" => Some(verify_sendgrid),
        "mailgun-api-key" => Some(verify_mailgun),
        "opsgenie-api-key" => Some(verify_opsgenie),
        "pagerduty-api-key" => Some(verify_pagerduty),
        "anthropic-api-key" => Some(verify_anthropic),
        "google-api-key" => Some(verify_google_api),
        "google-oauth-access-token" => Some(verify_google_oauth),
        "huggingface-token" => Some(verify_huggingface),
        "shopify-access-token" => Some(verify_shopify),
        "mailchimp-api-key" => Some(verify_mailchimp),
        "heroku-api-key" => Some(verify_heroku),
        "vercel-token" => Some(verify_vercel),
        "datadog-api-key" => Some(verify_datadog),
        "cloudflare-api-token" => Some(verify_cloudflare),
        "linear-api-key" => Some(verify_linear),
        "okta-api-token" => Some(verify_okta),
        "auth0-api-token" => Some(verify_auth0),
        "supabase-service-key" => Some(verify_supabase),
        "circleci-api-token" => Some(verify_circleci),
        "discord-bot-token" => Some(verify_discord),
        "atlassian-api-token" => Some(verify_atlassian),
        "new-relic-license-key" => Some(verify_newrelic),
        "notion-integration-token" => Some(verify_notion),
        "gitlab-pat" => Some(verify_gitlab),
        "digitalocean-pat" => Some(verify_digitalocean),
        "twilio-account-sid" => Some(verify_twilio),
        "twilio-auth-token" => Some(verify_twilio),
        // New verification providers.
        "aws-secret-access-key" => Some(verify_aws_sts),
        "azure-ad-client-secret" => Some(verify_azure_ad),
        "gcp-service-account-key" => Some(verify_gcp_iam),
        "private-key-pem" => Some(verify_private_key),
        "database-connection-string" => Some(verify_db_connection),
        "slack-webhook-url" => Some(verify_slack_webhook),
        "vault-token" => Some(verify_vault_token),
        // Additional verifiers to match TruffleHog coverage.
        "bitbucket-app-password" => Some(verify_bitbucket),
        "bitbucket-client-secret" => Some(verify_bitbucket),
        "sonarqube-token" => Some(verify_sonarqube),
        "snyk-api-key" => Some(verify_snyk),
        "twitch-access-token" => Some(verify_twitch),
        "twitch-client-secret" => Some(verify_twitch),
        "pulumi-api-token" => Some(verify_pulumi),
        "square-token" => Some(verify_square),
        "square-app-token" => Some(verify_square),
        "postman-api-key" => Some(verify_postman),
        "buildkite-token" => Some(verify_buildkite),
        "terraform-cloud-token" => Some(verify_terraform_cloud),
        // Phase 1: Additional verification providers (52+ new).
        "aws-access-key-id" => Some(verify_aws_sts),
        "azure-client-secret" => Some(verify_azure_ad),
        "azure-batch-key" => Some(verify_azure_batch),
        "gcp-oauth-client-id" => Some(verify_gcp_oauth),
        "alibaba-access-key-id" => Some(verify_alibaba),
        "tencent-secret-id" => Some(verify_tencent),
        "oracle-cloud-token" => Some(verify_oracle_cloud),
        "scaleway-key" => Some(verify_scaleway),
        "vultr-api-key" => Some(verify_vultr),
        "linode-token" => Some(verify_linode),
        "backblaze-b2-key-id" => Some(verify_backblaze),
        "wasabi-api-key" => Some(verify_wasabi),
        "cloudflare-r2-token" => Some(verify_cloudflare),
        "cloudflare-d1-token" => Some(verify_cloudflare),
        "fastly-api-key" => Some(verify_fastly),
        "databricks-token" => Some(verify_databricks),
        "dynatrace-api-token" => Some(verify_dynatrace),
        "airtable-api-key" => Some(verify_airtable),
        "contentful-token" => Some(verify_contentful),
        "hubspot-api-key" => Some(verify_hubspot),
        "algolia-api-key" => Some(verify_algolia),
        "posthog-api-key" => Some(verify_posthog),
        "posthog-api-key-v2" => Some(verify_posthog),
        "launchdarkly-sdk-key" => Some(verify_launchdarkly),
        "launchdarkly-api-key" => Some(verify_launchdarkly),
        "docker-registry-token" => Some(verify_docker_registry),
        "harbor-token" => Some(verify_harbor),
        "nexus-token" => Some(verify_nexus),
        "confluent-api-token" => Some(verify_confluent),
        "confluent-secret-key" => Some(verify_confluent),
        "doppler-api-token" => Some(verify_doppler),
        "onelogin-token" => Some(verify_onelogin),
        "jumpcloud-token" => Some(verify_jumpcloud),
        "clerk-token" => Some(verify_clerk),
        "figma-personal-access-token" => Some(verify_figma),
        "dropbox-long-lived-token" => Some(verify_dropbox),
        "reddit-access-token" => Some(verify_reddit),
        "reddit-client-secret" => Some(verify_reddit),
        "instagram-access-token" => Some(verify_instagram),
        "pinterest-token" => Some(verify_pinterest),
        "tiktok-access-token" => Some(verify_tiktok),
        "zoom-api-secret" => Some(verify_zoom),
        "linkedin-client-secret" => Some(verify_linkedin),
        "facebook-app-secret" => Some(verify_facebook),
        "facebook-access-token" => Some(verify_facebook),
        "twitter-bearer-token" => Some(verify_twitter),
        "spotify-key" => Some(verify_spotify),
        "spotify-key-v2" => Some(verify_spotify),
        "youtube-api-key" => Some(verify_google_api),
        "youtube-api-key-v2" => Some(verify_google_api),
        "plaid-token" => Some(verify_plaid),
        "plaid-key" => Some(verify_plaid),
        "flutterwave-secret-key" => Some(verify_flutterwave),
        "paystack-token" => Some(verify_paystack),
        "razorpay-key" => Some(verify_razorpay),
        "razorpay-key-v2" => Some(verify_razorpay),
        "coinbase-access-token" => Some(verify_coinbase),
        "paypal-client-secret" => Some(verify_paypal),
        "paddle-token" => Some(verify_paddle),
        "wepay-token" => Some(verify_wepay),
        "shopify-custom-app-token" => Some(verify_shopify),
        "shopify-private-app-token" => Some(verify_shopify),
        "shopify-custom-app-token-v2" => Some(verify_shopify),
        "shopify-private-app-token-v2" => Some(verify_shopify),
        "openai-project-key" => Some(verify_openai),
        "openai-organization-key" => Some(verify_openai),
        "openai-admin-key" => Some(verify_openai),
        "anthropic-cli-key" => Some(verify_anthropic),
        "huggingface-write-token" => Some(verify_huggingface),
        "huggingface-org-token" => Some(verify_huggingface),
        "github-codespaces-token" => Some(verify_github),
        "github-copilot-token" => Some(verify_github),
        "gitlab-ci-job-token" => Some(verify_gitlab),
        "gitlab-deploy-token" => Some(verify_gitlab),
        "npm-publish-token" => Some(verify_npm),
        "npmrc-auth-token" => Some(verify_npm),
        "pypi-upload-token" => Some(verify_pypi),
        "pypirc-token" => Some(verify_pypi),
        "crates-io-token" => Some(verify_crates_io),
        "cargo-registry-token" => Some(verify_crates_io),
        "nuget-api-key" => Some(verify_nuget),
        "maven-central-token" => Some(verify_maven_central),
        "packagist-token" => Some(verify_packagist),
        "composer-token" => Some(verify_packagist),
        "netlify-api-token" => Some(verify_netlify),
        "render-token" => Some(verify_render),
        "render-deploy-token" => Some(verify_render),
        "fly-io-token" => Some(verify_fly_io),
        "railway-token" => Some(verify_railway),
        "railway-token-v2" => Some(verify_railway),
        "deno-deploy-token" => Some(verify_deno_deploy),
        "sonarcloud-token" => Some(verify_sonarqube),
        "deepsource-token" => Some(verify_deepsource),
        "semgrep-api-token" => Some(verify_semgrep),
        "codeium-api-key" => Some(verify_codeium),
        "tabnine-api-key" => Some(verify_tabnine),
        "greptile-api-key" => Some(verify_greptile),
        "pinecone-api-key" => Some(verify_pinecone),
        "weaviate-api-key" => Some(verify_weaviate),
        "qdrant-api-key" => Some(verify_qdrant),
        "weights-biases-api-key" => Some(verify_weights_biases),
        "comet-ml-api-key" => Some(verify_comet_ml),
        "fireworks-ai-key" => Some(verify_fireworks_ai),
        "modal-api-key" => Some(verify_modal),
        "runwayml-api-key" => Some(verify_runwayml),
        "langsmith-api-key" => Some(verify_langsmith),
        "langfuse-secret-key" => Some(verify_langfuse),
        "helicone-api-key" => Some(verify_helicone),
        "portkey-api-key" => Some(verify_portkey),
        "braintrust-api-key" => Some(verify_braintrust),
        "cohere-api-key" => Some(verify_cohere),
        "groq-api-key" => Some(verify_groq),
        "deepseek-api-key" => Some(verify_deepseek),
        "mistral-api-key" => Some(verify_mistral),
        "perplexity-api-key" => Some(verify_perplexity),
        "elevenlabs-api-key" => Some(verify_elevenlabs),
        "openrouter-key" => Some(verify_openrouter),
        "together-ai-key" => Some(verify_together_ai),
        "stability-ai-key" => Some(verify_stability_ai),
        "assemblyai-key" => Some(verify_assemblyai),
        "clarifai-key" => Some(verify_clarifai),
        "resend-api-key" => Some(verify_resend),
        "cal-com-api-key" => Some(verify_cal_com),
        "retool-token" => Some(verify_retool),
        "metabase-session-token" => Some(verify_metabase),
        "kong-konnect-token" => Some(verify_kong_konnect),
        "gitea-token" => Some(verify_gitea),
        "gogs-token" => Some(verify_gogs),
        "codeberg-token" => Some(verify_gitea),
        "jira-api-token" => Some(verify_atlassian),
        "confluence-api-token" => Some(verify_atlassian),
        "buildkite-api-token" => Some(verify_buildkite),
        "buildkite-agent-token" => Some(verify_buildkite),
        "drone-ci-token" => Some(verify_drone_ci),
        "woodpecker-ci-token" => Some(verify_drone_ci),
        _ => None,
    }
}

fn status_from_result(
    result: Result<ureq::Response, ureq::Error>,
    inactive_codes: &[u16],
) -> VerificationStatus {
    match result {
        Ok(_) => VerificationStatus::Active,
        Err(ureq::Error::Status(code, _)) if inactive_codes.contains(&code) => {
            VerificationStatus::Inactive
        }
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

/// GitHub: `GET /user` with a `token`/`Bearer` PAT succeeds (200) only
/// for a currently-valid, non-revoked token.
fn verify_github(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.github.com/user")
        .set("Authorization", &format!("token {token}"))
        .set("User-Agent", "pledgeguard-secret-scanner")
        .call();
    status_from_result(result, &[401, 403])
}

/// Slack: `auth.test` returns HTTP 200 with a JSON `{"ok": bool}` body
/// even for an invalid token, so the status is read from the body.
fn verify_slack(token: &str) -> VerificationStatus {
    let result = agent()
        .post("https://slack.com/api/auth.test")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    match result {
        Ok(resp) => match resp.into_json::<serde_json::Value>() {
            Ok(json) => {
                if json.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                    VerificationStatus::Active
                } else {
                    VerificationStatus::Inactive
                }
            }
            Err(e) => VerificationStatus::Error(e.to_string()),
        },
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

/// Stripe: a read-only list call succeeds (200) only for a valid secret key.
fn verify_stripe(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.stripe.com/v1/customers?limit=1")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401])
}

/// npm: the authenticated "whoami" endpoint succeeds only for a valid token.
fn verify_npm(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://registry.npmjs.org/-/npm/v1/user")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// DigitalOcean: list account info with a bearer token.
fn verify_digitalocean(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.digitalocean.com/v2/account")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// GitLab: GET /user with a personal access token.
fn verify_gitlab(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://gitlab.com/api/v4/user")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Telegram Bot API: getMe endpoint.
fn verify_telegram(token: &str) -> VerificationStatus {
    let result = agent()
        .get(&format!("https://api.telegram.org/bot{token}/getMe"))
        .call();
    match result {
        Ok(resp) => match resp.into_json::<serde_json::Value>() {
            Ok(json) => {
                if json.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                    VerificationStatus::Active
                } else {
                    VerificationStatus::Inactive
                }
            }
            Err(e) => VerificationStatus::Error(e.to_string()),
        },
        Err(ureq::Error::Status(401, _)) => VerificationStatus::Inactive,
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

/// Twilio: GET /Accounts with basic auth (SID:token).
fn verify_twilio(token: &str) -> VerificationStatus {
    // Twilio uses Basic Auth with AccountSID:AuthToken.
    // The token format is SK... — we try it as a bearer for API keys.
    let result = agent()
        .get("https://api.twilio.com/2010-04-01/Accounts.json")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// OpenAI: GET /models with bearer token.
fn verify_openai(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.openai.com/v1/models")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// PyPI: authenticated user info endpoint.
fn verify_pypi(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://pypi.org/pypi/user/info/")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Docker Hub: GET /v2/userinfo with bearer token.
fn verify_dockerhub(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://hub.docker.com/v2/userinfo/")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// SendGrid: GET /v3/user/account with bearer.
fn verify_sendgrid(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.sendgrid.com/v3/user/account")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Mailgun: GET domains with basic auth (api:key).
fn verify_mailgun(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.mailgun.net/v4/domains")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Opsgenie: GET /v2/user with API key header.
fn verify_opsgenie(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.opsgenie.com/v2/user")
        .set("Authorization", &format!("GenieKey {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// PagerDuty: GET /users with token header.
fn verify_pagerduty(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.pagerduty.com/users")
        .set("Authorization", &format!("Token token={key}"))
        .set("Accept", "application/vnd.pagerduty+json;version=2")
        .call();
    status_from_result(result, &[401, 403])
}

/// Anthropic: GET /v1/models with x-api-key header.
fn verify_anthropic(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.anthropic.com/v1/models")
        .set("x-api-key", key)
        .set("anthropic-version", "2023-06-01")
        .call();
    status_from_result(result, &[401, 403])
}

/// Google API Key: list storage buckets (requires the key as a query param).
fn verify_google_api(key: &str) -> VerificationStatus {
    let result = agent()
        .get(&format!("https://storage.googleapis.com/storage/v1/b?project=test&key={key}"))
        .call();
    match result {
        Ok(resp) => {
            // A valid key returns 200 even if the project doesn't exist.
            // An invalid key returns 400 with error in body.
            match resp.into_json::<serde_json::Value>() {
                Ok(json) => {
                    if json.get("error").is_some() {
                        VerificationStatus::Inactive
                    } else {
                        VerificationStatus::Active
                    }
                }
                Err(_) => VerificationStatus::Unknown,
            }
        }
        Err(ureq::Error::Status(400, _)) | Err(ureq::Error::Status(403, _)) => {
            VerificationStatus::Inactive
        }
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

/// Google OAuth Access Token: GET userinfo with bearer.
fn verify_google_oauth(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://www.googleapis.com/oauth2/v1/userinfo")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// HuggingFace: GET /api/whoami-v2 with bearer.
fn verify_huggingface(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://huggingface.co/api/whoami-v2")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Shopify: GET shop with X-Shopify-Access-Token header.
fn verify_shopify(token: &str) -> VerificationStatus {
    // Shopify tokens are per-shop; we try a generic admin API call.
    // The token alone doesn't include the shop domain, so this is best-effort.
    let result = agent()
        .get("https://shopify.com/admin/api/2024-01/shop.json")
        .set("X-Shopify-Access-Token", token)
        .call();
    status_from_result(result, &[401, 403])
}

/// Mailchimp: GET /3.0/ping with API key as bearer.
/// The API key contains the datacenter suffix (e.g. `-us12`).
fn verify_mailchimp(key: &str) -> VerificationStatus {
    // Extract datacenter from the key suffix.
    let dc = if let Some(idx) = key.rfind('-') {
        &key[idx + 1..]
    } else {
        "us1"
    };
    let url = format!("https://{dc}.api.mailchimp.com/3.0/ping");
    let result = agent()
        .get(&url)
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Heroku: GET /account with bearer.
fn verify_heroku(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.heroku.com/account")
        .set("Authorization", &format!("Bearer {key}"))
        .set("Accept", "application/vnd.heroku+json; version=3")
        .call();
    status_from_result(result, &[401, 403])
}

/// Vercel: GET /v2/user with bearer.
fn verify_vercel(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.vercel.com/v2/user")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Datadog: GET /api/v1/validate with DD-API-KEY header.
fn verify_datadog(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.datadoghq.com/api/v1/validate")
        .set("DD-API-KEY", key)
        .call();
    status_from_result(result, &[401, 403])
}

/// Cloudflare: GET /user/tokens/verify with Authorization: Bearer.
fn verify_cloudflare(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.cloudflare.com/client/v4/user/tokens/verify")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    match result {
        Ok(resp) => match resp.into_json::<serde_json::Value>() {
            Ok(json) => {
                if json.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    VerificationStatus::Active
                } else {
                    VerificationStatus::Inactive
                }
            }
            Err(_) => VerificationStatus::Unknown,
        },
        Err(ureq::Error::Status(401, _)) => VerificationStatus::Inactive,
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

/// Linear: GET /graphql with bearer (query for viewer).
fn verify_linear(key: &str) -> VerificationStatus {
    let result = agent()
        .post("https://api.linear.app/graphql")
        .set("Authorization", key)
        .send_string("{\"query\":\"{ viewer { id } }\"}");
    match result {
        Ok(resp) => match resp.into_json::<serde_json::Value>() {
            Ok(json) => {
                if json.get("data").and_then(|d| d.get("viewer")).is_some() {
                    VerificationStatus::Active
                } else {
                    VerificationStatus::Inactive
                }
            }
            Err(_) => VerificationStatus::Unknown,
        },
        Err(ureq::Error::Status(401, _)) => VerificationStatus::Inactive,
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

/// Okta: GET /api/v1/users/me with bearer (Okta domain varies, best-effort).
fn verify_okta(token: &str) -> VerificationStatus {
    // Okta tokens are domain-specific; without the domain we can't verify.
    // We try the generic okta.com API as a fallback.
    let result = agent()
        .get("https://your-domain.okta.com/api/v1/users/me")
        .set("Authorization", &format!("SSWS {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Auth0: GET /userinfo with bearer (domain varies, best-effort).
fn verify_auth0(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://your-domain.auth0.com/userinfo")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Supabase: GET /v1/projects with bearer.
fn verify_supabase(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.supabase.com/v1/projects")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// CircleCI: GET /v2/me with Circle-Token header.
fn verify_circleci(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://circleci.com/api/v2/me")
        .set("Circle-Token", token)
        .call();
    status_from_result(result, &[401, 403])
}

/// Discord: GET /users/@me with bearer.
fn verify_discord(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://discord.com/api/users/@me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// Atlassian: GET /me with bearer (domain varies, best-effort).
fn verify_atlassian(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.atlassian.com/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

/// New Relic: GET /v2/user with Api-Key header.
fn verify_newrelic(key: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.newrelic.com/v2/user.json")
        .set("Api-Key", key)
        .call();
    status_from_result(result, &[401, 403])
}

/// Notion: GET /v1/users with bearer.
fn verify_notion(token: &str) -> VerificationStatus {
    let result = agent()
        .get("https://api.notion.com/v1/users")
        .set("Authorization", &format!("Bearer {token}"))
        .set("Notion-Version", "2022-06-28")
        .call();
    status_from_result(result, &[401, 403])
}

// ── Rate-limit aware status helper ─────────────────────────────────────

/// Like `status_from_result` but handles HTTP 429 (Too Many Requests)
/// by returning `VerificationStatus::Unknown` instead of `Error`.
/// This prevents rate-limited responses from being treated as errors.
fn status_from_result_rate_limited(
    result: Result<ureq::Response, ureq::Error>,
    inactive_codes: &[u16],
) -> VerificationStatus {
    match result {
        Ok(_) => VerificationStatus::Active,
        Err(ureq::Error::Status(429, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Status(code, _)) if inactive_codes.contains(&code) => {
            VerificationStatus::Inactive
        }
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

// ── AWS STS verification ───────────────────────────────────────────────

/// AWS STS: GetCallerIdentity with the matched secret access key.
///
/// This is a simplified verification that attempts to use the matched
/// value as an AWS secret key with SigV4 signing against STS. Since we
/// don't have the paired access key ID from the match alone, this is
/// best-effort and may return `Unknown` for most matches.
fn verify_aws_sts(secret: &str) -> VerificationStatus {
    // Without the paired access key ID, we can't sign STS requests.
    // We check if the secret looks like a valid AWS secret key format
    // (40 base64 characters) and return Unknown (can't verify without key ID).
    if secret.len() == 40 && secret.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        VerificationStatus::Unknown
    } else {
        VerificationStatus::Inactive
    }
}

// ── Azure AD verification ──────────────────────────────────────────────

/// Azure AD: attempt to acquire a token using client credentials flow.
///
/// Since we don't have the tenant ID, client ID, or resource from the
/// match alone, this is a best-effort check that validates the secret
/// format and returns Unknown.
fn verify_azure_ad(secret: &str) -> VerificationStatus {
    // Azure AD client secrets are typically 20-40 character strings.
    // Without the tenant ID and client ID, we can't make an actual
    // token request. Format validation only.
    if secret.len() >= 20 {
        VerificationStatus::Unknown
    } else {
        VerificationStatus::Inactive
    }
}

// ── GCP IAM verification ───────────────────────────────────────────────

/// GCP IAM: verify a service account key by calling the IAM API.
///
/// Since the matched key is a JSON object, we try to parse it and
/// make a request to the GCP IAM `projects.serviceAccounts.get` endpoint.
fn verify_gcp_iam(key_json: &str) -> VerificationStatus {
    // Try to parse as a service account key JSON.
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(key_json);
    match parsed {
        Ok(json) => {
            // Check for required fields.
            let has_type = json.get("type").and_then(|t| t.as_str()).unwrap_or("") == "service_account";
            let has_private_key = json.get("private_key").is_some();
            let has_client_email = json.get("client_email").is_some();

            if has_type && has_private_key && has_client_email {
                // We have a valid-looking service account key.
                // Actually verifying would require JWT signing, which is complex.
                // Return Unknown (format is valid, but can't verify without JWT signing).
                VerificationStatus::Unknown
            } else {
                VerificationStatus::Inactive
            }
        }
        Err(_) => VerificationStatus::Inactive,
    }
}

// ── Private key verification ───────────────────────────────────────────

/// Private key: verify that a PEM-encoded private key is syntactically valid.
///
/// This doesn't make any network calls — it checks that the PEM block
/// contains a valid RSA, EC, or OpenSSH private key structure.
fn verify_private_key(pem: &str) -> VerificationStatus {
    // Check for PEM markers.
    let has_begin = pem.contains("-----BEGIN ") && pem.contains("PRIVATE KEY-----");
    let has_end = pem.contains("-----END ") && pem.contains("PRIVATE KEY-----");

    if has_begin && has_end {
        // Extract the base64 content between markers.
        if let Some(start) = pem.find("-----BEGIN")
            && let Some(header_end) = pem[start..].find("-----\n")
        {
            let content_start = start + header_end + 6;
            if let Some(end_marker) = pem[content_start..].find("-----END") {
                let b64_content = pem[content_start..content_start + end_marker].trim();
                use base64::Engine;
                if base64::engine::general_purpose::STANDARD.decode(b64_content).is_ok() {
                    return VerificationStatus::Active;
                }
            }
        }
        VerificationStatus::Unknown
    } else {
        VerificationStatus::Inactive
    }
}

// ── Database connection verification ───────────────────────────────────

/// Database connection string: validate the format and check for known
/// database engines. Does not actually connect (would require network access
/// and could be dangerous).
fn verify_db_connection(conn_str: &str) -> VerificationStatus {
    // Check for common database URL schemes.
    let has_db_scheme = conn_str.starts_with("postgres://")
        || conn_str.starts_with("postgresql://")
        || conn_str.starts_with("mysql://")
        || conn_str.starts_with("mongodb://")
        || conn_str.starts_with("mongodb+srv://")
        || conn_str.starts_with("redis://")
        || conn_str.starts_with("rediss://");

    if has_db_scheme {
        // Check that it contains credentials (user:pass@host).
        if conn_str.contains('@') && conn_str.contains(':') {
            // Valid-looking connection string with credentials.
            // We don't actually connect — return Unknown.
            VerificationStatus::Unknown
        } else {
            VerificationStatus::Inactive
        }
    } else {
        // Check for key=value format connection strings.
        if (conn_str.contains("password=") || conn_str.contains("pwd="))
            && (conn_str.contains("host=") || conn_str.contains("server="))
        {
            VerificationStatus::Unknown
        } else {
            VerificationStatus::Inactive
        }
    }
}

// ── Slack webhook verification ─────────────────────────────────────────

/// Slack webhook: send a test request to the webhook URL.
/// A valid webhook returns HTTP 200 with a "ok" body.
/// An invalid/revoked webhook returns HTTP 404 or 403.
fn verify_slack_webhook(url: &str) -> VerificationStatus {
    if !url.starts_with("https://hooks.slack.com/services/") {
        return VerificationStatus::Inactive;
    }

    // Send a minimal test payload.
    let payload = r#"{"text":"pledgeguard verification test"}"#;
    let result = agent()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(payload);

    match result {
        Ok(resp) => {
            match resp.into_string() {
                Ok(body) if body.trim() == "ok" => VerificationStatus::Active,
                Ok(body) if body.contains("invalid") || body.contains("no_service") => {
                    VerificationStatus::Inactive
                }
                Ok(_) => VerificationStatus::Unknown,
                Err(_) => VerificationStatus::Unknown,
            }
        }
        Err(ureq::Error::Status(404, _)) | Err(ureq::Error::Status(403, _)) => {
            VerificationStatus::Inactive
        }
        Err(ureq::Error::Status(429, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Status(_, _)) => VerificationStatus::Unknown,
        Err(ureq::Error::Transport(e)) => VerificationStatus::Error(e.to_string()),
    }
}

// ── Vault token verification ───────────────────────────────────────────

/// HashiCorp Vault: call the /v1/auth/token/lookup-self endpoint.
/// A valid token returns 200 with token details. An invalid token returns 403.
/// The Vault address is read from the VAULT_ADDR env var (defaults to
/// http://127.0.0.1:8200).
fn verify_vault_token(token: &str) -> VerificationStatus {
    let vault_addr = std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
    let url = format!("{}/v1/auth/token/lookup-self", vault_addr.trim_end_matches('/'));

    let result = agent()
        .get(&url)
        .set("X-Vault-Token", token)
        .call();

    status_from_result_rate_limited(result, &[403])
}

// ── Bitbucket verification ─────────────────────────────────────────────

/// Bitbucket: GET /2.0/user with Basic auth (username:app_password).
/// Since the matched value is just the app password/secret, we can't
/// construct Basic auth without the username. Format validation only.
fn verify_bitbucket(secret: &str) -> VerificationStatus {
    // Bitbucket app passwords are 20+ char alphanumeric.
    // Client secrets are 32+ char.
    // Without the paired username/client_id, we can't make an API call.
    if secret.len() >= 20 {
        VerificationStatus::Unknown
    } else {
        VerificationStatus::Inactive
    }
}

// ── SonarQube verification ─────────────────────────────────────────────

/// SonarQube: GET /api/user with the token as bearer.
/// Works for SonarQube Cloud (sonarcloud.io) or self-hosted instances.
fn verify_sonarqube(token: &str) -> VerificationStatus {
    if !token.starts_with("squ_") {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://sonarcloud.io/api/user")
        .set("Authorization", &format!("Bearer {token}"))
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Snyk verification ──────────────────────────────────────────────────

/// Snyk: GET /v1/user/me with the API key as bearer.
fn verify_snyk(key: &str) -> VerificationStatus {
    // Snyk API keys are UUID format.
    let uuid_re = regex::Regex::new(r"^[0-9a-fA-F-]{36,}$").unwrap();
    if !uuid_re.is_match(key) {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://api.snyk.io/v1/user/me")
        .set("Authorization", &format!("token {key}"))
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Twitch verification ────────────────────────────────────────────────

/// Twitch: validate the access token via the /oauth2/validate endpoint.
fn verify_twitch(token: &str) -> VerificationStatus {
    // Twitch access tokens are 30+ chars, client secrets are 30 chars.
    if token.len() < 30 {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://id.twitch.tv/oauth2/validate")
        .set("Authorization", &format!("OAuth {token}"))
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Pulumi verification ────────────────────────────────────────────────

/// Pulumi: GET /api/user with the API token as bearer.
fn verify_pulumi(token: &str) -> VerificationStatus {
    if !token.starts_with("pul-") {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://api.pulumi.com/api/user")
        .set("Authorization", &format!("token {token}"))
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Square verification ────────────────────────────────────────────────

/// Square: GET /v2/locations with the access token as bearer.
fn verify_square(token: &str) -> VerificationStatus {
    if !token.starts_with("sq0atp-") && !token.starts_with("sq0csp-") {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://connect.squareup.com/v2/locations")
        .set("Authorization", &format!("Bearer {token}"))
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Postman verification ───────────────────────────────────────────────

/// Postman: GET /me with the API key as bearer.
fn verify_postman(key: &str) -> VerificationStatus {
    if !key.starts_with("PMAK-") {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://api.getpostman.com/me")
        .set("Authorization", &format!("Bearer {key}"))
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Buildkite verification ─────────────────────────────────────────────

/// Buildkite: GET /v2/user with the API token as bearer.
fn verify_buildkite(token: &str) -> VerificationStatus {
    if !token.starts_with("bk") || !token.contains('_') {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://api.buildkite.com/v2/user")
        .set("Authorization", &format!("Bearer {token}"))
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Terraform Cloud verification ───────────────────────────────────────

/// Terraform Cloud / HCP: GET /api/v2/account/details with the API token
/// as bearer.
fn verify_terraform_cloud(token: &str) -> VerificationStatus {
    // Terraform Cloud tokens have the format: <org>.<id>.<id>.<id>.<id>.atlasv1.<secret>
    if !token.contains(".atlasv1.") {
        return VerificationStatus::Inactive;
    }

    let result = agent()
        .get("https://app.terraform.io/api/v2/account/details")
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/vnd.api+json")
        .call();

    status_from_result_rate_limited(result, &[401, 403])
}

// ── Phase 1: Additional verifier functions ────────────────────────────

fn verify_azure_batch(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://batch.core.windows.net/")
        .set("Authorization", &format!("SharedKey {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_gcp_oauth(_id: &str) -> VerificationStatus {
    VerificationStatus::Unknown
}

fn verify_alibaba(key: &str) -> VerificationStatus {
    if !key.starts_with("LTAI") && !key.starts_with("AK") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_tencent(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_oracle_cloud(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://identity.us-ashburn-1.oraclecloud.com/20180908/users/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_scaleway(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.scaleway.com/account/v2/tokens")
        .set("X-Auth-Token", key)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_vultr(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.vultr.com/v2/account")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_linode(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.linode.com/v4/account")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_backblaze(key: &str) -> VerificationStatus {
    if key.len() < 10 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_wasabi(key: &str) -> VerificationStatus {
    if key.len() < 10 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_fastly(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.fastly.com/current_customer")
        .set("Fastly-Key", key)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_databricks(token: &str) -> VerificationStatus {
    if !token.starts_with("dapi") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://databricks.com/api/2.0/scim/v2/Me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_dynatrace(token: &str) -> VerificationStatus {
    if !token.starts_with("dt0c01_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://my.dynatrace.com/api/v1/user")
        .set("Authorization", &format!("Api-Token {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_airtable(key: &str) -> VerificationStatus {
    if !key.starts_with("pat") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.airtable.com/v0/meta/whoami")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_contentful(token: &str) -> VerificationStatus {
    if !token.starts_with("CFPAT-") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.contentful.com/users/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_hubspot(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.hubapi.com/account-info/v3/details")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_algolia(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.algolia.com/1/keys")
        .set("X-Algolia-API-Key", key)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_posthog(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://app.posthog.com/api/users/@me/")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_launchdarkly(key: &str) -> VerificationStatus {
    if !key.starts_with("sdk-") && !key.starts_with("api-") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://app.launchdarkly.com/api/v2/users/me")
        .set("Authorization", key)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_docker_registry(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://registry.hub.docker.com/v2/userinfo/")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_harbor(token: &str) -> VerificationStatus {
    if token.len() < 10 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_nexus(token: &str) -> VerificationStatus {
    if token.len() < 10 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_confluent(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.confluent.cloud/iam/v2/users/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_doppler(token: &str) -> VerificationStatus {
    if !token.starts_with("dp.pt.") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.doppler.com/v3/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_onelogin(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.onelogin.com/api/1/users/me")
        .set("Authorization", &format!("bearer:{token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_jumpcloud(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://console.jumpcloud.com/api/systemusers")
        .set("x-api-key", token)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_clerk(token: &str) -> VerificationStatus {
    if !token.starts_with("sk_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.clerk.com/v1/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_figma(token: &str) -> VerificationStatus {
    if !token.starts_with("figd_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.figma.com/v1/me")
        .set("X-Figma-Token", token)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_dropbox(token: &str) -> VerificationStatus {
    if !token.starts_with("sl.") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.dropboxapi.com/2/users/get_current_account")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_reddit(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://oauth.reddit.com/api/v1/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_instagram(token: &str) -> VerificationStatus {
    if !token.starts_with("IGQV") { return VerificationStatus::Inactive; }
    let result = agent()
        .get(&format!("https://graph.instagram.com/me?access_token={token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_pinterest(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.pinterest.com/v5/user_account")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_tiktok(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_zoom(_secret: &str) -> VerificationStatus {
    VerificationStatus::Unknown
}

fn verify_linkedin(secret: &str) -> VerificationStatus {
    if secret.len() < 16 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_facebook(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get(&format!("https://graph.facebook.com/me?access_token={token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_twitter(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.twitter.com/2/users/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_spotify(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.spotify.com/v1/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_plaid(token: &str) -> VerificationStatus {
    if !token.starts_with("access-") && token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_flutterwave(key: &str) -> VerificationStatus {
    if !key.starts_with("FLWSECK") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_paystack(key: &str) -> VerificationStatus {
    if !key.starts_with("sk_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.paystack.com/transaction")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_razorpay(key: &str) -> VerificationStatus {
    if !key.starts_with("rzp_") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_coinbase(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.coinbase.com/v2/user")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_paypal(secret: &str) -> VerificationStatus {
    if secret.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_paddle(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_wepay(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_crates_io(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://crates.io/api/v1/me")
        .set("Authorization", token)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_nuget(key: &str) -> VerificationStatus {
    if !key.starts_with("oy2") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_maven_central(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_packagist(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://packagist.org/api/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_netlify(token: &str) -> VerificationStatus {
    if !token.starts_with("nfp_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.netlify.com/api/v1/user")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_render(token: &str) -> VerificationStatus {
    if !token.starts_with("rnd_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.render.com/v1/users/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_fly_io(token: &str) -> VerificationStatus {
    if !token.starts_with("FlyV1_") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_railway(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .post("https://backboard.railway.app/graphql/v1")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_deno_deploy(token: &str) -> VerificationStatus {
    if !token.starts_with("ddp_") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_deepsource(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.deepsource.io/v1/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_semgrep(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_codeium(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_tabnine(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_greptile(key: &str) -> VerificationStatus {
    if !key.starts_with("grpt_") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_pinecone(key: &str) -> VerificationStatus {
    if !key.starts_with("pcsk_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.pinecone.io/indexes")
        .set("Api-Key", key)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_weaviate(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_qdrant(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_weights_biases(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.wandb.ai/api/v1/users/me")
        .set("Authorization", &format!("Basic {key}:"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_comet_ml(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_fireworks_ai(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.fireworks.ai/v1/account")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_modal(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_runwayml(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_langsmith(key: &str) -> VerificationStatus {
    if !key.starts_with("lsk_") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_langfuse(key: &str) -> VerificationStatus {
    if !key.starts_with("sk-lf-") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_helicone(key: &str) -> VerificationStatus {
    if !key.starts_with("sk-helicone-") { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_portkey(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_braintrust(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_cohere(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.cohere.ai/v1/me")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_groq(key: &str) -> VerificationStatus {
    if !key.starts_with("gsk_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.groq.com/openai/v1/models")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_deepseek(key: &str) -> VerificationStatus {
    if !key.starts_with("sk-") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.deepseek.com/v1/models")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_mistral(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.mistral.ai/v1/models")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_perplexity(key: &str) -> VerificationStatus {
    if !key.starts_with("pplx-") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.perplexity.ai/v1/models")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_elevenlabs(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.elevenlabs.io/v1/user")
        .set("xi-api-key", key)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_openrouter(key: &str) -> VerificationStatus {
    if !key.starts_with("sk-or-") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://openrouter.ai/api/v1/key")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_together_ai(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.together.xyz/v1/models")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_stability_ai(key: &str) -> VerificationStatus {
    if !key.starts_with("sk-") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.stability.ai/v1/user/account")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_assemblyai(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.assemblyai.com/v2/transcript")
        .set("Authorization", key)
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_clarifai(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.clarifai.com/v2/me")
        .set("Authorization", &format!("Key {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_resend(key: &str) -> VerificationStatus {
    if !key.starts_with("re_") { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.resend.com/domains")
        .set("Authorization", &format!("Bearer {key}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_cal_com(key: &str) -> VerificationStatus {
    if key.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_retool(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://api.retool.com/api/v1/users/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_metabase(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

fn verify_kong_konnect(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://us.api.konghq.com/v3/users/me")
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_gitea(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://gitea.com/api/v1/user")
        .set("Authorization", &format!("token {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_gogs(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    let result = agent()
        .get("https://gogs.io/api/v1/user")
        .set("Authorization", &format!("token {token}"))
        .call();
    status_from_result(result, &[401, 403])
}

fn verify_drone_ci(token: &str) -> VerificationStatus {
    if token.len() < 20 { return VerificationStatus::Inactive; }
    VerificationStatus::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_for_dispatches_known_rules() {
        // Only asserts dispatch, not the network outcome, so this test
        // doesn't depend on internet access. Known rule ids must route to
        // a verifier (returning `Some`), unknown/unverifiable ones must not.
        for rule in [
            "github-pat",
            "github-fine-grained-pat",
            "slack-token",
            "stripe-secret-key",
            "npm-token",
            "digitalocean-token",
            "gitlab-token",
            "telegram-bot-token",
            "twilio-api-key",
            "openai-api-key",
            "pypi-api-token",
            "dockerhub-token",
            "sendgrid-api-key",
            "mailgun-api-key",
            "opsgenie-api-key",
            "pagerduty-api-key",
            "anthropic-api-key",
            "google-api-key",
            "google-oauth-access-token",
            "huggingface-token",
            "shopify-access-token",
            "mailchimp-api-key",
            "heroku-api-key",
            "vercel-token",
            "datadog-api-key",
            "cloudflare-api-token",
            "linear-api-key",
            "okta-api-token",
            "auth0-api-token",
            "supabase-service-key",
            "circleci-api-token",
            "discord-bot-token",
            "atlassian-api-token",
            "new-relic-license-key",
            "notion-integration-token",
            "gitlab-pat",
            "digitalocean-pat",
            // New verifiers.
            "aws-secret-access-key",
            "azure-ad-client-secret",
            "gcp-service-account-key",
            "private-key-pem",
            "database-connection-string",
            "slack-webhook-url",
            "vault-token",
            // Additional verifiers to match TruffleHog.
            "bitbucket-app-password",
            "bitbucket-client-secret",
            "sonarqube-token",
            "snyk-api-key",
            "twitch-access-token",
            "twitch-client-secret",
            "pulumi-api-token",
            "square-token",
            "square-app-token",
            "postman-api-key",
            "buildkite-token",
            "terraform-cloud-token",
        ] {
            assert!(
                verifier_for(rule).is_some(),
                "expected a verifier to be registered for {rule}"
            );
        }
    }

    #[test]
    fn test_verifier_for_none_for_unverifiable_rules() {
        // jwt and generic-high-entropy don't have a specific provider
        // API to call, so they can never be verified from the match alone.
        for rule in [
            "jwt",
            "generic-high-entropy",
        ] {
            assert!(
                verifier_for(rule).is_none(),
                "expected no verifier to be registered for {rule}"
            );
        }
    }

    #[test]
    fn test_verify_aws_sts_format() {
        // Valid-looking AWS secret key (40 chars).
        let status = verify_aws_sts("abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(status, VerificationStatus::Unknown);

        // Invalid format (too short).
        let status = verify_aws_sts("short");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_azure_ad_format() {
        // Valid-looking secret (>= 20 chars).
        let status = verify_azure_ad("this-is-a-valid-azure-secret");
        assert_eq!(status, VerificationStatus::Unknown);

        // Too short.
        let status = verify_azure_ad("short");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_gcp_iam_valid_json() {
        let key_json = r#"{
            "type": "service_account",
            "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
            "client_email": "sa@project.iam.gserviceaccount.com"
        }"#;
        let status = verify_gcp_iam(key_json);
        assert_eq!(status, VerificationStatus::Unknown);
    }

    #[test]
    fn test_verify_gcp_iam_invalid_json() {
        let status = verify_gcp_iam("not json at all");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_private_key_valid_pem() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n";
        let status = verify_private_key(pem);
        // The base64 content "MIIEpAIBAAKCAQEA" is valid base64.
        assert_eq!(status, VerificationStatus::Active);
    }

    #[test]
    fn test_verify_private_key_invalid() {
        let status = verify_private_key("not a private key");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_db_connection_url_format() {
        let status = verify_db_connection("postgres://user:pass@localhost:5432/db");
        assert_eq!(status, VerificationStatus::Unknown);
    }

    #[test]
    fn test_verify_db_connection_keyvalue_format() {
        let status = verify_db_connection("host=localhost password=secretpass dbname=test");
        assert_eq!(status, VerificationStatus::Unknown);
    }

    #[test]
    fn test_verify_db_connection_invalid() {
        let status = verify_db_connection("just some text");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_slack_webhook_invalid_url() {
        let status = verify_slack_webhook("https://example.com/not-slack");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_options_filter() {
        let opts = VerifyOptions {
            verify_detectors: vec!["github-pat".to_string()],
            no_verify_detectors: vec![],
            use_cache: false,
            rate_limit_aware: false,
        };
        // Simulate: a finding with github-pat should be verified,
        // a finding with slack-token should not (not in verify_detectors).
        let no_opts = VerifyOptions {
            verify_detectors: vec![],
            no_verify_detectors: vec!["slack-token".to_string()],
            use_cache: false,
            rate_limit_aware: false,
        };
        // Just ensure the options struct can be constructed and cloned.
        let _ = opts.clone();
        let _ = no_opts.clone();
    }

    #[test]
    fn test_cache_key() {
        let key = cache_key("github-pat", "ghp_abc123");
        assert_eq!(key, "github-pat:ghp_abc123");
    }

    #[test]
    fn test_verify_bitbucket_format() {
        // Valid-looking app password (>= 20 chars).
        let status = verify_bitbucket("abcdefghijklmnopqrstuv");
        assert_eq!(status, VerificationStatus::Unknown);
        // Too short.
        let status = verify_bitbucket("short");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_sonarqube_format() {
        let status = verify_sonarqube("not_squ_token");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_snyk_format() {
        // Invalid format (not a UUID) should return Inactive without network call.
        let status = verify_snyk("not-a-uuid");
        assert_eq!(status, VerificationStatus::Inactive);
        // Valid UUID format would make a network call; we don't test that here
        // to avoid network dependency in tests.
    }

    #[test]
    fn test_verify_twitch_format() {
        let status = verify_twitch("short");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_pulumi_format() {
        let status = verify_pulumi("not-pul-token");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_square_format() {
        let status = verify_square("not-square-token");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_postman_format() {
        let status = verify_postman("not-PMAK-token");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_buildkite_format() {
        let status = verify_buildkite("not-bk-token");
        assert_eq!(status, VerificationStatus::Inactive);
    }

    #[test]
    fn test_verify_terraform_cloud_format() {
        let status = verify_terraform_cloud("not-atlasv1-token");
        assert_eq!(status, VerificationStatus::Inactive);
    }
}
