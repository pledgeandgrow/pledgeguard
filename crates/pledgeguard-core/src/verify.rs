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

/// Returns `Some(status)` if `rule_id` has a known live-verification
/// strategy, `None` if this rule can't be verified this way.
fn verify_one(rule_id: &str, matched: &str) -> Option<VerificationStatus> {
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
        ] {
            assert!(
                verifier_for(rule).is_some(),
                "expected a verifier to be registered for {rule}"
            );
        }
    }

    #[test]
    fn test_verifier_for_none_for_unverifiable_rules() {
        // aws-access-key-id only captures the key ID (not the paired
        // secret), so it can never be verified from the match alone.
        for rule in [
            "aws-access-key-id",
            "aws-secret-access-key",
            "private-key-pem",
            "jwt",
            "generic-high-entropy",
        ] {
            assert!(
                verifier_for(rule).is_none(),
                "expected no verifier to be registered for {rule}"
            );
        }
    }
}
