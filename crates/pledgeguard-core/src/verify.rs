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
