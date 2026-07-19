//! AI-powered secret analysis (goals 329-340).
//!
//! Provides LLM-powered analysis of scan findings using an OpenAI-compatible
//! API. All functions are optional — they only work when an API key is
//! provided via the `PLEDGEGUARD_AI_API_KEY` environment variable (or
//! `OPENAI_API_KEY` as a fallback). When no key is available, functions
//! return structured fallback results without making network calls.
//!
//! ## Supported features
//!
//! | Goal | Function | Description |
//! |---|---|---|
//! | 329 | [`classify_finding`] | Classify ambiguous findings as real secret / false positive / uncertain |
//! | 330 | [`remediation_suggestion`] | Generate fix suggestions for a finding |
//! | 331 | [`assess_false_positive`] | LLM-based false positive assessment |
//! | 332 | [`rotation_guidance`] | Generate secret rotation steps per provider |
//! | 333 | [`risk_score`] | LLM-based risk assessment per finding |
//! | 334 | [`generate_description`] | Auto-generate descriptions for custom rules |
//! | 335 | [`generate_regex`] | Generate detector regex from examples |
//! | 336 | [`generate_tests`] | Generate test cases for custom rules |
//! | 337 | [`migrate_config`] | Migrate Gitleaks/TruffleHog configs to PledgeGuard |
//! | 338 | [`scan_summary`] | Natural language summary of scan results |
//! | 339 | [`impact_analysis`] | Assess blast radius of leaked secrets |
//! | 340 | [`prioritize_findings`] | Rank findings by exploitability and impact |

use crate::finding::{Finding, Severity, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ── Configuration ─────────────────────────────────────────────────────

/// Configuration for AI-powered analysis.
#[derive(Debug, Clone)]
pub struct AiConfig {
    /// API key for the LLM provider. If empty, all AI functions return fallbacks.
    pub api_key: String,
    /// Base URL for the API (defaults to OpenAI). Can point to any
    /// OpenAI-compatible endpoint (e.g., Anthropic, local LLM).
    pub base_url: String,
    /// Model name to use for completions.
    pub model: String,
    /// Maximum tokens for responses.
    pub max_tokens: u32,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("PLEDGEGUARD_AI_API_KEY")
                .or_else(|_| std::env::var("OPENAI_API_KEY"))
                .unwrap_or_default(),
            base_url: std::env::var("PLEDGEGUARD_AI_BASE_URL")
                .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
            model: std::env::var("PLEDGEGUARD_AI_MODEL")
                .unwrap_or_else(|_| "gpt-4o-mini".to_string()),
            max_tokens: 2048,
            timeout_secs: 30,
        }
    }
}

impl AiConfig {
    /// Returns `true` if an API key is configured and AI functions will
    /// make real LLM calls.
    pub fn is_enabled(&self) -> bool {
        !self.api_key.is_empty()
    }
}

// ── HTTP client ───────────────────────────────────────────────────────

fn agent(timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout(Duration::from_secs(timeout_secs))
        .build()
}

/// Calls the LLM API with a system prompt and user prompt, returning the
/// text response. Returns `None` on any error (network, auth, parse).
fn llm_complete(config: &AiConfig, system: &str, user: &str) -> Option<String> {
    if !config.is_enabled() {
        return None;
    }

    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user }
        ],
        "max_tokens": config.max_tokens,
        "temperature": 0.1
    });

    let resp = agent(config.timeout_secs)
        .post(&url)
        .set("Authorization", &format!("Bearer {}", config.api_key))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .ok()?;

    let json: serde_json::Value = resp.into_json().ok()?;
    json.get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()
        .map(|s| s.to_string())
}

// ── Result types ──────────────────────────────────────────────────────

/// Classification result for a finding (goal 329).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    RealSecret,
    FalsePositive,
    Uncertain,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Classification::RealSecret => write!(f, "real_secret"),
            Classification::FalsePositive => write!(f, "false_positive"),
            Classification::Uncertain => write!(f, "uncertain"),
        }
    }
}

/// AI classification result with reasoning (goal 329).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub classification: Classification,
    pub confidence: f32,
    pub reasoning: String,
    pub source: String,
}

/// Remediation suggestion for a finding (goal 330).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggestion {
    pub finding_rule_id: String,
    pub suggestion: String,
    pub source: String,
}

/// False positive assessment (goal 331).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpAssessment {
    pub is_false_positive: bool,
    pub confidence: f32,
    pub reasoning: String,
    pub source: String,
}

/// Rotation guidance for a provider (goal 332).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationGuidance {
    pub provider: String,
    pub steps: Vec<String>,
    pub source: String,
}

/// Risk score for a finding (goal 333).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u32,
    pub level: String,
    pub reasoning: String,
    pub source: String,
}

/// Generated description for a custom rule (goal 334).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedDescription {
    pub description: String,
    pub source: String,
}

/// Generated regex from examples (goal 335).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedRegex {
    pub regex: String,
    pub explanation: String,
    pub source: String,
}

/// Generated test cases for a rule (goal 336).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedTests {
    pub test_cases: Vec<TestCase>,
    pub source: String,
}

/// A single test case for a detector rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub input: String,
    pub should_match: bool,
    pub description: String,
}

/// Config migration result (goal 337).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMigration {
    pub pledgeguard_config: String,
    pub notes: Vec<String>,
    pub source: String,
}

/// Scan summary in natural language (goal 338).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub summary: String,
    pub source: String,
}

/// Impact analysis for leaked secrets (goal 339).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    pub finding_rule_id: String,
    pub blast_radius: String,
    pub affected_services: Vec<String>,
    pub recommendations: Vec<String>,
    pub source: String,
}

/// Prioritized finding (goal 340).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedFinding {
    pub rule_id: String,
    pub path: String,
    pub priority: u32,
    pub exploitability: String,
    pub impact: String,
    pub reasoning: String,
    pub source: String,
}

// ── AI functions ──────────────────────────────────────────────────────

const FALLBACK: &str = "fallback";

/// Classify a finding as real secret, false positive, or uncertain (goal 329).
pub fn classify_finding(config: &AiConfig, finding: &Finding) -> ClassificationResult {
    let system = "You are a security expert analyzing secret scanner findings. Classify each finding as 'real_secret', 'false_positive', or 'uncertain'. Respond in JSON: {\"classification\": \"...\", \"confidence\": 0.0-1.0, \"reasoning\": \"...\"}";

    let user = format!(
        "Rule: {}\nDescription: {}\nSeverity: {}\nFile: {}\nLine: {}\nMatched (redacted): {}\nContext: {}\nLikely FP (heuristic): {}",
        finding.rule_id,
        finding.description,
        finding.severity,
        finding.path.display(),
        finding.line,
        crate::redact::redact(&finding.matched),
        crate::redact::redact_in(&finding.context, &finding.matched),
        finding.likely_false_positive,
    );

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(result) = serde_json::from_str::<ClassificationResult>(&text)
    {
        let mut result = result;
        result.source = "llm".to_string();
        return result;
    }

    ClassificationResult {
        classification: if finding.likely_false_positive {
            Classification::FalsePositive
        } else {
            Classification::Uncertain
        },
        confidence: 0.3,
        reasoning: "No LLM available; using heuristic-based fallback.".to_string(),
        source: FALLBACK.to_string(),
    }
}

/// Generate remediation suggestion for a finding (goal 330).
pub fn remediation_suggestion(config: &AiConfig, finding: &Finding) -> RemediationSuggestion {
    let system = "You are a security expert. Provide a concise remediation suggestion for the detected secret. Respond in JSON: {\"suggestion\": \"...\"}";

    let user = format!(
        "Rule: {}\nDescription: {}\nSeverity: {}\nFile: {}:{}\nContext: {}",
        finding.rule_id,
        finding.description,
        finding.severity,
        finding.path.display(),
        finding.line,
        crate::redact::redact_in(&finding.context, &finding.matched),
    );

    let suggestion = llm_complete(config, system, &user)
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("suggestion")?.as_str().map(|s| s.to_string()))
        })
        .unwrap_or_else(|| {
            format!(
                "Remove the {} from the source code and store it in a secure secret manager or environment variable. Rotate the secret if it was committed to version control.",
                finding.description
            )
        });

    RemediationSuggestion {
        finding_rule_id: finding.rule_id.clone(),
        suggestion,
        source: if config.is_enabled() { "llm".to_string() } else { FALLBACK.to_string() },
    }
}

/// Assess whether a finding is a false positive (goal 331).
pub fn assess_false_positive(config: &AiConfig, finding: &Finding) -> FpAssessment {
    let system = "You are a security expert assessing whether a secret scanner finding is a false positive. Consider: is the value a placeholder/example/test token? Is it in a comment or documentation? Is the format valid? Respond in JSON: {\"is_false_positive\": true/false, \"confidence\": 0.0-1.0, \"reasoning\": \"...\"}";

    let user = format!(
        "Rule: {}\nMatched (redacted): {}\nContext: {}\nHeuristic FP flag: {}\nFile: {}",
        finding.rule_id,
        crate::redact::redact(&finding.matched),
        crate::redact::redact_in(&finding.context, &finding.matched),
        finding.likely_false_positive,
        finding.path.display(),
    );

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
    {
        return FpAssessment {
            is_false_positive: v.get("is_false_positive").and_then(|b| b.as_bool()).unwrap_or(false),
            confidence: v.get("confidence").and_then(|c| c.as_f64()).map(|f| f as f32).unwrap_or(0.5),
            reasoning: v.get("reasoning").and_then(|r| r.as_str()).unwrap_or("").to_string(),
            source: "llm".to_string(),
        };
    }

    FpAssessment {
        is_false_positive: finding.likely_false_positive,
        confidence: 0.3,
        reasoning: "No LLM available; using heuristic-based fallback.".to_string(),
        source: FALLBACK.to_string(),
    }
}

/// Generate rotation guidance for a provider (goal 332).
pub fn rotation_guidance(config: &AiConfig, rule_id: &str) -> RotationGuidance {
    let system = "You are a security expert. Provide step-by-step instructions for rotating a leaked secret. Respond in JSON: {\"steps\": [\"step1\", \"step2\", ...]}";

    let user = format!("Provider/Rule: {rule_id}\nProvide rotation steps for this type of secret.");

    let steps = llm_complete(config, system, &user)
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("steps")?.as_array().map(|arr| {
                    arr.iter().filter_map(|s| s.as_str().map(String::from)).collect()
                }))
        })
        .unwrap_or_else(|| {
            vec![
                format!("1. Log in to the {rule_id} provider's dashboard or admin console."),
                "2. Navigate to the API keys, tokens, or credentials section.".to_string(),
                "3. Revoke or delete the leaked secret.".to_string(),
                "4. Create a new secret with the same or tighter permissions.".to_string(),
                "5. Update all applications and services that use the secret with the new value.".to_string(),
                "6. Store the new secret in a secure secret manager (e.g., Vault, AWS Secrets Manager).".to_string(),
                "7. Verify that the old secret no longer works.".to_string(),
            ]
        });

    RotationGuidance {
        provider: rule_id.to_string(),
        steps,
        source: if config.is_enabled() { "llm".to_string() } else { FALLBACK.to_string() },
    }
}

/// Score the risk of a finding (goal 333).
pub fn risk_score(config: &AiConfig, finding: &Finding) -> RiskScore {
    let system = "You are a security expert. Score the risk of a leaked secret on a scale of 1-100. Consider: severity, provider, exploitability, whether it's verified active. Respond in JSON: {\"score\": 1-100, \"level\": \"low\"/\"medium\"/\"high\"/\"critical\", \"reasoning\": \"...\"}";

    let verified = finding
        .verification
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "not_verified".to_string());

    let user = format!(
        "Rule: {}\nSeverity: {}\nVerified: {}\nFile: {}\nDescription: {}",
        finding.rule_id,
        finding.severity,
        verified,
        finding.path.display(),
        finding.description,
    );

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
    {
        let score = v.get("score").and_then(|s| s.as_u64()).unwrap_or(50) as u32;
        return RiskScore {
            score,
            level: v.get("level").and_then(|l| l.as_str()).unwrap_or("medium").to_string(),
            reasoning: v.get("reasoning").and_then(|r| r.as_str()).unwrap_or("").to_string(),
            source: "llm".to_string(),
        };
    }

    let score = match finding.severity {
        Severity::Critical => 90,
        Severity::High => 70,
        Severity::Medium => 50,
        Severity::Low => 25,
    };
    let level = match finding.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    };
    RiskScore {
        score,
        level: level.to_string(),
        reasoning: "No LLM available; using severity-based fallback.".to_string(),
        source: FALLBACK.to_string(),
    }
}

/// Generate a description for a custom rule (goal 334).
pub fn generate_description(config: &AiConfig, rule_id: &str, pattern: &str) -> GeneratedDescription {
    let system = "You are a security expert. Generate a concise human-readable description for a secret detector rule. Respond in JSON: {\"description\": \"...\"}";

    let user = format!("Rule ID: {rule_id}\nRegex pattern: {pattern}\nGenerate a description.");

    let description = llm_complete(config, system, &user)
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("description")?.as_str().map(|s| s.to_string()))
        })
        .unwrap_or_else(|| format!("Detector for {rule_id} pattern"));

    GeneratedDescription {
        description,
        source: if config.is_enabled() { "llm".to_string() } else { FALLBACK.to_string() },
    }
}

/// Generate a regex pattern from example secrets (goal 335).
pub fn generate_regex(config: &AiConfig, rule_name: &str, examples: &[&str]) -> GeneratedRegex {
    let system = "You are a security expert and regex specialist. Generate a regex pattern that matches the given example secrets. The regex should be specific enough to avoid false positives. Respond in JSON: {\"regex\": \"...\", \"explanation\": \"...\"}";

    let examples_str = examples.iter().map(|e| format!("- {e}")).collect::<Vec<_>>().join("\n");
    let user = format!("Rule name: {rule_name}\nExamples:\n{examples_str}\nGenerate a regex pattern.");

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
    {
        return GeneratedRegex {
            regex: v.get("regex").and_then(|r| r.as_str()).unwrap_or("").to_string(),
            explanation: v.get("explanation").and_then(|e| e.as_str()).unwrap_or("").to_string(),
            source: "llm".to_string(),
        };
    }

    GeneratedRegex {
        regex: r"[A-Za-z0-9]{20,}".to_string(),
        explanation: "Fallback generic high-entropy pattern. Provide an API key for LLM-generated regex.".to_string(),
        source: FALLBACK.to_string(),
    }
}

/// Generate test cases for a custom rule (goal 336).
pub fn generate_tests(config: &AiConfig, rule_id: &str, pattern: &str) -> GeneratedTests {
    let system = "You are a security expert. Generate test cases for a secret detector rule. Include both positive (should match) and negative (should not match) cases. Respond in JSON: {\"test_cases\": [{\"input\": \"...\", \"should_match\": true/false, \"description\": \"...\"}]}";

    let user = format!("Rule ID: {rule_id}\nRegex pattern: {pattern}\nGenerate test cases.");

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(result) = serde_json::from_str::<GeneratedTests>(&text)
    {
        let mut result = result;
        result.source = "llm".to_string();
        return result;
    }

    GeneratedTests {
        test_cases: vec![
            TestCase {
                input: format!("{}=REDACTED_EXAMPLE_VALUE", rule_id),
                should_match: true,
                description: "Basic positive test case".to_string(),
            },
            TestCase {
                input: "example=value".to_string(),
                should_match: false,
                description: "Generic non-matching case".to_string(),
            },
        ],
        source: FALLBACK.to_string(),
    }
}

/// Migrate a Gitleaks or TruffleHog config to PledgeGuard format (goal 337).
pub fn migrate_config(config: &AiConfig, source_format: &str, source_config: &str) -> ConfigMigration {
    let system = "You are a security expert. Convert a secret scanner configuration from one format to PledgeGuard's TOML format. PledgeGuard uses [[rules]] sections with id, description, severity, and pattern fields. Respond in JSON: {\"pledgeguard_config\": \"...\", \"notes\": [\"...\"]}";

    let user = format!("Source format: {source_format}\nSource config:\n{source_config}\nConvert to PledgeGuard TOML format.");

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
    {
        return ConfigMigration {
            pledgeguard_config: v.get("pledgeguard_config").and_then(|c| c.as_str()).unwrap_or("").to_string(),
            notes: v.get("notes")
                .and_then(|n| n.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            source: "llm".to_string(),
        };
    }

    ConfigMigration {
        pledgeguard_config: source_config.to_string(),
        notes: vec![
            "Automatic migration requires an AI API key.".to_string(),
            "Please manually review and convert the config to PledgeGuard TOML format.".to_string(),
            format!("See PledgeGuard docs for [[rules]] syntax. Source format was: {source_format}"),
        ],
        source: FALLBACK.to_string(),
    }
}

/// Generate a natural language summary of scan results (goal 338).
pub fn scan_summary(config: &AiConfig, findings: &[Finding]) -> ScanSummary {
    let system = "You are a security expert. Summarize secret scan results in clear, actionable language for a developer. Highlight the most critical findings and recommended actions. Respond in JSON: {\"summary\": \"...\"}";

    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
    let verified_active = findings
        .iter()
        .filter(|f| f.verification == Some(VerificationStatus::Active))
        .count();

    let rules: Vec<String> = findings
        .iter()
        .map(|f| f.rule_id.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let user = format!(
        "Total findings: {}\nCritical: {}\nHigh: {}\nMedium: {}\nLow: {}\nVerified active: {}\nUnique rules: {}\nTop rules: {}\nProvide a summary.",
        findings.len(),
        critical,
        high,
        medium,
        low,
        verified_active,
        rules.len(),
        rules.iter().take(10).cloned().collect::<Vec<_>>().join(", "),
    );

    let summary = llm_complete(config, system, &user)
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("summary")?.as_str().map(|s| s.to_string()))
        })
        .unwrap_or_else(|| {
            let mut s = format!(
                "Scan complete: {} finding(s) — {} critical, {} high, {} medium, {} low.",
                findings.len(), critical, high, medium, low
            );
            if verified_active > 0 {
                s.push_str(&format!(" {verified_active} finding(s) verified as active — rotate these immediately."));
            }
            if critical > 0 {
                s.push_str(" Critical findings require immediate attention.");
            } else if high > 0 {
                s.push_str(" High-severity findings should be addressed urgently.");
            } else if findings.is_empty() {
                s.push_str(" No secrets detected — your codebase appears clean.");
            }
            s
        });

    ScanSummary {
        summary,
        source: if config.is_enabled() { "llm".to_string() } else { FALLBACK.to_string() },
    }
}

/// Assess the blast radius of a leaked secret (goal 339).
pub fn impact_analysis(config: &AiConfig, finding: &Finding) -> ImpactAnalysis {
    let system = "You are a security expert. Assess the blast radius and impact of a leaked secret. Consider: what services are affected, what data could be exposed, what actions could an attacker take. Respond in JSON: {\"blast_radius\": \"...\", \"affected_services\": [\"...\"], \"recommendations\": [\"...\"]}";

    let verified = finding
        .verification
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "not_verified".to_string());

    let user = format!(
        "Rule: {}\nDescription: {}\nSeverity: {}\nVerified: {}\nFile: {}\nAssess the impact.",
        finding.rule_id,
        finding.description,
        finding.severity,
        verified,
        finding.path.display(),
    );

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
    {
        return ImpactAnalysis {
            finding_rule_id: finding.rule_id.clone(),
            blast_radius: v.get("blast_radius").and_then(|b| b.as_str()).unwrap_or("").to_string(),
            affected_services: v.get("affected_services")
                .and_then(|s| s.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            recommendations: v.get("recommendations")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            source: "llm".to_string(),
        };
    }

    let affected = vec![finding.rule_id.split('-').next().unwrap_or("unknown").to_string()];
    let recommendations = vec![
        "Rotate the secret immediately if it was committed to version control.".to_string(),
        "Review access logs for unauthorized usage.".to_string(),
        "Update all services that use this secret with a new value.".to_string(),
    ];

    ImpactAnalysis {
        finding_rule_id: finding.rule_id.clone(),
        blast_radius: format!("Potential unauthorized access to {} services.", finding.description),
        affected_services: affected,
        recommendations,
        source: FALLBACK.to_string(),
    }
}

/// Prioritize findings by exploitability and impact (goal 340).
pub fn prioritize_findings(config: &AiConfig, findings: &[Finding]) -> Vec<PrioritizedFinding> {
    let system = "You are a security expert. Prioritize secret findings by exploitability and impact. Higher priority = more urgent. Respond in JSON: {\"findings\": [{\"rule_id\": \"...\", \"path\": \"...\", \"priority\": 1-100, \"exploitability\": \"...\", \"impact\": \"...\", \"reasoning\": \"...\"}]}";

    let findings_json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "rule_id": f.rule_id,
                "severity": f.severity.to_string(),
                "path": f.path.display().to_string(),
                "verified": f.verification.as_ref().map(|v| v.to_string()).unwrap_or("not_verified".to_string()),
            })
        })
        .collect();

    let user = format!(
        "Findings to prioritize:\n{}\nRank by exploitability and impact.",
        serde_json::to_string_pretty(&findings_json).unwrap_or_default()
    );

    if let Some(text) = llm_complete(config, system, &user)
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(arr) = v.get("findings").and_then(|f| f.as_array())
    {
        let results: Vec<PrioritizedFinding> = arr
            .iter()
            .filter_map(|item| {
                Some(PrioritizedFinding {
                    rule_id: item.get("rule_id")?.as_str()?.to_string(),
                    path: item.get("path")?.as_str()?.to_string(),
                    priority: item.get("priority")?.as_u64()? as u32,
                    exploitability: item.get("exploitability")?.as_str()?.to_string(),
                    impact: item.get("impact")?.as_str()?.to_string(),
                    reasoning: item.get("reasoning")?.as_str()?.to_string(),
                    source: "llm".to_string(),
                })
            })
            .collect();
        if !results.is_empty() {
            return results;
        }
    }

    // Fallback: sort by severity, verified-active first.
    let mut sorted: Vec<(usize, &Finding)> = findings.iter().enumerate().collect();
    sorted.sort_by(|(_, a), (_, b)| {
        let a_active = a.verification == Some(VerificationStatus::Active);
        let b_active = b.verification == Some(VerificationStatus::Active);
        b_active
            .cmp(&a_active)
            .then(b.severity.cmp(&a.severity))
    });

    sorted
        .iter()
        .map(|(idx, f)| PrioritizedFinding {
            rule_id: f.rule_id.clone(),
            path: f.path.display().to_string(),
            priority: match f.severity {
                Severity::Critical => 90 - (*idx as u32).min(20),
                Severity::High => 70 - (*idx as u32).min(20),
                Severity::Medium => 50 - (*idx as u32).min(20),
                Severity::Low => 25 - (*idx as u32).min(10),
            },
            exploitability: if f.verification == Some(VerificationStatus::Active) {
                "high".to_string()
            } else {
                "medium".to_string()
            },
            impact: f.severity.to_string(),
            reasoning: "Severity-based fallback ranking.".to_string(),
            source: FALLBACK.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mock_finding() -> Finding {
        Finding {
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            severity: Severity::Critical,
            path: PathBuf::from("config.env"),
            line: 1,
            column: 1,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }
    }

    #[test]
    fn test_classify_finding_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let finding = mock_finding();
        let result = classify_finding(&config, &finding);
        assert_eq!(result.source, "fallback");
        assert_eq!(result.classification, Classification::Uncertain);
    }

    #[test]
    fn test_remediation_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let finding = mock_finding();
        let result = remediation_suggestion(&config, &finding);
        assert_eq!(result.source, "fallback");
        assert!(result.suggestion.contains("secret manager"));
    }

    #[test]
    fn test_rotation_guidance_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let result = rotation_guidance(&config, "github-pat");
        assert_eq!(result.source, "fallback");
        assert!(!result.steps.is_empty());
    }

    #[test]
    fn test_risk_score_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let finding = mock_finding();
        let result = risk_score(&config, &finding);
        assert_eq!(result.source, "fallback");
        assert_eq!(result.score, 90);
        assert_eq!(result.level, "critical");
    }

    #[test]
    fn test_scan_summary_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let findings = vec![mock_finding()];
        let result = scan_summary(&config, &findings);
        assert_eq!(result.source, "fallback");
        assert!(result.summary.contains("1 finding"));
    }

    #[test]
    fn test_prioritize_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let findings = vec![mock_finding()];
        let result = prioritize_findings(&config, &findings);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source, "fallback");
        assert!(result[0].priority > 0);
    }

    #[test]
    fn test_generate_regex_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let result = generate_regex(&config, "test-rule", &["AKIA1234567890ABCD"]);
        assert_eq!(result.source, "fallback");
        assert!(!result.regex.is_empty());
    }

    #[test]
    fn test_impact_analysis_fallback() {
        let config = AiConfig { api_key: String::new(), ..Default::default() };
        let finding = mock_finding();
        let result = impact_analysis(&config, &finding);
        assert_eq!(result.source, "fallback");
        assert!(!result.recommendations.is_empty());
    }
}
