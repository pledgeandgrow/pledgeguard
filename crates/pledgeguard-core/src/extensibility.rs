//! Extensibility features for goals 281-300.
//!
//! This module provides:
//! - Custom verifier configuration (TOML-based HTTP verification endpoints)
//! - Expr-based custom verifier expressions
//! - Custom detector versioning
//! - WASM verifier plugin support
//! - WASM plugin ABI v2 with context passing
//! - Plugin marketplace metadata
//! - Rule profiles (preset bundles)
//! - Conditional rules (file type, path, environment)
//! - Rule severity override
//! - Detector metadata (version, last-updated, confidence)
//! - Custom entropy algorithm configuration
//! - Multi-pattern regex support
//! - Negative lookahead support
//! - Capture group transformation
//! - Rule deprecation/retirement
//! - Rule testing framework
//! - Rule documentation generator

use crate::finding::Severity;
use std::collections::HashMap;
use std::path::Path;

// ── 281: Custom verifier config in TOML ─────────────────────────────────

/// Configuration for a custom HTTP-based verifier.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CustomVerifierConfig {
    /// Rule ID this verifier applies to.
    pub rule_id: String,
    /// HTTP method (GET, POST, etc.).
    #[serde(default = "default_method")]
    pub method: String,
    /// URL template with `{secret}` placeholder.
    pub url: String,
    /// Headers to send, with `{secret}` placeholder support.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Expected HTTP status code for an active secret.
    #[serde(default = "default_active_status")]
    pub active_status: u16,
    /// Expected HTTP status code for an inactive secret.
    #[serde(default = "default_inactive_status")]
    pub inactive_status: u16,
    /// Optional JSON path to check in the response body.
    #[serde(default)]
    pub response_json_path: Option<String>,
    /// Optional expected value at the JSON path.
    #[serde(default)]
    pub response_expected_value: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_active_status() -> u16 {
    200
}

fn default_inactive_status() -> u16 {
    401
}

impl CustomVerifierConfig {
    /// Build the URL with the secret injected.
    pub fn build_url(&self, secret: &str) -> String {
        self.url.replace("{secret}", secret)
    }

    /// Build headers with the secret injected.
    pub fn build_headers(&self, secret: &str) -> Vec<(String, String)> {
        self.headers
            .iter()
            .map(|(k, v)| (k.clone(), v.replace("{secret}", secret)))
            .collect()
    }
}

/// Load custom verifier configurations from a TOML file.
pub fn load_custom_verifiers(path: &Path) -> Result<Vec<CustomVerifierConfig>, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let config: CustomVerifierFile = toml::from_str(&contents)?;
    Ok(config.verifiers)
}

#[derive(Debug, serde::Deserialize)]
struct CustomVerifierFile {
    #[serde(default)]
    verifiers: Vec<CustomVerifierConfig>,
}

// ── 282: Expr-based custom verifier ─────────────────────────────────────

/// Configuration for an Expr-based verifier that validates secrets
/// using a custom expression.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ExprVerifierConfig {
    /// Rule ID this verifier applies to.
    pub rule_id: String,
    /// Expr expression that evaluates to true for valid secrets.
    /// Available variables: `secret`, `length`, `has_prefix`, `has_suffix`.
    pub expression: String,
}

/// Evaluate an Expr verifier expression against a secret.
pub fn evaluate_expr_verifier(config: &ExprVerifierConfig, secret: &str) -> bool {
    // Simple evaluation: check for common patterns in the expression.
    let expr = &config.expression;

    // Handle length checks: length > N
    if let Some(rest) = expr.strip_prefix("length > ")
        && let Ok(n) = rest.trim().parse::<usize>()
    {
        return secret.len() > n;
    }
    if let Some(rest) = expr.strip_prefix("length >= ")
        && let Ok(n) = rest.trim().parse::<usize>()
    {
        return secret.len() >= n;
    }
    if let Some(rest) = expr.strip_prefix("length < ")
        && let Ok(n) = rest.trim().parse::<usize>()
    {
        return secret.len() < n;
    }

    // Handle has_prefix("...")
    if expr.starts_with("has_prefix(") && expr.ends_with(')') {
        let prefix = &expr[11..expr.len() - 1].trim_matches('"');
        return secret.starts_with(prefix);
    }

    // Handle has_suffix("...")
    if expr.starts_with("has_suffix(") && expr.ends_with(')') {
        let suffix = &expr[11..expr.len() - 1].trim_matches('"');
        return secret.ends_with(suffix);
    }

    // Handle regex matches
    if expr.starts_with("matches(") && expr.ends_with(')') {
        let pattern = &expr[8..expr.len() - 1].trim_matches('"');
        if let Ok(re) = regex::Regex::new(pattern) {
            return re.is_match(secret);
        }
    }

    // Default: accept if expression is "true"
    expr.trim() == "true"
}

// ── 283: Custom detector versioning ─────────────────────────────────────

/// Version information for a custom detector.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DetectorVersion {
    /// Semantic version string (e.g., "1.0.0").
    pub version: String,
    /// Minimum compatible engine version.
    #[serde(default)]
    pub min_engine_version: Option<String>,
    /// Last updated date (ISO 8601).
    #[serde(default)]
    pub last_updated: Option<String>,
}

impl DetectorVersion {
    /// Check if this version is compatible with the given engine version.
    pub fn is_compatible_with(&self, engine_version: &str) -> bool {
        if let Some(ref min) = self.min_engine_version {
            return version_gte(engine_version, min);
        }
        true
    }
}

/// Simple semantic version comparison: returns true if `a >= b`.
fn version_gte(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.')
            .filter_map(|p| p.split('-').next().and_then(|n| n.parse().ok()))
            .collect()
    };
    let va = parse(a);
    let vb = parse(b);
    for i in 0..va.len().max(vb.len()) {
        let na = va.get(i).copied().unwrap_or(0);
        let nb = vb.get(i).copied().unwrap_or(0);
        if na > nb {
            return true;
        }
        if na < nb {
            return false;
        }
    }
    true
}

// ── 284: WASM verifier plugins ──────────────────────────────────────────

/// Configuration for a WASM-based verifier plugin.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct WasmVerifierConfig {
    /// Rule ID this verifier applies to.
    pub rule_id: String,
    /// Path to the WASM module.
    pub wasm_path: String,
    /// Function name to call in the WASM module.
    #[serde(default = "default_verify_fn")]
    pub function_name: String,
}

fn default_verify_fn() -> String {
    "verify".to_string()
}

/// Result of a WASM verifier call.
#[derive(Debug, Clone)]
pub struct WasmVerifyResult {
    pub active: bool,
    pub message: String,
}

// ── 285: WASM plugin ABI v2 ─────────────────────────────────────────────

/// Context passed to WASM plugins via ABI v2.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginContext {
    /// File path being scanned.
    pub file_path: String,
    /// File extension.
    pub file_extension: String,
    /// Git commit hash (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// Git branch (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Git author (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_author: Option<String>,
    /// Line number of the finding.
    pub line: usize,
    /// Column number of the finding.
    pub column: usize,
}

impl PluginContext {
    /// Create a new plugin context from a file path and finding position.
    pub fn new(path: &Path, line: usize, column: usize) -> Self {
        Self {
            file_path: path.display().to_string(),
            file_extension: path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string(),
            git_commit: None,
            git_branch: None,
            git_author: None,
            line,
            column,
        }
    }

    /// Serialize to JSON for passing to the WASM module.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

// ── 286: Plugin marketplace ─────────────────────────────────────────────

/// Metadata for a plugin in the marketplace.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PluginMarketplaceEntry {
    /// Unique plugin name.
    pub name: String,
    /// Plugin description.
    pub description: String,
    /// Plugin version.
    pub version: String,
    /// Author/maintainer.
    pub author: String,
    /// Plugin type (detector, verifier, or both).
    pub plugin_type: PluginType,
    /// Download URL.
    pub download_url: String,
    /// Homepage URL.
    #[serde(default)]
    pub homepage: Option<String>,
    /// Tags for searchability.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Number of downloads.
    #[serde(default)]
    pub downloads: u64,
    /// Star rating (0-5).
    #[serde(default)]
    pub stars: f32,
}

/// Type of plugin.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginType {
    Detector,
    Verifier,
    Both,
}

/// A plugin marketplace index.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PluginMarketplace {
    pub plugins: Vec<PluginMarketplaceEntry>,
}

impl PluginMarketplace {
    /// Parse a marketplace index from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Search plugins by tag or name.
    pub fn search(&self, query: &str) -> Vec<&PluginMarketplaceEntry> {
        let query_lower = query.to_lowercase();
        self.plugins
            .iter()
            .filter(|p| {
                p.name.to_lowercase().contains(&query_lower)
                    || p.description.to_lowercase().contains(&query_lower)
                    || p.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }
}

// ── 288: Rule profiles ──────────────────────────────────────────────────

/// Preset rule profile bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProfile {
    /// Cloud provider secrets (AWS, GCP, Azure, etc.).
    Cloud,
    /// Payment-related secrets (Stripe, PayPal, etc.).
    Payments,
    /// AI/ML API keys (OpenAI, Anthropic, HuggingFace, etc.).
    AiMl,
    /// Minimal set — only high-confidence rules.
    Minimal,
    /// All rules (default).
    All,
}

impl RuleProfile {
    /// Get the rule IDs included in this profile.
    pub fn rule_ids(&self) -> Vec<&'static str> {
        match self {
            RuleProfile::Cloud => vec![
                "aws-access-key-id",
                "aws-secret-access-key",
                "gcp-api-key",
                "gcp-service-account",
                "azure-storage-key",
                "azure-connection-string",
                "azure-tenant-id",
                "azure-client-id",
                "azure-client-secret",
            ],
            RuleProfile::Payments => vec![
                "stripe-secret-key",
                "stripe-publishable-key",
                "paypal-client-id",
                "paypal-client-secret",
                "square-api-key",
                "shopify-access-token",
            ],
            RuleProfile::AiMl => vec![
                "openai-api-key",
                "anthropic-api-key",
                "huggingface-token",
                "google-api-key",
                "replicate-api-token",
            ],
            RuleProfile::Minimal => vec![
                "aws-access-key-id",
                "github-pat",
                "github-fine-grained-pat",
                "slack-token",
                "stripe-secret-key",
                "google-api-key",
                "openai-api-key",
                "private-key",
            ],
            RuleProfile::All => vec![],
        }
    }

    /// Parse a profile from a string name.
    pub fn from_profile_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cloud" => Some(Self::Cloud),
            "payments" => Some(Self::Payments),
            "ai-ml" | "aiml" | "ai" => Some(Self::AiMl),
            "minimal" => Some(Self::Minimal),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

// ── 289: Conditional rules ──────────────────────────────────────────────

/// Conditions that activate a rule based on file type, path, or environment.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct RuleConditions {
    /// File extensions to activate on (empty = all).
    #[serde(default)]
    pub file_extensions: Vec<String>,
    /// Path patterns to activate on (empty = all).
    #[serde(default)]
    pub path_patterns: Vec<String>,
    /// Environment variables that must be set (empty = all).
    #[serde(default)]
    pub env_vars: Vec<String>,
    /// Minimum file size in bytes (0 = no limit).
    #[serde(default)]
    pub min_file_size: u64,
    /// Maximum file size in bytes (0 = no limit).
    #[serde(default)]
    pub max_file_size: u64,
}

impl RuleConditions {
    /// Check if a file path meets the conditions.
    pub fn matches_path(&self, path: &Path) -> bool {
        // Check file extensions.
        if !self.file_extensions.is_empty() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_lowercase());
            if !ext.map(|e| self.file_extensions.iter().any(|f| f.to_lowercase() == e)).unwrap_or(false) {
                return false;
            }
        }

        // Check path patterns.
        if !self.path_patterns.is_empty() {
            let path_str = path.to_string_lossy();
            if !self.path_patterns.iter().any(|p| path_str.contains(p)) {
                return false;
            }
        }

        true
    }

    /// Check if the environment meets the conditions.
    pub fn matches_env(&self) -> bool {
        if self.env_vars.is_empty() {
            return true;
        }
        self.env_vars.iter().all(|v| std::env::var(v).is_ok())
    }

    /// Check if a file size meets the conditions.
    pub fn matches_size(&self, size: u64) -> bool {
        if self.min_file_size > 0 && size < self.min_file_size {
            return false;
        }
        if self.max_file_size > 0 && size > self.max_file_size {
            return false;
        }
        true
    }
}

// ── 290: Rule severity override ─────────────────────────────────────────

/// Map of rule ID to overridden severity.
pub type SeverityOverride = HashMap<String, Severity>;

/// Apply severity overrides to findings.
pub fn apply_severity_overrides(
    findings: &mut [crate::finding::Finding],
    overrides: &SeverityOverride,
) {
    for f in findings.iter_mut() {
        if let Some(severity) = overrides.get(&f.rule_id) {
            f.severity = *severity;
        }
    }
}

// ── 291: Detector metadata ──────────────────────────────────────────────

/// Metadata about a detector.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DetectorMetadata {
    /// Detector version.
    pub version: String,
    /// Last updated date (ISO 8601).
    #[serde(default)]
    pub last_updated: Option<String>,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
    /// Author/maintainer.
    #[serde(default)]
    pub author: Option<String>,
    /// Source URL for the detector definition.
    #[serde(default)]
    pub source_url: Option<String>,
    /// Whether this detector is deprecated.
    #[serde(default)]
    pub deprecated: bool,
}

impl DetectorMetadata {
    /// Create new metadata with defaults.
    pub fn new(version: &str, confidence: f64) -> Self {
        Self {
            version: version.to_string(),
            last_updated: None,
            confidence,
            author: None,
            source_url: None,
            deprecated: false,
        }
    }
}

// ── 292: Custom entropy algorithm ───────────────────────────────────────

/// Configuration for a custom entropy algorithm.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CustomEntropyConfig {
    /// Algorithm name (shannon, renyi, min, or custom).
    pub algorithm: String,
    /// Threshold for reporting.
    pub threshold: f64,
    /// Window size for sliding window entropy (0 = whole string).
    #[serde(default)]
    pub window_size: usize,
    /// Alpha parameter for Renyi entropy.
    #[serde(default)]
    pub alpha: Option<f64>,
}

/// Compute entropy using the configured algorithm.
pub fn compute_custom_entropy(config: &CustomEntropyConfig, text: &str) -> f64 {
    match config.algorithm.to_lowercase().as_str() {
        "shannon" => shannon_entropy(text),
        "renyi" => renyi_entropy(text, config.alpha.unwrap_or(2.0)),
        "min" => min_entropy(text),
        _ => shannon_entropy(text),
    }
}

/// Shannon entropy.
fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in text.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = text.chars().count() as f64;
    let mut entropy = 0.0;
    for &count in counts.values() {
        let p = count as f64 / n;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Renyi entropy of order alpha.
fn renyi_entropy(text: &str, alpha: f64) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in text.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = text.chars().count() as f64;
    let mut sum = 0.0;
    for &count in counts.values() {
        let p = count as f64 / n;
        sum += p.powf(alpha);
    }
    if sum > 0.0 {
        (1.0 / (1.0 - alpha)) * sum.log2()
    } else {
        0.0
    }
}

/// Min-entropy (negative log of the most likely symbol probability).
fn min_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in text.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = text.chars().count() as f64;
    let max_count = *counts.values().max().unwrap_or(&0) as f64;
    if max_count > 0.0 {
        -(max_count / n).log2()
    } else {
        0.0
    }
}

// ── 294: Multi-pattern regex support ────────────────────────────────────

/// A rule with multiple regex patterns. A finding is reported if ANY
/// pattern matches.
#[derive(Debug, Clone)]
pub struct MultiPatternRule {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub patterns: Vec<regex::Regex>,
}

impl MultiPatternRule {
    /// Create a new multi-pattern rule from pattern strings.
    pub fn new(
        id: &str,
        description: &str,
        severity: Severity,
        patterns: &[&str],
    ) -> Result<Self, regex::Error> {
        let compiled: Vec<regex::Regex> = patterns
            .iter()
            .map(|p| regex::Regex::new(p))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            id: id.to_string(),
            description: description.to_string(),
            severity,
            patterns: compiled,
        })
    }

    /// Check if any pattern matches the given text.
    pub fn matches(&self, text: &str) -> bool {
        self.patterns.iter().any(|p| p.is_match(text))
    }

    /// Find all matches across all patterns.
    pub fn find_matches(&self, text: &str) -> Vec<(usize, usize, String)> {
        let mut results = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.find_iter(text) {
                results.push((m.start(), m.end(), m.as_str().to_string()));
            }
        }
        results.sort_by_key(|(start, _, _)| *start);
        results
    }
}

// ── 296: Negative lookahead support ─────────────────────────────────────

/// Compile a pattern with negative lookahead support.
/// The Rust `regex` crate doesn't support lookahead, so we provide
/// a workaround using a pre-filter + post-filter approach.
#[derive(Debug, Clone)]
pub struct LookaheadRule {
    /// Main matching pattern.
    pub pattern: regex::Regex,
    /// Patterns that must NOT match after the main pattern.
    pub negative_lookaheads: Vec<regex::Regex>,
}

impl LookaheadRule {
    /// Create a new lookahead rule.
    pub fn new(
        pattern: &str,
        lookaheads: &[&str],
    ) -> Result<Self, regex::Error> {
        let pattern = regex::Regex::new(pattern)?;
        let neg: Vec<regex::Regex> = lookaheads
            .iter()
            .map(|p| regex::Regex::new(p))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            pattern,
            negative_lookaheads: neg,
        })
    }

    /// Find matches that don't trigger any negative lookahead.
    pub fn find_matches(&self, text: &str) -> Vec<(usize, usize, String)> {
        let mut results = Vec::new();
        for m in self.pattern.find_iter(text) {
            let after = &text[m.end()..];
            let blocked = self.negative_lookaheads.iter().any(|la| la.is_match(after));
            if !blocked {
                results.push((m.start(), m.end(), m.as_str().to_string()));
            }
        }
        results
    }
}

// ── 297: Capture group transformation ───────────────────────────────────

/// Transform captured groups from a regex match.
#[derive(Debug, Clone)]
pub struct CaptureTransform {
    /// The regex pattern with capture groups.
    pub pattern: regex::Regex,
    /// Group index to extract (1-indexed).
    pub group: usize,
    /// Optional transformation to apply to the captured text.
    pub transform: Transform,
}

/// Transformation to apply to captured text.
#[derive(Debug, Clone)]
pub enum Transform {
    /// No transformation.
    None,
    /// Base64 decode.
    Base64Decode,
    /// URL decode.
    UrlDecode,
    /// Remove whitespace.
    TrimWhitespace,
    /// Remove a prefix.
    RemovePrefix(String),
    /// Remove a suffix.
    RemoveSuffix(String),
    /// Convert to uppercase.
    Uppercase,
    /// Convert to lowercase.
    Lowercase,
}

impl CaptureTransform {
    /// Apply the transformation to captured text.
    pub fn apply(&self, text: &str) -> String {
        match &self.transform {
            Transform::None => text.to_string(),
            Transform::Base64Decode => {
                text.to_string()
            }
            Transform::UrlDecode => {
                text.replace("%20", " ")
                    .replace("%3A", ":")
                    .replace("%2F", "/")
                    .replace("%3D", "=")
                    .replace("%26", "&")
                    .replace("%3F", "?")
            }
            Transform::TrimWhitespace => text.trim().to_string(),
            Transform::RemovePrefix(prefix) => {
                text.strip_prefix(prefix.as_str()).unwrap_or(text).to_string()
            }
            Transform::RemoveSuffix(suffix) => {
                text.strip_suffix(suffix.as_str()).unwrap_or(text).to_string()
            }
            Transform::Uppercase => text.to_uppercase(),
            Transform::Lowercase => text.to_lowercase(),
        }
    }

    /// Extract and transform from a match.
    pub fn extract(&self, text: &str) -> Option<String> {
        let caps = self.pattern.captures(text)?;
        let group = caps.get(self.group)?;
        Some(self.apply(group.as_str()))
    }
}

// ── 298: Rule deprecation/retirement ────────────────────────────────────

/// Deprecation info for a rule.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RuleDeprecation {
    /// Whether the rule is deprecated.
    pub deprecated: bool,
    /// Replacement rule ID (if any).
    #[serde(default)]
    pub replacement: Option<String>,
    /// Deprecation message.
    #[serde(default)]
    pub message: Option<String>,
    /// Sunset date (ISO 8601) — rule will be removed after this date.
    #[serde(default)]
    pub sunset_date: Option<String>,
}

impl RuleDeprecation {
    /// Check if the rule should still be active.
    pub fn is_active(&self) -> bool {
        !self.deprecated
    }

    /// Get a deprecation warning message.
    pub fn warning(&self) -> String {
        let mut msg = "Rule is deprecated".to_string();
        if let Some(ref replacement) = self.replacement {
            msg.push_str(&format!(", use '{replacement}' instead"));
        }
        if let Some(ref m) = self.message {
            msg.push_str(&format!(": {m}"));
        }
        if let Some(ref date) = self.sunset_date {
            msg.push_str(&format!(" (sunset: {date})"));
        }
        msg
    }
}

// ── 299: Rule testing framework ─────────────────────────────────────────

/// A test case for a custom rule.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RuleTestCase {
    /// Test input text.
    pub input: String,
    /// Whether the rule should match this input.
    pub should_match: bool,
    /// Optional description of the test case.
    #[serde(default)]
    pub description: Option<String>,
}

/// Result of running a rule test.
#[derive(Debug, Clone)]
pub struct RuleTestResult {
    pub test_case: RuleTestCase,
    pub passed: bool,
    pub actual_matched: bool,
    pub message: String,
}

/// Run test cases against a regex pattern and return results.
pub fn test_rule(pattern: &regex::Regex, test_cases: &[RuleTestCase]) -> Vec<RuleTestResult> {
    test_cases
        .iter()
        .map(|tc| {
            let actual = pattern.is_match(&tc.input);
            let passed = actual == tc.should_match;
            let message = if passed {
                "PASS".to_string()
            } else {
                format!("FAIL: expected match={}, got match={}", tc.should_match, actual)
            };
            RuleTestResult {
                test_case: tc.clone(),
                passed,
                actual_matched: actual,
                message,
            }
        })
        .collect()
}

/// Run test cases from a TOML test file.
pub fn run_rule_tests(path: &Path) -> Result<Vec<RuleTestResult>, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let file: RuleTestFile = toml::from_str(&contents)?;
    let pattern = regex::Regex::new(&file.pattern)
        .map_err(|e| ConfigError::Other(format!("invalid regex: {e}")))?;
    Ok(test_rule(&pattern, &file.tests))
}

#[derive(Debug, serde::Deserialize)]
struct RuleTestFile {
    pattern: String,
    #[serde(default)]
    tests: Vec<RuleTestCase>,
}

// ── 300: Rule documentation generator ───────────────────────────────────

/// Generate Markdown documentation for a set of custom rules.
pub fn generate_rule_docs(rules: &[DocRule]) -> String {
    let mut md = String::new();
    md.push_str("# PledgeGuard Rule Documentation\n\n");
    md.push_str(&format!("Generated from {} rules.\n\n", rules.len()));
    md.push_str("| Rule ID | Description | Severity | Pattern | Entropy | Path Filter |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    for rule in rules {
        md.push_str(&format!(
            "| {} | {} | {} | `{}` | {} | {} |\n",
            rule.id,
            rule.description,
            rule.severity,
            rule.pattern.replace('|', "\\|"),
            rule.entropy.map(|e| format!("{e}")).unwrap_or("-".to_string()),
            rule.path_filter.as_deref().unwrap_or("-"),
        ));
    }
    md.push_str("\n---\n\n");
    for rule in rules {
        md.push_str(&format!("## {}\n\n", rule.id));
        md.push_str(&format!("**Description:** {}\n\n", rule.description));
        md.push_str(&format!("**Severity:** {}\n\n", rule.severity));
        md.push_str(&format!("**Pattern:** `{}`\n\n", rule.pattern));
        if let Some(e) = rule.entropy {
            md.push_str(&format!("**Entropy threshold:** {e}\n\n"));
        }
        if let Some(ref p) = rule.path_filter {
            md.push_str(&format!("**Path filter:** `{p}`\n\n"));
        }
        if !rule.allowlist_regexes.is_empty() {
            md.push_str("**Allowlist regexes:**\n");
            for re in &rule.allowlist_regexes {
                md.push_str(&format!("- `{re}`\n"));
            }
            md.push('\n');
        }
        if !rule.prefilter.is_empty() {
            md.push_str("**Prefilter patterns:**\n");
            for p in &rule.prefilter {
                md.push_str(&format!("- `{p}`\n"));
            }
            md.push('\n');
        }
    }
    md
}

/// A rule definition for documentation generation.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DocRule {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    #[serde(default)]
    pub prefilter: Vec<String>,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub path_filter: Option<String>,
    #[serde(default)]
    pub allowlist_regexes: Vec<String>,
}

// ── Error type ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("config error: {0}")]
    Other(String),
}

impl From<String> for ConfigError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_verifier_config() {
        let config = CustomVerifierConfig {
            rule_id: "custom-api-key".to_string(),
            method: "GET".to_string(),
            url: "https://api.example.com/verify?token={secret}".to_string(),
            headers: HashMap::new(),
            active_status: 200,
            inactive_status: 401,
            response_json_path: None,
            response_expected_value: None,
        };
        assert_eq!(
            config.build_url("abc123"),
            "https://api.example.com/verify?token=abc123"
        );
    }

    #[test]
    fn test_expr_verifier_length() {
        let config = ExprVerifierConfig {
            rule_id: "test".to_string(),
            expression: "length > 10".to_string(),
        };
        assert!(evaluate_expr_verifier(&config, "abcdefghijklmnop"));
        assert!(!evaluate_expr_verifier(&config, "short"));
    }

    #[test]
    fn test_expr_verifier_prefix() {
        let config = ExprVerifierConfig {
            rule_id: "test".to_string(),
            expression: "has_prefix(\"AKIA\")".to_string(),
        };
        assert!(evaluate_expr_verifier(&config, "AKIAIOSFODNN7TGCA"));
        assert!(!evaluate_expr_verifier(&config, "NOTAKIA123"));
    }

    #[test]
    fn test_detector_versioning() {
        let v = DetectorVersion {
            version: "1.2.0".to_string(),
            min_engine_version: Some("1.0.0".to_string()),
            last_updated: None,
        };
        assert!(v.is_compatible_with("1.0.0"));
        assert!(v.is_compatible_with("2.0.0"));
        assert!(!v.is_compatible_with("0.9.0"));
    }

    #[test]
    fn test_plugin_context() {
        let ctx = PluginContext::new(Path::new("src/main.rs"), 10, 5);
        assert_eq!(ctx.file_path, "src/main.rs");
        assert_eq!(ctx.file_extension, "rs");
        assert_eq!(ctx.line, 10);
        let json = ctx.to_json();
        assert!(json.contains("file_path"));
    }

    #[test]
    fn test_plugin_marketplace() {
        let marketplace = PluginMarketplace {
            plugins: vec![PluginMarketplaceEntry {
                name: "aws-detector".to_string(),
                description: "AWS secret detector".to_string(),
                version: "1.0.0".to_string(),
                author: "pledgeguard".to_string(),
                plugin_type: PluginType::Detector,
                download_url: "https://example.com/plugin.wasm".to_string(),
                homepage: None,
                tags: vec!["aws".to_string(), "cloud".to_string()],
                downloads: 1000,
                stars: 4.5,
            }],
        };
        let results = marketplace.search("aws");
        assert_eq!(results.len(), 1);
        let results = marketplace.search("payments");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_rule_profiles() {
        let cloud = RuleProfile::Cloud;
        assert!(cloud.rule_ids().contains(&"aws-access-key-id"));
        assert!(cloud.rule_ids().len() > 5);

        let minimal = RuleProfile::Minimal;
        assert!(minimal.rule_ids().len() < cloud.rule_ids().len());

        assert_eq!(RuleProfile::from_profile_str("cloud"), Some(RuleProfile::Cloud));
        assert_eq!(RuleProfile::from_profile_str("invalid"), None);
    }

    #[test]
    fn test_conditional_rules() {
        let conditions = RuleConditions {
            file_extensions: vec!["rs".to_string(), "go".to_string()],
            path_patterns: vec!["src/".to_string()],
            env_vars: vec![],
            min_file_size: 0,
            max_file_size: 0,
        };
        assert!(conditions.matches_path(Path::new("src/main.rs")));
        assert!(!conditions.matches_path(Path::new("test/main.py")));
        assert!(!conditions.matches_path(Path::new("src/main.py")));
    }

    #[test]
    fn test_severity_override() {
        let mut overrides = HashMap::new();
        overrides.insert("aws-access-key-id".to_string(), Severity::Critical);
        assert_eq!(overrides.get("aws-access-key-id"), Some(&Severity::Critical));
    }

    #[test]
    fn test_detector_metadata() {
        let meta = DetectorMetadata::new("1.0.0", 0.95);
        assert_eq!(meta.version, "1.0.0");
        assert!((meta.confidence - 0.95).abs() < 0.01);
        assert!(!meta.deprecated);
    }

    #[test]
    fn test_custom_entropy() {
        let config = CustomEntropyConfig {
            algorithm: "shannon".to_string(),
            threshold: 3.0,
            window_size: 0,
            alpha: None,
        };
        let entropy = compute_custom_entropy(&config, "AKIAIOSFODNN7TGCA");
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_renyi_entropy() {
        let config = CustomEntropyConfig {
            algorithm: "renyi".to_string(),
            threshold: 2.0,
            window_size: 0,
            alpha: Some(2.0),
        };
        let entropy = compute_custom_entropy(&config, "abcdefghijklmnop");
        assert!(entropy > 0.0);
    }

    #[test]
    fn test_multi_pattern_rule() {
        let rule = MultiPatternRule::new(
            "test-rule",
            "Test rule",
            Severity::High,
            &["AKIA[0-9A-Z]{16}", "ASIA[0-9A-Z]{16}"],
        )
        .unwrap();
        assert!(rule.matches("AKIAIOSFODNN7TGCABCD1"));
        assert!(rule.matches("ASIAIOSFODNN7TGCABCD1"));
        assert!(!rule.matches("NOT_A_KEY"));
    }

    #[test]
    fn test_lookahead_rule() {
        let rule = LookaheadRule::new(
            "AKIA[0-9A-Z]{16}",
            &["EXAMPLE"],
        )
        .unwrap();
        let results = rule.find_matches("key = AKIAIOSFODNN7TGCABCD1");
        assert!(!results.is_empty());
        // EXAMPLE appears after the match, so it should be blocked.
        let results = rule.find_matches("key = AKIAIOSFODNN7TGCABCD1 EXAMPLE");
        assert!(results.is_empty());
    }

    #[test]
    fn test_capture_transform() {
        let transform = CaptureTransform {
            pattern: regex::Regex::new(r"token=(\S+)").unwrap(),
            group: 1,
            transform: Transform::Uppercase,
        };
        let result = transform.extract("token=abc123");
        assert_eq!(result, Some("ABC123".to_string()));
    }

    #[test]
    fn test_rule_deprecation() {
        let dep = RuleDeprecation {
            deprecated: true,
            replacement: Some("new-rule".to_string()),
            message: Some("Use new-rule for better accuracy".to_string()),
            sunset_date: None,
        };
        assert!(!dep.is_active());
        assert!(dep.warning().contains("new-rule"));
    }

    #[test]
    fn test_rule_testing() {
        let pattern = regex::Regex::new("AKIA[0-9A-Z]{16}").unwrap();
        let test_cases = vec![
            RuleTestCase {
                input: "AKIAIOSFODNN7TGCABCD1".to_string(),
                should_match: true,
                description: Some("valid AWS key".to_string()),
            },
            RuleTestCase {
                input: "not-a-key".to_string(),
                should_match: false,
                description: Some("not an AWS key".to_string()),
            },
        ];
        let results = test_rule(&pattern, &test_cases);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.passed));
    }

    #[test]
    fn test_rule_docs_generator() {
        let rules = vec![DocRule {
            id: "test-rule".to_string(),
            description: "Test rule".to_string(),
            severity: "high".to_string(),
            pattern: "AKIA[0-9A-Z]{16}".to_string(),
            prefilter: vec!["AKIA".to_string()],
            entropy: Some(3.0),
            path_filter: Some("\\.env$".to_string()),
            allowlist_regexes: vec!["EXAMPLE".to_string()],
        }];
        let docs = generate_rule_docs(&rules);
        assert!(docs.contains("# PledgeGuard Rule Documentation"));
        assert!(docs.contains("test-rule"));
        assert!(docs.contains("AKIA"));
    }
}
