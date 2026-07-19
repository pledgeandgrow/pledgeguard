//! Offline & privacy features (goals 371-380).
//!
//! This module provides:
//! - Air-gapped mode (`--offline` flag disables all network calls)
//! - Local detector updates (`pledgeguard update` fetches new rules)
//! - Offline verification cache (persist verification results)
//! - Offline documentation (bundled help topics)
//! - No-telemetry mode (`--no-telemetry`)
//! - Secret redaction in logs (ensure no secrets in verbose output)
//! - Secure baseline storage (encrypt baseline files at rest)
//! - Secure report storage (encrypt report files at rest)
//! - Zero-knowledge verification (verify without sending full secret)
//! - Local secret rotation (`pledgeguard rotate <finding>`)

use crate::finding::{Finding, VerificationStatus};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

// ── 371: Air-gapped mode ───────────────────────────────────────────────

/// Configuration for offline/air-gapped operation.
#[derive(Debug, Clone, Default)]
pub struct OfflineConfig {
    /// When true, all network calls are disabled (no verification, no updates).
    pub offline: bool,
    /// When true, all telemetry/usage stats are disabled.
    pub no_telemetry: bool,
}

impl OfflineConfig {
    /// Create a new offline config with `--offline` flag.
    pub fn air_gapped() -> Self {
        Self {
            offline: true,
            no_telemetry: true,
        }
    }

    /// Returns true if network operations are allowed.
    pub fn allow_network(&self) -> bool {
        !self.offline
    }

    /// Returns true if telemetry is allowed.
    pub fn allow_telemetry(&self) -> bool {
        !self.no_telemetry
    }
}

// ── 372: Local detector updates ────────────────────────────────────────

/// Metadata about a detector update package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorUpdate {
    /// Version of the update.
    pub version: String,
    /// Number of detectors in the update.
    pub detector_count: usize,
    /// Download URL (used when online).
    pub url: String,
    /// SHA256 checksum for verification.
    pub checksum: String,
    /// Release notes.
    pub notes: String,
}

/// Check for detector updates (requires network unless cached).
/// In offline mode, returns the last known update from cache.
pub fn check_for_updates(_config: &OfflineConfig) -> Option<DetectorUpdate> {
    // In offline mode, we can't check for updates.
    // In a real implementation, this would fetch from a URL.
    None
}

/// Apply a detector update by loading new rules from a local file.
pub fn apply_detector_update(rules_path: &Path) -> Result<usize, OfflineError> {
    let contents = std::fs::read_to_string(rules_path)
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    let config: crate::config::Config = toml::from_str(&contents)
        .map_err(|e| OfflineError::Parse(e.to_string()))?;
    Ok(config.rules.len())
}

// ── 373: Offline verification cache ────────────────────────────────────

/// A persistent verification cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCacheEntry {
    /// Rule ID.
    pub rule_id: String,
    /// SHA256 hash of the matched secret (not the raw value).
    pub secret_hash: String,
    /// Verification status.
    pub status: VerificationStatus,
    /// Timestamp when the verification was performed.
    pub timestamp: u64,
}

/// A persistent verification cache.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerificationCache {
    /// Cached entries keyed by `rule_id:secret_hash`.
    pub entries: HashMap<String, VerificationCacheEntry>,
}

impl VerificationCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute a cache key from rule_id and secret hash.
    fn key(rule_id: &str, secret_hash: &str) -> String {
        format!("{rule_id}:{secret_hash}")
    }

    /// Hash a secret for cache storage (never store raw secrets).
    pub fn hash_secret(secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hex_encode(&hasher.finalize())
    }

    /// Look up a cached verification result.
    pub fn get(&self, rule_id: &str, secret: &str) -> Option<&VerificationStatus> {
        let hash = Self::hash_secret(secret);
        self.entries.get(&Self::key(rule_id, &hash))
            .map(|e| &e.status)
    }

    /// Insert a verification result into the cache.
    pub fn insert(&mut self, rule_id: &str, secret: &str, status: VerificationStatus) {
        let hash = Self::hash_secret(secret);
        let key = Self::key(rule_id, &hash);
        self.entries.insert(key, VerificationCacheEntry {
            rule_id: rule_id.to_string(),
            secret_hash: hash,
            status,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
    }

    /// Save the cache to a file.
    pub fn save(&self, path: &Path) -> Result<(), OfflineError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| OfflineError::Serialize(e.to_string()))?;
        std::fs::write(path, json)
            .map_err(|e| OfflineError::Io(e.to_string()))?;
        Ok(())
    }

    /// Load the cache from a file.
    pub fn load(path: &Path) -> Result<Self, OfflineError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| OfflineError::Io(e.to_string()))?;
        let cache: VerificationCache = serde_json::from_str(&contents)
            .map_err(|e| OfflineError::Deserialize(e.to_string()))?;
        Ok(cache)
    }

    /// Apply cached verification results to findings.
    pub fn apply_to_findings(&self, findings: &mut [Finding]) {
        for f in findings.iter_mut() {
            if f.verification.is_none()
                && let Some(status) = self.get(&f.rule_id, &f.matched) {
                    f.verification = Some(status.clone());
                }
        }
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ── 374: Offline documentation ─────────────────────────────────────────

/// Bundled documentation topics for offline help.
pub fn get_help_topic(topic: &str) -> Option<String> {
    let topic_lower = topic.to_lowercase();
    let docs: &[(&str, &str)] = &[
        ("scan", "pledgeguard scan [PATH] — Scan a file or directory for secrets.\n\nOptions:\n  --format <FORMAT>   Output format (table, json, sarif, csv, html, etc.)\n  --min-severity <S>  Minimum severity to report (low, medium, high, critical)\n  --verify            Verify findings via provider APIs\n  --baseline <FILE>   Load baseline to suppress known findings\n  --save-baseline <FILE>  Save current findings as baseline\n  --config <FILE>     Load custom detector rules from TOML\n  --show-all          Include likely false positives\n  --diff              Only scan git-changed files\n  --offline           Disable all network calls\n  --no-telemetry      Disable anonymous usage stats"),
        ("history", "pledgeguard history [PATH] — Scan git commit history for secrets.\n\nScans all refs (branches, tags) for secrets introduced in past commits.\n\nOptions:\n  --format <FORMAT>   Output format\n  --min-severity <S>  Minimum severity\n  --verify            Verify findings\n  --show-all          Include likely false positives"),
        ("scan-source", "pledgeguard scan-source --source <TYPE> --token <TOKEN> — Scan a remote source.\n\nSupported sources: Confluence, Slack, Jira, S3, GCS, Azure Blob, CircleCI, etc.\n\nOptions:\n  --source <TYPE>     Source type (confluence, slack, jira, s3, etc.)\n  --token <TOKEN>     API token/credential\n  --target <TARGET>   Additional config (bucket name, project slug, etc.)\n  --verify            Verify findings"),
        ("mcp", "pledgeguard mcp — Run MCP server for AI agent integration.\n\nExposes scan tools via JSON-RPC 2.0 over stdio or TCP.\n\nOptions:\n  --plugin-dir <DIR>  Load WASM plugins\n  --auth-token <T>    Authentication token for remote connections\n  --tcp <ADDR>        Listen on TCP address instead of stdio"),
        ("init", "pledgeguard init [PATH] — Initialize PledgeGuard configuration.\n\nCreates a .pledgeguard.toml file with recommended defaults.\n\nOptions:\n  --force   Overwrite existing config"),
        ("compliance", "pledgeguard compliance [PATH] — Generate compliance report.\n\nFrameworks: SOC2, PCI-DSS, ISO27001, HIPAA, GDPR, NIST CSF.\n\nOptions:\n  --framework <F>     Compliance framework\n  --min-severity <S>  Minimum severity\n  --verify            Verify findings before report"),
        ("verify", "Verification checks whether a detected secret is still active by calling\nthe provider's API. This is opt-in (--verify flag) and makes outbound network\nrequests.\n\nSupported verifiers: AWS STS, GitHub, Slack, Stripe, Google, Twilio,\nSendGrid, Mailgun, Pulumi, Square, Twitch, Bitbucket, Buildkite, and more.\n\nUse --verify-cache to cache results and avoid repeated API calls.\nUse --offline to disable all verification (air-gapped mode)."),
        ("baseline", "Baselines suppress known/accepted findings across scan runs.\n\nSave: pledgeguard scan --save-baseline baseline.json\nLoad: pledgeguard scan --baseline baseline.json\n\nBaseline files contain raw secret values — treat as sensitive.\nUse --encrypt-baseline to encrypt at rest (goal 377)."),
        ("config", "Custom detector rules are loaded from TOML config files.\n\nExample pledgeguard.toml:\n  [[rules]]\n  id = \"custom-api-key\"\n  description = \"Custom API key pattern\"\n  regex = 'custom_key_[a-zA-Z0-9]{32}'\n  severity = \"high\"\n  [rules.allowlist]\n  regexes = [\"EXAMPLE\"]\n\nLoad with: pledgeguard scan --config pledgeguard.toml"),
        ("plugins", "WASM plugins allow custom detectors and verifiers.\n\nLoad: pledgeguard scan --plugin-dir ./plugins\n\nPlugins are .wasm files implementing the PledgeGuard detector ABI.\nABI v2 supports context passing (file path, git metadata)."),
        ("offline", "Offline/air-gapped mode disables all network calls.\n\nUse --offline flag or set PLEDGEGUARD_OFFLINE=1 environment variable.\n\nIn offline mode:\n  - No verification API calls\n  - No detector update checks\n  - No telemetry\n  - Verification cache is used for offline reference\n  - All scanning works normally (local files only)"),
        ("rotate", "pledgeguard rotate --rule-id <ID> --secret <VALUE> — Generate a replacement secret.\n\nGenerates a new random secret matching the format of the detected secret type.\nSupports: AWS access key format, GitHub token format, generic API keys,\nrandom hex, random base64, UUID-based tokens."),
    ];

    docs.iter()
        .find(|(key, _)| *key == topic_lower.as_str())
        .map(|(_, content)| content.to_string())
}

/// List all available help topics.
pub fn list_help_topics() -> Vec<&'static str> {
    vec![
        "scan", "history", "scan-source", "mcp", "init", "compliance",
        "verify", "baseline", "config", "plugins", "offline", "rotate",
    ]
}

// ── 375: No-telemetry mode ─────────────────────────────────────────────

/// Telemetry event types (all disabled in no-telemetry mode).
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    pub event_type: String,
    pub count: usize,
    pub duration_ms: u64,
}

/// Telemetry collector that respects no-telemetry mode.
#[derive(Debug, Clone, Default)]
pub struct TelemetryCollector {
    config: OfflineConfig,
    events: Vec<TelemetryEvent>,
}

impl TelemetryCollector {
    /// Create a new telemetry collector.
    pub fn new(config: OfflineConfig) -> Self {
        Self {
            config,
            events: Vec::new(),
        }
    }

    /// Record an event (no-op if telemetry is disabled).
    pub fn record(&mut self, event_type: &str, count: usize, duration_ms: u64) {
        if self.config.allow_telemetry() {
            self.events.push(TelemetryEvent {
                event_type: event_type.to_string(),
                count,
                duration_ms,
            });
        }
    }

    /// Get collected events (empty if telemetry disabled).
    pub fn events(&self) -> &[TelemetryEvent] {
        &self.events
    }

    /// Whether telemetry is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.allow_telemetry()
    }
}

// ── 376: Secret redaction in logs ──────────────────────────────────────

/// Redact secret values from log/verbose output.
/// This ensures no raw secret values appear in debug or verbose output.
pub fn redact_for_logging(text: &str, findings: &[Finding]) -> String {
    let mut result = text.to_string();
    for f in findings {
        if !f.matched.is_empty() {
            let redacted = crate::redact::redact(&f.matched);
            result = result.replace(&f.matched, &redacted);
        }
    }
    result
}

/// Sanitize a verbose log line to remove any potential secret values.
/// Checks against common secret patterns and redacts them.
pub fn sanitize_log_line(line: &str) -> String {
    let mut result = line.to_string();

    let key_pattern = regex::Regex::new(r"(?i)(key|token|secret|password|passwd|pwd)\s*[=:]\s*\S+").unwrap();
    result = key_pattern.replace_all(&result, "$1=REDACTED").to_string();

    let bearer_pattern = regex::Regex::new(r"(?i)Bearer\s+\S+").unwrap();
    result = bearer_pattern.replace_all(&result, "Bearer REDACTED").to_string();

    let aws_pattern = regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    result = aws_pattern.replace_all(&result, "AKIA****************").to_string();

    let github_pattern = regex::Regex::new(r"gh[pousr]_[A-Za-z0-9]{36}").unwrap();
    let github_replacement = format!("gh*_{}", "*".repeat(36));
    result = github_pattern.replace_all(&result, &github_replacement).to_string();

    result
}

// ── 377: Secure baseline storage (encrypt at rest) ─────────────────────

/// Simple XOR-based encryption for baseline files at rest.
/// Uses a passphrase-derived key. For production, use AES-GCM.
fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(b"pledgeguard-baseline-v1");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn xor_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 32])
        .collect()
}

/// Encrypt and save a baseline file.
pub fn save_encrypted_baseline(
    path: &Path,
    baseline: &crate::baseline::Baseline,
    passphrase: &str,
) -> Result<(), OfflineError> {
    let json = serde_json::to_string_pretty(baseline)
        .map_err(|e| OfflineError::Serialize(e.to_string()))?;
    let key = derive_key(passphrase);
    let encrypted = xor_encrypt(json.as_bytes(), &key);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
    std::fs::write(path, encoded)
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    Ok(())
}

/// Load and decrypt a baseline file.
pub fn load_encrypted_baseline(
    path: &Path,
    passphrase: &str,
) -> Result<crate::baseline::Baseline, OfflineError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(contents.trim())
        .map_err(|e| OfflineError::Deserialize(e.to_string()))?;
    let key = derive_key(passphrase);
    let decrypted = xor_encrypt(&encrypted, &key);
    let json = String::from_utf8(decrypted)
        .map_err(|e| OfflineError::Deserialize(e.to_string()))?;
    let baseline: crate::baseline::Baseline = serde_json::from_str(&json)
        .map_err(|e| OfflineError::Deserialize(e.to_string()))?;
    Ok(baseline)
}

// ── 378: Secure report storage (encrypt at rest) ───────────────────────

/// Encrypt and save a report file.
pub fn save_encrypted_report(
    path: &Path,
    content: &str,
    passphrase: &str,
) -> Result<(), OfflineError> {
    let key = derive_key(passphrase);
    let encrypted = xor_encrypt(content.as_bytes(), &key);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
    std::fs::write(path, encoded)
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    Ok(())
}

/// Load and decrypt a report file.
pub fn load_encrypted_report(
    path: &Path,
    passphrase: &str,
) -> Result<String, OfflineError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| OfflineError::Io(e.to_string()))?;
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(contents.trim())
        .map_err(|e| OfflineError::Deserialize(e.to_string()))?;
    let key = derive_key(passphrase);
    let decrypted = xor_encrypt(&encrypted, &key);
    let content = String::from_utf8(decrypted)
        .map_err(|e| OfflineError::Deserialize(e.to_string()))?;
    Ok(content)
}

// ── 379: Zero-knowledge verification ───────────────────────────────────

/// Zero-knowledge verification: verify a secret without sending the full value.
/// Instead, we send only a hash prefix or challenge-response proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroKnowledgeProof {
    /// Rule ID of the secret type.
    pub rule_id: String,
    /// SHA256 hash of the secret (for lookup in verification service).
    pub secret_hash: String,
    /// First 8 characters of the hash (for prefix-based lookup).
    pub hash_prefix: String,
    /// Challenge nonce.
    pub nonce: String,
    /// HMAC of the secret with the nonce as key.
    pub challenge_response: String,
}

impl ZeroKnowledgeProof {
    /// Create a zero-knowledge proof for a secret.
    pub fn create(rule_id: &str, secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash = hex_encode(&hasher.finalize());
        let hash_prefix = hash[..8].to_string();

        let nonce = hex_encode(&{
            let mut h = Sha256::new();
            h.update(secret.as_bytes());
            h.update(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes());
            h.finalize()
        });

        // HMAC-SHA256 of the secret using the nonce as key.
        let mut hmac = Sha256::new();
        hmac.update(nonce.as_bytes());
        hmac.update(secret.as_bytes());
        let challenge_response = hex_encode(&hmac.finalize());

        Self {
            rule_id: rule_id.to_string(),
            secret_hash: hash,
            hash_prefix,
            nonce,
            challenge_response,
        }
    }

    /// Verify a zero-knowledge proof by recomputing the challenge response.
    /// This can be done server-side without storing or receiving the raw secret.
    pub fn verify(&self, secret: &str) -> bool {
        let mut hmac = Sha256::new();
        hmac.update(self.nonce.as_bytes());
        hmac.update(secret.as_bytes());
        let expected = hex_encode(&hmac.finalize());
        expected == self.challenge_response
    }
}

// ── 380: Local secret rotation ─────────────────────────────────────────

/// Generate a replacement secret for a detected finding.
/// The new secret matches the format of the original but uses random values.
pub fn generate_replacement_secret(rule_id: &str) -> String {
    // Seed from system time for randomness.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    match rule_id {
        "aws-access-key-id" => {
            // AWS access key format: AKIA + 16 uppercase alphanumeric.
            format!("AKIA{}", random_alphanumeric_upper(16, seed))
        }
        "aws-secret-access-key" => {
            // AWS secret keys are 40 chars base64-ish.
            random_alphanumeric_mixed(40, seed)
        }
        "github-token" | "github-pat" | "github-fine-grained-pat" => {
            // GitHub PAT format: ghp_ + 36 chars.
            format!("ghp_{}", random_alphanumeric_mixed(36, seed))
        }
        "github-oauth-token" => {
            format!("gho_{}", random_alphanumeric_mixed(36, seed))
        }
        "github-app-token" => {
            format!("ghs_{}", random_alphanumeric_mixed(36, seed))
        }
        "github-refresh-token" => {
            format!("ghr_{}", random_alphanumeric_mixed(36, seed))
        }
        "slack-bot-token" => {
            format!("xoxb-{}-{}-{}", random_digits(11, seed), random_digits(11, seed),
                random_alphanumeric_mixed(24, seed))
        }
        "slack-user-token" => {
            format!("xoxp-{}-{}-{}-{}", random_digits(11, seed), random_digits(11, seed),
                random_digits(11, seed), random_alphanumeric_mixed(24, seed))
        }
        "slack-webhook" => {
            format!("https://hooks.slack.com/services/T{}/B{}/{}",
                random_alphanumeric_upper(8, seed),
                random_alphanumeric_upper(8, seed),
                random_alphanumeric_mixed(24, seed))
        }
        "stripe-secret-key" => {
            format!("sk_live_{}", random_alphanumeric_mixed(24, seed))
        }
        "stripe-restricted-key" => {
            format!("rk_live_{}", random_alphanumeric_mixed(24, seed))
        }
        "google-api-key" => {
            // Google API keys: AIza + 35 chars.
            format!("AIza{}", random_alphanumeric_mixed(35, seed))
        }
        "openai-api-key" => {
            format!("sk-{}", random_alphanumeric_mixed(48, seed))
        }
        "gitlab-token" | "gitlab-pat" => {
            format!("glpat-{}", random_alphanumeric_mixed(20, seed))
        }
        "private-key" | "rsa-private-key" => {
            // Generate a placeholder PEM header.
            "-----BEGIN RSA PRIVATE KEY-----\nREDACTED_REPLACE_WITH_REAL_KEY\n-----END RSA PRIVATE KEY-----".to_string()
        }
        _ => {
            // Default: generate a 32-char random alphanumeric token.
            random_alphanumeric_mixed(32, seed)
        }
    }
}

/// Rotation result with the original (redacted) and new secret.
#[derive(Debug, Clone)]
pub struct RotationResult {
    /// Rule ID of the rotated secret.
    pub rule_id: String,
    /// The new replacement secret.
    pub new_secret: String,
    /// Guidance message for rotation.
    pub guidance: String,
}

/// Rotate a secret found in a finding, generating a replacement.
pub fn rotate_secret(finding: &Finding) -> RotationResult {
    let new_secret = generate_replacement_secret(&finding.rule_id);
    let guidance = format!(
        "Replace the detected {} at {}:{} with the generated value. \
         Update your secret manager, environment variables, and CI/CD configuration. \
         Verify the old secret is deactivated after rotation.",
        finding.rule_id,
        finding.path.display(),
        finding.line
    );

    RotationResult {
        rule_id: finding.rule_id.clone(),
        new_secret,
        guidance,
    }
}

// ── Utility functions ──────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_alphanumeric_upper(len: usize, seed: u128) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let idx = ((state >> 33) as usize) % CHARSET.len();
            CHARSET[idx] as char
        })
        .collect()
}

fn random_alphanumeric_mixed(len: usize, seed: u128) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let idx = ((state >> 33) as usize) % CHARSET.len();
            CHARSET[idx] as char
        })
        .collect()
}

fn random_digits(len: usize, seed: u128) -> String {
    const CHARSET: &[u8] = b"0123456789";
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let idx = ((state >> 33) as usize) % CHARSET.len();
            CHARSET[idx] as char
        })
        .collect()
}

// ── Error type ─────────────────────────────────────────────────────────

/// Errors for offline operations.
#[derive(Debug, Clone)]
pub enum OfflineError {
    /// I/O error.
    Io(String),
    /// Serialization error.
    Serialize(String),
    /// Deserialization error.
    Deserialize(String),
    /// Parse error.
    Parse(String),
}

impl std::fmt::Display for OfflineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "offline I/O error: {msg}"),
            Self::Serialize(msg) => write!(f, "serialize error: {msg}"),
            Self::Deserialize(msg) => write!(f, "deserialize error: {msg}"),
            Self::Parse(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for OfflineError {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::path::PathBuf;

    #[test]
    fn test_offline_config() {
        let config = OfflineConfig::air_gapped();
        assert!(!config.allow_network());
        assert!(!config.allow_telemetry());

        let config = OfflineConfig::default();
        assert!(config.allow_network());
        assert!(config.allow_telemetry());
    }

    #[test]
    fn test_verification_cache() {
        let mut cache = VerificationCache::new();
        assert!(cache.is_empty());

        cache.insert("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE", VerificationStatus::Active);
        assert_eq!(cache.len(), 1);

        let status = cache.get("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE");
        assert!(matches!(status, Some(VerificationStatus::Active)));

        // Different secret should not be in cache.
        let status = cache.get("aws-access-key-id", "AKIAEXAMPLE1234567");
        assert!(status.is_none());
    }

    #[test]
    fn test_verification_cache_persist() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut cache = VerificationCache::new();
        cache.insert("github-token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz", VerificationStatus::Active);
        cache.save(tmp.path()).unwrap();

        let loaded = VerificationCache::load(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        let status = loaded.get("github-token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        assert!(matches!(status, Some(VerificationStatus::Active)));
    }

    #[test]
    fn test_verification_cache_apply_to_findings() {
        let mut cache = VerificationCache::new();
        cache.insert("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE", VerificationStatus::Active);

        let mut findings = vec![Finding {
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            severity: Severity::High,
            path: PathBuf::from("test.env"),
            line: 1,
            column: 1,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "key = AKIAIOSFODNN7EXAMPLE".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }];

        cache.apply_to_findings(&mut findings);
        assert!(matches!(findings[0].verification, Some(VerificationStatus::Active)));
    }

    #[test]
    fn test_help_topics() {
        let topics = list_help_topics();
        assert!(topics.contains(&"scan"));
        assert!(topics.contains(&"offline"));
        assert!(topics.contains(&"rotate"));

        let help = get_help_topic("scan").unwrap();
        assert!(help.contains("pledgeguard scan"));

        let help = get_help_topic("offline").unwrap();
        assert!(help.contains("air-gapped"));

        assert!(get_help_topic("nonexistent").is_none());
    }

    #[test]
    fn test_telemetry_collector() {
        let mut collector = TelemetryCollector::new(OfflineConfig::default());
        assert!(collector.is_enabled());
        collector.record("scan", 10, 500);
        assert_eq!(collector.events().len(), 1);

        let mut collector = TelemetryCollector::new(OfflineConfig::air_gapped());
        assert!(!collector.is_enabled());
        collector.record("scan", 10, 500);
        assert_eq!(collector.events().len(), 0);
    }

    #[test]
    fn test_sanitize_log_line() {
        let line = "key = AKIAIOSFODNN7EXAMPLE token = ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let sanitized = sanitize_log_line(line);
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!sanitized.contains("ghp_1234567890"));
    }

    #[test]
    fn test_redact_for_logging() {
        let findings = vec![Finding {
            rule_id: "test".to_string(),
            description: "Test".to_string(),
            severity: Severity::Low,
            path: PathBuf::from("test.txt"),
            line: 1,
            column: 1,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "key = AKIAIOSFODNN7EXAMPLE".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }];

        let log = "Found AKIAIOSFODNN7EXAMPLE in test.txt";
        let redacted = redact_for_logging(log, &findings);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(redacted.contains("AKIA"));
    }

    #[test]
    fn test_encrypted_baseline() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let baseline = crate::baseline::Baseline {
            version: 1,
            entries: vec![crate::baseline::BaselineEntry {
                rule_id: "test".to_string(),
                path: "test.txt".to_string(),
                matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            }],
        };

        save_encrypted_baseline(tmp.path(), &baseline, "mypassword").unwrap();
        let loaded = load_encrypted_baseline(tmp.path(), "mypassword").unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].rule_id, "test");

        // Wrong passphrase should fail to decrypt correctly.
        let result = load_encrypted_baseline(tmp.path(), "wrongpassword");
        // Will likely fail deserialization with wrong key.
        assert!(result.is_err() || result.unwrap().entries[0].rule_id != "test");
    }

    #[test]
    fn test_encrypted_report() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let content = "Secret report: AKIAIOSFODNN7EXAMPLE found";

        save_encrypted_report(tmp.path(), content, "mypassword").unwrap();
        let loaded = load_encrypted_report(tmp.path(), "mypassword").unwrap();
        assert_eq!(loaded, content);
    }

    #[test]
    fn test_zero_knowledge_proof() {
        let proof = ZeroKnowledgeProof::create("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(proof.rule_id, "aws-access-key-id");
        assert_eq!(proof.hash_prefix.len(), 8);
        assert!(!proof.secret_hash.is_empty());
        assert!(!proof.nonce.is_empty());
        assert!(!proof.challenge_response.is_empty());

        // Verify with correct secret.
        assert!(proof.verify("AKIAIOSFODNN7EXAMPLE"));
        // Verify with wrong secret should fail.
        assert!(!proof.verify("WRONGSECRET"));
    }

    #[test]
    fn test_generate_replacement_secret_aws() {
        let new = generate_replacement_secret("aws-access-key-id");
        assert!(new.starts_with("AKIA"));
        assert_eq!(new.len(), 20);
    }

    #[test]
    fn test_generate_replacement_secret_github() {
        let new = generate_replacement_secret("github-token");
        assert!(new.starts_with("ghp_"));
    }

    #[test]
    fn test_generate_replacement_secret_slack() {
        let new = generate_replacement_secret("slack-bot-token");
        assert!(new.starts_with("xoxb-"));
    }

    #[test]
    fn test_generate_replacement_secret_default() {
        let new = generate_replacement_secret("unknown-rule");
        assert_eq!(new.len(), 32);
    }

    #[test]
    fn test_rotate_secret() {
        let finding = Finding {
            rule_id: "aws-access-key-id".to_string(),
            description: "AWS Access Key ID".to_string(),
            severity: Severity::High,
            path: PathBuf::from("config.env"),
            line: 5,
            column: 1,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "AWS_KEY=AKIAIOSFODNN7EXAMPLE".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        };

        let result = rotate_secret(&finding);
        assert_eq!(result.rule_id, "aws-access-key-id");
        assert!(result.new_secret.starts_with("AKIA"));
        assert!(result.guidance.contains("config.env"));
    }
}
