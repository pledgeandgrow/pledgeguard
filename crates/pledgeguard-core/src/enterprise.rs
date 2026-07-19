//! Enterprise features for PledgeGuard (goals 401-420).
//!
//! Includes:
//! - **RBAC** (401): Role-based access control for MCP server
//! - **Audit logging** (402): Log all scan operations and verification calls
//! - **Scan diffing** (405): Compare two scan reports to show new/resolved findings
//! - **Finding lifecycle** (406): Track findings from detection to resolution
//! - **Suppression with expiry** (407): Suppress findings with automatic expiration
//! - **Compliance reporting** (415): Generate compliance reports (SOC2, PCI-DSS, ISO27001)
//! - **Webhook notifications** (419): Notify Slack/Teams/Discord on new findings

use crate::finding::{Finding, Severity, VerificationStatus};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── RBAC (goal 401) ───────────────────────────────────────────────

/// Permission levels for MCP server access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Can run scans and view results.
    Scan,
    /// Can verify secrets (makes outbound network calls).
    Verify,
    /// Can scan remote sources (requires credentials).
    ScanSource,
    /// Can list detectors.
    ListDetectors,
    /// Full administrative access.
    Admin,
}

/// A role that maps to a set of permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
}

/// RBAC configuration: maps tokens to roles.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RbacConfig {
    /// Maps auth token → role name.
    pub token_roles: HashMap<String, String>,
    /// Maps role name → role definition.
    pub roles: HashMap<String, Role>,
}

impl RbacConfig {
    /// Creates a default RBAC config with standard roles.
    pub fn with_defaults() -> Self {
        let mut roles = HashMap::new();
        roles.insert(
            "viewer".to_string(),
            Role {
                name: "viewer".to_string(),
                permissions: vec![Permission::Scan, Permission::ListDetectors],
            },
        );
        roles.insert(
            "scanner".to_string(),
            Role {
                name: "scanner".to_string(),
                permissions: vec![
                    Permission::Scan,
                    Permission::ListDetectors,
                    Permission::Verify,
                ],
            },
        );
        roles.insert(
            "operator".to_string(),
            Role {
                name: "operator".to_string(),
                permissions: vec![
                    Permission::Scan,
                    Permission::ListDetectors,
                    Permission::Verify,
                    Permission::ScanSource,
                ],
            },
        );
        roles.insert(
            "admin".to_string(),
            Role {
                name: "admin".to_string(),
                permissions: vec![
                    Permission::Scan,
                    Permission::ListDetectors,
                    Permission::Verify,
                    Permission::ScanSource,
                    Permission::Admin,
                ],
            },
        );

        Self {
            token_roles: HashMap::new(),
            roles,
        }
    }

    /// Assigns a token to a role.
    pub fn assign(&mut self, token: &str, role: &str) {
        self.token_roles.insert(token.to_string(), role.to_string());
    }

    /// Checks if a token has a given permission.
    pub fn has_permission(&self, token: &str, perm: &Permission) -> bool {
        let role_name = match self.token_roles.get(token) {
            Some(r) => r,
            None => return false,
        };
        let role = match self.roles.get(role_name) {
            Some(r) => r,
            None => return false,
        };
        role.permissions.contains(perm)
    }

    /// Gets the role name for a token.
    pub fn role_for(&self, token: &str) -> Option<&str> {
        self.token_roles.get(token).map(|s| s.as_str())
    }
}

// ─── Audit Logging (goal 402) ──────────────────────────────────────

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// The action performed (e.g. "scan", "verify", "scan_source").
    pub action: String,
    /// The user/token that performed the action.
    pub actor: String,
    /// Target of the action (path, source type, rule ID, etc.).
    pub target: String,
    /// Number of findings produced (for scan actions).
    pub findings_count: Option<usize>,
    /// Whether the action succeeded.
    pub success: bool,
    /// Optional error message.
    pub error: Option<String>,
}

/// Audit logger that appends entries to a log file.
pub struct AuditLogger {
    log_path: Option<PathBuf>,
    entries: Vec<AuditEntry>,
}

impl AuditLogger {
    /// Creates an audit logger that writes to the given path.
    pub fn new(log_path: Option<PathBuf>) -> Self {
        Self {
            log_path,
            entries: Vec::new(),
        }
    }

    /// Logs an action.
    pub fn log(
        &mut self,
        action: &str,
        actor: &str,
        target: &str,
        findings_count: Option<usize>,
        success: bool,
        error: Option<&str>,
    ) {
        let entry = AuditEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            action: action.to_string(),
            actor: actor.to_string(),
            target: target.to_string(),
            findings_count,
            success,
            error: error.map(String::from),
        };
        self.entries.push(entry);
    }

    /// Flushes all buffered entries to the log file (JSONL format).
    pub fn flush(&self) -> std::io::Result<()> {
        let path = match &self.log_path {
            Some(p) => p,
            None => return Ok(()),
        };
        let mut content = String::new();
        for entry in &self.entries {
            content.push_str(&serde_json::to_string(entry).unwrap_or_default());
            content.push('\n');
        }
        std::fs::write(path, content)
    }

    /// Returns all buffered entries.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

// ─── Scan Diffing (goal 405) ───────────────────────────────────────

/// The diff status of a finding compared to a previous scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    /// Finding is new (not in the previous scan).
    New,
    /// Finding was in the previous scan and is still present.
    Unchanged,
    /// Finding was in the previous scan but is no longer present.
    Resolved,
}

/// A finding with its diff status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFinding {
    pub finding: Finding,
    pub status: DiffStatus,
}

/// Computes the diff between two scan results.
///
/// Findings are matched by fingerprint (rule_id + path + line + matched).
pub fn diff_scans(previous: &[Finding], current: &[Finding]) -> Vec<DiffFinding> {
    let prev_fps: HashMap<String, &Finding> = previous
        .iter()
        .map(|f| (fingerprint(f), f))
        .collect();
    let curr_fps: HashMap<String, &Finding> = current
        .iter()
        .map(|f| (fingerprint(f), f))
        .collect();

    let mut result = Vec::new();

    // New and unchanged findings.
    for f in current {
        let status = if prev_fps.contains_key(&fingerprint(f)) {
            DiffStatus::Unchanged
        } else {
            DiffStatus::New
        };
        result.push(DiffFinding {
            finding: f.clone(),
            status,
        });
    }

    // Resolved findings.
    for f in previous {
        if !curr_fps.contains_key(&fingerprint(f)) {
            result.push(DiffFinding {
                finding: f.clone(),
                status: DiffStatus::Resolved,
            });
        }
    }

    result
}

/// Generates a stable fingerprint for a finding.
fn fingerprint(f: &Finding) -> String {
    format!("{}:{}:{}:{}", f.rule_id, f.path.display(), f.line, f.matched)
}

/// Summarizes a scan diff.
pub fn diff_summary(diff: &[DiffFinding]) -> DiffSummary {
    let new_count = diff.iter().filter(|d| d.status == DiffStatus::New).count();
    let resolved_count = diff
        .iter()
        .filter(|d| d.status == DiffStatus::Resolved)
        .count();
    let unchanged_count = diff
        .iter()
        .filter(|d| d.status == DiffStatus::Unchanged)
        .count();

    DiffSummary {
        new_count,
        resolved_count,
        unchanged_count,
        total: diff.len(),
    }
}

/// Summary of a scan diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub new_count: usize,
    pub resolved_count: usize,
    pub unchanged_count: usize,
    pub total: usize,
}

// ─── Finding Lifecycle (goal 406) ──────────────────────────────────

/// The lifecycle state of a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    /// Newly detected, not yet triaged.
    Open,
    /// Acknowledged, being investigated.
    InProgress,
    /// Fix is being applied (e.g. secret rotated).
    Remediating,
    /// Secret has been rotated/revoked and the finding is resolved.
    Resolved,
    /// Finding was a false positive and dismissed.
    FalsePositive,
    /// Finding is accepted as a known risk.
    Accepted,
}

/// A finding with lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedFinding {
    pub finding: Finding,
    pub state: FindingState,
    /// When the finding was first detected (Unix timestamp).
    pub detected_at: u64,
    /// When the state was last updated.
    pub updated_at: u64,
    /// User who last updated the state.
    pub updated_by: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional suppression (with expiry).
    pub suppression: Option<Suppression>,
}

/// A suppression record with optional expiry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    /// Reason for suppression.
    pub reason: String,
    /// Who suppressed the finding.
    pub suppressed_by: String,
    /// When the suppression was created (Unix timestamp).
    pub created_at: u64,
    /// Optional expiry timestamp. After this, the suppression is no longer active.
    pub expires_at: Option<u64>,
}

impl Suppression {
    /// Checks if the suppression is still active (not expired).
    pub fn is_active(&self) -> bool {
        match self.expires_at {
            Some(expiry) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                now < expiry
            }
            None => true,
        }
    }
}

/// A finding tracker manages the lifecycle of findings across scans.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingTracker {
    /// Maps fingerprint → tracked finding.
    pub findings: HashMap<String, TrackedFinding>,
}

impl FindingTracker {
    /// Creates a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests a new scan result, updating tracked findings.
    pub fn ingest(&mut self, scan_results: &[Finding], actor: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for f in scan_results {
            let fp = fingerprint(f);
            self.findings.entry(fp).or_insert(TrackedFinding {
                finding: f.clone(),
                state: FindingState::Open,
                detected_at: now,
                updated_at: now,
                updated_by: Some(actor.to_string()),
                comment: None,
                suppression: None,
            });
        }
    }

    /// Updates the state of a finding by fingerprint.
    pub fn update_state(
        &mut self,
        fingerprint: &str,
        state: FindingState,
        actor: &str,
        comment: Option<&str>,
    ) -> Result<(), String> {
        let tracked = self
            .findings
            .get_mut(fingerprint)
            .ok_or("finding not found")?;

        tracked.state = state;
        tracked.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        tracked.updated_by = Some(actor.to_string());
        if let Some(c) = comment {
            tracked.comment = Some(c.to_string());
        }
        Ok(())
    }

    /// Suppresses a finding with an optional expiry.
    pub fn suppress(
        &mut self,
        fingerprint: &str,
        reason: &str,
        suppressed_by: &str,
        expires_at: Option<u64>,
    ) -> Result<(), String> {
        let tracked = self
            .findings
            .get_mut(fingerprint)
            .ok_or("finding not found")?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        tracked.suppression = Some(Suppression {
            reason: reason.to_string(),
            suppressed_by: suppressed_by.to_string(),
            created_at: now,
            expires_at,
        });
        Ok(())
    }

    /// Filters out suppressed findings from a scan result.
    pub fn filter_suppressed(&self, findings: &[Finding]) -> Vec<Finding> {
        findings
            .iter()
            .filter(|f| {
                let fp = fingerprint(f);
                match self.findings.get(&fp) {
                    Some(tracked) => match &tracked.suppression {
                        Some(s) => !s.is_active(),
                        None => true,
                    },
                    None => true,
                }
            })
            .cloned()
            .collect()
    }

    /// Saves the tracker state to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, json)
    }

    /// Loads a tracker from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Returns findings filtered by state.
    pub fn by_state(&self, state: &FindingState) -> Vec<&TrackedFinding> {
        self.findings
            .values()
            .filter(|t| &t.state == state)
            .collect()
    }
}

// ─── Compliance Reporting (goal 415) ───────────────────────────────

/// Compliance framework identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Soc2,
    PciDss,
    Iso27001,
    Hipaa,
    Gdpr,
    NistCsf,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceFramework::Soc2 => write!(f, "SOC 2"),
            ComplianceFramework::PciDss => write!(f, "PCI-DSS"),
            ComplianceFramework::Iso27001 => write!(f, "ISO 27001"),
            ComplianceFramework::Hipaa => write!(f, "HIPAA"),
            ComplianceFramework::Gdpr => write!(f, "GDPR"),
            ComplianceFramework::NistCsf => write!(f, "NIST CSF"),
        }
    }
}

/// A compliance report generated from scan findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub generated_at: u64,
    pub scan_target: String,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub verified_active: usize,
    pub verified_inactive: usize,
    pub unverified: usize,
    pub findings_by_rule: HashMap<String, usize>,
    pub compliance_status: ComplianceStatus,
    pub recommendations: Vec<String>,
}

/// Overall compliance status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    /// No critical/high findings — compliant.
    Compliant,
    /// Medium findings present — compliant with warnings.
    CompliantWithWarnings,
    /// Critical or high findings present — non-compliant.
    NonCompliant,
}

/// Generates a compliance report from scan findings.
pub fn generate_compliance_report(
    findings: &[Finding],
    framework: ComplianceFramework,
    scan_target: &str,
) -> ComplianceReport {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = findings.iter().filter(|f| f.severity == Severity::Low).count();

    let verified_active = findings
        .iter()
        .filter(|f| f.verification == Some(VerificationStatus::Active))
        .count();
    let verified_inactive = findings
        .iter()
        .filter(|f| f.verification == Some(VerificationStatus::Inactive))
        .count();
    let unverified = findings
        .iter()
        .filter(|f| f.verification.is_none())
        .count();

    let mut findings_by_rule: HashMap<String, usize> = HashMap::new();
    for f in findings {
        *findings_by_rule.entry(f.rule_id.clone()).or_insert(0) += 1;
    }

    let status = if critical > 0 || high > 0 {
        ComplianceStatus::NonCompliant
    } else if medium > 0 {
        ComplianceStatus::CompliantWithWarnings
    } else {
        ComplianceStatus::Compliant
    };

    let mut recommendations = Vec::new();
    if critical > 0 {
        recommendations.push(format!(
            "Immediately rotate {critical} critical-severity secrets detected in the codebase."
        ));
    }
    if high > 0 {
        recommendations.push(format!(
            "Prioritize remediation of {high} high-severity findings within 24 hours."
        ));
    }
    if verified_active > 0 {
        recommendations.push(format!(
            "{verified_active} secrets were verified as ACTIVE — rotate them immediately."
        ));
    }
    if unverified > findings.len() / 2 {
        recommendations.push(
            "More than 50% of findings are unverified. Run with --verify to check active status.".to_string(),
        );
    }
    if recommendations.is_empty() {
        recommendations.push("No critical findings detected. Continue regular scanning.".to_string());
    }

    // Framework-specific recommendations.
    match framework {
        ComplianceFramework::PciDss => {
            if critical > 0 || high > 0 {
                recommendations.push(
                    "PCI-DSS Requirement 6.5.6: All security vulnerabilities must be remediated.".to_string(),
                );
            }
            recommendations.push(
                "PCI-DSS Requirement 3.2: Strong cryptography must be used for stored cardholder data.".to_string(),
            );
        }
        ComplianceFramework::Soc2 => {
            recommendations.push(
                "SOC 2 CC6.1: Security controls must prevent unauthorized access to sensitive data.".to_string(),
            );
        }
        ComplianceFramework::Iso27001 => {
            recommendations.push(
                "ISO 27001 A.8.3: Information access restriction and cryptography controls.".to_string(),
            );
        }
        ComplianceFramework::Hipaa => {
            recommendations.push(
                "HIPAA 164.312(a)(2)(iv): Encryption and decryption of electronic protected health information.".to_string(),
            );
        }
        ComplianceFramework::Gdpr => {
            recommendations.push(
                "GDPR Article 32: Security of processing — implement appropriate technical measures.".to_string(),
            );
        }
        ComplianceFramework::NistCsf => {
            recommendations.push(
                "NIST CSF PR.DS-1: Data-at-rest is protected. Rotate exposed secrets.".to_string(),
            );
        }
    }

    ComplianceReport {
        framework,
        generated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        scan_target: scan_target.to_string(),
        total_findings: findings.len(),
        critical_findings: critical,
        high_findings: high,
        medium_findings: medium,
        low_findings: low,
        verified_active,
        verified_inactive,
        unverified,
        findings_by_rule,
        compliance_status: status,
        recommendations,
    }
}

impl ComplianceReport {
    /// Renders the report as a human-readable string.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("═══════════════════════════════════════════════\n");
        s.push_str(&format!("  {} Compliance Report\n", self.framework));
        s.push_str("═══════════════════════════════════════════════\n\n");
        s.push_str(&format!("Scan target:     {}\n", self.scan_target));
        s.push_str(&format!("Total findings:  {}\n", self.total_findings));
        s.push_str(&format!("  Critical:      {}\n", self.critical_findings));
        s.push_str(&format!("  High:          {}\n", self.high_findings));
        s.push_str(&format!("  Medium:        {}\n", self.medium_findings));
        s.push_str(&format!("  Low:           {}\n\n", self.low_findings));
        s.push_str("Verification:\n");
        s.push_str(&format!("  Active:        {}\n", self.verified_active));
        s.push_str(&format!("  Inactive:      {}\n", self.verified_inactive));
        s.push_str(&format!("  Unverified:    {}\n\n", self.unverified));
        s.push_str(&format!("Compliance status: {:?}\n\n", self.compliance_status));
        s.push_str("Recommendations:\n");
        for (i, rec) in self.recommendations.iter().enumerate() {
            s.push_str(&format!("  {}. {rec}\n", i + 1));
        }
        s
    }
}

// ─── Webhook Notifications (goal 419) ──────────────────────────────

/// Webhook destination for notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL (e.g. Slack incoming webhook, Teams connector URL).
    pub url: String,
    /// Webhook type (slack, teams, discord, generic).
    pub webhook_type: WebhookType,
    /// Minimum severity to trigger a notification.
    pub min_severity: Severity,
    /// Only notify on verified-active secrets.
    pub only_verified_active: bool,
}

/// Supported webhook types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookType {
    Slack,
    Teams,
    Discord,
    Generic,
}

/// Sends a webhook notification for scan findings.
pub fn send_webhook(
    config: &WebhookConfig,
    findings: &[Finding],
    scan_target: &str,
) -> Result<(), String> {
    // Filter findings by severity.
    let relevant: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity >= config.min_severity)
        .filter(|f| {
            if config.only_verified_active {
                f.verification == Some(VerificationStatus::Active)
            } else {
                true
            }
        })
        .collect();

    if relevant.is_empty() {
        return Ok(());
    }

    let payload = match config.webhook_type {
        WebhookType::Slack => build_slack_payload(&relevant, scan_target),
        WebhookType::Teams => build_teams_payload(&relevant, scan_target),
        WebhookType::Discord => build_discord_payload(&relevant, scan_target),
        WebhookType::Generic => build_generic_payload(&relevant, scan_target),
    };

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();

    let resp = agent
        .post(&config.url)
        .set("Content-Type", "application/json")
        .send_string(&payload);

    match resp {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("webhook failed: {e}")),
    }
}

fn build_slack_payload(findings: &[&Finding], scan_target: &str) -> String {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let blocks = json!({
        "blocks": [
            {
                "type": "header",
                "text": { "type": "plain_text", "text": "🚨 PledgeGuard: Secrets Detected" }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "*Scan target:* {}\n*Total findings:* {} ({} critical, {} high)\n*Top rules:*",
                        scan_target,
                        findings.len(),
                        critical,
                        high
                    )
                }
            }
        ]
    });
    blocks.to_string()
}

fn build_teams_payload(findings: &[&Finding], scan_target: &str) -> String {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let theme_color = if critical > 0 { "FF0000" } else { "FFA500" };
    json!({
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": format!("PledgeGuard: {} secrets detected in {}", findings.len(), scan_target),
        "sections": [{
            "activityTitle": "🚨 PledgeGuard: Secrets Detected",
            "facts": [
                { "name": "Scan target", "value": scan_target },
                { "name": "Total findings", "value": findings.len().to_string() },
                { "name": "Critical", "value": critical.to_string() },
                { "name": "High", "value": high.to_string() }
            ]
        }]
    }).to_string()
}

fn build_discord_payload(findings: &[&Finding], scan_target: &str) -> String {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    let color = if critical > 0 { 0xFF0000 } else { 0xFFA500 };
    json!({
        "embeds": [{
            "title": "🚨 PledgeGuard: Secrets Detected",
            "color": color,
            "fields": [
                { "name": "Scan target", "value": scan_target, "inline": true },
                { "name": "Total findings", "value": findings.len().to_string(), "inline": true },
                { "name": "Critical", "value": critical.to_string(), "inline": true },
                { "name": "High", "value": high.to_string(), "inline": true }
            ]
        }]
    }).to_string()
}

fn build_generic_payload(findings: &[&Finding], scan_target: &str) -> String {
    let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = findings.iter().filter(|f| f.severity == Severity::High).count();
    json!({
        "scanner": "pledgeguard",
        "scan_target": scan_target,
        "total_findings": findings.len(),
        "critical": critical,
        "high": high,
        "findings": findings.iter().map(|f| {
            f.redacted()
        }).collect::<Vec<_>>()
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(rule: &str, path: &str, line: usize, matched: &str, severity: Severity) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            description: "test".to_string(),
            severity,
            path: PathBuf::from(path),
            line,
            column: 1,
            matched: matched.to_string(),
            context: matched.to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }
    }

    #[test]
    fn test_rbac_defaults() {
        let mut rbac = RbacConfig::with_defaults();
        rbac.token_roles.insert("tok1".to_string(), "viewer".to_string());
        rbac.token_roles.insert("tok2".to_string(), "admin".to_string());
        assert!(rbac.has_permission("tok1", &Permission::Scan));
        assert!(!rbac.has_permission("tok1", &Permission::ScanSource));
        assert!(rbac.has_permission("tok2", &Permission::ScanSource));
        assert!(rbac.has_permission("tok2", &Permission::Admin));
    }

    #[test]
    fn test_rbac_unknown_token() {
        let rbac = RbacConfig::with_defaults();
        assert!(!rbac.has_permission("unknown", &Permission::Scan));
    }

    #[test]
    fn test_audit_logger() {
        let mut logger = AuditLogger::new(None);
        logger.log("scan", "admin", "./src", Some(5), true, None);
        assert_eq!(logger.entries().len(), 1);
        assert_eq!(logger.entries()[0].action, "scan");
        assert_eq!(logger.entries()[0].findings_count, Some(5));
    }

    #[test]
    fn test_diff_scans() {
        let prev = vec![
            make_finding("aws-key", "a.rs", 1, "AKIA123", Severity::Critical),
            make_finding("github-pat", "b.rs", 2, "ghp_abc", Severity::Critical),
        ];
        let curr = vec![
            make_finding("aws-key", "a.rs", 1, "AKIA123", Severity::Critical),
            make_finding("slack-token", "c.rs", 3, "xoxb-xyz", Severity::High),
        ];

        let diff = diff_scans(&prev, &curr);
        let summary = diff_summary(&diff);

        assert_eq!(summary.new_count, 1);
        assert_eq!(summary.resolved_count, 1);
        assert_eq!(summary.unchanged_count, 1);
    }

    #[test]
    fn test_finding_tracker() {
        let mut tracker = FindingTracker::new();
        let findings = vec![
            make_finding("aws-key", "a.rs", 1, "AKIA123", Severity::Critical),
        ];

        tracker.ingest(&findings, "scanner");
        assert_eq!(tracker.findings.len(), 1);

        let fp = fingerprint(&findings[0]);
        tracker.update_state(&fp, FindingState::InProgress, "analyst", None).unwrap();
        assert_eq!(tracker.by_state(&FindingState::InProgress).len(), 1);
    }

    #[test]
    fn test_suppression_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let active = Suppression {
            reason: "test".to_string(),
            suppressed_by: "admin".to_string(),
            created_at: now,
            expires_at: Some(now + 3600),
        };
        assert!(active.is_active());

        let expired = Suppression {
            reason: "test".to_string(),
            suppressed_by: "admin".to_string(),
            created_at: now - 7200,
            expires_at: Some(now - 3600),
        };
        assert!(!expired.is_active());

        let permanent = Suppression {
            reason: "test".to_string(),
            suppressed_by: "admin".to_string(),
            created_at: now,
            expires_at: None,
        };
        assert!(permanent.is_active());
    }

    #[test]
    fn test_compliance_report() {
        let findings = vec![
            make_finding("aws-key", "a.rs", 1, "AKIA123", Severity::Critical),
            make_finding("github-pat", "b.rs", 2, "ghp_abc", Severity::High),
            make_finding("generic", "c.rs", 3, "somekey", Severity::Medium),
        ];

        let report = generate_compliance_report(
            &findings,
            ComplianceFramework::PciDss,
            "./src",
        );

        assert_eq!(report.total_findings, 3);
        assert_eq!(report.critical_findings, 1);
        assert_eq!(report.high_findings, 1);
        assert_eq!(report.compliance_status, ComplianceStatus::NonCompliant);
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_compliance_report_compliant() {
        let findings: Vec<Finding> = vec![];
        let report = generate_compliance_report(
            &findings,
            ComplianceFramework::Soc2,
            "./src",
        );
        assert_eq!(report.compliance_status, ComplianceStatus::Compliant);
    }

    #[test]
    fn test_tracker_filter_suppressed() {
        let mut tracker = FindingTracker::new();
        let findings = vec![
            make_finding("aws-key", "a.rs", 1, "AKIA123", Severity::Critical),
            make_finding("github-pat", "b.rs", 2, "ghp_abc", Severity::High),
        ];

        tracker.ingest(&findings, "scanner");

        // Suppress the first finding.
        let fp = fingerprint(&findings[0]);
        tracker.suppress(&fp, "false positive", "admin", None).unwrap();

        let filtered = tracker.filter_suppressed(&findings);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id, "github-pat");
    }
}
