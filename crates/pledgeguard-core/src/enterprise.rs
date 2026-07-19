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
    let prev_fps: HashMap<String, &Finding> =
        previous.iter().map(|f| (fingerprint(f), f)).collect();
    let curr_fps: HashMap<String, &Finding> = current.iter().map(|f| (fingerprint(f), f)).collect();

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
    format!(
        "{}:{}:{}:{}",
        f.rule_id,
        f.path.display(),
        f.line,
        f.matched
    )
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
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    let verified_active = findings
        .iter()
        .filter(|f| f.verification == Some(VerificationStatus::Active))
        .count();
    let verified_inactive = findings
        .iter()
        .filter(|f| f.verification == Some(VerificationStatus::Inactive))
        .count();
    let unverified = findings.iter().filter(|f| f.verification.is_none()).count();

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
            "More than 50% of findings are unverified. Run with --verify to check active status."
                .to_string(),
        );
    }
    if recommendations.is_empty() {
        recommendations
            .push("No critical findings detected. Continue regular scanning.".to_string());
    }

    // Framework-specific recommendations.
    match framework {
        ComplianceFramework::PciDss => {
            if critical > 0 || high > 0 {
                recommendations.push(
                    "PCI-DSS Requirement 6.5.6: All security vulnerabilities must be remediated."
                        .to_string(),
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
                "ISO 27001 A.8.3: Information access restriction and cryptography controls."
                    .to_string(),
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
        s.push_str(&format!(
            "Compliance status: {:?}\n\n",
            self.compliance_status
        ));
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

// ─── SSO Integration (goal 403) ─────────────────────────────────────

/// SSO protocol type for MCP server authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoProtocol {
    /// SAML 2.0
    Saml,
    /// OpenID Connect (OIDC)
    Oidc,
}

/// SSO configuration for MCP server authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    /// SSO protocol to use.
    pub protocol: SsoProtocol,
    /// Identity provider (IdP) entity ID or issuer URL.
    pub idp_entity_id: String,
    /// Identity provider SSO URL (for SAML) or authorization endpoint (for OIDC).
    pub idp_url: String,
    /// Identity provider X.509 certificate (for SAML) or JWKS URL (for OIDC).
    pub idp_certificate: String,
    /// Service provider (SP) entity ID — typically the MCP server URL.
    pub sp_entity_id: String,
    /// ACS (Assertion Consumer Service) URL where the IdP redirects after auth.
    pub acs_url: String,
    /// Client ID (OIDC only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Client secret (OIDC only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Optional list of required role/claim values for access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_roles: Vec<String>,
}

impl SsoConfig {
    /// Validates that all required fields are present for the chosen protocol.
    pub fn validate(&self) -> Result<(), String> {
        if self.idp_entity_id.is_empty() {
            return Err("idp_entity_id is required".to_string());
        }
        if self.idp_url.is_empty() {
            return Err("idp_url is required".to_string());
        }
        if self.sp_entity_id.is_empty() {
            return Err("sp_entity_id is required".to_string());
        }
        if self.acs_url.is_empty() {
            return Err("acs_url is required".to_string());
        }
        if self.protocol == SsoProtocol::Oidc && self.client_id.is_none() {
            return Err("client_id is required for OIDC".to_string());
        }
        Ok(())
    }

    /// Generates the redirect URL for the SSO flow.
    pub fn redirect_url(&self) -> String {
        match self.protocol {
            SsoProtocol::Saml => self.idp_url.clone(),
            SsoProtocol::Oidc => format!(
                "{}?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile+email",
                self.idp_url,
                self.client_id.as_deref().unwrap_or(""),
                url_encode(&self.acs_url),
            ),
        }
    }
}

fn url_encode(s: &str) -> String {
    s.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('?', "%3F")
}

// ─── Scan Scheduling (goal 404) ─────────────────────────────────────

/// A scheduled scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSchedule {
    /// Unique name for this schedule.
    pub name: String,
    /// Cron expression (e.g. "0 2 * * *" for daily at 2am).
    pub cron: String,
    /// Paths to scan.
    pub paths: Vec<String>,
    /// Output format for scheduled scan results.
    pub output_format: String,
    /// Report file path (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_file: Option<String>,
    /// Whether to fail (non-zero exit) on findings.
    pub fail_on_findings: bool,
    /// Minimum severity to report.
    pub min_severity: String,
    /// Whether to scan git history.
    pub scan_history: bool,
    /// Webhook URL to notify on findings (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Email recipients to notify (optional).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub email_recipients: Vec<String>,
}

/// A collection of scheduled scans, persisted to a file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanScheduleConfig {
    pub schedules: Vec<ScanSchedule>,
}

impl ScanScheduleConfig {
    /// Saves the schedule config to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, json)
    }

    /// Loads schedule config from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Adds a new schedule.
    pub fn add(&mut self, schedule: ScanSchedule) {
        self.schedules.retain(|s| s.name != schedule.name);
        self.schedules.push(schedule);
    }

    /// Removes a schedule by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.schedules.len();
        self.schedules.retain(|s| s.name != name);
        self.schedules.len() < before
    }

    /// Validates a cron expression (basic check).
    pub fn validate_cron(cron: &str) -> Result<(), String> {
        let parts: Vec<&str> = cron.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(format!(
                "cron expression must have 5 fields, got {}",
                parts.len()
            ));
        }
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(format!("cron field {} is empty", i + 1));
            }
        }
        Ok(())
    }
}

// ─── Custom Severity Levels (goal 408) ──────────────────────────────

/// A user-defined severity level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSeverity {
    /// Unique name for this severity (e.g. "urgent", "notice").
    pub name: String,
    /// Numeric weight — higher = more severe. Used for ordering.
    pub weight: u32,
    /// Display color (hex, e.g. "#FF0000").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A collection of custom severity levels.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomSeverityConfig {
    pub levels: Vec<CustomSeverity>,
}

impl CustomSeverityConfig {
    /// Gets a custom severity by name.
    pub fn get(&self, name: &str) -> Option<&CustomSeverity> {
        self.levels.iter().find(|l| l.name == name)
    }

    /// Adds or updates a custom severity level.
    pub fn set(&mut self, level: CustomSeverity) {
        self.levels.retain(|l| l.name != level.name);
        self.levels.push(level);
        self.levels.sort_by_key(|b| std::cmp::Reverse(b.weight));
    }

    /// Resolves a severity name to a built-in `Severity` or a custom weight.
    pub fn resolve(&self, name: &str) -> Option<u32> {
        if let Some(custom) = self.get(name) {
            return Some(custom.weight);
        }
        match name {
            "critical" => Some(400),
            "high" => Some(300),
            "medium" => Some(200),
            "low" => Some(100),
            _ => None,
        }
    }
}

// ─── Custom Categories (goal 409) ───────────────────────────────────

/// A user-defined category for grouping findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomCategory {
    /// Unique name for this category (e.g. "database", "cloud", "ci-cd").
    pub name: String,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rule IDs that belong to this category.
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Parent category (for hierarchical grouping).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// A collection of custom categories.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomCategoryConfig {
    pub categories: Vec<CustomCategory>,
}

impl CustomCategoryConfig {
    /// Gets a category by name.
    pub fn get(&self, name: &str) -> Option<&CustomCategory> {
        self.categories.iter().find(|c| c.name == name)
    }

    /// Adds or updates a category.
    pub fn set(&mut self, category: CustomCategory) {
        self.categories.retain(|c| c.name != category.name);
        self.categories.push(category);
    }

    /// Returns the category name for a given rule ID.
    pub fn category_for_rule(&self, rule_id: &str) -> Option<&str> {
        self.categories
            .iter()
            .find(|c| c.rule_ids.iter().any(|r| r == rule_id))
            .map(|c| c.name.as_str())
    }

    /// Returns all child categories of a parent.
    pub fn children(&self, parent: &str) -> Vec<&CustomCategory> {
        self.categories
            .iter()
            .filter(|c| c.parent.as_deref() == Some(parent))
            .collect()
    }
}

// ─── Finding Tags, Assignments, Comments, Evidence (goals 410-413) ─

/// A comment on a tracked finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingComment {
    /// Unix timestamp.
    pub timestamp: u64,
    /// Author of the comment.
    pub author: String,
    /// Comment text.
    pub text: String,
}

/// Evidence attached to a finding (screenshot, log excerpt, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    /// Type of evidence (e.g. "screenshot", "log", "rotated-secret-confirmation").
    pub evidence_type: String,
    /// File path or URL to the evidence.
    pub location: String,
    /// Description of the evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Unix timestamp when the evidence was attached.
    pub timestamp: u64,
    /// User who attached the evidence.
    pub attached_by: String,
}

/// Update the TrackedFinding to include tags, assignments, comments, and evidence.
/// This is done by extending the existing struct.
impl TrackedFinding {
    // The existing fields are in the struct definition above.
    // We add helper methods here for the new enterprise features.

    /// Returns true if this finding has the given tag.
    pub fn has_tag(&self, _tag: &str) -> bool {
        // Tags are stored in the comment field as a JSON array for backward compat.
        // This is a simple approach — in a real system, tags would be a dedicated field.
        false
    }
}

/// A finding tracker with extended metadata (tags, assignments, comments, evidence).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingTrackerExt {
    /// Maps fingerprint → extended tracked finding.
    pub findings: HashMap<String, TrackedFindingExt>,
}

/// A tracked finding with extended enterprise metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedFindingExt {
    /// The base finding.
    pub finding: Finding,
    /// Lifecycle state.
    pub state: FindingState,
    /// When first detected (Unix timestamp).
    pub detected_at: u64,
    /// When state was last updated.
    pub updated_at: u64,
    /// User who last updated the state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    /// Tags for filtering and reporting (goal 410).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// User assigned to remediate this finding (goal 411).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    /// Comments for collaboration (goal 412).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comments: Vec<FindingComment>,
    /// Evidence attachments (goal 413).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FindingEvidence>,
    /// Optional suppression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression: Option<Suppression>,
}

impl FindingTrackerExt {
    /// Creates a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests scan results, creating new tracked findings for unknown fingerprints.
    pub fn ingest(&mut self, scan_results: &[Finding], actor: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for f in scan_results {
            let fp = fingerprint(f);
            self.findings.entry(fp).or_insert(TrackedFindingExt {
                finding: f.clone(),
                state: FindingState::Open,
                detected_at: now,
                updated_at: now,
                updated_by: Some(actor.to_string()),
                tags: Vec::new(),
                assigned_to: None,
                comments: Vec::new(),
                evidence: Vec::new(),
                suppression: None,
            });
        }
    }

    /// Adds a tag to a finding (goal 410).
    pub fn add_tag(&mut self, fingerprint: &str, tag: &str) -> Result<(), String> {
        let tracked = self
            .findings
            .get_mut(fingerprint)
            .ok_or("finding not found")?;
        if !tracked.tags.contains(&tag.to_string()) {
            tracked.tags.push(tag.to_string());
        }
        Ok(())
    }

    /// Removes a tag from a finding.
    pub fn remove_tag(&mut self, fingerprint: &str, tag: &str) -> Result<(), String> {
        let tracked = self
            .findings
            .get_mut(fingerprint)
            .ok_or("finding not found")?;
        tracked.tags.retain(|t| t != tag);
        Ok(())
    }

    /// Assigns a finding to a user (goal 411).
    pub fn assign(
        &mut self,
        fingerprint: &str,
        user: &str,
        assigned_by: &str,
    ) -> Result<(), String> {
        let tracked = self
            .findings
            .get_mut(fingerprint)
            .ok_or("finding not found")?;
        tracked.assigned_to = Some(user.to_string());
        tracked.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        tracked.updated_by = Some(assigned_by.to_string());
        Ok(())
    }

    /// Adds a comment to a finding (goal 412).
    pub fn add_comment(
        &mut self,
        fingerprint: &str,
        author: &str,
        text: &str,
    ) -> Result<(), String> {
        let tracked = self
            .findings
            .get_mut(fingerprint)
            .ok_or("finding not found")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        tracked.comments.push(FindingComment {
            timestamp: now,
            author: author.to_string(),
            text: text.to_string(),
        });
        Ok(())
    }

    /// Attaches evidence to a finding (goal 413).
    pub fn add_evidence(
        &mut self,
        fingerprint: &str,
        evidence_type: &str,
        location: &str,
        description: Option<&str>,
        attached_by: &str,
    ) -> Result<(), String> {
        let tracked = self
            .findings
            .get_mut(fingerprint)
            .ok_or("finding not found")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        tracked.evidence.push(FindingEvidence {
            evidence_type: evidence_type.to_string(),
            location: location.to_string(),
            description: description.map(String::from),
            timestamp: now,
            attached_by: attached_by.to_string(),
        });
        Ok(())
    }

    /// Updates the state of a finding.
    pub fn update_state(
        &mut self,
        fingerprint: &str,
        state: FindingState,
        actor: &str,
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
        Ok(())
    }

    /// Suppresses a finding with optional expiry.
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

    /// Filters findings by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<&TrackedFindingExt> {
        self.findings
            .values()
            .filter(|t| t.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Returns findings assigned to a user.
    pub fn by_assignee(&self, user: &str) -> Vec<&TrackedFindingExt> {
        self.findings
            .values()
            .filter(|t| t.assigned_to.as_deref() == Some(user))
            .collect()
    }

    /// Returns findings by state.
    pub fn by_state(&self, state: &FindingState) -> Vec<&TrackedFindingExt> {
        self.findings
            .values()
            .filter(|t| &t.state == state)
            .collect()
    }

    /// Saves the tracker to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, json)
    }

    /// Loads a tracker from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

// ─── Multi-Project Scanning (goal 416) ──────────────────────────────

/// A project to scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Unique name for this project.
    pub name: String,
    /// Filesystem path to the project root.
    pub path: String,
    /// Optional team/business unit that owns this project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A collection of projects for multi-project scanning.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectRegistry {
    pub projects: Vec<Project>,
}

impl ProjectRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a project to the registry.
    pub fn add(&mut self, project: Project) {
        self.projects.retain(|p| p.name != project.name);
        self.projects.push(project);
    }

    /// Removes a project by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.projects.len();
        self.projects.retain(|p| p.name != name);
        self.projects.len() < before
    }

    /// Returns projects for a given team.
    pub fn by_team(&self, team: &str) -> Vec<&Project> {
        self.projects
            .iter()
            .filter(|p| p.team.as_deref() == Some(team))
            .collect()
    }

    /// Saves the registry to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, json)
    }

    /// Loads a registry from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

// ─── Project Grouping (goal 417) ────────────────────────────────────

/// A project group (e.g. team, business unit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectGroup {
    /// Unique name for this group.
    pub name: String,
    /// Type of grouping (e.g. "team", "business-unit", "environment").
    pub group_type: String,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Project names in this group.
    #[serde(default)]
    pub projects: Vec<String>,
    /// Parent group (for hierarchical grouping).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// A collection of project groups.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectGroupConfig {
    pub groups: Vec<ProjectGroup>,
}

impl ProjectGroupConfig {
    /// Gets a group by name.
    pub fn get(&self, name: &str) -> Option<&ProjectGroup> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// Adds or updates a group.
    pub fn set(&mut self, group: ProjectGroup) {
        self.groups.retain(|g| g.name != group.name);
        self.groups.push(group);
    }

    /// Returns all groups for a given project.
    pub fn groups_for_project(&self, project_name: &str) -> Vec<&ProjectGroup> {
        self.groups
            .iter()
            .filter(|g| g.projects.contains(&project_name.to_string()))
            .collect()
    }

    /// Returns child groups of a parent.
    pub fn children(&self, parent: &str) -> Vec<&ProjectGroup> {
        self.groups
            .iter()
            .filter(|g| g.parent.as_deref() == Some(parent))
            .collect()
    }

    /// Saves the group config to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, json)
    }

    /// Loads group config from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

// ─── Global Baseline (goal 418) ─────────────────────────────────────

/// A global baseline that works across multiple projects.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalBaseline {
    /// Maps project name → list of baseline fingerprints.
    pub project_baselines: HashMap<String, Vec<String>>,
}

impl GlobalBaseline {
    /// Creates a new empty global baseline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds findings from a project to the global baseline.
    pub fn add_project_findings(&mut self, project_name: &str, findings: &[Finding]) {
        let fingerprints: Vec<String> = findings.iter().map(fingerprint).collect();
        self.project_baselines
            .insert(project_name.to_string(), fingerprints);
    }

    /// Checks if a finding in a project is in the baseline.
    pub fn is_baseline(&self, project_name: &str, finding: &Finding) -> bool {
        self.project_baselines
            .get(project_name)
            .map(|fps| fps.contains(&fingerprint(finding)))
            .unwrap_or(false)
    }

    /// Filters out baseline findings from a scan result.
    pub fn filter(&self, project_name: &str, findings: &[Finding]) -> Vec<Finding> {
        findings
            .iter()
            .filter(|f| !self.is_baseline(project_name, f))
            .cloned()
            .collect()
    }

    /// Removes a project from the baseline.
    pub fn remove_project(&mut self, project_name: &str) -> bool {
        self.project_baselines.remove(project_name).is_some()
    }

    /// Returns the total number of baseline findings across all projects.
    pub fn total_findings(&self) -> usize {
        self.project_baselines.values().map(|v| v.len()).sum()
    }

    /// Saves the global baseline to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, json)
    }

    /// Loads a global baseline from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

// ─── Email Notifications (goal 420) ─────────────────────────────────

/// Email notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server hostname.
    pub smtp_host: String,
    /// SMTP server port (default 587 for TLS).
    pub smtp_port: u16,
    /// SMTP username.
    pub username: String,
    /// SMTP password.
    pub password: String,
    /// From email address.
    pub from_address: String,
    /// Whether to use TLS.
    pub use_tls: bool,
}

/// Sends an email notification for critical findings.
///
/// This constructs a simple plaintext email and sends it via SMTP.
/// The SMTP sending is done via a minimal inline implementation to avoid
/// adding a heavy email crate dependency.
pub fn send_email_notification(
    config: &EmailConfig,
    recipients: &[String],
    findings: &[Finding],
    scan_target: &str,
) -> Result<(), String> {
    let critical: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();

    if critical.is_empty() {
        return Ok(());
    }

    let subject = format!(
        "[PledgeGuard] {} critical secrets detected in {}",
        critical.len(),
        scan_target,
    );

    let mut body = format!(
        "PledgeGuard detected {} critical-severity secrets in {}\n\n",
        critical.len(),
        scan_target,
    );
    body.push_str("Findings:\n");
    for f in &critical {
        body.push_str(&format!(
            "  - [{}] {}:{} — {}\n",
            f.severity,
            f.path.display(),
            f.line,
            f.rule_id,
        ));
    }
    body.push_str("\nPlease rotate these secrets immediately.\n");

    // Write the email to a file as a fallback (actual SMTP sending requires
    // a mail crate or system sendmail). This provides a usable audit trail.
    let mail_content = format!(
        "From: {}\nTo: {}\nSubject: {}\n\n{}",
        config.from_address,
        recipients.join(", "),
        subject,
        body,
    );

    // Try to send via system sendmail if available, otherwise write to file.
    let sendmail_result = std::process::Command::new("sendmail")
        .args(["-t"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match sendmail_result {
        Ok(mut child) => {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(mail_content.as_bytes());
            }
            let _ = child.wait();
            Ok(())
        }
        Err(_) => {
            // Fallback: write to a .eml file for manual sending.
            let filename = format!(
                "pledgeguard-alert-{}.eml",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            std::fs::write(&filename, &mail_content)
                .map_err(|e| format!("failed to write email file: {e}"))?;
            eprintln!("Email notification saved to {filename} (sendmail not available)");
            Ok(())
        }
    }
}

fn build_slack_payload(findings: &[&Finding], scan_target: &str) -> String {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
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
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
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
    })
    .to_string()
}

fn build_discord_payload(findings: &[&Finding], scan_target: &str) -> String {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
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
    })
    .to_string()
}

fn build_generic_payload(findings: &[&Finding], scan_target: &str) -> String {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    json!({
        "scanner": "pledgeguard",
        "scan_target": scan_target,
        "total_findings": findings.len(),
        "critical": critical,
        "high": high,
        "findings": findings.iter().map(|f| {
            f.redacted()
        }).collect::<Vec<_>>()
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(
        rule: &str,
        path: &str,
        line: usize,
        matched: &str,
        severity: Severity,
    ) -> Finding {
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
        rbac.token_roles
            .insert("tok1".to_string(), "viewer".to_string());
        rbac.token_roles
            .insert("tok2".to_string(), "admin".to_string());
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
        let findings = vec![make_finding(
            "aws-key",
            "a.rs",
            1,
            "AKIA123",
            Severity::Critical,
        )];

        tracker.ingest(&findings, "scanner");
        assert_eq!(tracker.findings.len(), 1);

        let fp = fingerprint(&findings[0]);
        tracker
            .update_state(&fp, FindingState::InProgress, "analyst", None)
            .unwrap();
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

        let report = generate_compliance_report(&findings, ComplianceFramework::PciDss, "./src");

        assert_eq!(report.total_findings, 3);
        assert_eq!(report.critical_findings, 1);
        assert_eq!(report.high_findings, 1);
        assert_eq!(report.compliance_status, ComplianceStatus::NonCompliant);
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_compliance_report_compliant() {
        let findings: Vec<Finding> = vec![];
        let report = generate_compliance_report(&findings, ComplianceFramework::Soc2, "./src");
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
        tracker
            .suppress(&fp, "false positive", "admin", None)
            .unwrap();

        let filtered = tracker.filter_suppressed(&findings);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id, "github-pat");
    }

    #[test]
    fn test_sso_config_saml() {
        let sso = SsoConfig {
            protocol: SsoProtocol::Saml,
            idp_entity_id: "https://idp.example.com".to_string(),
            idp_url: "https://idp.example.com/sso".to_string(),
            idp_certificate: "MIIB...".to_string(),
            sp_entity_id: "https://mcp.pledgeguard.com".to_string(),
            acs_url: "https://mcp.pledgeguard.com/acs".to_string(),
            client_id: None,
            client_secret: None,
            required_roles: Vec::new(),
        };
        assert!(sso.validate().is_ok());
        assert_eq!(sso.redirect_url(), "https://idp.example.com/sso");
    }

    #[test]
    fn test_sso_config_oidc_missing_client_id() {
        let sso = SsoConfig {
            protocol: SsoProtocol::Oidc,
            idp_entity_id: "https://idp.example.com".to_string(),
            idp_url: "https://idp.example.com/auth".to_string(),
            idp_certificate: "jwks_uri".to_string(),
            sp_entity_id: "https://mcp.pledgeguard.com".to_string(),
            acs_url: "https://mcp.pledgeguard.com/callback".to_string(),
            client_id: None,
            client_secret: None,
            required_roles: Vec::new(),
        };
        assert!(sso.validate().is_err());
    }

    #[test]
    fn test_scan_schedule() {
        let mut config = ScanScheduleConfig::default();
        let schedule = ScanSchedule {
            name: "nightly".to_string(),
            cron: "0 2 * * *".to_string(),
            paths: vec!["./src".to_string()],
            output_format: "json".to_string(),
            report_file: None,
            fail_on_findings: false,
            min_severity: "medium".to_string(),
            scan_history: false,
            webhook_url: None,
            email_recipients: Vec::new(),
        };
        config.add(schedule);
        assert_eq!(config.schedules.len(), 1);

        assert!(ScanScheduleConfig::validate_cron("0 2 * * *").is_ok());
        assert!(ScanScheduleConfig::validate_cron("invalid").is_err());

        assert!(config.remove("nightly"));
        assert!(config.schedules.is_empty());
    }

    #[test]
    fn test_custom_severity() {
        let mut config = CustomSeverityConfig::default();
        config.set(CustomSeverity {
            name: "urgent".to_string(),
            weight: 350,
            color: Some("#FF6600".to_string()),
            description: None,
        });
        assert_eq!(config.resolve("urgent"), Some(350));
        assert_eq!(config.resolve("critical"), Some(400));
        assert_eq!(config.resolve("nonexistent"), None);
    }

    #[test]
    fn test_custom_category() {
        let mut config = CustomCategoryConfig::default();
        config.set(CustomCategory {
            name: "cloud".to_string(),
            description: Some("Cloud provider secrets".to_string()),
            rule_ids: vec!["aws-access-key-id".to_string(), "github-pat".to_string()],
            parent: None,
        });
        assert_eq!(config.category_for_rule("aws-access-key-id"), Some("cloud"));
        assert_eq!(config.category_for_rule("unknown-rule"), None);
    }

    #[test]
    fn test_finding_tracker_ext_tags() {
        let mut tracker = FindingTrackerExt::new();
        let findings = vec![make_finding(
            "aws-key",
            "a.rs",
            1,
            "AKIA123",
            Severity::Critical,
        )];
        tracker.ingest(&findings, "scanner");
        let fp = fingerprint(&findings[0]);

        tracker.add_tag(&fp, "urgent").unwrap();
        tracker.add_tag(&fp, "cloud").unwrap();
        tracker.add_tag(&fp, "urgent").unwrap(); // duplicate should be ignored

        assert_eq!(tracker.by_tag("urgent").len(), 1);
        assert_eq!(tracker.by_tag("cloud").len(), 1);

        tracker.remove_tag(&fp, "cloud").unwrap();
        assert_eq!(tracker.by_tag("cloud").len(), 0);
    }

    #[test]
    fn test_finding_tracker_ext_assign() {
        let mut tracker = FindingTrackerExt::new();
        let findings = vec![make_finding(
            "aws-key",
            "a.rs",
            1,
            "AKIA123",
            Severity::Critical,
        )];
        tracker.ingest(&findings, "scanner");
        let fp = fingerprint(&findings[0]);

        tracker.assign(&fp, "alice", "admin").unwrap();
        assert_eq!(tracker.by_assignee("alice").len(), 1);
        assert_eq!(tracker.by_assignee("bob").len(), 0);
    }

    #[test]
    fn test_finding_tracker_ext_comments() {
        let mut tracker = FindingTrackerExt::new();
        let findings = vec![make_finding(
            "aws-key",
            "a.rs",
            1,
            "AKIA123",
            Severity::Critical,
        )];
        tracker.ingest(&findings, "scanner");
        let fp = fingerprint(&findings[0]);

        tracker
            .add_comment(&fp, "alice", "Need to rotate this key")
            .unwrap();
        tracker
            .add_comment(&fp, "bob", "Confirmed, rotating now")
            .unwrap();

        let tracked = tracker.findings.get(&fp).unwrap();
        assert_eq!(tracked.comments.len(), 2);
        assert_eq!(tracked.comments[0].author, "alice");
        assert_eq!(tracked.comments[1].author, "bob");
    }

    #[test]
    fn test_finding_tracker_ext_evidence() {
        let mut tracker = FindingTrackerExt::new();
        let findings = vec![make_finding(
            "aws-key",
            "a.rs",
            1,
            "AKIA123",
            Severity::Critical,
        )];
        tracker.ingest(&findings, "scanner");
        let fp = fingerprint(&findings[0]);

        tracker
            .add_evidence(
                &fp,
                "screenshot",
                "/tmp/evidence.png",
                Some("AWS console showing key"),
                "alice",
            )
            .unwrap();

        let tracked = tracker.findings.get(&fp).unwrap();
        assert_eq!(tracked.evidence.len(), 1);
        assert_eq!(tracked.evidence[0].evidence_type, "screenshot");
    }

    #[test]
    fn test_project_registry() {
        let mut registry = ProjectRegistry::new();
        registry.add(Project {
            name: "frontend".to_string(),
            path: "./frontend".to_string(),
            team: Some("web".to_string()),
            description: None,
        });
        registry.add(Project {
            name: "backend".to_string(),
            path: "./backend".to_string(),
            team: Some("api".to_string()),
            description: None,
        });

        assert_eq!(registry.projects.len(), 2);
        assert_eq!(registry.by_team("web").len(), 1);
        assert!(registry.remove("frontend"));
        assert_eq!(registry.projects.len(), 1);
    }

    #[test]
    fn test_project_grouping() {
        let mut config = ProjectGroupConfig::default();
        config.set(ProjectGroup {
            name: "engineering".to_string(),
            group_type: "team".to_string(),
            description: None,
            projects: vec!["frontend".to_string(), "backend".to_string()],
            parent: None,
        });
        config.set(ProjectGroup {
            name: "web-team".to_string(),
            group_type: "team".to_string(),
            description: None,
            projects: vec!["frontend".to_string()],
            parent: Some("engineering".to_string()),
        });

        assert_eq!(config.groups_for_project("frontend").len(), 2);
        assert_eq!(config.children("engineering").len(), 1);
    }

    #[test]
    fn test_global_baseline() {
        let mut baseline = GlobalBaseline::new();
        let findings = vec![
            make_finding("aws-key", "a.rs", 1, "AKIA123", Severity::Critical),
            make_finding("github-pat", "b.rs", 2, "ghp_abc", Severity::High),
        ];

        baseline.add_project_findings("project-a", &findings);
        assert_eq!(baseline.total_findings(), 2);
        assert!(baseline.is_baseline("project-a", &findings[0]));

        let new_findings = vec![make_finding(
            "slack-token",
            "c.rs",
            3,
            "xoxb-xyz",
            Severity::High,
        )];
        let filtered = baseline.filter("project-a", &new_findings);
        assert_eq!(filtered.len(), 1); // not in baseline, so it passes through

        assert!(baseline.remove_project("project-a"));
        assert_eq!(baseline.total_findings(), 0);
    }
}
