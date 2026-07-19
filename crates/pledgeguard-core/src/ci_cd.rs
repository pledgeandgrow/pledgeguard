//! CI/CD integration features (goals 342-370).
//!
//! This module provides:
//! - CI/CD pipeline templates (GitLab CI, CircleCI orb, Jenkins, DroneCI,
//!   Azure DevOps, Bitbucket Pipelines, TeamCity, Husky, lint-staged)
//! - CLI scan options (--since-commit, --since-date, --branch, --pr-number,
//!   --commit-range, --exit-code, --ignore-exit-code, --fail-on-severity,
//!   --max-findings, --ci-mode, --report-append, --baseline-auto, --enforce-baseline)
//! - PR/MR comment integrations (GitHub, GitLab, Azure DevOps)
//! - SARIF auto-upload to GitHub Code Scanning
//! - JUnit auto-upload to CI test runners

use crate::finding::Finding;
use std::path::Path;

// ── 342: GitLab CI template ────────────────────────────────────────────

/// Generate a `.gitlab-ci.yml` template for PledgeGuard scanning.
pub fn gitlab_ci_template() -> String {
    r#"# PledgeGuard secret scanning — GitLab CI template
# Include this in your .gitlab-ci.yml:
#   include:
#     - remote: 'https://raw.githubusercontent.com/pledgeandgrow/pledgeguard/main/gitlab-ci.yml'

pledgeguard:
  stage: test
  image: rust:latest
  before_script:
    - cargo install pledgeguard
  script:
    - pledgeguard scan . --format sarif --report-file pledgeguard-report.sarif --fail-on-findings
  artifacts:
    reports:
      dotenv: pledgeguard-report.sarif
    paths:
      - pledgeguard-report.sarif
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"#
    .to_string()
}

// ── 343: CircleCI orb ──────────────────────────────────────────────────

/// Generate a CircleCI orb template for PledgeGuard scanning.
pub fn circleci_orb_template() -> String {
    r#"version: 2.1

# PledgeGuard CircleCI Orb
# Usage in your config.yml:
#   orbs:
#     pledgeguard: pledgeandgrow/pledgeguard@1.0.0
#   jobs:
#     scan:
#       executor: pledgeguard/default
#       steps:
#         - checkout
#         - pledgeguard/scan:
#             path: .
#             fail-on-findings: true

commands:
  scan:
    description: "Scan for secrets with PledgeGuard"
    parameters:
      path:
        type: string
        default: "."
      fail-on-findings:
        type: boolean
        default: true
      format:
        type: string
        default: "sarif"
    steps:
      - run:
          name: Install PledgeGuard
          command: cargo install pledgeguard
      - run:
          name: Run PledgeGuard scan
          command: |
            pledgeguard scan <<parameters.path>> \
              --format <<parameters.format>> \
              --report-file pledgeguard-report.<<parameters.format>> \
              $([[ <<parameters.fail-on-findings>> == true ]] && echo "--fail-on-findings")
      - store_artifacts:
          path: pledgeguard-report.<<parameters.format>>

executors:
  default:
    description: "Rust executor for PledgeGuard"
    docker:
      - image: rust:latest
"#
    .to_string()
}

// ── 344: Jenkins plugin ────────────────────────────────────────────────

/// Generate a Jenkins pipeline snippet for PledgeGuard scanning.
pub fn jenkins_pipeline_template() -> String {
    r#"// PledgeGuard Jenkins Pipeline
// Add this as a Jenkinsfile in your repository:

pipeline {
    agent any

    stages {
        stage('Install PledgeGuard') {
            steps {
                sh 'cargo install pledgeguard || true'
            }
        }

        stage('Scan for Secrets') {
            steps {
                sh '''
                    pledgeguard scan . \
                        --format sarif \
                        --report-file pledgeguard-report.sarif \
                        --fail-on-findings
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'pledgeguard-report.sarif', allowEmptyArchive: true
                    publishHTML(target: [
                        reportDir: '.',
                        reportFiles: 'pledgeguard-report.sarif',
                        reportName: 'PledgeGuard Report'
                    ])
                }
            }
        }
    }
}
"#
    .to_string()
}

// ── 345: DroneCI plugin ────────────────────────────────────────────────

/// Generate a DroneCI plugin entrypoint template.
pub fn droneci_plugin_template() -> String {
    r#"# PledgeGuard DroneCI Plugin
# Usage in your .drone.yml:
#   steps:
#     - name: pledgeguard-scan
#       image: pledgeandgrow/pledgeguard:latest
#       commands:
#         - pledgeguard scan . --format sarif --report-file report.sarif --fail-on-findings
#       when:
#         event: [push, pull_request]

kind: pipeline
type: docker
name: pledgeguard-scan

steps:
  - name: scan
    image: pledgeandgrow/pledgeguard:latest
    commands:
      - pledgeguard scan . --format sarif --report-file pledgeguard-report.sarif --fail-on-findings
    when:
      event: [push, pull_request]

  - name: upload
    image: plugins/s3
    settings:
      bucket: pledgeguard-reports
      source: pledgeguard-report.sarif
      target: /${DRONE_REPO}/${DRONE_BUILD_NUMBER}/
    when:
      status: [success, failure]
"#
    .to_string()
}

// ── 346: Azure DevOps extension ────────────────────────────────────────

/// Generate an Azure DevOps Pipeline template for PledgeGuard.
pub fn azure_devops_template() -> String {
    r#"# PledgeGuard Azure DevOps Pipeline
# Add this as a YAML pipeline in Azure DevOps:

trigger:
  branches:
    include:
      - main
      - master

pr:
  branches:
    include:
      - '*'

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: CmdLine@2
    displayName: 'Install PledgeGuard'
    inputs:
      script: 'cargo install pledgeguard'

  - task: CmdLine@2
    displayName: 'Run PledgeGuard scan'
    inputs:
      script: |
        pledgeguard scan . \
          --format sarif \
          --report-file $(Build.ArtifactStagingDirectory)/pledgeguard-report.sarif \
          --fail-on-findings
    continueOnError: true

  - task: PublishBuildArtifacts@1
    displayName: 'Publish PledgeGuard report'
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/pledgeguard-report.sarif'
      ArtifactName: 'PledgeGuardReport'
      publishLocation: 'Container'
"#
    .to_string()
}

// ── 347: Bitbucket Pipelines pipe ──────────────────────────────────────

/// Generate a Bitbucket Pipelines pipe template.
pub fn bitbucket_pipe_template() -> String {
    r"# PledgeGuard Bitbucket Pipelines Pipe
# Usage in your bitbucket-pipelines.yml:

pipelines:
  default:
    - step:
        name: Scan for secrets
        image: pledgeandgrow/pledgeguard:latest
        script:
          - pledgeguard scan . --format sarif --report-file pledgeguard-report.sarif --fail-on-findings
        artifacts:
          - pledgeguard-report.sarif

  pull-requests:
    '**':
      - step:
          name: PR secret scan
          image: pledgeandgrow/pledgeguard:latest
          script:
            - pledgeguard scan . --format sarif --fail-on-findings
".to_string()
}

// ── 348: TeamCity build feature ────────────────────────────────────────

/// Generate a TeamCity build feature template.
pub fn teamcity_template() -> String {
    r#"# PledgeGuard TeamCity Build Feature
# Add this to your TeamCity project configuration:

## Build Step: PledgeGuard Secret Scan

### Command Line Runner
```
cargo install pledgeguard
pledgeguard scan . --format sarif --report-file pledgeguard-report.sarif --fail-on-findings
```

### Artifact Paths
```
pledgeguard-report.sarif => pledgeguard
```

### Build Failure Conditions
- Fail build if: exit code is not zero
- Fail build if: log output contains "CRITICAL"
"#
    .to_string()
}

// ── 350: Husky hook ────────────────────────────────────────────────────

/// Generate a Husky hook configuration for PledgeGuard.
pub fn husky_hook_template() -> String {
    r#"#!/usr/bin/env sh
# Husky pre-commit hook for PledgeGuard
# Install: npx husky add .husky/pre-commit "pledgeguard scan --diff --fail-on-findings"

. "$(dirname -- "$0")/_/husky.sh"

pledgeguard scan --diff --fail-on-findings --format github-actions
"#
    .to_string()
}

// ── 351: lint-staged config ────────────────────────────────────────────

/// Generate a lint-staged configuration for PledgeGuard.
pub fn lint_staged_template() -> String {
    r#"{
  "**/*": "pledgeguard scan --diff --fail-on-findings --format github-actions"
}
"#
    .to_string()
}

// ── 352-357: CLI scan options ──────────────────────────────────────────

/// Configuration for incremental/PR-scoped scanning.
#[derive(Debug, Clone, Default)]
pub struct ScanScope {
    /// Scan only commits after this commit SHA (goal 352).
    pub since_commit: Option<String>,
    /// Scan only commits after this date (goal 353).
    pub since_date: Option<String>,
    /// Scan only this branch (goal 354).
    pub branch: Option<String>,
    /// PR number to scan via API (goal 356).
    pub pr_number: Option<u64>,
    /// Commit range A..B to scan (goal 357).
    pub commit_range: Option<String>,
}

impl ScanScope {
    /// Build git log arguments from the scan scope.
    pub fn git_log_args(&self) -> Vec<String> {
        let mut args = vec!["log".to_string(), "--oneline".to_string()];

        if let Some(ref range) = self.commit_range {
            args.push(range.clone());
        } else if let Some(ref since) = self.since_commit {
            args.push(format!("{since}..HEAD"));
        }

        if let Some(ref date) = self.since_date {
            args.push(format!("--since={date}"));
        }

        if let Some(ref branch) = self.branch {
            args.push(branch.clone());
        }

        args
    }

    /// Check if any scope filter is set.
    pub fn is_scoped(&self) -> bool {
        self.since_commit.is_some()
            || self.since_date.is_some()
            || self.branch.is_some()
            || self.pr_number.is_some()
            || self.commit_range.is_some()
    }
}

// ── 358-362: Exit code and CI mode options ─────────────────────────────

/// Configuration for CI exit code behavior.
#[derive(Debug, Clone, Default)]
pub struct ExitCodeConfig {
    /// Custom exit code on findings (default: 1) (goal 358).
    pub exit_code: Option<i32>,
    /// Always exit 0 regardless of findings (goal 359).
    pub ignore_exit_code: bool,
    /// Fail only on findings >= this severity (goal 360).
    pub fail_on_severity: Option<crate::finding::Severity>,
    /// Stop after N findings (goal 361).
    pub max_findings: Option<usize>,
    /// CI-optimized mode: no color, JSON output, fail-on-findings (goal 362).
    pub ci_mode: bool,
}

impl ExitCodeConfig {
    /// Determine the exit code based on findings and config.
    pub fn compute_exit_code(&self, findings: &[Finding]) -> i32 {
        if self.ignore_exit_code {
            return 0;
        }

        let filtered: Vec<&Finding> = if let Some(ref min_sev) = self.fail_on_severity {
            findings.iter().filter(|f| f.severity >= *min_sev).collect()
        } else {
            findings.iter().collect()
        };

        if let Some(max) = self.max_findings
            && filtered.len() > max
        {
            return self.exit_code.unwrap_or(1);
        }

        if !filtered.is_empty() {
            self.exit_code.unwrap_or(1)
        } else {
            0
        }
    }
}

// ── 363: Report append ─────────────────────────────────────────────────

/// Append findings to an existing report file (for multi-scan aggregation).
pub fn append_report(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{content}")?;
    Ok(())
}

// ── 364-365: Baseline auto and enforce ─────────────────────────────────

/// Baseline management for CI mode.
#[derive(Debug, Clone, Default)]
pub struct BaselineCiConfig {
    /// Auto-create baseline on first run, enforce on subsequent (goal 364).
    pub auto: bool,
    /// Fail if baseline is missing or outdated (goal 365).
    pub enforce: bool,
}

impl BaselineCiConfig {
    /// Check if baseline file exists.
    pub fn baseline_exists(path: &Path) -> bool {
        path.exists()
    }

    /// Determine baseline action for this run.
    /// Returns (should_create, should_enforce).
    pub fn determine_action(&self, baseline_path: &Path) -> (bool, bool) {
        let exists = Self::baseline_exists(baseline_path);
        if self.auto {
            if exists { (false, true) } else { (true, false) }
        } else if self.enforce && !exists {
            (false, true) // enforce will fail
        } else {
            (false, false)
        }
    }
}

// ── 366-368: PR/MR comment integrations ────────────────────────────────

/// Configuration for posting findings as PR/MR comments.
#[derive(Debug, Clone)]
pub struct PrCommentConfig {
    /// CI platform type.
    pub platform: CiPlatform,
    /// API token for authentication.
    pub token: String,
    /// Repository slug (e.g., "owner/repo").
    pub repo_slug: String,
    /// PR/MR number.
    pub pr_number: u64,
    /// API base URL (for self-hosted instances).
    pub base_url: Option<String>,
}

/// Supported CI platforms for PR comments.
#[derive(Debug, Clone, PartialEq)]
pub enum CiPlatform {
    GitHub,
    GitLab,
    AzureDevOps,
}

/// Format findings as a PR/MR comment body.
pub fn format_pr_comment(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "## PledgeGuard Scan Results\n\nNo secrets found. Your code is clean!".to_string();
    }

    let mut comment = String::new();
    comment.push_str("## PledgeGuard Scan Results\n\n");
    comment.push_str(&format!(
        "Found **{}** potential secret(s):\n\n",
        findings.len()
    ));
    comment.push_str("| Severity | Rule | File | Line | Matched |\n");
    comment.push_str("|----------|------|------|------|---------|\n");

    for f in findings {
        let matched = crate::redact::redact(&f.matched);
        comment.push_str(&format!(
            "| {} | {} | {} | {} | `{}` |\n",
            f.severity,
            f.rule_id,
            f.path.display(),
            f.line,
            matched
        ));
    }

    comment.push_str("\n---\n");
    comment.push_str("Please review and remove or rotate any leaked secrets. ");
    comment.push_str("Use `pledgeguard rotate` to generate replacement secrets.");

    comment
}

/// Post findings as a GitHub PR comment (goal 366).
pub fn post_github_pr_comment(
    config: &PrCommentConfig,
    findings: &[Finding],
) -> Result<(), CiError> {
    let body = format_pr_comment(findings);
    let base = config
        .base_url
        .as_deref()
        .unwrap_or("https://api.github.com");
    let url = format!(
        "{base}/repos/{}/issues/{}/comments",
        config.repo_slug, config.pr_number
    );

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();

    let payload = serde_json::json!({ "body": body }).to_string();

    agent
        .post(&url)
        .set("Authorization", &format!("Bearer {}", config.token))
        .set("Accept", "application/vnd.github.v3+json")
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| CiError::Http(e.to_string()))?;

    Ok(())
}

/// Post findings as a GitLab MR comment (goal 367).
pub fn post_gitlab_mr_comment(
    config: &PrCommentConfig,
    findings: &[Finding],
) -> Result<(), CiError> {
    let body = format_pr_comment(findings);
    let base = config
        .base_url
        .as_deref()
        .unwrap_or("https://gitlab.com/api/v4");
    let url = format!(
        "{base}/projects/{}/merge_requests/{}/notes",
        percent_encode(&config.repo_slug),
        config.pr_number
    );

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();

    let payload = serde_json::json!({ "body": body }).to_string();

    agent
        .post(&url)
        .set("PRIVATE-TOKEN", &config.token)
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| CiError::Http(e.to_string()))?;

    Ok(())
}

/// Post findings as an Azure DevOps PR comment (goal 368).
pub fn post_azure_devops_pr_comment(
    config: &PrCommentConfig,
    findings: &[Finding],
) -> Result<(), CiError> {
    let body = format_pr_comment(findings);
    let base = config
        .base_url
        .as_deref()
        .unwrap_or("https://dev.azure.com");
    let url = format!(
        "{base}/{}/_apis/git/repositories/{}/pullRequests/{}/threads?api-version=7.0",
        config.repo_slug.split('/').next().unwrap_or("org"),
        config.repo_slug.split('/').nth(1).unwrap_or("repo"),
        config.pr_number
    );

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();

    let payload = serde_json::json!({
        "comments": [{ "content": body, "commentType": 1 }],
        "status": 1
    })
    .to_string();

    agent
        .post(&url)
        .set("Authorization", &format!("Bearer {}", config.token))
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| CiError::Http(e.to_string()))?;

    Ok(())
}

// ── 369: SARIF auto-upload ─────────────────────────────────────────────

/// Upload SARIF report to GitHub Code Scanning (goal 369).
pub fn upload_sarif_to_github(
    token: &str,
    repo_slug: &str,
    sarif_content: &str,
    commit_sha: &str,
    ref_name: &str,
) -> Result<(), CiError> {
    let url = format!(
        "https://api.github.com/repos/{}/code-scanning/sarifs",
        repo_slug
    );

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(60))
        .build();

    use base64::Engine;
    let encoded_sarif = base64::engine::general_purpose::STANDARD.encode(sarif_content.as_bytes());

    let payload = serde_json::json!({
        "sarif": encoded_sarif,
        "commit_sha": commit_sha,
        "ref": ref_name,
        "tool_name": "pledgeguard"
    })
    .to_string();

    agent
        .post(&url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/vnd.github.v3+json")
        .set("Content-Type", "application/json")
        .send_string(&payload)
        .map_err(|e| CiError::Http(e.to_string()))?;

    Ok(())
}

// ── 370: JUnit auto-upload ─────────────────────────────────────────────

/// Generate JUnit XML for CI test runner upload (goal 370).
/// Wraps findings as test cases so CI systems can display them natively.
pub fn generate_junit_for_ci(findings: &[Finding], suite_name: &str) -> String {
    let total = findings.len();
    let failures = findings
        .iter()
        .filter(|f| f.severity >= crate::finding::Severity::High)
        .count();

    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuites tests=\"{total}\" failures=\"{failures}\" errors=\"0\" time=\"0\">\n"
    ));
    xml.push_str(&format!(
        "  <testsuite name=\"{suite_name}\" tests=\"{total}\" failures=\"{failures}\" errors=\"0\">\n"
    ));

    for f in findings {
        let test_name = format!("{}_L{}_{}", f.rule_id, f.line, f.path.display());
        let is_failure = f.severity >= crate::finding::Severity::High;
        if is_failure {
            xml.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"{}\">\n",
                test_name, f.rule_id
            ));
            xml.push_str(&format!(
                "      <failure message=\"{} in {}:{}\">{}</failure>\n",
                f.description,
                f.path.display(),
                f.line,
                crate::redact::redact(&f.matched)
            ));
            xml.push_str("    </testcase>\n");
        } else {
            xml.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"{}\"/>\n",
                test_name, f.rule_id
            ));
        }
    }

    xml.push_str("  </testsuite>\n");
    xml.push_str("</testsuites>\n");
    xml
}

// ── Error type ─────────────────────────────────────────────────────────

/// Simple percent-encoding for URL components.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            for byte in c.to_string().as_bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

/// Errors for CI/CD operations.
#[derive(Debug, Clone)]
pub enum CiError {
    /// HTTP error.
    Http(String),
    /// Configuration error.
    Config(String),
    /// I/O error.
    Io(String),
}

impl std::fmt::Display for CiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(msg) => write!(f, "CI HTTP error: {msg}"),
            Self::Config(msg) => write!(f, "CI config error: {msg}"),
            Self::Io(msg) => write!(f, "CI I/O error: {msg}"),
        }
    }
}

impl std::error::Error for CiError {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::path::PathBuf;

    fn make_finding(rule: &str, sev: Severity, line: usize) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            description: "Test secret".to_string(),
            severity: sev,
            path: PathBuf::from("src/config.rs"),
            line,
            column: 1,
            matched: "AKIAIOSFODNN7EXAMPLE".to_string(),
            context: "key = AKIAIOSFODNN7EXAMPLE".to_string(),
            commit: None,
            likely_false_positive: false,
            verification: None,
        }
    }

    #[test]
    fn test_gitlab_ci_template() {
        let template = gitlab_ci_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains(".gitlab-ci.yml"));
        assert!(template.contains("sarif"));
    }

    #[test]
    fn test_circleci_orb_template() {
        let template = circleci_orb_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("orb"));
        assert!(template.contains("commands"));
    }

    #[test]
    fn test_jenkins_template() {
        let template = jenkins_pipeline_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("Jenkinsfile"));
        assert!(template.contains("pipeline"));
    }

    #[test]
    fn test_droneci_template() {
        let template = droneci_plugin_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("drone"));
        assert!(template.contains(".drone.yml"));
    }

    #[test]
    fn test_azure_devops_template() {
        let template = azure_devops_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("Azure"));
        assert!(template.contains("CmdLine@2"));
    }

    #[test]
    fn test_bitbucket_template() {
        let template = bitbucket_pipe_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("bitbucket-pipelines"));
    }

    #[test]
    fn test_teamcity_template() {
        let template = teamcity_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("TeamCity"));
    }

    #[test]
    fn test_husky_template() {
        let template = husky_hook_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("husky"));
        assert!(template.contains("pre-commit"));
    }

    #[test]
    fn test_lint_staged_template() {
        let template = lint_staged_template();
        assert!(template.contains("pledgeguard"));
        assert!(template.contains("lint-staged") || template.contains("**/*"));
    }

    #[test]
    fn test_scan_scope() {
        let scope = ScanScope {
            since_commit: Some("abc123".to_string()),
            ..Default::default()
        };
        assert!(scope.is_scoped());
        let args = scope.git_log_args();
        assert!(args.contains(&"abc123..HEAD".to_string()));

        let scope = ScanScope::default();
        assert!(!scope.is_scoped());
    }

    #[test]
    fn test_scan_scope_date() {
        let scope = ScanScope {
            since_date: Some("2024-01-01".to_string()),
            ..Default::default()
        };
        let args = scope.git_log_args();
        assert!(args.iter().any(|a| a.contains("--since=2024-01-01")));
    }

    #[test]
    fn test_scan_scope_branch() {
        let scope = ScanScope {
            branch: Some("feature/foo".to_string()),
            ..Default::default()
        };
        let args = scope.git_log_args();
        assert!(args.contains(&"feature/foo".to_string()));
    }

    #[test]
    fn test_scan_scope_commit_range() {
        let scope = ScanScope {
            commit_range: Some("abc..def".to_string()),
            ..Default::default()
        };
        let args = scope.git_log_args();
        assert!(args.contains(&"abc..def".to_string()));
    }

    #[test]
    fn test_exit_code_config() {
        let findings = vec![make_finding("aws-key", Severity::High, 1)];
        let config = ExitCodeConfig::default();
        assert_eq!(config.compute_exit_code(&findings), 1);

        let config = ExitCodeConfig {
            ignore_exit_code: true,
            ..Default::default()
        };
        assert_eq!(config.compute_exit_code(&findings), 0);

        let config = ExitCodeConfig {
            exit_code: Some(42),
            ..Default::default()
        };
        assert_eq!(config.compute_exit_code(&findings), 42);
    }

    #[test]
    fn test_exit_code_fail_on_severity() {
        let findings = vec![make_finding("low-sev", Severity::Low, 1)];
        let config = ExitCodeConfig {
            fail_on_severity: Some(Severity::High),
            ..Default::default()
        };
        assert_eq!(config.compute_exit_code(&findings), 0);

        let findings = vec![make_finding("high-sev", Severity::Critical, 1)];
        let config = ExitCodeConfig {
            fail_on_severity: Some(Severity::High),
            ..Default::default()
        };
        assert_eq!(config.compute_exit_code(&findings), 1);
    }

    #[test]
    fn test_exit_code_max_findings() {
        let findings = vec![
            make_finding("a", Severity::High, 1),
            make_finding("b", Severity::High, 2),
            make_finding("c", Severity::High, 3),
        ];
        let config = ExitCodeConfig {
            max_findings: Some(2),
            ..Default::default()
        };
        assert_eq!(config.compute_exit_code(&findings), 1);

        let config = ExitCodeConfig {
            max_findings: Some(10),
            ..Default::default()
        };
        assert_eq!(config.compute_exit_code(&findings), 1);
    }

    #[test]
    fn test_append_report() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        append_report(tmp.path(), "first").unwrap();
        append_report(tmp.path(), "second").unwrap();
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        assert!(content.contains("first"));
        assert!(content.contains("second"));
    }

    #[test]
    fn test_baseline_ci_config() {
        let config = BaselineCiConfig {
            auto: true,
            ..Default::default()
        };
        // Use a path that doesn't exist yet.
        let path = Path::new("/nonexistent/test-baseline-auto.json");
        let (create, enforce) = config.determine_action(path);
        assert!(create);
        assert!(!enforce);

        // Simulate existing baseline by using a temp file.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "{}").unwrap();
        let (create, enforce) = config.determine_action(tmp.path());
        assert!(!create);
        assert!(enforce);
    }

    #[test]
    fn test_baseline_enforce() {
        let config = BaselineCiConfig {
            enforce: true,
            ..Default::default()
        };
        let path = Path::new("/nonexistent/baseline.json");
        let (create, _enforce) = config.determine_action(path);
        assert!(!create);
    }

    #[test]
    fn test_format_pr_comment_empty() {
        let comment = format_pr_comment(&[]);
        assert!(comment.contains("No secrets found"));
    }

    #[test]
    fn test_format_pr_comment_with_findings() {
        let findings = vec![
            make_finding("aws-key", Severity::Critical, 1),
            make_finding("github-token", Severity::High, 2),
        ];
        let comment = format_pr_comment(&findings);
        assert!(comment.contains("2"));
        assert!(comment.contains("aws-key"));
        assert!(comment.contains("github-token"));
        assert!(comment.contains("pledgeguard rotate"));
    }

    #[test]
    fn test_generate_junit_for_ci() {
        let findings = vec![
            make_finding("aws-key", Severity::Critical, 1),
            make_finding("low-sev", Severity::Low, 2),
        ];
        let xml = generate_junit_for_ci(&findings, "pledgeguard-scan");
        assert!(xml.contains("testsuites"));
        assert!(xml.contains("pledgeguard-scan"));
        assert!(xml.contains("failure"));
        assert!(xml.contains("aws-key"));
    }
}
