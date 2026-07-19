//! Advanced IaC detection (goals 471-500).
//!
//! This module provides detection of secrets in infrastructure-as-code files
//! and deployment configuration files, including:
//! - Secret pair/chain detection (AWS key pairs, OAuth chains)
//! - .env file detection
//! - AWS credentials file detection
//! - Docker Compose, Kubernetes, Terraform, Ansible, Chef, Puppet
//! - CloudFormation, Pulumi, Serverless, AWS CDK, Terraform Cloud
//! - CI/CD config files (GitHub Actions, GitLab CI, CircleCI, Jenkins, DroneCI)
//! - GitOps tools (ArgoCD, Helm, Kustomize, Skaffold, Tilt, Garden, DevSpace, Okteto, Acorn)
//! - Cosign signing keys

use crate::content_decode::{extract_yaml_values, parse_env_file, parse_hcl, parse_ini};
use crate::finding::{Finding, Severity};
use std::path::Path;

/// Helper: create a finding.
fn make_finding(
    rule_id: &str,
    description: &str,
    severity: Severity,
    path: &Path,
    line: usize,
    matched: &str,
    context: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        description: description.to_string(),
        severity,
        path: path.to_path_buf(),
        line,
        column: 1,
        matched: matched.to_string(),
        context: context.to_string(),
        commit: None,
        likely_false_positive: false,
        verification: None,
    }
}

/// Sensitive key names that indicate a secret value.
const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "credential",
    "auth",
    "bearer",
    "client_secret",
    "clientsecret",
];

/// Check if a key name looks like it holds a secret.
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEY_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Check if a value looks like a placeholder/example (not a real secret).
fn is_placeholder_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    // Check for common example/placeholder patterns.
    // Use word-boundary checks to avoid matching "EXAMPLE" in real AWS keys.
    lower == "example"
        || lower.starts_with("example-")
        || lower.starts_with("your-")
        || lower.starts_with("xxx")
        || lower.contains("changeme")
        || lower.contains("placeholder")
        || lower.contains("<")
        || lower.contains("${")
        || lower.contains("{{")
        || value.is_empty()
}

/// Extract a clean value from a YAML/JSON value string (strip quotes, comments).
fn clean_value(val: &str) -> String {
    let trimmed = val.trim();
    let trimmed = trimmed.trim_start_matches('"').trim_end_matches('"');
    let trimmed = trimmed.trim_start_matches('\'').trim_end_matches('\'');
    if let Some(comment_pos) = trimmed.find('#') {
        trimmed[..comment_pos].trim().to_string()
    } else {
        trimmed.to_string()
    }
}

// ── 471: Secret pair detection ─────────────────────────────────────────

/// Detect AWS Access Key ID + Secret Access Key pairs in the same file.
/// Returns findings with elevated severity when both parts of a pair are found.
pub fn detect_secret_pairs(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut has_access_key = false;
    let mut has_secret_key = false;
    let mut access_key_line = 0;
    let mut secret_key_line = 0;
    let mut access_key_val = String::new();
    let mut secret_key_val = String::new();

    for (idx, line) in content.lines().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("aws_access_key_id") || lower.contains("aws-access-key-id"))
            && let Some(eq) = line.find(['=', ':'])
        {
            let val = clean_value(&line[eq + 1..]);
            if val.starts_with("AKIA") || val.starts_with("ASIA") {
                has_access_key = true;
                access_key_line = idx + 1;
                access_key_val = val;
            }
        }
        if (lower.contains("aws_secret_access_key") || lower.contains("aws-secret-access-key"))
            && let Some(eq) = line.find(['=', ':'])
        {
            let val = clean_value(&line[eq + 1..]);
            if !is_placeholder_value(&val) && val.len() >= 20 {
                has_secret_key = true;
                secret_key_line = idx + 1;
                secret_key_val = val;
            }
        }
    }

    if has_access_key && has_secret_key {
        findings.push(make_finding(
            "iac-aws-key-pair",
            "AWS Access Key ID + Secret Access Key pair detected in same file",
            Severity::Critical,
            path,
            access_key_line,
            &format!("{access_key_val} + {secret_key_val}"),
            &format!("Pair at lines {access_key_line} and {secret_key_line}"),
        ));
    }

    findings
}

// ── 472: Secret chain detection ────────────────────────────────────────

/// Detect OAuth/client credential chains (client_id + client_secret + tenant_id).
pub fn detect_secret_chains(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut has_client_id = false;
    let mut has_client_secret = false;
    let mut has_tenant_id = false;
    let mut chain_line = 0;

    for (idx, line) in content.lines().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("client_id") || lower.contains("clientid"))
            && let Some(eq) = line.find(['=', ':'])
        {
            let val = clean_value(&line[eq + 1..]);
            if !is_placeholder_value(&val) {
                has_client_id = true;
                chain_line = idx + 1;
            }
        }
        if (lower.contains("client_secret") || lower.contains("clientsecret"))
            && let Some(eq) = line.find(['=', ':'])
        {
            let val = clean_value(&line[eq + 1..]);
            if !is_placeholder_value(&val) {
                has_client_secret = true;
                chain_line = idx + 1;
            }
        }
        if (lower.contains("tenant_id") || lower.contains("tenantid"))
            && let Some(eq) = line.find(['=', ':'])
        {
            let val = clean_value(&line[eq + 1..]);
            if !is_placeholder_value(&val) {
                has_tenant_id = true;
            }
        }
    }

    if has_client_id && has_client_secret && has_tenant_id {
        findings.push(make_finding(
            "iac-oauth-credential-chain",
            "OAuth credential chain detected: client_id + client_secret + tenant_id",
            Severity::Critical,
            path,
            chain_line,
            "credential chain",
            "All three OAuth chain components found in same file",
        ));
    }

    findings
}

// ── 473: .env file detection ───────────────────────────────────────────

/// Detect secrets in .env files by flagging all KEY=VALUE pairs with sensitive keys.
pub fn detect_env_file_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = parse_env_file(content);

    for (key, value) in entries {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-env-file-secret",
                &format!("Secret in .env file: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}={value}"),
            ));
        }
    }

    findings
}

// ── 474: AWS credentials file detection ────────────────────────────────

/// Detect secrets in AWS credentials files (~/.aws/credentials).
/// Parses [default] and [profile X] sections for aws_access_key_id and aws_secret_access_key.
pub fn detect_aws_credentials_file(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = parse_ini(content);

    for (key, value) in entries {
        let lower = key.to_lowercase();
        if (lower.contains("aws_access_key_id")
            || lower.contains("aws_secret_access_key")
            || lower.contains("aws_session_token"))
            && !is_placeholder_value(&value)
        {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-aws-credentials-file",
                &format!("AWS credential in credentials file: {key}"),
                Severity::Critical,
                path,
                line_num,
                &value,
                &format!("{key}={value}"),
            ));
        }
    }

    findings
}

// ── 475: Docker compose secret detection ───────────────────────────────

/// Detect secrets in docker-compose.yml files.
/// Looks for environment variables, secrets, and hardcoded passwords.
pub fn detect_docker_compose_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Scan YAML key: value pairs.
    let values = extract_yaml_values(content);
    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-docker-compose-secret",
                &format!("Secret in docker-compose: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    // Also scan list-item environment variables: - KEY=VALUE
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("- ")
            && let Some(eq) = rest.find('=')
        {
            let key = &rest[..eq];
            let value = clean_value(&rest[eq + 1..]);
            if is_sensitive_key(key) && !is_placeholder_value(&value) {
                findings.push(make_finding(
                    "iac-docker-compose-secret",
                    &format!("Secret in docker-compose env: {key}"),
                    Severity::High,
                    path,
                    idx + 1,
                    &value,
                    &format!("{key}={value}"),
                ));
            }
        }
    }

    findings
}

// ── 476: Kubernetes pod env detection ──────────────────────────────────

/// Detect secrets in Kubernetes pod environment variables.
pub fn detect_k8s_pod_env_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if (key.contains("env") || key.contains("ENV"))
            && is_sensitive_key(&value)
            && !is_placeholder_value(&value)
        {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-k8s-pod-env-secret",
                &format!("Secret in K8s pod env: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 477: Terraform variable detection ──────────────────────────────────

/// Detect secrets in Terraform variable defaults.
pub fn detect_terraform_variable_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = parse_hcl(content);

    for (key, value) in values {
        if key.contains("default") && is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-terraform-variable-secret",
                &format!("Secret in Terraform variable: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key} = {value}"),
            ));
        }
    }

    findings
}

// ── 478: Ansible vault detection ───────────────────────────────────────

/// Detect unencrypted Ansible vault content.
/// Ansible vault files start with `$ANSIBLE_VAULT;` — if content is not encrypted,
/// flag any sensitive values.
pub fn detect_ansible_vault(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check if file is properly encrypted with Ansible Vault.
    let is_encrypted = content.contains("$ANSIBLE_VAULT;");

    if is_encrypted {
        return findings; // Properly encrypted — no findings.
    }

    // Check for Ansible-style variables with sensitive values.
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('-') || trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some(colon_pos) = trimmed.find(':') {
            let key = trimmed[..colon_pos].trim().trim_start_matches('-').trim();
            let value = clean_value(&trimmed[colon_pos + 1..]);
            if is_sensitive_key(key) && !is_placeholder_value(&value) {
                findings.push(make_finding(
                    "iac-ansible-unencrypted-secret",
                    &format!("Unencrypted Ansible secret: {key}"),
                    Severity::High,
                    path,
                    idx + 1,
                    &value,
                    trimmed,
                ));
            }
        }
    }

    findings
}

// ── 479: Chef data bag detection ───────────────────────────────────────

/// Detect secrets in Chef data bag JSON files.
pub fn detect_chef_data_bag(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content)
        && let Some(obj) = json.as_object()
    {
        for (key, value) in obj {
            if is_sensitive_key(key)
                && let Some(s) = value.as_str()
                && !is_placeholder_value(s)
            {
                let line_num = content
                    .lines()
                    .position(|l| l.contains(key))
                    .map(|i| i + 1)
                    .unwrap_or(1);
                findings.push(make_finding(
                    "iac-chef-data-bag-secret",
                    &format!("Secret in Chef data bag: {key}"),
                    Severity::High,
                    path,
                    line_num,
                    s,
                    &format!("{key}: {s}"),
                ));
            }
        }
    }

    findings
}

// ── 480: Puppet hiera detection ────────────────────────────────────────

/// Detect secrets in Puppet Hiera data files (YAML format).
pub fn detect_puppet_hiera(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-puppet-hiera-secret",
                &format!("Secret in Puppet Hiera: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 481: CloudFormation template detection ─────────────────────────────

/// Detect secrets in AWS CloudFormation templates (JSON/YAML).
pub fn detect_cloudformation_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try JSON first.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        scan_json_for_secrets(
            &json,
            path,
            &mut findings,
            "iac-cfn-secret",
            "CloudFormation",
        );
        return findings;
    }

    // Fall back to YAML key-value extraction.
    let values = extract_yaml_values(content);
    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-cfn-secret",
                &format!("Secret in CloudFormation: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

/// Recursively scan a JSON value for sensitive keys.
fn scan_json_for_secrets(
    value: &serde_json::Value,
    path: &Path,
    findings: &mut Vec<Finding>,
    rule_id: &str,
    context: &str,
) {
    if let Some(obj) = value.as_object() {
        for (key, val) in obj {
            if is_sensitive_key(key)
                && let Some(s) = val.as_str()
                && !is_placeholder_value(s)
            {
                findings.push(make_finding(
                    rule_id,
                    &format!("Secret in {context}: {key}"),
                    Severity::High,
                    path,
                    1,
                    s,
                    &format!("{key}: {s}"),
                ));
            }
            scan_json_for_secrets(val, path, findings, rule_id, context);
        }
    } else if let Some(arr) = value.as_array() {
        for item in arr {
            scan_json_for_secrets(item, path, findings, rule_id, context);
        }
    }
}

// ── 482: Pulumi stack config detection ─────────────────────────────────

/// Detect secrets in Pulumi stack config files (Pulumi.<stack>.yaml).
pub fn detect_pulumi_config(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Scan line-by-line for nested YAML keys like pulumi:token: value
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Look for the last colon followed by a space (to get the value).
        if let Some(colon_pos) = trimmed.rfind(": ") {
            let key_part = &trimmed[..colon_pos];
            let value = clean_value(&trimmed[colon_pos + 2..]);
            // Check if any part of the key is sensitive.
            let key_lower = key_part.to_lowercase();
            if (is_sensitive_key(key_part)
                || key_lower.contains("token")
                || key_lower.contains("secret"))
                && !is_placeholder_value(&value)
                && !value.starts_with("true")
            {
                findings.push(make_finding(
                    "iac-pulumi-config-secret",
                    &format!("Secret in Pulumi config: {key_part}"),
                    Severity::High,
                    path,
                    idx + 1,
                    &value,
                    &format!("{key_part}: {value}"),
                ));
            }
        }
    }

    // Also check YAML key-value pairs.
    let values = extract_yaml_values(content);
    for (key, value) in values {
        if (is_sensitive_key(&key) || key.contains("secure"))
            && !is_placeholder_value(&value)
            && !value.starts_with("true")
        {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-pulumi-config-secret",
                &format!("Secret in Pulumi config: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 483: Serverless framework detection ────────────────────────────────

/// Detect secrets in serverless.yml files.
pub fn detect_serverless_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-serverless-secret",
                &format!("Secret in serverless.yml: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 484: AWS CDK detection ─────────────────────────────────────────────

/// Detect secrets in AWS CDK stack code (TypeScript/Python patterns).
pub fn detect_cdk_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("cdk") || lower.contains("construct") || lower.contains("stack"))
            && is_sensitive_key(&lower)
            && let Some(eq) = line.find('=')
        {
            let value = clean_value(&line[eq + 1..]);
            if !is_placeholder_value(&value) {
                findings.push(make_finding(
                    "iac-cdk-secret",
                    &format!("Secret in AWS CDK code at line {}", idx + 1),
                    Severity::High,
                    path,
                    idx + 1,
                    &value,
                    line.trim(),
                ));
            }
        }
    }

    findings
}

// ── 485: Terraform Cloud workspace detection ───────────────────────────

/// Detect secrets in Terraform Cloud workspace variable files.
pub fn detect_terraform_cloud_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        scan_json_for_secrets(
            &json,
            path,
            &mut findings,
            "iac-tfc-secret",
            "Terraform Cloud",
        );
    } else {
        let values = extract_yaml_values(content);
        for (key, value) in values {
            if is_sensitive_key(&key) && !is_placeholder_value(&value) {
                let line_num = content
                    .lines()
                    .position(|l| l.contains(&key))
                    .map(|i| i + 1)
                    .unwrap_or(1);
                findings.push(make_finding(
                    "iac-tfc-secret",
                    &format!("Secret in TFC workspace: {key}"),
                    Severity::High,
                    path,
                    line_num,
                    &value,
                    &format!("{key}: {value}"),
                ));
            }
        }
    }

    findings
}

// ── 486: GitHub Actions secret detection ───────────────────────────────

/// Detect secrets in GitHub Actions workflow YAML files.
pub fn detect_github_actions_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Look for hardcoded secrets instead of ${{ secrets.* }} references.
        if trimmed.contains("secrets.")
            && !trimmed.contains("${{")
            && let Some(eq) = trimmed.find('=')
        {
            let value = clean_value(&trimmed[eq + 1..]);
            if !is_placeholder_value(&value) {
                findings.push(make_finding(
                    "iac-github-actions-secret",
                    &format!(
                        "Hardcoded secret in GitHub Actions workflow: line {}",
                        idx + 1
                    ),
                    Severity::High,
                    path,
                    idx + 1,
                    &value,
                    trimmed,
                ));
            }
        }
    }

    // Also check for env vars with sensitive keys.
    let values = extract_yaml_values(content);
    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) && !value.contains("${{") {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-github-actions-secret",
                &format!("Secret in GitHub Actions env: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 487: GitLab CI variable detection ──────────────────────────────────

/// Detect secrets in .gitlab-ci.yml files.
pub fn detect_gitlab_ci_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-gitlab-ci-secret",
                &format!("Secret in GitLab CI: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 488: CircleCI context detection ────────────────────────────────────

/// Detect secrets in CircleCI config files (.circleci/config.yml).
pub fn detect_circleci_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-circleci-secret",
                &format!("Secret in CircleCI config: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 489: Jenkins credentials detection ─────────────────────────────────

/// Detect secrets in Jenkinsfile (Groovy) files.
pub fn detect_jenkins_credentials(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let lower = line.to_lowercase();
        if lower.contains("credentials")
            || lower.contains("withcredentials")
            || lower.contains("secret")
            || lower.contains("password")
        {
            // Look for hardcoded values in single-quoted strings.
            let mut in_quote = false;
            let mut current_val = String::new();
            for c in line.chars() {
                if c == '\'' {
                    if in_quote {
                        if !is_placeholder_value(&current_val)
                            && !current_val.starts_with('$')
                            && !current_val.starts_with("${")
                            && current_val.len() >= 8
                        {
                            findings.push(make_finding(
                                "iac-jenkins-credential",
                                &format!("Hardcoded credential in Jenkinsfile: line {}", idx + 1),
                                Severity::High,
                                path,
                                idx + 1,
                                &current_val,
                                line.trim(),
                            ));
                        }
                        current_val.clear();
                    }
                    in_quote = !in_quote;
                } else if in_quote {
                    current_val.push(c);
                }
            }
        }
    }

    findings
}

// ── 490: DroneCI secret detection ──────────────────────────────────────

/// Detect secrets in .drone.yml files.
pub fn detect_droneci_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-droneci-secret",
                &format!("Secret in DroneCI config: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 491: ArgoCD ApplicationSet detection ───────────────────────────────

/// Detect secrets in ArgoCD ApplicationSet templates.
pub fn detect_argocd_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        scan_json_for_secrets(
            &json,
            path,
            &mut findings,
            "iac-argocd-secret",
            "ArgoCD ApplicationSet",
        );
    } else {
        let values = extract_yaml_values(content);
        for (key, value) in values {
            if is_sensitive_key(&key) && !is_placeholder_value(&value) {
                let line_num = content
                    .lines()
                    .position(|l| l.contains(&key))
                    .map(|i| i + 1)
                    .unwrap_or(1);
                findings.push(make_finding(
                    "iac-argocd-secret",
                    &format!("Secret in ArgoCD ApplicationSet: {key}"),
                    Severity::High,
                    path,
                    line_num,
                    &value,
                    &format!("{key}: {value}"),
                ));
            }
        }
    }

    findings
}

// ── 492: Helm values production detection ──────────────────────────────

/// Detect secrets in production Helm values files (values-prod.yaml, values-production.yaml).
pub fn detect_helm_values_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-helm-values-secret",
                &format!("Secret in Helm values: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 493: Kustomize patch detection ─────────────────────────────────────

/// Detect secrets in Kustomize patch files.
pub fn detect_kustomize_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        scan_json_for_secrets(
            &json,
            path,
            &mut findings,
            "iac-kustomize-secret",
            "Kustomize patch",
        );
    } else {
        let values = extract_yaml_values(content);
        for (key, value) in values {
            if is_sensitive_key(&key) && !is_placeholder_value(&value) {
                let line_num = content
                    .lines()
                    .position(|l| l.contains(&key))
                    .map(|i| i + 1)
                    .unwrap_or(1);
                findings.push(make_finding(
                    "iac-kustomize-secret",
                    &format!("Secret in Kustomize patch: {key}"),
                    Severity::High,
                    path,
                    line_num,
                    &value,
                    &format!("{key}: {value}"),
                ));
            }
        }
    }

    findings
}

// ── 494: Skaffold detection ────────────────────────────────────────────

/// Detect secrets in skaffold.yaml files.
pub fn detect_skaffold_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-skaffold-secret",
                &format!("Secret in skaffold.yaml: {key}"),
                Severity::Medium,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 495: Tilt detection ────────────────────────────────────────────────

/// Detect secrets in Tiltfile (Starlark) files.
pub fn detect_tiltfile_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("secret") || lower.contains("password") || lower.contains("token"))
            && (lower.contains("setenv") || lower.contains("="))
            && let Some(eq) = line.find('=')
        {
            let value = clean_value(&line[eq + 1..]);
            if !is_placeholder_value(&value) && !value.starts_with("$") {
                findings.push(make_finding(
                    "iac-tilt-secret",
                    &format!("Secret in Tiltfile: line {}", idx + 1),
                    Severity::Medium,
                    path,
                    idx + 1,
                    &value,
                    line.trim(),
                ));
            }
        }
    }

    findings
}

// ── 496: Garden detection ──────────────────────────────────────────────

/// Detect secrets in garden.yml files.
pub fn detect_garden_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-garden-secret",
                &format!("Secret in garden.yml: {key}"),
                Severity::Medium,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 497: DevSpace detection ────────────────────────────────────────────

/// Detect secrets in devspace.yaml files.
pub fn detect_devspace_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-devspace-secret",
                &format!("Secret in devspace.yaml: {key}"),
                Severity::Medium,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 498: Okteto manifest detection ─────────────────────────────────────

/// Detect secrets in okteto.yml files.
pub fn detect_okteto_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let values = extract_yaml_values(content);

    for (key, value) in values {
        if is_sensitive_key(&key) && !is_placeholder_value(&value) {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-okteto-secret",
                &format!("Secret in okteto.yml: {key}"),
                Severity::Medium,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    findings
}

// ── 499: Acorn detection ───────────────────────────────────────────────

/// Detect secrets in Acornfile (Starlark-like) files.
pub fn detect_acorn_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("secret") || lower.contains("password") || lower.contains("token"))
            && lower.contains(':')
            && let Some(colon) = line.find(':')
        {
            let value = clean_value(&line[colon + 1..]);
            if !is_placeholder_value(&value) && !value.starts_with("$") {
                findings.push(make_finding(
                    "iac-acorn-secret",
                    &format!("Secret in Acornfile: line {}", idx + 1),
                    Severity::Medium,
                    path,
                    idx + 1,
                    &value,
                    line.trim(),
                ));
            }
        }
    }

    findings
}

// ── 500: Cosign detection ──────────────────────────────────────────────

/// Detect signing keys and passwords in Cosign configuration files.
pub fn detect_cosign_secrets(content: &str, path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Cosign config can be YAML or env-style.
    let values = extract_yaml_values(content);

    for (key, value) in values {
        let lower = key.to_lowercase();
        if (lower.contains("cosign")
            || lower.contains("signing")
            || lower.contains("key")
            || is_sensitive_key(&key))
            && !is_placeholder_value(&value)
        {
            let line_num = content
                .lines()
                .position(|l| l.contains(&key))
                .map(|i| i + 1)
                .unwrap_or(1);
            findings.push(make_finding(
                "iac-cosign-signing-key",
                &format!("Cosign signing key/secret: {key}"),
                Severity::High,
                path,
                line_num,
                &value,
                &format!("{key}: {value}"),
            ));
        }
    }

    // Also check for PEM-encoded private keys.
    if content.contains("-----BEGIN PRIVATE KEY-----")
        || content.contains("-----BEGIN EC PRIVATE KEY-----")
    {
        let line_num = content
            .lines()
            .position(|l| l.contains("-----BEGIN"))
            .map(|i| i + 1)
            .unwrap_or(1);
        findings.push(make_finding(
            "iac-cosign-private-key",
            "Private key in Cosign configuration",
            Severity::Critical,
            path,
            line_num,
            "-----BEGIN PRIVATE KEY-----",
            "PEM-encoded private key found",
        ));
    }

    findings
}

// ── Unified IaC scanner ────────────────────────────────────────────────

/// IaC file type detection based on filename.
#[derive(Debug, Clone, PartialEq)]
pub enum IaCFileType {
    EnvFile,
    AwsCredentials,
    DockerCompose,
    Kubernetes,
    Terraform,
    Ansible,
    ChefDataBag,
    PuppetHiera,
    CloudFormation,
    PulumiConfig,
    Serverless,
    AwsCdk,
    TerraformCloud,
    GitHubActions,
    GitLabCI,
    CircleCI,
    Jenkinsfile,
    DroneCI,
    ArgoCD,
    HelmValues,
    Kustomize,
    Skaffold,
    Tiltfile,
    Garden,
    DevSpace,
    Okteto,
    Acorn,
    Cosign,
    Unknown,
}

/// Detect the IaC file type from a file path.
pub fn detect_iac_file_type(path: &Path) -> IaCFileType {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let path_str = path.to_string_lossy();

    // .env files
    if name == ".env" || name.starts_with(".env.") {
        return IaCFileType::EnvFile;
    }

    // AWS credentials
    if name == "credentials" && path_str.contains(".aws") {
        return IaCFileType::AwsCredentials;
    }

    // Docker Compose
    if name.starts_with("docker-compose") && (name.ends_with(".yml") || name.ends_with(".yaml")) {
        return IaCFileType::DockerCompose;
    }

    // Kubernetes
    if (name.ends_with(".yaml") || name.ends_with(".yml"))
        && (name.contains("deployment")
            || name.contains("pod")
            || name.contains("k8s")
            || name.contains("manifest")
            || path_str.contains("k8s/")
            || path_str.contains("kubernetes/"))
    {
        return IaCFileType::Kubernetes;
    }

    // Terraform
    if name.ends_with(".tf") || name.ends_with(".tfvars") {
        return IaCFileType::Terraform;
    }

    // Ansible
    if path_str.contains("ansible") || name.contains("vault") {
        return IaCFileType::Ansible;
    }

    // Chef data bag
    if path_str.contains("data_bag") || path_str.contains("databag") {
        return IaCFileType::ChefDataBag;
    }

    // Puppet Hiera
    if path_str.contains("hiera") || name.starts_with("hiera") {
        return IaCFileType::PuppetHiera;
    }

    // CloudFormation
    if name.contains("cloudformation")
        || name.contains("cfn")
        || (name.starts_with("template") && (name.ends_with(".json") || name.ends_with(".yaml")))
    {
        return IaCFileType::CloudFormation;
    }

    // Pulumi
    if name.starts_with("Pulumi.") && (name.ends_with(".yaml") || name.ends_with(".yml")) {
        return IaCFileType::PulumiConfig;
    }

    // Serverless
    if name == "serverless.yml" || name == "serverless.yaml" {
        return IaCFileType::Serverless;
    }

    // AWS CDK
    if (name.ends_with(".ts") || name.ends_with(".py"))
        && (path_str.contains("cdk") || path_str.contains("stack"))
    {
        return IaCFileType::AwsCdk;
    }

    // Terraform Cloud
    if name.contains("terraform-cloud") || name.contains("tfc") {
        return IaCFileType::TerraformCloud;
    }

    // GitHub Actions
    if path_str.contains(".github/workflows/")
        && (name.ends_with(".yml") || name.ends_with(".yaml"))
    {
        return IaCFileType::GitHubActions;
    }

    // GitLab CI
    if name == ".gitlab-ci.yml" || name == ".gitlab-ci.yaml" {
        return IaCFileType::GitLabCI;
    }

    // CircleCI
    if path_str.contains(".circleci/") && name == "config.yml" {
        return IaCFileType::CircleCI;
    }

    // Jenkins
    if name == "Jenkinsfile" {
        return IaCFileType::Jenkinsfile;
    }

    // DroneCI
    if name == ".drone.yml" || name == ".drone.yaml" {
        return IaCFileType::DroneCI;
    }

    // ArgoCD
    if name.contains("argocd") || name.contains("applicationset") {
        return IaCFileType::ArgoCD;
    }

    // Helm values
    if (name.starts_with("values-") || name == "values.yaml")
        && (name.ends_with(".yaml") || name.ends_with(".yml"))
    {
        return IaCFileType::HelmValues;
    }

    // Kustomize
    if name.contains("kustomize") || name == "kustomization.yaml" || name == "kustomization.yml" {
        return IaCFileType::Kustomize;
    }

    // Skaffold
    if name == "skaffold.yaml" || name == "skaffold.yml" {
        return IaCFileType::Skaffold;
    }

    // Tilt
    if name == "Tiltfile" {
        return IaCFileType::Tiltfile;
    }

    // Garden
    if name == "garden.yml" || name == "garden.yaml" {
        return IaCFileType::Garden;
    }

    // DevSpace
    if name == "devspace.yaml" || name == "devspace.yml" {
        return IaCFileType::DevSpace;
    }

    // Okteto
    if name == "okteto.yml" || name == "okteto.yaml" {
        return IaCFileType::Okteto;
    }

    // Acorn
    if name == "Acornfile" {
        return IaCFileType::Acorn;
    }

    // Cosign
    if name.contains("cosign") {
        return IaCFileType::Cosign;
    }

    IaCFileType::Unknown
}

/// Run all applicable IaC detectors on a file based on its type.
pub fn scan_iac_file(content: &str, path: &Path) -> Vec<Finding> {
    let file_type = detect_iac_file_type(path);
    let mut findings = Vec::new();

    // Always run pair and chain detection.
    findings.extend(detect_secret_pairs(content, path));
    findings.extend(detect_secret_chains(content, path));

    match file_type {
        IaCFileType::EnvFile => {
            findings.extend(detect_env_file_secrets(content, path));
        }
        IaCFileType::AwsCredentials => {
            findings.extend(detect_aws_credentials_file(content, path));
        }
        IaCFileType::DockerCompose => {
            findings.extend(detect_docker_compose_secrets(content, path));
        }
        IaCFileType::Kubernetes => {
            findings.extend(detect_k8s_pod_env_secrets(content, path));
        }
        IaCFileType::Terraform => {
            findings.extend(detect_terraform_variable_secrets(content, path));
        }
        IaCFileType::Ansible => {
            findings.extend(detect_ansible_vault(content, path));
        }
        IaCFileType::ChefDataBag => {
            findings.extend(detect_chef_data_bag(content, path));
        }
        IaCFileType::PuppetHiera => {
            findings.extend(detect_puppet_hiera(content, path));
        }
        IaCFileType::CloudFormation => {
            findings.extend(detect_cloudformation_secrets(content, path));
        }
        IaCFileType::PulumiConfig => {
            findings.extend(detect_pulumi_config(content, path));
        }
        IaCFileType::Serverless => {
            findings.extend(detect_serverless_secrets(content, path));
        }
        IaCFileType::AwsCdk => {
            findings.extend(detect_cdk_secrets(content, path));
        }
        IaCFileType::TerraformCloud => {
            findings.extend(detect_terraform_cloud_secrets(content, path));
        }
        IaCFileType::GitHubActions => {
            findings.extend(detect_github_actions_secrets(content, path));
        }
        IaCFileType::GitLabCI => {
            findings.extend(detect_gitlab_ci_secrets(content, path));
        }
        IaCFileType::CircleCI => {
            findings.extend(detect_circleci_secrets(content, path));
        }
        IaCFileType::Jenkinsfile => {
            findings.extend(detect_jenkins_credentials(content, path));
        }
        IaCFileType::DroneCI => {
            findings.extend(detect_droneci_secrets(content, path));
        }
        IaCFileType::ArgoCD => {
            findings.extend(detect_argocd_secrets(content, path));
        }
        IaCFileType::HelmValues => {
            findings.extend(detect_helm_values_secrets(content, path));
        }
        IaCFileType::Kustomize => {
            findings.extend(detect_kustomize_secrets(content, path));
        }
        IaCFileType::Skaffold => {
            findings.extend(detect_skaffold_secrets(content, path));
        }
        IaCFileType::Tiltfile => {
            findings.extend(detect_tiltfile_secrets(content, path));
        }
        IaCFileType::Garden => {
            findings.extend(detect_garden_secrets(content, path));
        }
        IaCFileType::DevSpace => {
            findings.extend(detect_devspace_secrets(content, path));
        }
        IaCFileType::Okteto => {
            findings.extend(detect_okteto_secrets(content, path));
        }
        IaCFileType::Acorn => {
            findings.extend(detect_acorn_secrets(content, path));
        }
        IaCFileType::Cosign => {
            findings.extend(detect_cosign_secrets(content, path));
        }
        IaCFileType::Unknown => {}
    }

    findings
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(name: &str) -> PathBuf {
        PathBuf::from(name)
    }

    #[test]
    fn test_is_sensitive_key() {
        assert!(is_sensitive_key("API_KEY"));
        assert!(is_sensitive_key("password"));
        assert!(is_sensitive_key("client_secret"));
        assert!(is_sensitive_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_sensitive_key("name"));
        assert!(!is_sensitive_key("port"));
    }

    #[test]
    fn test_is_placeholder_value() {
        assert!(is_placeholder_value("your-api-key"));
        assert!(is_placeholder_value("xxx"));
        assert!(is_placeholder_value("${MY_VAR}"));
        assert!(is_placeholder_value("{{ .Values.secret }}"));
        assert!(!is_placeholder_value("AKIAIOSFODNN7EXAMPLE"));
        assert!(!is_placeholder_value("supersecret123"));
    }

    #[test]
    fn test_detect_secret_pairs() {
        let content = r#"
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"#;
        let findings = detect_secret_pairs(content, &p("config.tf"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "iac-aws-key-pair");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_detect_secret_pairs_no_pair() {
        let content = "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"";
        let findings = detect_secret_pairs(content, &p("config.tf"));
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_detect_secret_chains() {
        let content = r#"
client_id = "abc123def456"
client_secret = "supersecret789"
tenant_id = "tenant-uuid-here"
"#;
        let findings = detect_secret_chains(content, &p("config.yaml"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "iac-oauth-credential-chain");
    }

    #[test]
    fn test_detect_env_file_secrets() {
        let content = "# comment\nAWS_SECRET_KEY=supersecretvalue123\nPORT=8080";
        let findings = detect_env_file_secrets(content, &p(".env"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "iac-env-file-secret");
    }

    #[test]
    fn test_detect_aws_credentials_file() {
        let content = r#"
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;
        let findings = detect_aws_credentials_file(content, &p("credentials"));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "iac-aws-credentials-file");
    }

    #[test]
    fn test_detect_docker_compose_secrets() {
        let content = r#"
services:
  db:
    environment:
      - POSTGRES_PASSWORD=supersecret123
"#;
        let findings = detect_docker_compose_secrets(content, &p("docker-compose.yml"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_ansible_vault_unencrypted() {
        let content = r#"
- name: Set DB password
  db_password: supersecret123
"#;
        let findings = detect_ansible_vault(content, &p("vault.yml"));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "iac-ansible-unencrypted-secret");
    }

    #[test]
    fn test_detect_ansible_vault_encrypted() {
        let content = "$ANSIBLE_VAULT;1.1;AES256\n6162636465666768";
        let findings = detect_ansible_vault(content, &p("vault.yml"));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_detect_chef_data_bag() {
        let content = r#"{"id":"db","password":"supersecret123"}"#;
        let findings = detect_chef_data_bag(content, &p("data_bag.json"));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "iac-chef-data-bag-secret");
    }

    #[test]
    fn test_detect_cloudformation_json() {
        let content =
            r#"{"Resources":{"DB":{"Properties":{"MasterUserPassword":"supersecret123"}}}}"#;
        let findings = detect_cloudformation_secrets(content, &p("template.json"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_github_actions_secrets() {
        let content = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      API_KEY: hardcoded-secret-value
"#;
        let findings = detect_github_actions_secrets(content, &p("ci.yml"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_jenkins_credentials() {
        let content = r#"pipeline { stages { stage('test') { steps { withCredentials('my-hardcoded-secret-value') } } } }"#;
        let findings = detect_jenkins_credentials(content, &p("Jenkinsfile"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_cosign_pem_key() {
        let content = "-----BEGIN PRIVATE KEY-----\nMIGkAgEBBDEA\n-----END PRIVATE KEY-----";
        let findings = detect_cosign_secrets(content, &p("cosign.key"));
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "iac-cosign-private-key");
    }

    #[test]
    fn test_detect_iac_file_type() {
        assert_eq!(detect_iac_file_type(&p(".env")), IaCFileType::EnvFile);
        assert_eq!(
            detect_iac_file_type(&p("docker-compose.yml")),
            IaCFileType::DockerCompose
        );
        assert_eq!(detect_iac_file_type(&p("main.tf")), IaCFileType::Terraform);
        assert_eq!(
            detect_iac_file_type(&p("Jenkinsfile")),
            IaCFileType::Jenkinsfile
        );
        assert_eq!(detect_iac_file_type(&p("Tiltfile")), IaCFileType::Tiltfile);
        assert_eq!(
            detect_iac_file_type(&p("skaffold.yaml")),
            IaCFileType::Skaffold
        );
        assert_eq!(detect_iac_file_type(&p("okteto.yml")), IaCFileType::Okteto);
        assert_eq!(detect_iac_file_type(&p("Acornfile")), IaCFileType::Acorn);
        assert_eq!(detect_iac_file_type(&p("random.txt")), IaCFileType::Unknown);
    }

    #[test]
    fn test_scan_iac_file_env() {
        let content = "API_KEY=supersecret123\nPORT=8080";
        let findings = scan_iac_file(content, &p(".env"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_iac_file_terraform() {
        let content = r#"
variable "db_password" {
  default = "supersecret123"
}
"#;
        let findings = scan_iac_file(content, &p("variables.tf"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_helm_values_secrets() {
        let content = "password: supersecret123\nimage: nginx:latest";
        let findings = detect_helm_values_secrets(content, &p("values.yaml"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_pulumi_config() {
        let content = "config:\n  pulumi:token: supersecret123";
        let findings = detect_pulumi_config(content, &p("Pulumi.dev.yaml"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_serverless_secrets() {
        let content = "provider:\n  name: aws\n  environment:\n    API_KEY: supersecret123";
        let findings = detect_serverless_secrets(content, &p("serverless.yml"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_detect_kustomize_secrets() {
        let content = r#"{"apiVersion":"v1","data":{"password":"supersecret123"}}"#;
        let findings = detect_kustomize_secrets(content, &p("kustomization.yaml"));
        assert!(!findings.is_empty());
    }
}
