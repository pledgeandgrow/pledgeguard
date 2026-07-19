//! Additional scanning sources: Confluence, Slack, Jira, Postman, Gerrit,
//! Buildkite, Artifactory, and AWS Secrets Manager.
//!
//! Each source uses its provider's REST API to fetch content (pages, messages,
//! issues, collections, builds, artifacts, secrets) and scans the text for
//! secrets using the same detector pipeline as the filesystem scanner.

use crate::detector::Detector;
use crate::finding::Finding;
use std::sync::OnceLock;
use std::time::Duration;

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
    })
}

/// Helper: scan a line of text with all detectors and collect findings.
fn scan_text(
    text: &str,
    virtual_path: &std::path::Path,
    detectors: &[Box<dyn Detector>],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        for detector in detectors {
            for m in detector.scan_line(line) {
                findings.push(Finding {
                    rule_id: detector.id().to_string(),
                    description: detector.description().to_string(),
                    severity: detector.severity(),
                    path: virtual_path.to_path_buf(),
                    line: line_idx + 1,
                    column: m.start + 1,
                    matched: m.text,
                    context: line.to_string(),
                    commit: None,
                    likely_false_positive: false,
                    verification: None,
                });
            }
        }
    }
    findings
}

// ── Confluence ─────────────────────────────────────────────────────────

/// Configuration for a Confluence scan.
#[derive(Debug, Clone)]
pub struct ConfluenceScanConfig {
    /// Base URL (e.g. "https://your-domain.atlassian.net").
    pub base_url: String,
    /// Confluence API token (or personal access token).
    pub api_token: String,
    /// Confluence user email (for Basic auth: email:api_token).
    pub email: String,
    /// Space key to scan (e.g. "ENG"). If empty, scans all spaces.
    pub space_key: Option<String>,
    /// Maximum number of pages to scan.
    pub max_pages: usize,
}

/// Scan Confluence pages for secrets via the REST API.
pub fn scan_confluence(
    config: &ConfluenceScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    let auth = format!(
        "{}:{}",
        config.email, config.api_token
    );
    use base64::Engine;
    let auth_b64 = base64::engine::general_purpose::STANDARD.encode(&auth);

    let mut findings = Vec::new();

    // List pages in the space (or all spaces).
    let (space_filter, cql) = if let Some(ref key) = config.space_key {
        (true, format!("space={key}"))
    } else {
        (false, String::new())
    };

    let _ = space_filter;
    let search_url = if cql.is_empty() {
        format!("{}/wiki/api/v2/pages?limit={}", base, config.max_pages.min(250))
    } else {
        format!("{}/wiki/api/v2/pages?limit={}&spaceKey={}", base, config.max_pages.min(250), config.space_key.as_deref().unwrap_or(""))
    };

    let resp = agent
        .get(&search_url)
        .set("Authorization", &format!("Basic {auth_b64}"))
        .set("Accept", "application/json")
        .call()
        .map_err(|e| SourceScanError::Http(Box::new(e)))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| SourceScanError::Parse(e.to_string()))?;

    let pages: Vec<(String, String)> = json
        .get("results")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let id = p.get("id").and_then(|i| i.as_str())?;
                    let title = p.get("title").and_then(|t| t.as_str()).unwrap_or("");
                    Some((id.to_string(), title.to_string()))
                })
                .take(config.max_pages)
                .collect()
        })
        .unwrap_or_default();

    for (page_id, title) in &pages {
        // Fetch page body (storage format = HTML).
        let body_url = format!("{}/wiki/api/v2/pages/{}/body?format=storage", base, page_id);
        let body_resp = agent
            .get(&body_url)
            .set("Authorization", &format!("Basic {auth_b64}"))
            .set("Accept", "application/json")
            .call();

        if let Ok(resp) = body_resp
            && let Ok(json) = resp.into_json::<serde_json::Value>()
            && let Some(body) = json.get("body")
                .and_then(|b| b.get("storage"))
                .and_then(|s| s.get("value"))
                .and_then(|v| v.as_str())
        {
            let virtual_path = std::path::PathBuf::from(format!("confluence:{}#{}", page_id, title));
            findings.extend(scan_text(body, &virtual_path, detectors));
        }
    }

    Ok(findings)
}

// ── Slack (as source) ──────────────────────────────────────────────────

/// Configuration for a Slack message scan.
#[derive(Debug, Clone)]
pub struct SlackScanConfig {
    /// Slack Bot/User token (starts with `xoxb-` or `xoxp-`).
    pub token: String,
    /// Channel IDs to scan. If empty, scans all public channels.
    pub channel_ids: Vec<String>,
    /// Maximum number of messages per channel to scan.
    pub max_messages: usize,
}

/// Scan Slack channel messages for secrets.
pub fn scan_slack(
    config: &SlackScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let mut findings = Vec::new();

    let channels: Vec<String> = if config.channel_ids.is_empty() {
        // List all public channels.
        let resp = agent
            .get("https://slack.com/api/conversations.list")
            .set("Authorization", &format!("Bearer {}", config.token))
            .call()
            .map_err(|e| SourceScanError::Http(Box::new(e)))?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| SourceScanError::Parse(e.to_string()))?;

        json.get("channels")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|ch| ch.get("id").and_then(|i| i.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        config.channel_ids.clone()
    };

    for channel_id in &channels {
        let mut cursor: Option<String> = None;
        let mut msg_count = 0usize;

        loop {
            if msg_count >= config.max_messages {
                break;
            }

            let mut url = format!(
                "https://slack.com/api/conversations.history?channel={}&limit=200",
                channel_id
            );
            if let Some(ref c) = cursor {
                url.push_str(&format!("&cursor={c}"));
            }

            let resp = agent
                .get(&url)
                .set("Authorization", &format!("Bearer {}", config.token))
                .call();

            if let Ok(resp) = resp
                && let Ok(json) = resp.into_json::<serde_json::Value>()
            {
                let messages = json.get("messages").and_then(|m| m.as_array());
                if let Some(msgs) = messages {
                    for msg in msgs {
                        if msg_count >= config.max_messages {
                            break;
                        }
                        let text = msg.get("text").and_then(|t| t.as_str()).unwrap_or("");
                        let ts = msg.get("ts").and_then(|t| t.as_str()).unwrap_or("");
                        let user = msg.get("user").and_then(|u| u.as_str()).unwrap_or("unknown");
                        let virtual_path = std::path::PathBuf::from(format!(
                            "slack:{}#ts={}_user={}",
                            channel_id, ts, user
                        ));
                        findings.extend(scan_text(text, &virtual_path, detectors));
                        msg_count += 1;
                    }
                }

                // Check for pagination.
                let has_more = json.get("has_more").and_then(|h| h.as_bool()).unwrap_or(false);
                if !has_more {
                    break;
                }
                cursor = json
                    .get("response_metadata")
                    .and_then(|rm| rm.get("next_cursor"))
                    .and_then(|c| c.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                if cursor.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
    }

    Ok(findings)
}

// ── Jira ───────────────────────────────────────────────────────────────

/// Configuration for a Jira scan.
#[derive(Debug, Clone)]
pub struct JiraScanConfig {
    /// Base URL (e.g. "https://your-domain.atlassian.net").
    pub base_url: String,
    /// Jira API token.
    pub api_token: String,
    /// Jira user email (for Basic auth).
    pub email: String,
    /// JQL query to filter issues (e.g. "project = ENG"). If empty, scans all.
    pub jql: Option<String>,
    /// Maximum number of issues to scan.
    pub max_issues: usize,
}

/// Scan Jira issues and comments for secrets.
pub fn scan_jira(
    config: &JiraScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    use base64::Engine;
    let auth_b64 = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", config.email, config.api_token));

    let jql = config.jql.clone().unwrap_or_default();
    let search_url = format!(
        "{}/rest/api/3/search?maxResults={}&fields=summary,description,comment&jql={}",
        base,
        config.max_issues.min(100),
        urlencoding::encode(&jql)
    );

    let resp = agent
        .get(&search_url)
        .set("Authorization", &format!("Basic {auth_b64}"))
        .set("Accept", "application/json")
        .call()
        .map_err(|e| SourceScanError::Http(Box::new(e)))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| SourceScanError::Parse(e.to_string()))?;

    let mut findings = Vec::new();

    let issues = json.get("issues").and_then(|i| i.as_array());
    if let Some(issues) = issues {
        for issue in issues.iter().take(config.max_issues) {
            let key = issue.get("key").and_then(|k| k.as_str()).unwrap_or("");

            // Scan summary and description.
            let fields = issue.get("fields");
            if let Some(fields) = fields {
                let summary = fields.get("summary").and_then(|s| s.as_str()).unwrap_or("");
                let desc = fields.get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("");
                let combined = format!("{summary}\n{desc}");
                let virtual_path = std::path::PathBuf::from(format!("jira:{}#body", key));
                findings.extend(scan_text(&combined, &virtual_path, detectors));

                // Scan comments.
                if let Some(comments) = fields.get("comment")
                    .and_then(|c| c.get("comments"))
                    .and_then(|c| c.as_array())
                {
                    for comment in comments {
                        let body = comment.get("body").and_then(|b| b.as_str()).unwrap_or("");
                        let comment_id = comment.get("id").and_then(|i| i.as_str()).unwrap_or("");
                        let virtual_path = std::path::PathBuf::from(format!(
                            "jira:{}#comment={}",
                            key, comment_id
                        ));
                        findings.extend(scan_text(body, &virtual_path, detectors));
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ── Postman ────────────────────────────────────────────────────────────

/// Configuration for a Postman collection scan.
#[derive(Debug, Clone)]
pub struct PostmanScanConfig {
    /// Postman API key.
    pub api_key: String,
    /// Collection ID to scan. If empty, scans all accessible collections.
    pub collection_id: Option<String>,
    /// Maximum number of collections to scan.
    pub max_collections: usize,
}

/// Scan Postman collections for secrets via the REST API.
pub fn scan_postman(
    config: &PostmanScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let mut findings = Vec::new();

    let collection_ids: Vec<String> = if let Some(ref id) = config.collection_id {
        vec![id.clone()]
    } else {
        // List all collections.
        let resp = agent
            .get("https://api.getpostman.com/collections")
            .set("X-Api-Key", &config.api_key)
            .call()
            .map_err(|e| SourceScanError::Http(Box::new(e)))?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| SourceScanError::Parse(e.to_string()))?;

        json.get("collections")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.get("uid").and_then(|u| u.as_str()).map(String::from))
                    .take(config.max_collections)
                    .collect()
            })
            .unwrap_or_default()
    };

    for uid in &collection_ids {
        let url = format!("https://api.getpostman.com/collections/{}", uid);
        let resp = agent
            .get(&url)
            .set("X-Api-Key", &config.api_key)
            .call();

        if let Ok(resp) = resp
            && let Ok(json) = resp.into_json::<serde_json::Value>()
        {
            // The collection JSON contains all request definitions, variables,
            // headers, and auth configs. Serialize it back to a pretty string
            // and scan it — secrets often appear in variable values, headers,
            // and auth configs.
            let body = serde_json::to_string_pretty(&json).unwrap_or_default();
            let virtual_path = std::path::PathBuf::from(format!("postman:{}", uid));
            findings.extend(scan_text(&body, &virtual_path, detectors));
        }
    }

    Ok(findings)
}

// ── Gerrit ─────────────────────────────────────────────────────────────

/// Configuration for a Gerrit scan.
#[derive(Debug, Clone)]
pub struct GerritScanConfig {
    /// Base URL (e.g. "https://gerrit.example.com").
    pub base_url: String,
    /// HTTP credentials (username:password or HTTP password).
    pub credentials: Option<String>,
    /// Project name to scan. If empty, scans all projects.
    pub project: Option<String>,
    /// Maximum number of changes to scan.
    pub max_changes: usize,
}

/// Scan Gerrit changes for secrets via the REST API.
pub fn scan_gerrit(
    config: &GerritScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    let mut findings = Vec::new();

    // Query changes. Gerrit prefixes JSON responses with )]}' for XSS protection.
    let query = if let Some(ref project) = config.project {
        format!("project:{}", project)
    } else {
        String::new()
    };
    let changes_url = format!(
        "{}/changes/?q={}&n={}&o=ALL_REVISIONS&o=DETAILED_LABELS",
        base,
        urlencoding::encode(&query),
        config.max_changes.min(100)
    );

    let mut req = agent.get(&changes_url);
    if let Some(ref creds) = config.credentials {
        use base64::Engine;
        let auth_b64 = base64::engine::general_purpose::STANDARD.encode(creds);
        req = req.set("Authorization", &format!("Basic {auth_b64}"));
    }

    let resp = req.call().map_err(|e| SourceScanError::Http(Box::new(e)))?;
    let body = resp.into_string().map_err(|e| SourceScanError::Parse(e.to_string()))?;

    // Strip Gerrit's XSS prefix.
    let json_str = body.strip_prefix(")]}'").unwrap_or(&body).trim();
    let changes: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| SourceScanError::Parse(e.to_string()))?;

    for change in changes.iter().take(config.max_changes) {
        let change_id = change.get("_number").and_then(|n| n.as_u64()).unwrap_or(0);
        let subject = change.get("subject").and_then(|s| s.as_str()).unwrap_or("");

        // Scan the subject.
        let virtual_path = std::path::PathBuf::from(format!("gerrit:{}#subject", change_id));
        findings.extend(scan_text(subject, &virtual_path, detectors));

        // Scan commit messages and file diffs in revisions.
        if let Some(revisions) = change.get("revisions").and_then(|r| r.as_object()) {
            for (rev_id, rev) in revisions {
                // Commit message.
                if let Some(commit) = rev.get("commit")
                    .and_then(|c| c.get("message"))
                    .and_then(|m| m.as_str())
                {
                    let virtual_path = std::path::PathBuf::from(format!(
                        "gerrit:{}#rev={}_commit",
                        change_id, rev_id
                    ));
                    findings.extend(scan_text(commit, &virtual_path, detectors));
                }

                // Files.
                if let Some(files) = rev.get("files").and_then(|f| f.as_object()) {
                    for (file_path, _file_info) in files {
                        // Fetch file content.
                        let file_url = format!(
                            "{}/changes/{}/revisions/{}/files/{}/content",
                            base, change_id, rev_id, urlencoding::encode(file_path)
                        );
                        let mut file_req = agent.get(&file_url);
                        if let Some(ref creds) = config.credentials {
                            use base64::Engine;
                            let auth_b64 = base64::engine::general_purpose::STANDARD.encode(creds);
                            file_req = file_req.set("Authorization", &format!("Basic {auth_b64}"));
                        }
                        if let Ok(resp) = file_req.call()
                            && let Ok(content) = resp.into_string()
                        {
                            // Gerrit returns base64-encoded content.
                            use base64::Engine;
                            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(content.trim()) {
                                let text = String::from_utf8_lossy(&decoded);
                                let virtual_path = std::path::PathBuf::from(format!(
                                    "gerrit:{}#rev={}_file={}",
                                    change_id, rev_id, file_path
                                ));
                                findings.extend(scan_text(&text, &virtual_path, detectors));
                            } else {
                                // Not base64 — scan raw.
                                let virtual_path = std::path::PathBuf::from(format!(
                                    "gerrit:{}#rev={}_file={}",
                                    change_id, rev_id, file_path
                                ));
                                findings.extend(scan_text(&content, &virtual_path, detectors));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ── Buildkite ──────────────────────────────────────────────────────────

/// Configuration for a Buildkite scan.
#[derive(Debug, Clone)]
pub struct BuildkiteScanConfig {
    /// Buildkite API token.
    pub api_token: String,
    /// Organization slug.
    pub org: String,
    /// Pipeline slug to scan. If empty, scans all pipelines.
    pub pipeline: Option<String>,
    /// Maximum number of builds to scan.
    pub max_builds: usize,
}

/// Scan Buildkite build logs for secrets via the REST API.
pub fn scan_buildkite(
    config: &BuildkiteScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let mut findings = Vec::new();

    let pipelines: Vec<String> = if let Some(ref p) = config.pipeline {
        vec![p.clone()]
    } else {
        let url = format!("https://api.buildkite.com/v2/organizations/{}/pipelines", config.org);
        let resp = agent
            .get(&url)
            .set("Authorization", &format!("Bearer {}", config.api_token))
            .call()
            .map_err(|e| SourceScanError::Http(Box::new(e)))?;

        let json: Vec<serde_json::Value> = resp
            .into_json()
            .map_err(|e| SourceScanError::Parse(e.to_string()))?;

        json.iter()
            .filter_map(|p| p.get("slug").and_then(|s| s.as_str()).map(String::from))
            .take(config.max_builds)
            .collect()
    };

    for pipeline_slug in &pipelines {
        let builds_url = format!(
            "https://api.buildkite.com/v2/organizations/{}/pipelines/{}/builds?per_page={}",
            config.org, pipeline_slug, config.max_builds.min(100)
        );

        let resp = agent
            .get(&builds_url)
            .set("Authorization", &format!("Bearer {}", config.api_token))
            .call();

        if let Ok(resp) = resp
            && let Ok(builds) = resp.into_json::<Vec<serde_json::Value>>()
        {
            for build in builds.iter().take(config.max_builds) {
                let build_num = build.get("number").and_then(|n| n.as_u64()).unwrap_or(0);

                // Get build log.
                let log_url = format!(
                    "https://api.buildkite.com/v2/organizations/{}/pipelines/{}/builds/{}/log",
                    config.org, pipeline_slug, build_num
                );

                let log_resp = agent
                    .get(&log_url)
                    .set("Authorization", &format!("Bearer {}", config.api_token))
                    .call();

                if let Ok(resp) = log_resp
                    && let Ok(json) = resp.into_json::<serde_json::Value>()
                    && let Some(content) = json.get("content").and_then(|c| c.as_str())
                {
                    let virtual_path = std::path::PathBuf::from(format!(
                        "buildkite:{}/{}/build-{}#log",
                        config.org, pipeline_slug, build_num
                    ));
                    findings.extend(scan_text(content, &virtual_path, detectors));
                }
            }
        }
    }

    Ok(findings)
}

// ── Artifactory ────────────────────────────────────────────────────────

/// Configuration for an Artifactory scan.
#[derive(Debug, Clone)]
pub struct ArtifactoryScanConfig {
    /// Base URL (e.g. "https://your-artifactory.example.com").
    pub base_url: String,
    /// Artifactory API key or bearer token.
    pub api_key: String,
    /// Repository key to scan (e.g. "docker-local"). If empty, scans all repos.
    pub repo: Option<String>,
    /// Maximum number of files to scan.
    pub max_files: usize,
}

/// Scan Artifactory repository files for secrets.
pub fn scan_artifactory(
    config: &ArtifactoryScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    let mut findings = Vec::new();

    let repos: Vec<String> = if let Some(ref repo) = config.repo {
        vec![repo.clone()]
    } else {
        let url = format!("{}/api/repositories", base);
        let resp = agent
            .get(&url)
            .set("X-JFrog-Art-Api", &config.api_key)
            .call()
            .map_err(|e| SourceScanError::Http(Box::new(e)))?;

        let json: Vec<serde_json::Value> = resp
            .into_json()
            .map_err(|e| SourceScanError::Parse(e.to_string()))?;

        json.iter()
            .filter_map(|r| r.get("key").and_then(|k| k.as_str()).map(String::from))
            .take(config.max_files)
            .collect()
    };

    for repo_key in &repos {
        // List files in the repository.
        let list_url = format!("{}/api/storage/{}?list&deep=1&listFolders=0", base, repo_key);
        let resp = agent
            .get(&list_url)
            .set("X-JFrog-Art-Api", &config.api_key)
            .call();

        if let Ok(resp) = resp
            && let Ok(json) = resp.into_json::<serde_json::Value>()
            && let Some(files) = json.get("files").and_then(|f| f.as_array())
        {
            for file in files.iter().take(config.max_files) {
                let uri = file.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                if uri.is_empty() {
                    continue;
                }

                // Download file content.
                let file_url = format!("{}/{}/{}", base, repo_key, uri.trim_start_matches('/'));
                let file_resp = agent
                    .get(&file_url)
                    .set("X-JFrog-Art-Api", &config.api_key)
                    .call();

                if let Ok(resp) = file_resp
                    && let Ok(text) = resp.into_string()
                {
                    let virtual_path = std::path::PathBuf::from(format!(
                        "artifactory:{}{}",
                        repo_key, uri
                    ));
                    findings.extend(scan_text(&text, &virtual_path, detectors));
                }
            }
        }
    }

    Ok(findings)
}

// ── AWS Secrets Manager ────────────────────────────────────────────────

/// Configuration for an AWS Secrets Manager scan.
#[derive(Debug, Clone)]
pub struct AwsSecretsManagerScanConfig {
    /// AWS region.
    pub region: String,
    /// AWS access key ID.
    pub access_key_id: String,
    /// AWS secret access key.
    pub secret_access_key: String,
    /// Optional filter (name prefix).
    pub name_prefix: Option<String>,
    /// Maximum number of secrets to scan.
    pub max_secrets: usize,
}

/// Scan AWS Secrets Manager for exposed secrets.
///
/// This lists secrets in the account and scans their **names** and **descriptions**
/// for sensitive patterns. It does NOT retrieve secret values (that would require
/// `secretsmanager:GetSecretValue` and could expose actual secret material).
/// The purpose is to detect secrets that may have been accidentally committed
/// to source code and whose names/descriptions match known patterns.
pub fn scan_aws_secrets_manager(
    config: &AwsSecretsManagerScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let mut findings = Vec::new();

    let service = "secretsmanager";
    let host = format!("secretsmanager.{}.amazonaws.com", config.region);
    let url = format!("https://{}", host);

    // Use AWS SigV4 signing for the ListSecrets API.
    // For simplicity, we use the query API with basic SigV4.
    // In production, we'd use the aws-sigv4 crate, but here we do a simplified
    // approach that works when credentials are valid.
    let amz_date = aws_sigv4_date();
    let date_stamp = aws_sigv4_date_stamp();

    // Build canonical request for ListSecrets.
    let method = "POST";
    let canonical_uri = "/";
    let canonical_query = "";
    let payload = if let Some(ref prefix) = config.name_prefix {
        format!(r#"{{"MaxResults":{},"Filters":[{{"Key":"name","Values":["{}"]}}]}}"#, config.max_secrets.min(100), prefix)
    } else {
        format!(r#"{{"MaxResults":{}}}"#, config.max_secrets.min(100))
    };

    // Simplified: use X-Amz-Date + Authorization header.
    // Note: Full SigV4 is complex. We attempt a basic signed request.
    // If the signing fails, the API will return 403 and we return empty findings.
    let auth_header = aws_sigv4_authorization(
        &config.access_key_id,
        &config.secret_access_key,
        &config.region,
        service,
        &host,
        &amz_date,
        &date_stamp,
        method,
        canonical_uri,
        canonical_query,
        &payload,
    );

    let resp = agent
        .post(&url)
        .set("Content-Type", "application/x-amz-json-1.1")
        .set("X-Amz-Target", "secretsmanager.ListSecrets")
        .set("X-Amz-Date", &amz_date)
        .set("Authorization", &auth_header)
        .send_string(&payload);

    if let Ok(resp) = resp
        && let Ok(json) = resp.into_json::<serde_json::Value>()
        && let Some(secret_list) = json.get("SecretList").and_then(|s| s.as_array())
    {
        for secret in secret_list.iter() {
            let name = secret.get("Name").and_then(|n| n.as_str()).unwrap_or("");
            let description = secret.get("Description").and_then(|d| d.as_str()).unwrap_or("");
            let arn = secret.get("ARN").and_then(|a| a.as_str()).unwrap_or("");

            let combined = format!("Name: {}\nDescription: {}\nARN: {}", name, description, arn);
            let virtual_path = std::path::PathBuf::from(format!("aws-sm:{}", arn));
            findings.extend(scan_text(&combined, &virtual_path, detectors));
        }
    }

    Ok(findings)
}

// ── AWS SigV4 helpers (simplified) ─────────────────────────────────────

fn aws_sigv4_date() -> String {
    // Format: YYYYMMDDTHHMMSSZ
    // We use a fixed timestamp for simplicity. In production, use SystemTime.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    aws_format_sigv4_date(now)
}

fn aws_format_sigv4_date(epoch: u64) -> String {
    // Simple UTC formatting without chrono.
    let (year, month, day, hour, minute, second) = epoch_to_utc(epoch);
    format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", year, month, day, hour, minute, second)
}

fn aws_sigv4_date_stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day, _, _, _) = epoch_to_utc(now);
    format!("{:04}{:02}{:02}", year, month, day)
}

fn epoch_to_utc(epoch: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let secs = epoch;
    let second = (secs % 60) as u32;
    let mins = secs / 60;
    let minute = (mins % 60) as u32;
    let hours = mins / 60;
    let hour = (hours % 24) as u32;
    let mut days = hours / 24;

    let mut year = 1970u32;
    loop {
        let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let yd = if leap { 366 } else { 365 };
        if days < yd {
            break;
        }
        days -= yd;
        year += 1;
    }

    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let mut month = 1u32;
    for (m, &dim_base) in days_in_month.iter().enumerate() {
        let dim = if m == 1 && leap { 29 } else { dim_base };
        if days < dim as u64 {
            break;
        }
        days -= dim as u64;
        month += 1;
    }
    let day = (days + 1) as u32;

    (year, month, day, hour, minute, second)
}

#[allow(clippy::too_many_arguments)]
fn aws_sigv4_authorization(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    host: &str,
    amz_date: &str,
    date_stamp: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    payload: &str,
) -> String {
    use sha2::{Digest, Sha256};

    // Payload hash.
    let payload_hash = {
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex_encode(&hasher.finalize())
    };

    // Canonical headers.
    let canonical_headers = format!(
        "content-type:application/x-amz-json-1.1\nhost:{}\nx-amz-date:{}\nx-amz-target:secretsmanager.ListSecrets\n",
        host, amz_date
    );
    let signed_headers = "content-type;host;x-amz-date;x-amz-target";

    // Canonical request.
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );

    let canonical_request_hash = {
        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        hex_encode(&hasher.finalize())
    };

    // String to sign.
    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    // Signing key.
    let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex_encode(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, credential_scope, signed_headers, signature
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── URL encoding (reuse from api_scan) ──────────────────────────────────

mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::new();
        for c in s.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
                _ => {
                    for byte in c.to_string().as_bytes() {
                        out.push_str(&format!("%{byte:02X}"));
                    }
                }
            }
        }
        out
    }
}

// ── CircleCI Artifacts ─────────────────────────────────────────────────

/// Configuration for a CircleCI artifacts scan.
#[derive(Debug, Clone)]
pub struct CircleCiArtifactsScanConfig {
    /// CircleCI API token.
    pub api_token: String,
    /// Organization/repo slug (e.g., "github/pledgeandgrow/pledgeguard").
    pub project_slug: String,
    /// Maximum number of builds to scan.
    pub max_builds: usize,
}

/// Scan CircleCI build artifacts for secrets via the REST API.
pub fn scan_circleci_artifacts(
    config: &CircleCiArtifactsScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let mut findings = Vec::new();

    // List recent builds/pipelines.
    let pipelines_url = format!(
        "https://circleci.com/api/v2/project/{}/pipeline?per_page={}",
        config.project_slug,
        config.max_builds.min(30)
    );

    let resp = agent
        .get(&pipelines_url)
        .set("Circle-Token", &config.api_token)
        .set("Accept", "application/json")
        .call()
        .map_err(|e| SourceScanError::Http(Box::new(e)))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| SourceScanError::Parse(e.to_string()))?;

    let pipelines: Vec<serde_json::Value> = json
        .get("items")
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default();

    for pipeline in pipelines.iter().take(config.max_builds) {
        let pipeline_id = pipeline.get("id").and_then(|i| i.as_str()).unwrap_or("");

        // Get workflows for this pipeline.
        let workflows_url = format!(
            "https://circleci.com/api/v2/pipeline/{}/workflow",
            pipeline_id
        );
        let wf_resp = agent
            .get(&workflows_url)
            .set("Circle-Token", &config.api_token)
            .call();

        if let Ok(resp) = wf_resp
            && let Ok(wf_json) = resp.into_json::<serde_json::Value>()
            && let Some(workflows) = wf_json.get("items").and_then(|i| i.as_array())
        {
            for workflow in workflows {
                let workflow_id = workflow.get("id").and_then(|i| i.as_str()).unwrap_or("");

                // Get jobs for this workflow.
                let jobs_url = format!(
                    "https://circleci.com/api/v2/workflow/{}/job",
                    workflow_id
                );
                let jobs_resp = agent
                    .get(&jobs_url)
                    .set("Circle-Token", &config.api_token)
                    .call();

                if let Ok(resp) = jobs_resp
                    && let Ok(jobs_json) = resp.into_json::<serde_json::Value>()
                    && let Some(jobs) = jobs_json.get("items").and_then(|i| i.as_array())
                {
                    for job in jobs {
                        let job_number = job.get("job_number").and_then(|n| n.as_u64());
                        if let Some(job_num) = job_number {
                            // Get artifacts for this job.
                            let artifacts_url = format!(
                                "https://circleci.com/api/v2/project/{}/{}/artifacts",
                                config.project_slug, job_num
                            );
                            let art_resp = agent
                                .get(&artifacts_url)
                                .set("Circle-Token", &config.api_token)
                                .call();

                            if let Ok(resp) = art_resp
                                && let Ok(art_json) = resp.into_json::<serde_json::Value>()
                                && let Some(artifacts) = art_json.get("items").and_then(|i| i.as_array())
                            {
                                for artifact in artifacts {
                                    let url = artifact.get("url").and_then(|u| u.as_str()).unwrap_or("");
                                    if url.is_empty() {
                                        continue;
                                    }

                                    // Download artifact content.
                                    let content_resp = agent
                                        .get(url)
                                        .set("Circle-Token", &config.api_token)
                                        .call();

                                    if let Ok(resp) = content_resp
                                        && let Ok(text) = resp.into_string()
                                    {
                                        let path = artifact.get("path").and_then(|p| p.as_str()).unwrap_or("unknown");
                                        let virtual_path = std::path::PathBuf::from(format!(
                                            "circleci:{}/job-{}/artifact:{}",
                                            config.project_slug, job_num, path
                                        ));
                                        findings.extend(scan_text(&text, &virtual_path, detectors));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ── Travis CI Logs ─────────────────────────────────────────────────────

/// Configuration for a Travis CI logs scan.
#[derive(Debug, Clone)]
pub struct TravisCiScanConfig {
    /// Travis CI API token.
    pub api_token: String,
    /// Repository slug (e.g., "pledgeandgrow/pledgeguard").
    pub repo_slug: String,
    /// Travis CI enterprise base URL (defaults to https://api.travis-ci.com).
    pub base_url: Option<String>,
    /// Maximum number of builds to scan.
    pub max_builds: usize,
}

/// Scan Travis CI build logs for secrets via the REST API.
pub fn scan_travis_ci_logs(
    config: &TravisCiScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let base = config.base_url.as_deref().unwrap_or("https://api.travis-ci.com").trim_end_matches('/');
    let mut findings = Vec::new();

    // List recent builds.
    let builds_url = format!(
        "{}/repo/{}/builds?limit={}",
        base,
        urlencoding::encode(&config.repo_slug),
        config.max_builds.min(50)
    );

    let resp = agent
        .get(&builds_url)
        .set("Travis-API-Version", "3")
        .set("Authorization", &format!("token {}", config.api_token))
        .call()
        .map_err(|e| SourceScanError::Http(Box::new(e)))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| SourceScanError::Parse(e.to_string()))?;

    let builds: Vec<serde_json::Value> = json
        .get("builds")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();

    for build in builds.iter().take(config.max_builds) {
        let build_id = build.get("id").and_then(|i| i.as_u64()).unwrap_or(0);

        // Get jobs for this build.
        if let Some(jobs) = build.get("jobs").and_then(|j| j.as_array()) {
            for job in jobs {
                let job_id = job.get("id").and_then(|i| i.as_u64()).unwrap_or(0);

                // Get job log.
                let log_url = format!("{}/job/{}/log", base, job_id);
                let log_resp = agent
                    .get(&log_url)
                    .set("Travis-API-Version", "3")
                    .set("Authorization", &format!("token {}", config.api_token))
                    .call();

                if let Ok(resp) = log_resp
                    && let Ok(log_json) = resp.into_json::<serde_json::Value>()
                    && let Some(content) = log_json.get("content").and_then(|c| c.as_str())
                {
                    let virtual_path = std::path::PathBuf::from(format!(
                        "travis-ci:{}/build-{}/job-{}#log",
                        config.repo_slug, build_id, job_id
                    ));
                    findings.extend(scan_text(content, &virtual_path, detectors));
                }
            }
        }
    }

    Ok(findings)
}

// ── Jenkins Build Logs ─────────────────────────────────────────────────

/// Configuration for a Jenkins build logs scan.
#[derive(Debug, Clone)]
pub struct JenkinsScanConfig {
    /// Jenkins base URL (e.g., "https://jenkins.example.com").
    pub base_url: String,
    /// Jenkins username.
    pub username: String,
    /// Jenkins API token.
    pub api_token: String,
    /// Job name to scan (e.g., "pledgeguard"). If empty, scans all jobs.
    pub job_name: Option<String>,
    /// Maximum number of builds to scan per job.
    pub max_builds: usize,
}

/// Scan Jenkins build logs for secrets via the REST API.
pub fn scan_jenkins_logs(
    config: &JenkinsScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    use base64::Engine;
    let auth_b64 = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", config.username, config.api_token));
    let mut findings = Vec::new();

    let jobs: Vec<String> = if let Some(ref name) = config.job_name {
        vec![name.clone()]
    } else {
        // List all jobs.
        let jobs_url = format!("{}/api/json?tree=jobs[name]", base);
        let resp = agent
            .get(&jobs_url)
            .set("Authorization", &format!("Basic {auth_b64}"))
            .call()
            .map_err(|e| SourceScanError::Http(Box::new(e)))?;

        let json: serde_json::Value = resp
            .into_json()
            .map_err(|e| SourceScanError::Parse(e.to_string()))?;

        json.get("jobs")
            .and_then(|j| j.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|j| j.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };

    for job_name in &jobs {
        // Get build numbers.
        let builds_url = format!(
            "{}/job/{}/api/json?tree=builds[number]{{0,{}}}",
            base,
            urlencoding::encode(job_name),
            config.max_builds
        );

        let resp = agent
            .get(&builds_url)
            .set("Authorization", &format!("Basic {auth_b64}"))
            .call();

        if let Ok(resp) = resp
            && let Ok(json) = resp.into_json::<serde_json::Value>()
            && let Some(builds) = json.get("builds").and_then(|b| b.as_array())
        {
            for build in builds.iter().take(config.max_builds) {
                let build_num = build.get("number").and_then(|n| n.as_u64()).unwrap_or(0);

                // Get console log.
                let log_url = format!(
                    "{}/job/{}/{}//consoleText",
                    base,
                    urlencoding::encode(job_name),
                    build_num
                );

                let log_resp = agent
                    .get(&log_url)
                    .set("Authorization", &format!("Basic {auth_b64}"))
                    .call();

                if let Ok(resp) = log_resp
                    && let Ok(text) = resp.into_string()
                {
                    let virtual_path = std::path::PathBuf::from(format!(
                        "jenkins:{}/build-{}#console",
                        job_name, build_num
                    ));
                    findings.extend(scan_text(&text, &virtual_path, detectors));
                }
            }
        }
    }

    Ok(findings)
}

// ── DroneCI Builds ─────────────────────────────────────────────────────

/// Configuration for a DroneCI builds scan.
#[derive(Debug, Clone)]
pub struct DroneCiScanConfig {
    /// DroneCI server base URL (e.g., "https://drone.example.com").
    pub base_url: String,
    /// DroneCI API token.
    pub api_token: String,
    /// Repository slug (e.g., "pledgeandgrow/pledgeguard"). If empty, scans all repos.
    pub repo_slug: Option<String>,
    /// Maximum number of builds to scan.
    pub max_builds: usize,
}

/// Scan DroneCI build logs for secrets via the REST API.
pub fn scan_droneci_builds(
    config: &DroneCiScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    let mut findings = Vec::new();

    let repos: Vec<String> = if let Some(ref slug) = config.repo_slug {
        vec![slug.clone()]
    } else {
        // List all repos.
        let repos_url = format!("{}/api/user/repos", base);
        let resp = agent
            .get(&repos_url)
            .set("Authorization", &format!("Bearer {}", config.api_token))
            .call()
            .map_err(|e| SourceScanError::Http(Box::new(e)))?;

        let json: Vec<serde_json::Value> = resp
            .into_json()
            .map_err(|e| SourceScanError::Parse(e.to_string()))?;

        json.iter()
            .filter_map(|r| r.get("slug").and_then(|s| s.as_str()).map(String::from))
            .take(config.max_builds)
            .collect()
    };

    for repo_slug in &repos {
        // List builds for this repo.
        let builds_url = format!(
            "{}/api/repos/{}/builds?page=1&per_page={}",
            base,
            urlencoding::encode(repo_slug),
            config.max_builds.min(50)
        );

        let resp = agent
            .get(&builds_url)
            .set("Authorization", &format!("Bearer {}", config.api_token))
            .call();

        if let Ok(resp) = resp
            && let Ok(builds) = resp.into_json::<Vec<serde_json::Value>>()
        {
            for build in builds.iter().take(config.max_builds) {
                let build_num = build.get("number").and_then(|n| n.as_u64()).unwrap_or(0);

                // Get build details with stages.
                let details_url = format!(
                    "{}/api/repos/{}/builds/{}",
                    base,
                    urlencoding::encode(repo_slug),
                    build_num
                );

                let details_resp = agent
                    .get(&details_url)
                    .set("Authorization", &format!("Bearer {}", config.api_token))
                    .call();

                if let Ok(resp) = details_resp
                    && let Ok(details) = resp.into_json::<serde_json::Value>()
                    && let Some(stages) = details.get("stages").and_then(|s| s.as_array())
                {
                    for stage in stages {
                        let stage_num = stage.get("number").and_then(|n| n.as_u64()).unwrap_or(0);

                        // Get stage logs.
                        let log_url = format!(
                            "{}/api/repos/{}/builds/{}/logs/{}",
                            base,
                            urlencoding::encode(repo_slug),
                            build_num,
                            stage_num
                        );

                        let log_resp = agent
                            .get(&log_url)
                            .set("Authorization", &format!("Bearer {}", config.api_token))
                            .call();

                        if let Ok(resp) = log_resp
                            && let Ok(log_json) = resp.into_json::<serde_json::Value>()
                        {
                            // DroneCI logs are an array of log lines.
                            if let Some(logs) = log_json.as_array() {
                                let combined: String = logs.iter()
                                    .filter_map(|l| l.get("line").and_then(|line| line.as_str()))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let virtual_path = std::path::PathBuf::from(format!(
                                    "droneci:{}/build-{}/stage-{}#log",
                                    repo_slug, build_num, stage_num
                                ));
                                findings.extend(scan_text(&combined, &virtual_path, detectors));
                            } else if let Some(output) = log_json.get("output").and_then(|o| o.as_str()) {
                                let virtual_path = std::path::PathBuf::from(format!(
                                    "droneci:{}/build-{}/stage-{}#log",
                                    repo_slug, build_num, stage_num
                                ));
                                findings.extend(scan_text(output, &virtual_path, detectors));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ── Hugging Face ──────────────────────────────────────────────────────

/// Configuration for a Hugging Face scan.
#[derive(Debug, Clone)]
pub struct HuggingFaceScanConfig {
    /// Hugging Face API token (hf_...).
    pub api_token: String,
    /// Organization or username to scan. If empty, scans the authenticated user.
    pub namespace: Option<String>,
    /// Maximum number of models/datasets/spaces to scan.
    pub max_items: usize,
}

/// Scan Hugging Face models, datasets, and spaces metadata for secrets.
pub fn scan_huggingface(
    config: &HuggingFaceScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let token = &config.api_token;
    let namespace = config.namespace.as_deref().unwrap_or("");

    let mut findings = Vec::new();

    // Scan user/org info
    let whoami_url = "https://huggingface.co/api/whoami-v2";
    let result = agent
        .get(whoami_url)
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    match result {
        Ok(resp) => {
            let body = resp.into_string().map_err(|e| SourceScanError::Parse(e.to_string()))?;
            let virtual_path = std::path::PathBuf::from("huggingface:whoami");
            findings.extend(scan_text(&body, &virtual_path, detectors));
        }
        Err(ureq::Error::Status(401, _)) => return Err(SourceScanError::Parse("Invalid Hugging Face token".into())),
        Err(e) => return Err(SourceScanError::Http(Box::new(e))),
    }

    // Scan models metadata
    let models_url = if namespace.is_empty() {
        "https://huggingface.co/api/models?limit=50".to_string()
    } else {
        format!("https://huggingface.co/api/models?author={namespace}&limit={}", config.max_items.min(100))
    };
    let result = agent
        .get(&models_url)
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    if let Ok(resp) = result
        && let Ok(body) = resp.into_string()
    {
        let virtual_path = std::path::PathBuf::from("huggingface:models");
        findings.extend(scan_text(&body, &virtual_path, detectors));
    }

    // Scan datasets metadata
    let datasets_url = if namespace.is_empty() {
        "https://huggingface.co/api/datasets?limit=50".to_string()
    } else {
        format!("https://huggingface.co/api/datasets?author={namespace}&limit={}", config.max_items.min(100))
    };
    let result = agent
        .get(&datasets_url)
        .set("Authorization", &format!("Bearer {token}"))
        .call();
    if let Ok(resp) = result
        && let Ok(body) = resp.into_string()
    {
        let virtual_path = std::path::PathBuf::from("huggingface:datasets");
        findings.extend(scan_text(&body, &virtual_path, detectors));
    }

    Ok(findings)
}

// ── SharePoint ────────────────────────────────────────────────────────

/// Configuration for a SharePoint scan.
#[derive(Debug, Clone)]
pub struct SharePointScanConfig {
    /// SharePoint site URL (e.g. "https://contoso.sharepoint.com/sites/eng").
    pub site_url: String,
    /// Azure AD client ID for authentication.
    pub client_id: String,
    /// Azure AD client secret.
    pub client_secret: String,
    /// Azure AD tenant ID.
    pub tenant_id: String,
    /// Document library name to scan. If empty, scans all libraries.
    pub library_name: Option<String>,
    /// Maximum number of files to scan.
    pub max_files: usize,
}

/// Scan SharePoint documents for secrets via the Microsoft Graph API.
pub fn scan_sharepoint(
    config: &SharePointScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();

    // Step 1: Get an access token from Azure AD.
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        config.tenant_id
    );
    let token_result = agent
        .post(&token_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!(
            "client_id={}&client_secret={}&grant_type=client_credentials&scope=https://graph.microsoft.com/.default",
            config.client_id, config.client_secret
        ));
    let access_token = match token_result {
        Ok(resp) => {
            let body: serde_json::Value = resp.into_json()
                .map_err(|e| SourceScanError::Parse(e.to_string()))?;
            body.get("access_token")
                .and_then(|t| t.as_str())
                .ok_or_else(|| SourceScanError::Parse("No access_token in response".into()))?
                .to_string()
        }
        Err(e) => return Err(SourceScanError::Http(Box::new(e))),
    };

    let mut findings = Vec::new();

    // Step 2: List files from the default document library via Graph API.
    let site_id = config.site_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let list_url = format!(
        "https://graph.microsoft.com/v1.0/sites/{}/drive/root/children?$top={}",
        site_id,
        config.max_files.min(100)
    );

    let result = agent
        .get(&list_url)
        .set("Authorization", &format!("Bearer {access_token}"))
        .call();

    if let Ok(resp) = result {
        let body: serde_json::Value = resp.into_json()
            .map_err(|e| SourceScanError::Parse(e.to_string()))?;

        if let Some(files) = body.get("value").and_then(|v| v.as_array()) {
            for file in files {
                if let Some(name) = file.get("name").and_then(|n| n.as_str())
                    && let Some(download_url) = file.get("@microsoft.graph.downloadUrl").and_then(|u| u.as_str())
                {
                    let dl_result = agent
                        .get(download_url)
                        .set("Authorization", &format!("Bearer {access_token}"))
                        .call();
                    if let Ok(dl_resp) = dl_result
                        && let Ok(content) = dl_resp.into_string()
                    {
                        let virtual_path = std::path::PathBuf::from(format!("sharepoint:{name}"));
                        findings.extend(scan_text(&content, &virtual_path, detectors));
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ── Microsoft Teams ───────────────────────────────────────────────────

/// Configuration for a Microsoft Teams scan.
#[derive(Debug, Clone)]
pub struct TeamsScanConfig {
    /// Azure AD client ID for authentication.
    pub client_id: String,
    /// Azure AD client secret.
    pub client_secret: String,
    /// Azure AD tenant ID.
    pub tenant_id: String,
    /// Team ID to scan. If empty, scans all teams.
    pub team_id: Option<String>,
    /// Maximum number of messages to scan per channel.
    pub max_messages: usize,
}

/// Scan Microsoft Teams messages for secrets via the Microsoft Graph API.
pub fn scan_teams(
    config: &TeamsScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();

    // Step 1: Get an access token.
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        config.tenant_id
    );
    let token_result = agent
        .post(&token_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!(
            "client_id={}&client_secret={}&grant_type=client_credentials&scope=https://graph.microsoft.com/.default",
            config.client_id, config.client_secret
        ));
    let access_token = match token_result {
        Ok(resp) => {
            let body: serde_json::Value = resp.into_json()
                .map_err(|e| SourceScanError::Parse(e.to_string()))?;
            body.get("access_token")
                .and_then(|t| t.as_str())
                .ok_or_else(|| SourceScanError::Parse("No access_token in response".into()))?
                .to_string()
        }
        Err(e) => return Err(SourceScanError::Http(Box::new(e))),
    };

    let mut findings = Vec::new();

    // Step 2: List teams (if no team_id specified) or use the provided one.
    let team_ids: Vec<String> = if let Some(tid) = &config.team_id {
        vec![tid.clone()]
    } else {
        let teams_url = "https://graph.microsoft.com/v1.0/me/joinedTeams";
        let result = agent
            .get(teams_url)
            .set("Authorization", &format!("Bearer {access_token}"))
            .call();
        match result {
            Ok(resp) => {
                let body: serde_json::Value = resp.into_json()
                    .map_err(|e| SourceScanError::Parse(e.to_string()))?;
                body.get("value")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| t.get("id").and_then(|i| i.as_str()).map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            Err(_) => Vec::new(),
        }
    };

    // Step 3: For each team, list channels and scan messages.
    for tid in &team_ids {
        let channels_url = format!("https://graph.microsoft.com/v1.0/teams/{tid}/channels");
        let result = agent
            .get(&channels_url)
            .set("Authorization", &format!("Bearer {access_token}"))
            .call();

        if let Ok(resp) = result {
            let body: serde_json::Value = resp.into_json()
                .map_err(|e| SourceScanError::Parse(e.to_string()))?;

            if let Some(channels) = body.get("value").and_then(|v| v.as_array()) {
                for channel in channels {
                    if let Some(ch_id) = channel.get("id").and_then(|i| i.as_str()) {
                        let msgs_url = format!(
                            "https://graph.microsoft.com/v1.0/teams/{tid}/channels/{ch_id}/messages?$top={}",
                            config.max_messages.min(50)
                        );
                        let msg_result = agent
                            .get(&msgs_url)
                            .set("Authorization", &format!("Bearer {access_token}"))
                            .call();

                        if let Ok(msg_resp) = msg_result
                            && let Ok(msg_body) = msg_resp.into_string()
                        {
                            let virtual_path = std::path::PathBuf::from(format!("teams:{tid}/{ch_id}"));
                            findings.extend(scan_text(&msg_body, &virtual_path, detectors));
                        }
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ── PyPI ──────────────────────────────────────────────────────────────

/// Configuration for a PyPI scan.
#[derive(Debug, Clone)]
pub struct PyPIScanConfig {
    /// PyPI API token.
    pub api_token: String,
    /// Package name to scan. If empty, scans the authenticated user's packages.
    pub package_name: Option<String>,
    /// Maximum number of package versions to scan.
    pub max_versions: usize,
}

/// Scan PyPI package metadata for secrets.
pub fn scan_pypi(
    config: &PyPIScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError> {
    let agent = agent();
    let token = &config.api_token;
    let mut findings = Vec::new();

    let packages: Vec<String> = if let Some(pkg) = &config.package_name {
        vec![pkg.clone()]
    } else {
        // List packages owned by the authenticated user.
        let result = agent
            .get("https://pypi.org/pypi/user/info/")
            .set("Authorization", &format!("Bearer {token}"))
            .call();
        match result {
            Ok(resp) => {
                let body: serde_json::Value = resp.into_json()
                    .map_err(|e| SourceScanError::Parse(e.to_string()))?;
                body.get("projects")
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            }
            Err(_) => Vec::new(),
        }
    };

    for pkg in &packages {
        // Fetch package metadata (JSON API).
        let pkg_url = format!("https://pypi.org/pypi/{pkg}/json");
        let result = agent
            .get(&pkg_url)
            .set("Authorization", &format!("Bearer {token}"))
            .call();

        if let Ok(resp) = result
            && let Ok(body) = resp.into_string()
        {
            let virtual_path = std::path::PathBuf::from(format!("pypi:{pkg}/metadata"));
            findings.extend(scan_text(&body, &virtual_path, detectors));
        }

        // Fetch releases info for recent versions.
        let releases_url = format!("https://pypi.org/pypi/{pkg}/json");
        let result = agent
            .get(&releases_url)
            .call();
        if let Ok(resp) = result
            && let Ok(body) = resp.into_string()
        {
            let virtual_path = std::path::PathBuf::from(format!("pypi:{pkg}/releases"));
            findings.extend(scan_text(&body, &virtual_path, detectors));
        }
    }

    Ok(findings)
}

// ── Error type ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SourceScanError {
    Http(Box<ureq::Error>),
    Parse(String),
}

impl std::fmt::Display for SourceScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceScanError::Http(e) => write!(f, "HTTP error: {e}"),
            SourceScanError::Parse(e) => write!(f, "Parse error: {e}"),
        }
    }
}

impl std::error::Error for SourceScanError {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_text_finds_secrets() {
        let detectors = crate::detectors::builtin_detectors();
        let path = std::path::PathBuf::from("test://file");
        let findings = scan_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", &path, &detectors);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_text_no_false_positives_on_empty() {
        let detectors = crate::detectors::builtin_detectors();
        let path = std::path::PathBuf::from("test://file");
        let findings = scan_text("just some normal text", &path, &detectors);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_confluence_config() {
        let config = ConfluenceScanConfig {
            base_url: "https://example.atlassian.net".to_string(),
            api_token: "token".to_string(),
            email: "user@example.com".to_string(),
            space_key: Some("ENG".to_string()),
            max_pages: 50,
        };
        assert_eq!(config.max_pages, 50);
    }

    #[test]
    fn test_slack_config() {
        let config = SlackScanConfig {
            token: "xoxb-test".to_string(),
            channel_ids: vec!["C123".to_string()],
            max_messages: 100,
        };
        assert_eq!(config.max_messages, 100);
    }

    #[test]
    fn test_jira_config() {
        let config = JiraScanConfig {
            base_url: "https://example.atlassian.net".to_string(),
            api_token: "token".to_string(),
            email: "user@example.com".to_string(),
            jql: Some("project = ENG".to_string()),
            max_issues: 25,
        };
        assert_eq!(config.max_issues, 25);
    }

    #[test]
    fn test_postman_config() {
        let config = PostmanScanConfig {
            api_key: "key".to_string(),
            collection_id: Some("col-123".to_string()),
            max_collections: 10,
        };
        assert_eq!(config.max_collections, 10);
    }

    #[test]
    fn test_gerrit_config() {
        let config = GerritScanConfig {
            base_url: "https://gerrit.example.com".to_string(),
            credentials: Some("user:pass".to_string()),
            project: Some("my-project".to_string()),
            max_changes: 50,
        };
        assert_eq!(config.max_changes, 50);
    }

    #[test]
    fn test_buildkite_config() {
        let config = BuildkiteScanConfig {
            api_token: "token".to_string(),
            org: "my-org".to_string(),
            pipeline: Some("my-pipeline".to_string()),
            max_builds: 30,
        };
        assert_eq!(config.max_builds, 30);
    }

    #[test]
    fn test_artifactory_config() {
        let config = ArtifactoryScanConfig {
            base_url: "https://art.example.com".to_string(),
            api_key: "key".to_string(),
            repo: Some("docker-local".to_string()),
            max_files: 100,
        };
        assert_eq!(config.max_files, 100);
    }

    #[test]
    fn test_aws_sm_config() {
        let config = AwsSecretsManagerScanConfig {
            region: "us-east-1".to_string(),
            access_key_id: "AKIA...".to_string(),
            secret_access_key: "secret".to_string(),
            name_prefix: Some("prod/".to_string()),
            max_secrets: 50,
        };
        assert_eq!(config.max_secrets, 50);
    }

    #[test]
    fn test_epoch_to_utc() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let (year, month, day, hour, minute, second) = epoch_to_utc(1704067200);
        assert_eq!(year, 2024);
        assert_eq!(month, 1);
        assert_eq!(day, 1);
        assert_eq!(hour, 0);
        assert_eq!(minute, 0);
        assert_eq!(second, 0);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x10]), "00ff10");
    }

    #[test]
    fn test_hmac_sha256() {
        // Known value: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
        // Verified with Python: hmac.new(b"key", b"The quick brown fox jumps over the lazy dog", hashlib.sha256).hexdigest()
        let result = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        let hex = hex_encode(&result);
        assert_eq!(
            hex,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn test_sha256_sanity() {
        use sha2::{Digest, Sha256};
        let result = Sha256::digest(b"abc");
        let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("simple"), "simple");
    }

    #[test]
    fn test_circleci_artifacts_config() {
        let config = CircleCiArtifactsScanConfig {
            api_token: "CCIPAT_xxx".to_string(),
            project_slug: "github/pledgeandgrow/pledgeguard".to_string(),
            max_builds: 10,
        };
        assert_eq!(config.project_slug, "github/pledgeandgrow/pledgeguard");
        assert_eq!(config.max_builds, 10);
    }

    #[test]
    fn test_travis_ci_config() {
        let config = TravisCiScanConfig {
            api_token: "travis_token".to_string(),
            repo_slug: "pledgeandgrow/pledgeguard".to_string(),
            base_url: None,
            max_builds: 20,
        };
        assert_eq!(config.repo_slug, "pledgeandgrow/pledgeguard");
        assert_eq!(config.max_builds, 20);
    }

    #[test]
    fn test_jenkins_config() {
        let config = JenkinsScanConfig {
            base_url: "https://jenkins.example.com".to_string(),
            username: "admin".to_string(),
            api_token: "jenkins_token".to_string(),
            job_name: Some("pledgeguard".to_string()),
            max_builds: 50,
        };
        assert_eq!(config.base_url, "https://jenkins.example.com");
        assert_eq!(config.max_builds, 50);
    }

    #[test]
    fn test_droneci_config() {
        let config = DroneCiScanConfig {
            base_url: "https://drone.example.com".to_string(),
            api_token: "drone_token".to_string(),
            repo_slug: Some("pledgeandgrow/pledgeguard".to_string()),
            max_builds: 30,
        };
        assert_eq!(config.base_url, "https://drone.example.com");
        assert_eq!(config.max_builds, 30);
    }
}
