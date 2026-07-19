//! GitHub and GitLab API scanning.
//!
//! Scans repositories via their REST APIs without needing a local clone.
//! Fetches file contents from the default branch and scans them for secrets.
//! Requires a personal access token for authentication.

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

/// Configuration for a GitHub API scan.
#[derive(Debug, Clone)]
pub struct GitHubScanConfig {
    /// Repository owner (e.g. "pledgeandgrow").
    pub owner: String,
    /// Repository name (e.g. "pledgeguard").
    pub repo: String,
    /// GitHub personal access token.
    pub token: String,
    /// Optional branch/ref to scan (defaults to default branch).
    pub r#ref: Option<String>,
    /// Maximum number of files to scan (safety limit).
    pub max_files: usize,
}

/// Configuration for a GitLab API scan.
#[derive(Debug, Clone)]
pub struct GitLabScanConfig {
    /// Project ID (numeric) or URL-encoded path (e.g. "group%2Fproject").
    pub project: String,
    /// GitLab personal access token.
    pub token: String,
    /// GitLab instance base URL (defaults to "https://gitlab.com").
    pub base_url: String,
    /// Optional branch/ref to scan.
    pub r#ref: Option<String>,
    /// Maximum number of files to scan.
    pub max_files: usize,
}

/// Scan a GitHub repository via its API.
pub fn scan_github_repo(
    config: &GitHubScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, ApiScanError> {
    let agent = agent();
    let ref_param = config.r#ref.as_deref().unwrap_or("");
    let _ref_query = if ref_param.is_empty() {
        String::new()
    } else {
        format!("?ref={ref_param}")
    };

    // Get the repository tree.
    let tree_url = format!(
        "https://api.github.com/repos/{}/{}/git/trees/HEAD{}",
        config.owner,
        config.repo,
        if ref_param.is_empty() {
            "?recursive=1".to_string()
        } else {
            format!("?ref={ref_param}&recursive=1")
        }
    );

    let resp = agent
        .get(&tree_url)
        .set("Authorization", &format!("token {}", config.token))
        .set("User-Agent", "pledgeguard-secret-scanner")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| ApiScanError::Http(Box::new(e)))?;

    let tree: serde_json::Value = resp
        .into_json()
        .map_err(|e| ApiScanError::Parse(e.to_string()))?;

    let files: Vec<(String, String)> = tree
        .get("tree")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("blob"))
                .filter_map(|e| {
                    let path = e.get("path").and_then(|p| p.as_str())?;
                    let sha = e.get("sha").and_then(|s| s.as_str())?;
                    Some((path.to_string(), sha.to_string()))
                })
                .take(config.max_files)
                .collect()
        })
        .unwrap_or_default();

    let mut findings = Vec::new();
    for (file_path, _sha) in &files {
        // Fetch file contents.
        let content_url = format!(
            "https://api.github.com/repos/{}/{}/contents/{}{}",
            config.owner,
            config.repo,
            file_path,
            if ref_param.is_empty() {
                String::new()
            } else {
                format!("?ref={ref_param}")
            }
        );

        let content_resp = agent
            .get(&content_url)
            .set("Authorization", &format!("token {}", config.token))
            .set("User-Agent", "pledgeguard-secret-scanner")
            .set("Accept", "application/vnd.github+json")
            .call();

        if let Ok(resp) = content_resp
            && let Ok(json) = resp.into_json::<serde_json::Value>()
            && let Some(content_b64) = json.get("content").and_then(|c| c.as_str())
        {
            use base64::Engine;
            if let Ok(decoded) =
                base64::engine::general_purpose::STANDARD.decode(content_b64.trim())
            {
                let text = String::from_utf8_lossy(&decoded);
                let virtual_path = std::path::PathBuf::from(format!(
                    "github:{}/{}#{}",
                    config.owner, config.repo, file_path
                ));
                for (line_idx, line) in text.lines().enumerate() {
                    for detector in detectors {
                        for m in detector.scan_line(line) {
                            findings.push(Finding {
                                rule_id: detector.id().to_string(),
                                description: detector.description().to_string(),
                                severity: detector.severity(),
                                path: virtual_path.clone(),
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
            }
        }
    }

    Ok(findings)
}

/// Scan a GitLab repository via its API.
pub fn scan_gitlab_repo(
    config: &GitLabScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, ApiScanError> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');

    // Get the repository tree.
    let ref_param = config.r#ref.as_deref().unwrap_or("main");
    let tree_url = format!(
        "{}/api/v4/projects/{}/repository/tree?ref={}&recursive=true&per_page=100",
        base, config.project, ref_param
    );

    let resp = agent
        .get(&tree_url)
        .set("Authorization", &format!("Bearer {}", config.token))
        .call()
        .map_err(|e| ApiScanError::Http(Box::new(e)))?;

    let tree: Vec<serde_json::Value> = resp
        .into_json()
        .map_err(|e| ApiScanError::Parse(e.to_string()))?;

    let files: Vec<String> = tree
        .iter()
        .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("blob"))
        .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(String::from))
        .take(config.max_files)
        .collect();

    let mut findings = Vec::new();
    for file_path in &files {
        let encoded_path = urlencoding::encode(file_path);
        let content_url = format!(
            "{}/api/v4/projects/{}/repository/files/{}?ref={}",
            base, config.project, encoded_path, ref_param
        );

        let content_resp = agent
            .get(&content_url)
            .set("Authorization", &format!("Bearer {}", config.token))
            .call();

        if let Ok(resp) = content_resp
            && let Ok(json) = resp.into_json::<serde_json::Value>()
            && let Some(content_b64) = json.get("content").and_then(|c| c.as_str())
        {
            use base64::Engine;
            if let Ok(decoded) =
                base64::engine::general_purpose::STANDARD.decode(content_b64.trim())
            {
                let text = String::from_utf8_lossy(&decoded);
                let virtual_path =
                    std::path::PathBuf::from(format!("gitlab:{}#{}", config.project, file_path));
                for (line_idx, line) in text.lines().enumerate() {
                    for detector in detectors {
                        for m in detector.scan_line(line) {
                            findings.push(Finding {
                                rule_id: detector.id().to_string(),
                                description: detector.description().to_string(),
                                severity: detector.severity(),
                                path: virtual_path.clone(),
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
            }
        }
    }

    Ok(findings)
}

#[derive(Debug)]
pub enum ApiScanError {
    Http(Box<ureq::Error>),
    Parse(String),
}

impl std::fmt::Display for ApiScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiScanError::Http(e) => write!(f, "HTTP error: {e}"),
            ApiScanError::Parse(e) => write!(f, "Parse error: {e}"),
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("src/main.rs"), "src%2Fmain.rs");
        assert_eq!(urlencoding::encode("group/project"), "group%2Fproject");
    }

    #[test]
    fn test_github_config_defaults() {
        let config = GitHubScanConfig {
            owner: "test".to_string(),
            repo: "repo".to_string(),
            token: "token".to_string(),
            r#ref: None,
            max_files: 100,
        };
        assert_eq!(config.owner, "test");
        assert_eq!(config.max_files, 100);
    }

    #[test]
    fn test_gitlab_config_defaults() {
        let config = GitLabScanConfig {
            project: "42".to_string(),
            token: "token".to_string(),
            base_url: "https://gitlab.com".to_string(),
            r#ref: None,
            max_files: 100,
        };
        assert_eq!(config.base_url, "https://gitlab.com");
    }
}
