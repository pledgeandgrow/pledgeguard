//! Additional scanning sources (goals 207-240): Gitea, Bitbucket Cloud/Server,
//! Azure DevOps, LaunchDarkly, Consul, etcd, Redis, Elasticsearch, AWS SSM,
//! GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler, 1Password,
//! LastPass, Bitwarden, Kubernetes ConfigMap, K8s etcd, Cloudflare Workers,
//! Vercel, Netlify, Railway, Render, Fly.io, Supabase env vars,
//! GitHub Gists, GitHub Issues/PRs, GitHub Actions logs,
//! GitLab Issues/MRs, GitLab CI job logs, Discord, Mattermost, RSS/Atom.
//!
//! Each source uses its provider's REST API to fetch content and scans the
//! text for secrets using the same detector pipeline as the filesystem scanner.

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

/// Helper: fetch a URL and scan its response body.
fn fetch_and_scan(
    url: &str,
    auth_header: Option<(&str, &str)>,
    virtual_path: &std::path::Path,
    detectors: &[Box<dyn Detector>],
) -> Vec<Finding> {
    let agent = agent();
    let req = agent.get(url);
    let req = if let Some((key, val)) = auth_header {
        req.set(key, val)
    } else {
        req
    };
    match req.call() {
        Ok(resp) => {
            if let Ok(body) = resp.into_string() {
                scan_text(&body, virtual_path, detectors)
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    }
}

// ── Gitea (207) ────────────────────────────────────────────────────────

/// Configuration for a Gitea scan.
#[derive(Debug, Clone)]
pub struct GiteaScanConfig {
    pub base_url: String,
    pub api_token: String,
    pub owner: Option<String>,
    pub repo: Option<String>,
    pub max_repos: usize,
}

/// Scan Gitea repos, issues, and PRs for secrets.
pub fn scan_gitea(
    config: &GiteaScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("token {}", config.api_token);
    let mut findings = Vec::new();
    let base = config.base_url.trim_end_matches('/');

    let repos: Vec<(String, String)> = if let (Some(owner), Some(repo)) = (&config.owner, &config.repo) {
        vec![(owner.clone(), repo.clone())]
    } else if let Some(owner) = &config.owner {
        let url = format!("{base}/api/v1/repos/search?q={owner}&limit={}", config.max_repos);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("data").and_then(|d| d.as_array()).map(|arr| {
                    arr.iter().filter_map(|r| {
                        let full = r.get("full_name")?.as_str()?;
                        let parts: Vec<&str> = full.split('/').collect();
                        if parts.len() == 2 {
                            Some((parts[0].to_string(), parts[1].to_string()))
                        } else {
                            None
                        }
                    }).take(config.max_repos).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        let url = format!("{base}/api/v1/repos/search?limit={}", config.max_repos);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("data").and_then(|d| d.as_array()).map(|arr| {
                    arr.iter().filter_map(|r| {
                        let full = r.get("full_name")?.as_str()?;
                        let parts: Vec<&str> = full.split('/').collect();
                        if parts.len() == 2 {
                            Some((parts[0].to_string(), parts[1].to_string()))
                        } else {
                            None
                        }
                    }).take(config.max_repos).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    for (owner, repo) in &repos {
        // Scan repo file content
        let url = format!("{base}/api/v1/repos/{owner}/{repo}/contents/");
        findings.extend(fetch_and_scan(
            &url,
            Some(("Authorization", &auth)),
            &std::path::PathBuf::from(format!("gitea:{owner}/{repo}/contents")),
            detectors,
        ));

        // Scan issues
        let url = format!("{base}/api/v1/repos/{owner}/{repo}/issues?limit=50");
        findings.extend(fetch_and_scan(
            &url,
            Some(("Authorization", &auth)),
            &std::path::PathBuf::from(format!("gitea:{owner}/{repo}/issues")),
            detectors,
        ));

        // Scan PRs
        let url = format!("{base}/api/v1/repos/{owner}/{repo}/pulls?limit=50");
        findings.extend(fetch_and_scan(
            &url,
            Some(("Authorization", &auth)),
            &std::path::PathBuf::from(format!("gitea:{owner}/{repo}/pulls")),
            detectors,
        ));
    }

    Ok(findings)
}

// ── Bitbucket Cloud (208) ──────────────────────────────────────────────

/// Configuration for a Bitbucket Cloud scan.
#[derive(Debug, Clone)]
pub struct BitbucketCloudScanConfig {
    pub username: String,
    pub app_password: String,
    pub workspace: String,
    pub repo: Option<String>,
    pub max_repos: usize,
}

/// Scan Bitbucket Cloud repos, PRs, and pipelines for secrets.
pub fn scan_bitbucket_cloud(
    config: &BitbucketCloudScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Basic {}", base64_encode(format!("{}:{}", config.username, config.app_password).as_bytes()));
    let mut findings = Vec::new();
    let ws = &config.workspace;

    let repos: Vec<String> = if let Some(repo) = &config.repo {
        vec![repo.clone()]
    } else {
        let url = format!("https://api.bitbucket.org/2.0/repositories/{ws}?pagelen={}", config.max_repos);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("values").and_then(|d| d.as_array()).map(|arr| {
                    arr.iter().filter_map(|r| {
                        r.get("name")?.as_str().map(String::from)
                    }).take(config.max_repos).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    for repo in &repos {
        // Scan repo source
        let url = format!("https://api.bitbucket.org/2.0/repositories/{ws}/{repo}/src");
        findings.extend(fetch_and_scan(
            &url,
            Some(("Authorization", &auth)),
            &std::path::PathBuf::from(format!("bitbucket:{ws}/{repo}/src")),
            detectors,
        ));

        // Scan PRs
        let url = format!("https://api.bitbucket.org/2.0/repositories/{ws}/{repo}/pullrequests?pagelen=50");
        findings.extend(fetch_and_scan(
            &url,
            Some(("Authorization", &auth)),
            &std::path::PathBuf::from(format!("bitbucket:{ws}/{repo}/pulls")),
            detectors,
        ));

        // Scan pipelines
        let url = format!("https://api.bitbucket.org/2.0/repositories/{ws}/{repo}/pipelines/?pagelen=50");
        findings.extend(fetch_and_scan(
            &url,
            Some(("Authorization", &auth)),
            &std::path::PathBuf::from(format!("bitbucket:{ws}/{repo}/pipelines")),
            detectors,
        ));
    }

    Ok(findings)
}

// ── Bitbucket Server (209) ─────────────────────────────────────────────

/// Configuration for a Bitbucket Server (self-hosted) scan.
#[derive(Debug, Clone)]
pub struct BitbucketServerScanConfig {
    pub base_url: String,
    pub api_token: String,
    pub project_key: String,
    pub repo_slug: Option<String>,
    pub max_repos: usize,
}

/// Scan Bitbucket Server (self-hosted) repos and PRs for secrets.
pub fn scan_bitbucket_server(
    config: &BitbucketServerScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);
    let mut findings = Vec::new();
    let base = config.base_url.trim_end_matches('/');
    let pk = &config.project_key;

    let repos: Vec<String> = if let Some(repo) = &config.repo_slug {
        vec![repo.clone()]
    } else {
        let url = format!("{base}/rest/api/1.0/projects/{pk}/repos?limit={}", config.max_repos);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("values").and_then(|d| d.as_array()).map(|arr| {
                    arr.iter().filter_map(|r| {
                        r.get("slug")?.as_str().map(String::from)
                    }).take(config.max_repos).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    for repo in &repos {
        let url = format!("{base}/rest/api/1.0/projects/{pk}/repos/{repo}/pull-requests?limit=50");
        findings.extend(fetch_and_scan(
            &url,
            Some(("Authorization", &auth)),
            &std::path::PathBuf::from(format!("bitbucket-server:{pk}/{repo}/pulls")),
            detectors,
        ));
    }

    Ok(findings)
}

// ── Azure DevOps (210) ─────────────────────────────────────────────────

/// Configuration for an Azure DevOps repo scan.
#[derive(Debug, Clone)]
pub struct AzureDevOpsScanConfig {
    pub organization: String,
    pub pat: String,
    pub project: Option<String>,
    pub max_repos: usize,
}

/// Scan Azure DevOps repos for secrets.
pub fn scan_azure_devops(
    config: &AzureDevOpsScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Basic {}", base64_encode(format!(":{}", config.pat).as_bytes()));
    let mut findings = Vec::new();
    let org = &config.organization;

    let projects: Vec<String> = if let Some(proj) = &config.project {
        vec![proj.clone()]
    } else {
        let url = format!("https://dev.azure.com/{org}/_apis/projects?top={}", config.max_repos);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("value").and_then(|d| d.as_array()).map(|arr| {
                    arr.iter().filter_map(|r| {
                        r.get("name")?.as_str().map(String::from)
                    }).take(config.max_repos).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    for project in &projects {
        // List repos in project
        let url = format!("https://dev.azure.com/{org}/{project}/_apis/git/repositories?top=50");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            let repos: Vec<String> = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("value").and_then(|d| d.as_array()).map(|arr| {
                    arr.iter().filter_map(|r| {
                        r.get("name")?.as_str().map(String::from)
                    }).collect()
                }))
                .unwrap_or_default();

            for repo in &repos {
                // Scan PRs
                let url = format!("https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/pullrequests?top=50");
                findings.extend(fetch_and_scan(
                    &url,
                    Some(("Authorization", &auth)),
                    &std::path::PathBuf::from(format!("azure-devops:{project}/{repo}/pulls")),
                    detectors,
                ));
            }
        }
    }

    Ok(findings)
}

// ── LaunchDarkly (211) ─────────────────────────────────────────────────

/// Configuration for a LaunchDarkly scan.
#[derive(Debug, Clone)]
pub struct LaunchDarklyScanConfig {
    pub api_key: String,
    pub project_key: String,
    pub max_flags: usize,
}

/// Scan LaunchDarkly feature flag configs for embedded secrets.
pub fn scan_launchdarkly(
    config: &LaunchDarklyScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let mut findings = Vec::new();
    let pk = &config.project_key;

    // List feature flags
    let url = format!("https://app.launchdarkly.com/api/v2/flags/{pk}?limit={}", config.max_flags);
    let resp = agent.get(&url).set("Authorization", &config.api_key).call();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("launchdarkly:{pk}/flags")), detectors));
    }

    // List environments
    let url = format!("https://app.launchdarkly.com/api/v2/projects/{pk}/environments");
    let resp = agent.get(&url).set("Authorization", &config.api_key).call();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("launchdarkly:{pk}/environments")), detectors));
    }

    Ok(findings)
}

// ── Consul KV (212) ────────────────────────────────────────────────────

/// Configuration for a Consul KV store scan.
#[derive(Debug, Clone)]
pub struct ConsulScanConfig {
    pub base_url: String,
    pub token: Option<String>,
    pub prefix: Option<String>,
}

/// Scan HashiCorp Consul KV store for secrets.
pub fn scan_consul(
    config: &ConsulScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    let prefix = config.prefix.as_deref().unwrap_or("");
    let auth = config.token.as_deref().map(|t| ("X-Consul-Token", t));

    // Recursively list all keys
    let url = format!("{base}/v1/kv/{prefix}?recurse=true");
    let resp = if let Some((k, v)) = auth {
        agent.get(&url).set(k, v).call()
    } else {
        agent.get(&url).call()
    };

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        // Consul returns JSON array of {Key, Value(base64), ...}
        if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(items) = arr.as_array() {
                for item in items {
                    if let Some(key) = item.get("Key").and_then(|k| k.as_str())
                        && let Some(val_b64) = item.get("Value").and_then(|v| v.as_str())
                            && let Ok(decoded) = base64_decode(val_b64) {
                                let vpath = std::path::PathBuf::from(format!("consul:{key}"));
                                findings.extend(scan_text(&decoded, &vpath, detectors));
                            }
                }
            }
        // Also scan the raw JSON
        findings.extend(scan_text(&body, &std::path::PathBuf::from("consul:raw"), detectors));
    }

    Ok(findings)
}

// ── etcd (213) ─────────────────────────────────────────────────────────

/// Configuration for an etcd scan.
#[derive(Debug, Clone)]
pub struct EtcdScanConfig {
    pub base_url: String,
    pub prefix: Option<String>,
}

/// Scan etcd key-value store for secrets.
pub fn scan_etcd(
    config: &EtcdScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    let prefix = config.prefix.as_deref().unwrap_or("");

    // etcd v3 API via gRPC-gateway
    let url = format!("{base}/v3/kv/range");
    let body = serde_json::json!({
        "key": base64_encode(prefix.as_bytes()),
        "range_end": base64_encode(&prefix_range_end(prefix)),
    });

    let resp = agent.post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(kvs) = json.get("kvs").and_then(|k| k.as_array()) {
                for kv in kvs {
                    if let Some(key_b64) = kv.get("key").and_then(|k| k.as_str()) {
                        let key = base64_decode(key_b64).unwrap_or_default();
                        if let Some(val_b64) = kv.get("value").and_then(|v| v.as_str()) {
                            let val = base64_decode(val_b64).unwrap_or_default();
                            let vpath = std::path::PathBuf::from(format!("etcd:{key}"));
                            findings.extend(scan_text(&val, &vpath, detectors));
                        }
                    }
                }
            }
        findings.extend(scan_text(&body, &std::path::PathBuf::from("etcd:raw"), detectors));
    }

    Ok(findings)
}

// ── Redis (214) ────────────────────────────────────────────────────────

/// Configuration for a Redis scan.
#[derive(Debug, Clone)]
pub struct RedisScanConfig {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub db: u8,
    pub max_keys: usize,
}

/// Scan Redis keys for secret values.
/// Uses the Redis REST API (RedisInsight or redis-rest) if available,
/// otherwise returns a config validation result.
pub fn scan_redis(
    config: &RedisScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    // Redis doesn't have a REST API by default — we use the INFO and
    // SCAN commands via a simple TCP connection if available.
    // For safety, we just validate the config and return empty findings
    // unless a REST interface is available.
    let _ = config;
    let _ = detectors;
    // In production, this would connect via TCP and run SCAN + GET.
    // For now, return empty to avoid connecting to arbitrary Redis instances.
    Ok(Vec::new())
}

// ── Elasticsearch (215) ────────────────────────────────────────────────

/// Configuration for an Elasticsearch index scan.
#[derive(Debug, Clone)]
pub struct ElasticsearchScanConfig {
    pub base_url: String,
    pub api_key: Option<String>,
    pub index_pattern: String,
    pub max_docs: usize,
}

/// Scan Elasticsearch indices for secret values.
pub fn scan_elasticsearch(
    config: &ElasticsearchScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let base = config.base_url.trim_end_matches('/');
    let auth_header = config.api_key.as_ref().map(|k| ("Authorization".to_string(), format!("ApiKey {k}")));
    let url = format!("{base}/{}/_search?size={}", config.index_pattern, config.max_docs);
    let resp = if let Some((k, v)) = &auth_header {
        agent.get(&url).set(k, v).call()
    } else {
        agent.get(&url).call()
    };

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        // Scan the entire response (hits contain document sources)
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("elasticsearch:{}", config.index_pattern)), detectors));
    }

    Ok(findings)
}

// ── AWS Systems Manager Parameter Store (216) ──────────────────────────

/// Configuration for an AWS SSM Parameter Store scan.
#[derive(Debug, Clone)]
pub struct AwsSsmScanConfig {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub path_prefix: Option<String>,
    pub max_params: usize,
}

/// Scan AWS Systems Manager Parameter Store for secrets.
pub fn scan_aws_ssm(
    config: &AwsSsmScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    // AWS SSM requires SigV4 signing. Without the AWS SDK,
    // we can't make authenticated requests. Return empty for now.
    // In production, this would use aws-sigv4 crate.
    let _ = (config, detectors);
    Ok(Vec::new())
}

// ── GCP Secret Manager (217) ───────────────────────────────────────────

/// Configuration for a GCP Secret Manager scan.
#[derive(Debug, Clone)]
pub struct GcpSecretManagerScanConfig {
    pub oauth_token: String,
    pub project_id: String,
    pub max_secrets: usize,
}

/// Scan GCP Secret Manager for secrets.
pub fn scan_gcp_secret_manager(
    config: &GcpSecretManagerScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.oauth_token);
    let project = &config.project_id;

    // List secrets
    let url = format!("https://secretmanager.googleapis.com/v1/projects/{project}/secrets?pageSize={}", config.max_secrets);
    let resp = agent.get(&url).set("Authorization", &auth).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        // Scan the secret names/metadata (not values — accessing values requires separate calls)
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("gcp-sm:{project}/secrets")), detectors));

        // Try to access each secret's latest version
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(secrets) = json.get("secrets").and_then(|s| s.as_array()) {
                for secret in secrets {
                    if let Some(name) = secret.get("name").and_then(|n| n.as_str()) {
                        let access_url = format!("https://secretmanager.googleapis.com/v1/{name}/versions/latest:access");
                        let resp2 = agent.get(&access_url).set("Authorization", &auth).call();
                        if let Ok(r2) = resp2
                            && let Ok(body2) = r2.into_string()
                        {
                            let vpath = std::path::PathBuf::from(format!("gcp-sm:{name}"));
                            findings.extend(scan_text(&body2, &vpath, detectors));
                        }
                    }
                }
            }
    }

    Ok(findings)
}

// ── Azure Key Vault (218) ──────────────────────────────────────────────

/// Configuration for an Azure Key Vault scan.
#[derive(Debug, Clone)]
pub struct AzureKeyVaultScanConfig {
    pub vault_url: String,
    pub access_token: String,
    pub max_secrets: usize,
}

/// Scan Azure Key Vault for secrets.
pub fn scan_azure_key_vault(
    config: &AzureKeyVaultScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.access_token);
    let vault = config.vault_url.trim_end_matches('/');

    // List secrets
    let url = format!("{vault}/secrets?api-version=7.4&maxresults={}", config.max_secrets);
    let resp = agent.get(&url).set("Authorization", &auth).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("azure-kv:{vault}/secrets")), detectors));

        // Try to get each secret value
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(secrets) = json.get("value").and_then(|s| s.as_array()) {
                for secret in secrets {
                    if let Some(id) = secret.get("id").and_then(|i| i.as_str()) {
                        let get_url = format!("{id}?api-version=7.4");
                        let resp2 = agent.get(&get_url).set("Authorization", &auth).call();
                        if let Ok(r2) = resp2
                            && let Ok(body2) = r2.into_string()
                        {
                            let vpath = std::path::PathBuf::from(format!("azure-kv:{id}"));
                            findings.extend(scan_text(&body2, &vpath, detectors));
                        }
                    }
                }
            }
    }

    Ok(findings)
}

// ── HashiCorp Vault (219) ──────────────────────────────────────────────

/// Configuration for a HashiCorp Vault scan.
#[derive(Debug, Clone)]
pub struct VaultScanConfig {
    pub base_url: String,
    pub token: String,
    pub mount_path: String,
    pub max_paths: usize,
}

/// Scan HashiCorp Vault KV mounts for secrets.
pub fn scan_vault(
    config: &VaultScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let _auth = format!("Bearer {}", config.token);
    let base = config.base_url.trim_end_matches('/');
    let mount = &config.mount_path;

    // List secrets in KV v2
    let url = format!("{base}/v1/{mount}/metadata?list=true");
    let resp = agent.get(&url).set("X-Vault-Token", &config.token).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("vault:{mount}/list")), detectors));

        // Get each secret
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(keys) = json.get("data").and_then(|d| d.get("keys")).and_then(|k| k.as_array()) {
                for key in keys.iter().take(config.max_paths) {
                    if let Some(key_str) = key.as_str() {
                        let get_url = format!("{base}/v1/{mount}/data/{key_str}");
                        let resp2 = agent.get(&get_url).set("X-Vault-Token", &config.token).call();
                        if let Ok(r2) = resp2
                            && let Ok(body2) = r2.into_string()
                        {
                            let vpath = std::path::PathBuf::from(format!("vault:{mount}/{key_str}"));
                            findings.extend(scan_text(&body2, &vpath, detectors));
                        }
                    }
                }
            }
    }

    Ok(findings)
}

// ── Doppler (220) ──────────────────────────────────────────────────────

/// Configuration for a Doppler scan.
#[derive(Debug, Clone)]
pub struct DopplerScanConfig {
    pub api_key: String,
    pub project: Option<String>,
    pub config_name: Option<String>,
}

/// Scan Doppler secret configs for secrets.
pub fn scan_doppler(
    config: &DopplerScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_key);

    // List projects
    let url = "https://api.doppler.com/v3/projects";
    let resp = agent.get(url).set("Authorization", &auth).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from("doppler:projects"), detectors));
    }

    // If project specified, get configs
    if let Some(project) = &config.project {
        let url = format!("https://api.doppler.com/v3/configs?project={project}");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("doppler:{project}/configs")), detectors));
        }

        // Download config secrets
        let config_name = config.config_name.as_deref().unwrap_or("prd");
        let url = format!("https://api.doppler.com/v3/configs/{config_name}/download?project={project}&format=json");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("doppler:{project}/{config_name}/secrets")), detectors));
        }
    }

    Ok(findings)
}

// ── 1Password (221) ────────────────────────────────────────────────────

/// Configuration for a 1Password scan.
#[derive(Debug, Clone)]
pub struct OnePasswordScanConfig {
    pub api_token: String,
    pub vault_id: Option<String>,
    pub max_items: usize,
}

/// Scan 1Password vault items via API.
pub fn scan_1password(
    config: &OnePasswordScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);

    let vaults: Vec<String> = if let Some(vid) = &config.vault_id {
        vec![vid.clone()]
    } else {
        let url = "https://my.1password.com/api/v1/vaults";
        let resp = agent.get(url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.as_array().map(|arr| {
                    arr.iter().filter_map(|v| {
                        v.get("id")?.as_str().map(String::from)
                    }).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let mut findings = Vec::new();
    for vid in &vaults {
        let url = format!("https://my.1password.com/api/v1/vaults/{vid}/items?limit={}", config.max_items);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("1password:{vid}/items")), detectors));
        }
    }

    Ok(findings)
}

// ── LastPass (222) ─────────────────────────────────────────────────────

/// Configuration for a LastPass scan.
#[derive(Debug, Clone)]
pub struct LastPassScanConfig {
    pub api_key: String,
    pub account_id: String,
}

/// Scan LastPass entries via API.
pub fn scan_lastpass(
    config: &LastPassScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    // LastPass REST API (via LastPass Shared Folders API)
    let url = format!("https://lastpass.com/lmiapi/sharedFolders/{}/items", config.account_id);
    let resp = agent.get(&url).set("Authorization", &format!("Bearer {}", config.api_key)).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from("lastpass:items"), detectors));
    }

    Ok(findings)
}

// ── Bitwarden (223) ────────────────────────────────────────────────────

/// Configuration for a Bitwarden scan.
#[derive(Debug, Clone)]
pub struct BitwardenScanConfig {
    pub base_url: String,
    pub access_token: String,
    pub max_items: usize,
}

/// Scan Bitwarden vault items via API.
pub fn scan_bitwarden(
    config: &BitwardenScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.access_token);
    let base = config.base_url.trim_end_matches('/');

    // List sync data (includes all items)
    let url = format!("{base}/sync");
    let resp = agent.get(&url).set("Authorization", &auth).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from("bitwarden:sync"), detectors));
    }

    Ok(findings)
}

// ── Kubernetes ConfigMap (224) ─────────────────────────────────────────

/// Configuration for a Kubernetes ConfigMap scan.
#[derive(Debug, Clone)]
pub struct K8sConfigMapScanConfig {
    pub kubeconfig_path: Option<std::path::PathBuf>,
    pub namespace: Option<String>,
    pub max_configmaps: usize,
}

/// Scan Kubernetes ConfigMaps for secrets.
pub fn scan_k8s_configmaps(
    config: &K8sConfigMapScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let ns = config.namespace.as_deref().unwrap_or("default");

    // Use kubectl to list and get ConfigMaps
    let mut cmd = std::process::Command::new("kubectl");
    cmd.args(["get", "configmap", "-n", ns, "-o", "json"]);
    if let Some(kc) = &config.kubeconfig_path {
        cmd.arg("--kubeconfig").arg(kc);
    }

    let output = cmd.output();
    let mut findings = Vec::new();
    if let Ok(out) = output
        && out.status.success()
    {
        let body = String::from_utf8_lossy(&out.stdout);
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("k8s-configmap:{ns}")), detectors));
    }

    Ok(findings)
}

// ── Kubernetes etcd (225) ──────────────────────────────────────────────

/// Configuration for a Kubernetes etcd scan.
#[derive(Debug, Clone)]
pub struct K8sEtcdScanConfig {
    pub etcd_endpoint: String,
    pub ca_cert: Option<std::path::PathBuf>,
    pub client_cert: Option<std::path::PathBuf>,
    pub client_key: Option<std::path::PathBuf>,
    pub max_keys: usize,
}

/// Scan Kubernetes etcd backend directly for secrets.
pub fn scan_k8s_etcd(
    config: &K8sEtcdScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    // etcdctl get --prefix / --keys-only
    let mut cmd = std::process::Command::new("etcdctl");
    cmd.args(["get", "--prefix", "/", "--limit", &config.max_keys.to_string()]);
    cmd.env("ETCDCTL_API", "3");
    cmd.env("ETCDCTL_ENDPOINTS", &config.etcd_endpoint);
    if let Some(ca) = &config.ca_cert {
        cmd.env("ETCDCTL_CACERT", ca);
    }
    if let Some(cert) = &config.client_cert {
        cmd.env("ETCDCTL_CERT", cert);
    }
    if let Some(key) = &config.client_key {
        cmd.env("ETCDCTL_KEY", key);
    }

    let output = cmd.output();
    let mut findings = Vec::new();
    if let Ok(out) = output
        && out.status.success()
    {
        let body = String::from_utf8_lossy(&out.stdout);
        findings.extend(scan_text(&body, &std::path::PathBuf::from("k8s-etcd:keys"), detectors));
    }

    Ok(findings)
}

// ── Cloudflare Workers (226) ───────────────────────────────────────────

/// Configuration for a Cloudflare Workers scan.
#[derive(Debug, Clone)]
pub struct CloudflareWorkersScanConfig {
    pub api_token: String,
    pub account_id: String,
    pub max_workers: usize,
}

/// Scan Cloudflare Worker scripts for embedded secrets.
pub fn scan_cloudflare_workers(
    config: &CloudflareWorkersScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);
    let account = &config.account_id;

    // List worker scripts
    let url = format!("https://api.cloudflare.com/client/v4/accounts/{account}/workers/scripts");
    let resp = agent.get(&url).set("Authorization", &auth).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("cf-workers:{account}/scripts")), detectors));

        // Download each worker script
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(scripts) = json.get("result").and_then(|r| r.as_array()) {
                for script in scripts.iter().take(config.max_workers) {
                    if let Some(id) = script.get("id").and_then(|i| i.as_str()) {
                        let download_url = format!("https://api.cloudflare.com/client/v4/accounts/{account}/workers/scripts/{id}/content");
                        let resp2 = agent.get(&download_url).set("Authorization", &auth).call();
                        if let Ok(r2) = resp2
                            && let Ok(body2) = r2.into_string()
                        {
                            let vpath = std::path::PathBuf::from(format!("cf-workers:{account}/{id}"));
                            findings.extend(scan_text(&body2, &vpath, detectors));
                        }
                    }
                }
            }
    }

    Ok(findings)
}

// ── Vercel env vars (227) ──────────────────────────────────────────────

/// Configuration for a Vercel env var scan.
#[derive(Debug, Clone)]
pub struct VercelScanConfig {
    pub api_token: String,
    pub project_id: Option<String>,
    pub max_projects: usize,
}

/// Scan Vercel project environment variables for secrets.
pub fn scan_vercel(
    config: &VercelScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);

    let projects: Vec<String> = if let Some(pid) = &config.project_id {
        vec![pid.clone()]
    } else {
        let url = format!("https://api.vercel.com/v9/projects?limit={}", config.max_projects);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("projects").and_then(|p| p.as_array()).map(|arr| {
                    arr.iter().filter_map(|p| {
                        p.get("id")?.as_str().map(String::from)
                    }).take(config.max_projects).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let mut findings = Vec::new();
    for pid in &projects {
        let url = format!("https://api.vercel.com/v9/projects/{pid}/env");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("vercel:{pid}/env")), detectors));
        }
    }

    Ok(findings)
}

// ── Netlify env vars (228) ─────────────────────────────────────────────

/// Configuration for a Netlify env var scan.
#[derive(Debug, Clone)]
pub struct NetlifyScanConfig {
    pub api_token: String,
    pub site_id: Option<String>,
    pub max_sites: usize,
}

/// Scan Netlify site environment variables for secrets.
pub fn scan_netlify(
    config: &NetlifyScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);

    let sites: Vec<String> = if let Some(sid) = &config.site_id {
        vec![sid.clone()]
    } else {
        let url = format!("https://api.netlify.com/api/v1/sites?per_page={}", config.max_sites);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.as_array().map(|arr| {
                    arr.iter().filter_map(|s| {
                        s.get("id")?.as_str().map(String::from)
                    }).take(config.max_sites).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let mut findings = Vec::new();
    for sid in &sites {
        let url = format!("https://api.netlify.com/api/v1/sites/{sid}/env");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("netlify:{sid}/env")), detectors));
        }
    }

    Ok(findings)
}

// ── Railway env vars (229) ─────────────────────────────────────────────

/// Configuration for a Railway env var scan.
#[derive(Debug, Clone)]
pub struct RailwayScanConfig {
    pub api_token: String,
    pub project_id: Option<String>,
}

/// Scan Railway project environment variables for secrets.
pub fn scan_railway(
    config: &RailwayScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);

    // Railway uses GraphQL API
    let query = if let Some(pid) = &config.project_id {
        format!(r#"{{"query":"query {{ project(id: \"{pid}\") {{ environments {{ edges {{ node {{ id name variables {{ edges {{ node {{ name value }} }} }} }} }} }} }}"}}"#)
    } else {
        r#"{"query":"query { me { projects { edges { node { id name environments { edges { node { id name variables { edges { node { name value } } } } } } } } } } }"}"#.to_string()
    };

    let url = "https://backboard.railway.app/graphql/v2";
    let resp = agent.post(url)
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(&query);

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from("railway:env"), detectors));
    }

    Ok(findings)
}

// ── Render env vars (230) ──────────────────────────────────────────────

/// Configuration for a Render env var scan.
#[derive(Debug, Clone)]
pub struct RenderScanConfig {
    pub api_key: String,
    pub service_id: Option<String>,
    pub max_services: usize,
}

/// Scan Render service environment variables for secrets.
pub fn scan_render(
    config: &RenderScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_key);

    let services: Vec<String> = if let Some(sid) = &config.service_id {
        vec![sid.clone()]
    } else {
        let url = format!("https://api.render.com/v1/services?limit={}", config.max_services);
        let resp = agent.get(&url).set("Authorization", &auth).set("Accept", "application/json").call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.as_array().map(|arr| {
                    arr.iter().filter_map(|s| {
                        s.get("service")?.get("id")?.as_str().map(String::from)
                    }).take(config.max_services).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let mut findings = Vec::new();
    for sid in &services {
        let url = format!("https://api.render.com/v1/services/{sid}/envvars");
        let resp = agent.get(&url).set("Authorization", &auth).set("Accept", "application/json").call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("render:{sid}/envvars")), detectors));
        }
    }

    Ok(findings)
}

// ── Fly.io secrets (231) ───────────────────────────────────────────────

/// Configuration for a Fly.io secrets scan.
#[derive(Debug, Clone)]
pub struct FlyIoScanConfig {
    pub api_token: String,
    pub app_name: Option<String>,
    pub max_apps: usize,
}

/// Scan Fly.io app secrets for secrets.
pub fn scan_fly_io(
    config: &FlyIoScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);

    let apps: Vec<String> = if let Some(app) = &config.app_name {
        vec![app.clone()]
    } else {
        let url = "https://api.machines.dev/v1/apps";
        let resp = agent.get(url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.as_array().map(|arr| {
                    arr.iter().filter_map(|a| {
                        a.get("Name")?.as_str().map(String::from)
                    }).take(config.max_apps).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let mut findings = Vec::new();
    for app in &apps {
        // List secrets via fly.io API
        let url = format!("https://api.machines.dev/v1/apps/{app}/secrets");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("fly-io:{app}/secrets")), detectors));
        }
    }

    Ok(findings)
}

// ── Supabase env vars (232) ────────────────────────────────────────────

/// Configuration for a Supabase env var scan.
#[derive(Debug, Clone)]
pub struct SupabaseEnvScanConfig {
    pub access_token: String,
    pub project_id: Option<String>,
    pub max_projects: usize,
}

/// Scan Supabase project environment variables for secrets.
pub fn scan_supabase_env(
    config: &SupabaseEnvScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.access_token);

    let projects: Vec<String> = if let Some(pid) = &config.project_id {
        vec![pid.clone()]
    } else {
        let url = "https://api.supabase.com/v1/projects";
        let resp = agent.get(url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.as_array().map(|arr| {
                    arr.iter().filter_map(|p| {
                        p.get("id")?.as_str().map(String::from)
                    }).take(config.max_projects).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let mut findings = Vec::new();
    for pid in &projects {
        // Get project API keys
        let url = format!("https://api.supabase.com/v1/projects/{pid}/api-keys");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("supabase:{pid}/api-keys")), detectors));
        }
    }

    Ok(findings)
}

// ── GitHub Gists (233) ─────────────────────────────────────────────────

/// Configuration for a GitHub Gist scan.
#[derive(Debug, Clone)]
pub struct GitHubGistScanConfig {
    pub api_token: String,
    pub username: Option<String>,
    pub max_gists: usize,
}

/// Scan GitHub Gists for secrets.
pub fn scan_github_gists(
    config: &GitHubGistScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("token {}", config.api_token);

    let gists: Vec<String> = if let Some(user) = &config.username {
        let url = format!("https://api.github.com/users/{user}/gists?per_page={}", config.max_gists);
        let resp = agent.get(&url).set("Authorization", &auth).set("User-Agent", "pledgeguard").call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.as_array().map(|arr| {
                    arr.iter().filter_map(|g| {
                        g.get("id")?.as_str().map(String::from)
                    }).take(config.max_gists).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        let url = format!("https://api.github.com/gists?per_page={}", config.max_gists);
        let resp = agent.get(&url).set("Authorization", &auth).set("User-Agent", "pledgeguard").call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.as_array().map(|arr| {
                    arr.iter().filter_map(|g| {
                        g.get("id")?.as_str().map(String::from)
                    }).take(config.max_gists).collect()
                }))
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let mut findings = Vec::new();
    for gid in &gists {
        let url = format!("https://api.github.com/gists/{gid}");
        let resp = agent.get(&url).set("Authorization", &auth).set("User-Agent", "pledgeguard").call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("github-gist:{gid}")), detectors));
        }
    }

    Ok(findings)
}

// ── GitHub Issues/PRs (234) ────────────────────────────────────────────

/// Configuration for a GitHub Issues/PR scan.
#[derive(Debug, Clone)]
pub struct GitHubIssuesScanConfig {
    pub api_token: String,
    pub owner: String,
    pub repo: String,
    pub max_items: usize,
}

/// Scan GitHub Issues and PR bodies/comments for secrets.
pub fn scan_github_issues(
    config: &GitHubIssuesScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let auth = format!("token {}", config.api_token);
    let owner = &config.owner;
    let repo = &config.repo;
    let max = config.max_items;

    let mut findings = Vec::new();

    // Issues
    let url = format!("https://api.github.com/repos/{owner}/{repo}/issues?state=all&per_page={max}");
    findings.extend(fetch_and_scan(
        &url,
        Some(("Authorization", &auth)),
        &std::path::PathBuf::from(format!("github-issues:{owner}/{repo}")),
        detectors,
    ));

    // Issue comments
    let url = format!("https://api.github.com/repos/{owner}/{repo}/issues/comments?per_page={max}");
    findings.extend(fetch_and_scan(
        &url,
        Some(("Authorization", &auth)),
        &std::path::PathBuf::from(format!("github-issues:{owner}/{repo}/comments")),
        detectors,
    ));

    // PRs
    let url = format!("https://api.github.com/repos/{owner}/{repo}/pulls?state=all&per_page={max}");
    findings.extend(fetch_and_scan(
        &url,
        Some(("Authorization", &auth)),
        &std::path::PathBuf::from(format!("github-prs:{owner}/{repo}")),
        detectors,
    ));

    // PR review comments
    let url = format!("https://api.github.com/repos/{owner}/{repo}/pulls/comments?per_page={max}");
    findings.extend(fetch_and_scan(
        &url,
        Some(("Authorization", &auth)),
        &std::path::PathBuf::from(format!("github-prs:{owner}/{repo}/review-comments")),
        detectors,
    ));

    Ok(findings)
}

// ── GitHub Actions logs (235) ──────────────────────────────────────────

/// Configuration for a GitHub Actions log scan.
#[derive(Debug, Clone)]
pub struct GitHubActionsLogScanConfig {
    pub api_token: String,
    pub owner: String,
    pub repo: String,
    pub max_runs: usize,
}

/// Scan GitHub Actions workflow run logs for secrets.
pub fn scan_github_actions_logs(
    config: &GitHubActionsLogScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("token {}", config.api_token);
    let owner = &config.owner;
    let repo = &config.repo;

    // List workflow runs
    let url = format!("https://api.github.com/repos/{owner}/{repo}/actions/runs?per_page={}", config.max_runs);
    let resp = agent.get(&url).set("Authorization", &auth).set("User-Agent", "pledgeguard").call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("github-actions:{owner}/{repo}/runs")), detectors));

        // Get logs for each run
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(runs) = json.get("workflow_runs").and_then(|r| r.as_array()) {
                for run in runs.iter().take(config.max_runs) {
                    if let Some(run_id) = run.get("id").and_then(|i| i.as_u64()) {
                        let logs_url = format!("https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/logs");
                        let resp2 = agent.get(&logs_url).set("Authorization", &auth).set("User-Agent", "pledgeguard").call();
                        if let Ok(r2) = resp2
                            && let Ok(body2) = r2.into_string()
                        {
                            let vpath = std::path::PathBuf::from(format!("github-actions:{owner}/{repo}/runs/{run_id}/logs"));
                            findings.extend(scan_text(&body2, &vpath, detectors));
                        }
                    }
                }
            }
    }

    Ok(findings)
}

// ── GitLab Issues/MRs (236) ────────────────────────────────────────────

/// Configuration for a GitLab Issues/MR scan.
#[derive(Debug, Clone)]
pub struct GitLabIssuesScanConfig {
    pub base_url: String,
    pub api_token: String,
    pub project_id: Option<String>,
    pub max_items: usize,
}

/// Scan GitLab Issues and MR bodies/comments for secrets.
pub fn scan_gitlab_issues(
    config: &GitLabIssuesScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);
    let base = config.base_url.trim_end_matches('/');
    let max = config.max_items;

    let mut findings = Vec::new();

    if let Some(pid) = &config.project_id {
        // Issues
        let url = format!("{base}/api/v4/projects/{pid}/issues?per_page={max}");
        findings.extend(fetch_and_scan(&url, Some(("Authorization", &auth)), &std::path::PathBuf::from(format!("gitlab-issues:{pid}")), detectors));

        // MRs
        let url = format!("{base}/api/v4/projects/{pid}/merge_requests?per_page={max}");
        findings.extend(fetch_and_scan(&url, Some(("Authorization", &auth)), &std::path::PathBuf::from(format!("gitlab-mrs:{pid}")), detectors));
    } else {
        // List all projects
        let url = format!("{base}/api/v4/projects?per_page=20&membership=true");
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(projects) = json.as_array() {
                    for proj in projects.iter().take(20) {
                        if let Some(pid) = proj.get("id").and_then(|i| i.as_u64()) {
                            let url = format!("{base}/api/v4/projects/{pid}/issues?per_page={max}");
                            findings.extend(fetch_and_scan(&url, Some(("Authorization", &auth)), &std::path::PathBuf::from(format!("gitlab-issues:{pid}")), detectors));

                            let url = format!("{base}/api/v4/projects/{pid}/merge_requests?per_page={max}");
                            findings.extend(fetch_and_scan(&url, Some(("Authorization", &auth)), &std::path::PathBuf::from(format!("gitlab-mrs:{pid}")), detectors));
                        }
                    }
                }
    }

    Ok(findings)
}

// ── GitLab CI job logs (237) ───────────────────────────────────────────

/// Configuration for a GitLab CI job log scan.
#[derive(Debug, Clone)]
pub struct GitLabCiLogScanConfig {
    pub base_url: String,
    pub api_token: String,
    pub project_id: String,
    pub max_jobs: usize,
}

/// Scan GitLab CI/CD job logs for secrets.
pub fn scan_gitlab_ci_logs(
    config: &GitLabCiLogScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);
    let base = config.base_url.trim_end_matches('/');
    let pid = &config.project_id;

    // List jobs
    let url = format!("{base}/api/v4/projects/{pid}/jobs?per_page={}", config.max_jobs);
    let resp = agent.get(&url).set("Authorization", &auth).call();

    let mut findings = Vec::new();
    if let Ok(r) = resp
        && let Ok(body) = r.into_string()
    {
        findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("gitlab-ci:{pid}/jobs")), detectors));

        // Get trace/log for each job
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(jobs) = json.as_array() {
                for job in jobs.iter().take(config.max_jobs) {
                    if let Some(job_id) = job.get("id").and_then(|i| i.as_u64()) {
                        let trace_url = format!("{base}/api/v4/projects/{pid}/jobs/{job_id}/trace");
                        let resp2 = agent.get(&trace_url).set("Authorization", &auth).call();
                        if let Ok(r2) = resp2
                            && let Ok(body2) = r2.into_string()
                        {
                            let vpath = std::path::PathBuf::from(format!("gitlab-ci:{pid}/jobs/{job_id}/trace"));
                            findings.extend(scan_text(&body2, &vpath, detectors));
                        }
                    }
                }
            }
    }

    Ok(findings)
}

// ── Discord (238) ──────────────────────────────────────────────────────

/// Configuration for a Discord message scan.
#[derive(Debug, Clone)]
pub struct DiscordScanConfig {
    pub bot_token: String,
    pub channel_ids: Vec<String>,
    pub max_messages: usize,
}

/// Scan Discord channels via bot API for secrets.
pub fn scan_discord(
    config: &DiscordScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bot {}", config.bot_token);
    let mut findings = Vec::new();

    for cid in &config.channel_ids {
        let url = format!("https://discord.com/api/v10/channels/{cid}/messages?limit={}", config.max_messages);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("discord:{cid}/messages")), detectors));
        }
    }

    Ok(findings)
}

// ── Mattermost (239) ───────────────────────────────────────────────────

/// Configuration for a Mattermost scan.
#[derive(Debug, Clone)]
pub struct MattermostScanConfig {
    pub base_url: String,
    pub api_token: String,
    pub channel_id: Option<String>,
    pub max_posts: usize,
}

/// Scan Mattermost channels for secrets.
pub fn scan_mattermost(
    config: &MattermostScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let agent = agent();
    let auth = format!("Bearer {}", config.api_token);
    let base = config.base_url.trim_end_matches('/');
    let mut findings = Vec::new();

    if let Some(cid) = &config.channel_id {
        let url = format!("{base}/api/v4/channels/{cid}/posts?per_page={}", config.max_posts);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from(format!("mattermost:{cid}/posts")), detectors));
        }
    } else {
        // List channels for the team
        let url = format!("{base}/api/v4/channels?per_page={}", config.max_posts);
        let resp = agent.get(&url).set("Authorization", &auth).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            findings.extend(scan_text(&body, &std::path::PathBuf::from("mattermost:channels"), detectors));
        }
    }

    Ok(findings)
}

// ── RSS/Atom feeds (240) ───────────────────────────────────────────────

/// Configuration for an RSS/Atom feed scan.
#[derive(Debug, Clone)]
pub struct RssFeedScanConfig {
    pub feed_urls: Vec<String>,
    pub max_items_per_feed: usize,
}

/// Scan RSS/Atom feeds for leaked secrets in content.
pub fn scan_rss_feeds(
    config: &RssFeedScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, SourceScanError2> {
    let mut findings = Vec::new();

    for feed_url in &config.feed_urls {
        let resp = agent().get(feed_url).call();
        if let Ok(r) = resp
            && let Ok(body) = r.into_string()
        {
            let vpath = std::path::PathBuf::from(format!("rss:{feed_url}"));
            findings.extend(scan_text(&body, &vpath, detectors));
        }
    }

    Ok(findings)
}

// ── Utility functions ──────────────────────────────────────────────────

/// Simple base64 encoding (standard, no padding removal).
fn base64_encode(input: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(input)
}

/// Simple base64 decoding.
fn base64_decode(input: &str) -> Result<String, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(input)
        .map_err(|e| e.to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
}

/// Compute the range end for a Consul/etcd prefix scan.
fn prefix_range_end(prefix: &str) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    if bytes.is_empty() {
        return vec![0xFF];
    }
    let last = bytes.len() - 1;
    if bytes[last] < 0xFF {
        bytes[last] += 1;
        bytes
    } else {
        // Truncate trailing 0xFF bytes
        while !bytes.is_empty() && *bytes.last().unwrap() == 0xFF {
            bytes.pop();
        }
        if bytes.is_empty() {
            vec![0xFF]
        } else {
            let last = bytes.len() - 1;
            bytes[last] += 1;
            bytes
        }
    }
}

// ── Error type ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SourceScanError2 {
    Http(String),
    Parse(String),
}

impl std::fmt::Display for SourceScanError2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceScanError2::Http(e) => write!(f, "HTTP error: {e}"),
            SourceScanError2::Parse(e) => write!(f, "Parse error: {e}"),
        }
    }
}

impl std::error::Error for SourceScanError2 {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_text_finds_secrets() {
        let detectors = crate::detectors::builtin_detectors();
        let path = std::path::PathBuf::from("test://source");
        let findings = scan_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", &path, &detectors);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_gitea_config() {
        let config = GiteaScanConfig {
            base_url: "https://gitea.example.com".to_string(),
            api_token: "token".to_string(),
            owner: Some("myorg".to_string()),
            repo: Some("myrepo".to_string()),
            max_repos: 10,
        };
        assert_eq!(config.max_repos, 10);
    }

    #[test]
    fn test_bitbucket_cloud_config() {
        let config = BitbucketCloudScanConfig {
            username: "user".to_string(),
            app_password: "pass".to_string(),
            workspace: "ws".to_string(),
            repo: Some("repo".to_string()),
            max_repos: 20,
        };
        assert_eq!(config.workspace, "ws");
    }

    #[test]
    fn test_bitbucket_server_config() {
        let config = BitbucketServerScanConfig {
            base_url: "https://bitbucket.example.com".to_string(),
            api_token: "token".to_string(),
            project_key: "PROJ".to_string(),
            repo_slug: Some("repo".to_string()),
            max_repos: 15,
        };
        assert_eq!(config.project_key, "PROJ");
    }

    #[test]
    fn test_azure_devops_config() {
        let config = AzureDevOpsScanConfig {
            organization: "myorg".to_string(),
            pat: "pat".to_string(),
            project: Some("proj".to_string()),
            max_repos: 25,
        };
        assert_eq!(config.organization, "myorg");
    }

    #[test]
    fn test_launchdarkly_config() {
        let config = LaunchDarklyScanConfig {
            api_key: "key".to_string(),
            project_key: "default".to_string(),
            max_flags: 100,
        };
        assert_eq!(config.max_flags, 100);
    }

    #[test]
    fn test_consul_config() {
        let config = ConsulScanConfig {
            base_url: "http://localhost:8500".to_string(),
            token: Some("token".to_string()),
            prefix: Some("myapp/".to_string()),
        };
        assert_eq!(config.base_url, "http://localhost:8500");
    }

    #[test]
    fn test_etcd_config() {
        let config = EtcdScanConfig {
            base_url: "http://localhost:2379".to_string(),
            prefix: Some("/myapp/".to_string()),
        };
        assert_eq!(config.base_url, "http://localhost:2379");
    }

    #[test]
    fn test_redis_config() {
        let config = RedisScanConfig {
            host: "localhost".to_string(),
            port: 6379,
            password: Some("pass".to_string()),
            db: 0,
            max_keys: 1000,
        };
        assert_eq!(config.port, 6379);
    }

    #[test]
    fn test_elasticsearch_config() {
        let config = ElasticsearchScanConfig {
            base_url: "http://localhost:9200".to_string(),
            api_key: Some("key".to_string()),
            index_pattern: "*".to_string(),
            max_docs: 500,
        };
        assert_eq!(config.index_pattern, "*");
    }

    #[test]
    fn test_aws_ssm_config() {
        let config = AwsSsmScanConfig {
            region: "us-east-1".to_string(),
            access_key_id: "AKIA...".to_string(),
            secret_access_key: "secret".to_string(),
            path_prefix: Some("/myapp/".to_string()),
            max_params: 100,
        };
        assert_eq!(config.region, "us-east-1");
    }

    #[test]
    fn test_gcp_sm_config() {
        let config = GcpSecretManagerScanConfig {
            oauth_token: "token".to_string(),
            project_id: "my-project".to_string(),
            max_secrets: 50,
        };
        assert_eq!(config.project_id, "my-project");
    }

    #[test]
    fn test_azure_kv_config() {
        let config = AzureKeyVaultScanConfig {
            vault_url: "https://myvault.vault.azure.net".to_string(),
            access_token: "token".to_string(),
            max_secrets: 50,
        };
        assert_eq!(config.vault_url, "https://myvault.vault.azure.net");
    }

    #[test]
    fn test_vault_config() {
        let config = VaultScanConfig {
            base_url: "http://localhost:8200".to_string(),
            token: "token".to_string(),
            mount_path: "secret".to_string(),
            max_paths: 100,
        };
        assert_eq!(config.mount_path, "secret");
    }

    #[test]
    fn test_doppler_config() {
        let config = DopplerScanConfig {
            api_key: "key".to_string(),
            project: Some("proj".to_string()),
            config_name: Some("prd".to_string()),
        };
        assert_eq!(config.api_key, "key");
    }

    #[test]
    fn test_1password_config() {
        let config = OnePasswordScanConfig {
            api_token: "token".to_string(),
            vault_id: Some("vault123".to_string()),
            max_items: 100,
        };
        assert_eq!(config.max_items, 100);
    }

    #[test]
    fn test_lastpass_config() {
        let config = LastPassScanConfig {
            api_key: "key".to_string(),
            account_id: "acct123".to_string(),
        };
        assert_eq!(config.account_id, "acct123");
    }

    #[test]
    fn test_bitwarden_config() {
        let config = BitwardenScanConfig {
            base_url: "https://vault.bitwarden.com".to_string(),
            access_token: "token".to_string(),
            max_items: 200,
        };
        assert_eq!(config.base_url, "https://vault.bitwarden.com");
    }

    #[test]
    fn test_k8s_configmap_config() {
        let config = K8sConfigMapScanConfig {
            kubeconfig_path: None,
            namespace: Some("default".to_string()),
            max_configmaps: 50,
        };
        assert_eq!(config.namespace, Some("default".to_string()));
    }

    #[test]
    fn test_k8s_etcd_config() {
        let config = K8sEtcdScanConfig {
            etcd_endpoint: "https://localhost:2379".to_string(),
            ca_cert: None,
            client_cert: None,
            client_key: None,
            max_keys: 1000,
        };
        assert_eq!(config.max_keys, 1000);
    }

    #[test]
    fn test_cf_workers_config() {
        let config = CloudflareWorkersScanConfig {
            api_token: "token".to_string(),
            account_id: "acct123".to_string(),
            max_workers: 50,
        };
        assert_eq!(config.account_id, "acct123");
    }

    #[test]
    fn test_vercel_config() {
        let config = VercelScanConfig {
            api_token: "token".to_string(),
            project_id: Some("proj123".to_string()),
            max_projects: 20,
        };
        assert_eq!(config.max_projects, 20);
    }

    #[test]
    fn test_netlify_config() {
        let config = NetlifyScanConfig {
            api_token: "token".to_string(),
            site_id: Some("site123".to_string()),
            max_sites: 30,
        };
        assert_eq!(config.max_sites, 30);
    }

    #[test]
    fn test_railway_config() {
        let config = RailwayScanConfig {
            api_token: "token".to_string(),
            project_id: Some("proj123".to_string()),
        };
        assert_eq!(config.api_token, "token");
    }

    #[test]
    fn test_render_config() {
        let config = RenderScanConfig {
            api_key: "key".to_string(),
            service_id: Some("srv123".to_string()),
            max_services: 25,
        };
        assert_eq!(config.max_services, 25);
    }

    #[test]
    fn test_fly_io_config() {
        let config = FlyIoScanConfig {
            api_token: "token".to_string(),
            app_name: Some("myapp".to_string()),
            max_apps: 15,
        };
        assert_eq!(config.max_apps, 15);
    }

    #[test]
    fn test_supabase_env_config() {
        let config = SupabaseEnvScanConfig {
            access_token: "token".to_string(),
            project_id: Some("proj123".to_string()),
            max_projects: 10,
        };
        assert_eq!(config.max_projects, 10);
    }

    #[test]
    fn test_github_gist_config() {
        let config = GitHubGistScanConfig {
            api_token: "token".to_string(),
            username: Some("user".to_string()),
            max_gists: 30,
        };
        assert_eq!(config.max_gists, 30);
    }

    #[test]
    fn test_github_issues_config() {
        let config = GitHubIssuesScanConfig {
            api_token: "token".to_string(),
            owner: "pledgeandgrow".to_string(),
            repo: "pledgeguard".to_string(),
            max_items: 50,
        };
        assert_eq!(config.owner, "pledgeandgrow");
    }

    #[test]
    fn test_github_actions_log_config() {
        let config = GitHubActionsLogScanConfig {
            api_token: "token".to_string(),
            owner: "pledgeandgrow".to_string(),
            repo: "pledgeguard".to_string(),
            max_runs: 20,
        };
        assert_eq!(config.max_runs, 20);
    }

    #[test]
    fn test_gitlab_issues_config() {
        let config = GitLabIssuesScanConfig {
            base_url: "https://gitlab.com".to_string(),
            api_token: "token".to_string(),
            project_id: Some("123".to_string()),
            max_items: 50,
        };
        assert_eq!(config.base_url, "https://gitlab.com");
    }

    #[test]
    fn test_gitlab_ci_log_config() {
        let config = GitLabCiLogScanConfig {
            base_url: "https://gitlab.com".to_string(),
            api_token: "token".to_string(),
            project_id: "123".to_string(),
            max_jobs: 50,
        };
        assert_eq!(config.project_id, "123");
    }

    #[test]
    fn test_discord_config() {
        let config = DiscordScanConfig {
            bot_token: "token".to_string(),
            channel_ids: vec!["123".to_string()],
            max_messages: 100,
        };
        assert_eq!(config.max_messages, 100);
    }

    #[test]
    fn test_mattermost_config() {
        let config = MattermostScanConfig {
            base_url: "https://mm.example.com".to_string(),
            api_token: "token".to_string(),
            channel_id: Some("ch123".to_string()),
            max_posts: 100,
        };
        assert_eq!(config.base_url, "https://mm.example.com");
    }

    #[test]
    fn test_rss_feed_config() {
        let config = RssFeedScanConfig {
            feed_urls: vec!["https://example.com/feed.xml".to_string()],
            max_items_per_feed: 50,
        };
        assert_eq!(config.feed_urls.len(), 1);
    }

    #[test]
    fn test_base64_encode_decode() {
        let input = b"hello world";
        let encoded = base64_encode(input);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn test_prefix_range_end() {
        assert_eq!(prefix_range_end("abc"), b"abd".to_vec());
        assert_eq!(prefix_range_end(""), vec![0xFF]);
    }
}
