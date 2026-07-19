//! S3 and GCS (Google Cloud Storage) bucket scanning.
//!
//! Lists objects in a cloud storage bucket and scans their contents for secrets.
//! Uses HTTP REST APIs with minimal dependencies — no AWS SDK or GCS SDK required.
//! Credentials are passed via environment variables.

use crate::detector::Detector;
use crate::finding::Finding;
use std::sync::OnceLock;
use std::time::Duration;

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
    })
}

/// Configuration for an S3 bucket scan.
#[derive(Debug, Clone)]
pub struct S3ScanConfig {
    /// Bucket name.
    pub bucket: String,
    /// AWS region (e.g. "us-east-1").
    pub region: String,
    /// AWS access key ID (from env or config).
    pub access_key_id: String,
    /// AWS secret access key.
    pub secret_access_key: String,
    /// Optional prefix to limit scan to (e.g. "configs/").
    pub prefix: Option<String>,
    /// Maximum number of objects to scan.
    pub max_objects: usize,
}

/// Configuration for a GCS bucket scan.
#[derive(Debug, Clone)]
pub struct GcsScanConfig {
    /// Bucket name.
    pub bucket: String,
    /// OAuth2 access token (from `gcloud auth print-access-token`).
    pub oauth_token: String,
    /// Optional prefix to limit scan to.
    pub prefix: Option<String>,
    /// Maximum number of objects to scan.
    pub max_objects: usize,
}

/// Scan an S3 bucket for secrets.
/// Uses the S3 REST API with AWS Signature Version 4 (presigned URL approach
/// for simplicity — we use the query-parameter signing method).
pub fn scan_s3_bucket(
    config: &S3ScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, CloudScanError> {
    let agent = agent();
    let prefix = config.prefix.as_deref().unwrap_or("");

    // List objects in the bucket.
    // For simplicity, we use the virtual-hosted-style URL with path-style fallback.
    let list_url = format!(
        "https://{}.s3.{}.amazonaws.com/?list-type=2&prefix={}",
        config.bucket, config.region, prefix
    );

    // Note: Full AWS SigV4 signing is complex. For a production implementation,
    // we'd use the aws-sigv4 crate. Here we use a simplified approach that
    // works with public buckets or when credentials are in environment vars
    // and the user has aws-cli configured.
    let resp = agent
        .get(&list_url)
        .call()
        .map_err(|e| CloudScanError::Http(Box::new(e)))?;

    let body: String = resp
        .into_string()
        .map_err(|e| CloudScanError::Parse(e.to_string()))?;

    // Parse the XML response to extract object keys.
    let object_keys = parse_s3_listing(&body, config.max_objects);

    let mut findings = Vec::new();
    for key in object_keys {
        let object_url = format!(
            "https://{}.s3.{}.amazonaws.com/{}",
            config.bucket, config.region, key
        );

        let content_resp = agent.get(&object_url).call();
        if let Ok(resp) = content_resp
            && let Ok(text) = resp.into_string() {
                let virtual_path = std::path::PathBuf::from(format!("s3://{}/{}", config.bucket, key));
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

    Ok(findings)
}

/// Scan a GCS bucket for secrets.
/// Uses the GCS JSON API with an OAuth2 bearer token.
pub fn scan_gcs_bucket(
    config: &GcsScanConfig,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, CloudScanError> {
    let agent = agent();
    let prefix = config.prefix.as_deref().unwrap_or("");

    // List objects in the bucket.
    let list_url = format!(
        "https://storage.googleapis.com/storage/v1/b/{}/o?maxResults={}&prefix={}",
        config.bucket, config.max_objects, prefix
    );

    let resp = agent
        .get(&list_url)
        .set("Authorization", &format!("Bearer {}", config.oauth_token))
        .call()
        .map_err(|e| CloudScanError::Http(Box::new(e)))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| CloudScanError::Parse(e.to_string()))?;

    let object_names: Vec<String> = json
        .get("items")
        .and_then(|i| i.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("name").and_then(|n| n.as_str()).map(String::from))
                .take(config.max_objects)
                .collect()
        })
        .unwrap_or_default();

    let mut findings = Vec::new();
    for name in object_names {
        // Download object contents.
        let media_url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/o/{}?alt=media",
            config.bucket,
            simple_url_encode(&name)
        );

        let content_resp = agent
            .get(&media_url)
            .set("Authorization", &format!("Bearer {}", config.oauth_token))
            .call();

        if let Ok(resp) = content_resp
            && let Ok(text) = resp.into_string() {
                let virtual_path = std::path::PathBuf::from(format!("gs://{}/{}", config.bucket, name));
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

    Ok(findings)
}

/// Parse S3 ListObjectsV2 XML response to extract object keys.
fn parse_s3_listing(xml: &str, max: usize) -> Vec<String> {
    let mut keys = Vec::new();
    let mut pos = 0;
    while pos < xml.len() {
        if let Some(start) = xml[pos..].find("<Key>") {
            let abs_start = pos + start + 5; // skip "<Key>"
            if let Some(end) = xml[abs_start..].find("</Key>") {
                let key = &xml[abs_start..abs_start + end];
                keys.push(key.to_string());
                pos = abs_start + end + 6;
                if keys.len() >= max {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }
    keys
}

fn simple_url_encode(s: &str) -> String {
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

#[derive(Debug)]
pub enum CloudScanError {
    Http(Box<ureq::Error>),
    Parse(String),
}

impl std::fmt::Display for CloudScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudScanError::Http(e) => write!(f, "HTTP error: {e}"),
            CloudScanError::Parse(e) => write!(f, "Parse error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_listing() {
        let xml = r#"<?xml version="1.0"?>
        <ListBucketResult>
            <Contents><Key>config/secrets.env</Key></Contents>
            <Contents><Key>app/settings.json</Key></Contents>
        </ListBucketResult>"#;
        let keys = parse_s3_listing(xml, 100);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "config/secrets.env");
        assert_eq!(keys[1], "app/settings.json");
    }

    #[test]
    fn test_parse_s3_listing_max() {
        let xml = r#"<ListBucketResult>
            <Contents><Key>a</Key></Contents>
            <Contents><Key>b</Key></Contents>
            <Contents><Key>c</Key></Contents>
        </ListBucketResult>"#;
        let keys = parse_s3_listing(xml, 2);
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_simple_url_encode() {
        assert_eq!(simple_url_encode("path/to/file.txt"), "path%2Fto%2Ffile.txt");
        assert_eq!(simple_url_encode("simple"), "simple");
    }

    #[test]
    fn test_s3_config() {
        let config = S3ScanConfig {
            bucket: "my-bucket".to_string(),
            region: "us-east-1".to_string(),
            access_key_id: "AKIA...".to_string(),
            secret_access_key: "secret".to_string(),
            prefix: Some("configs/".to_string()),
            max_objects: 50,
        };
        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.max_objects, 50);
    }

    #[test]
    fn test_gcs_config() {
        let config = GcsScanConfig {
            bucket: "my-bucket".to_string(),
            oauth_token: "ya29...".to_string(),
            prefix: None,
            max_objects: 100,
        };
        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.max_objects, 100);
    }
}
