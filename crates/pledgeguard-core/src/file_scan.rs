//! File-based scanning sources: Helm Charts, Terraform State files,
//! and Kubernetes Secret manifests.
//!
//! These are local file scanners that target specific file formats
//! commonly containing plaintext secrets.

use crate::detector::Detector;
use crate::finding::Finding;
use std::path::Path;

/// Helper: scan a text string with all detectors.
fn scan_text(text: &str, virtual_path: &Path, detectors: &[Box<dyn Detector>]) -> Vec<Finding> {
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

// ── Helm Charts ────────────────────────────────────────────────────────

/// Scan a Helm chart directory for secrets.
///
/// Helm charts contain `values.yaml` files, templates, and `Chart.yaml`.
/// Secrets often appear in `values.yaml` (e.g., database passwords, API keys)
/// or in template files that embed credentials.
pub fn scan_helm_chart(
    chart_dir: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, FileScanError> {
    let mut findings = Vec::new();

    // Scan values.yaml, values-*.yaml, and templates/*.yaml
    let values_path = chart_dir.join("values.yaml");
    if values_path.is_file() {
        let content = std::fs::read_to_string(&values_path).map_err(FileScanError::Io)?;
        let virtual_path = Path::new("helm")
            .join(chart_dir.file_name().unwrap_or_default())
            .join("values.yaml");
        findings.extend(scan_text(&content, &virtual_path, detectors));
    }

    // Scan values-*.yaml override files.
    if let Ok(entries) = std::fs::read_dir(chart_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("values-")
                && (name_str.ends_with(".yaml") || name_str.ends_with(".yml"))
                && let Ok(content) = std::fs::read_to_string(entry.path())
            {
                let virtual_path = Path::new("helm")
                    .join(chart_dir.file_name().unwrap_or_default())
                    .join(name_str.as_ref());
                findings.extend(scan_text(&content, &virtual_path, detectors));
            }
        }
    }

    // Scan templates directory.
    let templates_dir = chart_dir.join("templates");
    if templates_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&templates_dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "yaml" | "yml" | "tpl" | "txt")
                    && let Ok(content) = std::fs::read_to_string(&path)
                {
                    let virtual_path = Path::new("helm")
                        .join(chart_dir.file_name().unwrap_or_default())
                        .join("templates")
                        .join(path.file_name().unwrap_or_default());
                    findings.extend(scan_text(&content, &virtual_path, detectors));
                }
            }
        }
    }

    // Scan Chart.yaml for metadata (sometimes contains registry credentials).
    let chart_path = chart_dir.join("Chart.yaml");
    if chart_path.is_file()
        && let Ok(content) = std::fs::read_to_string(&chart_path)
    {
        let virtual_path = Path::new("helm")
            .join(chart_dir.file_name().unwrap_or_default())
            .join("Chart.yaml");
        findings.extend(scan_text(&content, &virtual_path, detectors));
    }

    Ok(findings)
}

// ── Terraform State Files ──────────────────────────────────────────────

/// Scan a Terraform state file for secrets.
///
/// Terraform state files (`terraform.tfstate`) often contain plaintext
/// secrets: database passwords, API keys, private keys, and other sensitive
/// values that Terraform manages. This scanner reads the state file and
/// scans all string values for known secret patterns.
pub fn scan_terraform_state(
    state_path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, FileScanError> {
    let content = std::fs::read_to_string(state_path).map_err(FileScanError::Io)?;

    // State files are JSON — parse and extract all string values, then scan them.
    // Also scan the raw file line-by-line for detector patterns.
    let mut findings = Vec::new();

    // Line-by-line scan of the raw file.
    let virtual_path =
        Path::new("terraform-state").join(state_path.file_name().unwrap_or_default());
    findings.extend(scan_text(&content, &virtual_path, detectors));

    // Additionally, parse JSON and extract string values from known sensitive paths.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
        // Walk all string values in the JSON tree.
        let mut string_values = Vec::new();
        extract_strings(&json, &mut string_values);

        for (path_str, value) in &string_values {
            for detector in detectors {
                for m in detector.scan_line(value) {
                    findings.push(Finding {
                        rule_id: detector.id().to_string(),
                        description: detector.description().to_string(),
                        severity: detector.severity(),
                        path: virtual_path.clone(),
                        line: 0, // JSON value — no specific line
                        column: 0,
                        matched: m.text,
                        context: format!("{}: {}", path_str, value),
                        commit: None,
                        likely_false_positive: false,
                        verification: None,
                    });
                }
            }
        }
    }

    Ok(findings)
}

/// Recursively extract all string values from a JSON tree, recording their JSON path.
fn extract_strings(value: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::String(s) => {
            // Only extract strings that look like they could be secrets
            // (longer than 10 chars, not empty, not a URL/boolean-like).
            if s.len() > 10 {
                out.push((String::new(), s.clone()));
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let mut child_out = Vec::new();
                extract_strings(val, &mut child_out);
                for (mut path, s) in child_out {
                    if path.is_empty() {
                        path = key.clone();
                    } else {
                        path = format!("{}.{}", key, path);
                    }
                    out.push((path, s));
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let mut child_out = Vec::new();
                extract_strings(val, &mut child_out);
                for (mut path, s) in child_out {
                    if path.is_empty() {
                        path = format!("[{i}]");
                    } else {
                        path = format!("[{i}].{path}");
                    }
                    out.push((path, s));
                }
            }
        }
        _ => {}
    }
}

// ── Kubernetes Secrets ─────────────────────────────────────────────────

/// Scan a Kubernetes Secret manifest for secrets.
///
/// Kubernetes Secret manifests contain base64-encoded secret data.
/// This scanner decodes the base64 values and scans both the encoded
/// and decoded forms for known secret patterns.
pub fn scan_k8s_secret(
    manifest_path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, FileScanError> {
    let content = std::fs::read_to_string(manifest_path).map_err(FileScanError::Io)?;

    let mut findings = Vec::new();
    let virtual_path = Path::new("k8s-secret").join(manifest_path.file_name().unwrap_or_default());

    // Scan the raw manifest first (may contain plaintext in stringData).
    findings.extend(scan_text(&content, &virtual_path, detectors));

    // Parse as YAML/JSON and decode base64 data values.
    // We use serde_json since YAML is a superset of JSON for simple cases.
    // For robustness, we also do a line-by-line base64 decode pass.
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
        // Check if this is a Secret resource.
        let kind = json.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        if kind == "Secret" {
            // Decode data field (base64-encoded values).
            if let Some(data) = json.get("data").and_then(|d| d.as_object()) {
                use base64::Engine;
                for (key, value) in data {
                    if let Some(encoded) = value.as_str()
                        && let Ok(decoded) =
                            base64::engine::general_purpose::STANDARD.decode(encoded)
                    {
                        let decoded_str = String::from_utf8_lossy(&decoded);
                        let virtual_path = virtual_path.join(format!("data/{}", key));
                        findings.extend(scan_text(&decoded_str, &virtual_path, detectors));
                    }
                }
            }

            // Scan stringData field (plaintext values).
            if let Some(string_data) = json.get("stringData").and_then(|d| d.as_object()) {
                for (key, value) in string_data {
                    if let Some(s) = value.as_str() {
                        let virtual_path = virtual_path.join(format!("stringData/{}", key));
                        findings.extend(scan_text(s, &virtual_path, detectors));
                    }
                }
            }
        }
    }

    // Fallback: line-by-line base64 decode for any line that looks like a key: value pair.
    for (line_idx, line) in content.lines().enumerate() {
        if let Some(colon_pos) = line.find(':') {
            let value_part = line[colon_pos + 1..].trim().trim_matches('"');
            if value_part.len() > 10
                && value_part
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
            {
                use base64::Engine;
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value_part) {
                    let decoded_str = String::from_utf8_lossy(&decoded);
                    if decoded_str.len() > 5 {
                        let virtual_path = virtual_path.join(format!("line-{}", line_idx + 1));
                        findings.extend(scan_text(&decoded_str, &virtual_path, detectors));
                    }
                }
            }
        }
    }

    Ok(findings)
}

// ── Error type ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum FileScanError {
    Io(std::io::Error),
}

impl std::fmt::Display for FileScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileScanError::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for FileScanError {}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_text_finds_secrets() {
        let detectors = crate::detectors::builtin_detectors();
        let path = std::path::PathBuf::from("test://file");
        let findings = scan_text(
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
            &path,
            &detectors,
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_extract_strings() {
        let json: serde_json::Value = serde_json::json!({
            "name": "test",
            "password": "supersecretpassword123",
            "nested": {
                "api_key": "AKIAIOSFODNN7EXAMPLE"
            },
            "list": ["short", "a-very-long-string-value-here"]
        });
        let mut strings = Vec::new();
        extract_strings(&json, &mut strings);
        // Only strings > 10 chars are extracted
        assert!(strings.iter().any(|(_, s)| s == "supersecretpassword123"));
        assert!(strings.iter().any(|(_, s)| s == "AKIAIOSFODNN7EXAMPLE"));
        assert!(
            strings
                .iter()
                .any(|(_, s)| s == "a-very-long-string-value-here")
        );
        // "test" and "short" are too short
        assert!(!strings.iter().any(|(_, s)| s == "test"));
        assert!(!strings.iter().any(|(_, s)| s == "short"));
    }

    #[test]
    fn test_scan_terraform_state_with_secrets() {
        let detectors = crate::detectors::builtin_detectors();
        let state_content = r#"{
            "version": 4,
            "terraform_version": "1.5.0",
            "resources": [
                {
                    "type": "aws_db_instance",
                    "instances": [
                        {
                            "attributes": {
                                "password": "AKIAIOSFODNN7EXAMPLE"
                            }
                        }
                    ]
                }
            ]
        }"#;
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), state_content).unwrap();
        let findings = scan_terraform_state(temp.path(), &detectors).unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_k8s_secret_with_base64() {
        use base64::Engine;
        let detectors = crate::detectors::builtin_detectors();
        let secret_value = "AKIAIOSFODNN7EXAMPLE";
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret_value);
        let manifest = format!(
            r#"{{
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {{"name": "test-secret"}},
            "data": {{
                "aws_key": "{}"
            }}
        }}"#,
            encoded
        );
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), &manifest).unwrap();
        let findings = scan_k8s_secret(temp.path(), &detectors).unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_k8s_secret_with_string_data() {
        let detectors = crate::detectors::builtin_detectors();
        let manifest = r#"{
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "test-secret"},
            "stringData": {
                "api_key": "AKIAIOSFODNN7EXAMPLE"
            }
        }"#;
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), manifest).unwrap();
        let findings = scan_k8s_secret(temp.path(), &detectors).unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_file_scan_error_display() {
        let err = FileScanError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"));
        assert!(err.to_string().contains("IO error"));
    }
}
