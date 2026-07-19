//! Docker image scanning.
//!
//! Extracts filesystem layers from a Docker image (tar format) and scans
//! the contained files for secrets. Docker images saved via `docker save`
//! are tar archives containing layer tarballs and a manifest.json.

use crate::detector::Detector;
use crate::finding::Finding;
use std::io::Read;
use std::path::Path;

/// Scan a Docker image (saved as a tar via `docker save`) for secrets.
/// Each layer's tarball is extracted in memory and its files are scanned.
pub fn scan_docker_image(
    image_path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, DockerScanError> {
    let file = std::fs::File::open(image_path)?;
    let mut archive = tar::Archive::new(file);

    let mut layer_tars: Vec<String> = Vec::new();
    let mut manifest_found = false;

    // First pass: find manifest.json and collect layer paths.
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_os_str() == "manifest.json" {
            manifest_found = true;
            let mut manifest_str = String::new();
            entry.read_to_string(&mut manifest_str)?;
            if let Ok(manifest) = serde_json::from_str::<Vec<serde_json::Value>>(&manifest_str)
                && let Some(first) = manifest.first()
                && let Some(layers) = first.get("Layers").and_then(|l| l.as_array()) {
                        for layer in layers {
                            if let Some(layer_path) = layer.as_str() {
                                layer_tars.push(layer_path.to_string());
                            }
                        }
            }
        }
    }

    // If no manifest was found, try scanning all .tar files as layers.
    if !manifest_found {
        let file = std::fs::File::open(image_path)?;
        let mut archive = tar::Archive::new(file);
        for entry in archive.entries()? {
            let entry = entry?;
            let path = entry.path()?.to_string_lossy().to_string();
            if path.ends_with(".tar") || path.ends_with("/layer.tar") {
                layer_tars.push(path);
            }
        }
    }

    let mut findings = Vec::new();

    // Second pass: extract and scan each layer.
    for layer_path in &layer_tars {
        let file = std::fs::File::open(image_path)?;
        let mut archive = tar::Archive::new(file);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let entry_path = entry.path()?.to_string_lossy().to_string();
            if entry_path == *layer_path {
                let mut layer_data = Vec::new();
                entry.read_to_end(&mut layer_data)?;
                // Scan the layer tarball.
                let layer_findings = scan_layer_tar(&layer_data, image_path, layer_path, detectors)?;
                findings.extend(layer_findings);
                break;
            }
        }
    }

    Ok(findings)
}

/// Scan a single layer's tarball for secrets.
fn scan_layer_tar(
    layer_data: &[u8],
    image_path: &Path,
    layer_name: &str,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, DockerScanError> {
    let cursor = std::io::Cursor::new(layer_data);
    let mut archive = tar::Archive::new(cursor);
    let mut findings = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_dir() {
            continue;
        }

        let entry_path = entry.path()?.to_string_lossy().to_string();
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        // Skip binary files (check for null bytes in first 1KB).
        if contents.len() > 1024 && contents[..1024].contains(&0) {
            continue;
        }
        if contents.is_empty() {
            continue;
        }

        let text = String::from_utf8_lossy(&contents);
        let virtual_path = image_path.join(format!("{layer_name}/{entry_path}"));

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

    Ok(findings)
}

/// Check if a path looks like a Docker image tar.
pub fn is_docker_image(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    name.ends_with(".tar") || name.contains(".tar") || ext == "tar"
}

#[derive(Debug)]
pub enum DockerScanError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for DockerScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DockerScanError::Io(e) => write!(f, "IO error: {e}"),
            DockerScanError::Json(e) => write!(f, "JSON parse error: {e}"),
        }
    }
}

impl From<std::io::Error> for DockerScanError {
    fn from(e: std::io::Error) -> Self {
        DockerScanError::Io(e)
    }
}

impl From<serde_json::Error> for DockerScanError {
    fn from(e: serde_json::Error) -> Self {
        DockerScanError::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_docker_image() {
        assert!(is_docker_image(Path::new("myimage.tar")));
        assert!(is_docker_image(Path::new("ubuntu-22.04.tar")));
        assert!(!is_docker_image(Path::new("config.yaml")));
    }
}
