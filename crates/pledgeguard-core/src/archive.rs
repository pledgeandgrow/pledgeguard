//! Archive scanning (zip/tar.gz).
//!
//! Extracts archive files in memory and scans their contents for secrets.
//! Supports .zip, .tar.gz, and .tar files.

use crate::detector::Detector;
use crate::finding::Finding;
use std::io::Read;
use std::path::Path;

/// Scan a zip archive for secrets in its contained files.
pub fn scan_zip(
    zip_path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, std::io::Error> {
    let file = std::fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut findings = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        if entry.is_dir() {
            continue;
        }

        let entry_name = entry.name().to_string();
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        // Scan each line of the extracted file.
        let text = String::from_utf8_lossy(&contents);
        let virtual_path = zip_path.join(&entry_name);

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

/// Scan a tar archive (optionally gzipped) for secrets.
pub fn scan_tar(
    tar_path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, std::io::Error> {
    let file = std::fs::File::open(tar_path)?;
    let mut ar = tar::Archive::new(file);

    let mut findings = Vec::new();

    for entry in ar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if path.as_os_str().is_empty() {
            continue;
        }

        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;

        let text = String::from_utf8_lossy(&contents);
        let virtual_path = tar_path.join(&path);

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

/// Detect if a path is an archive we can scan.
pub fn is_archive(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(ext.to_lowercase().as_str(), "zip" | "tar" | "gz" | "tgz")
}

/// Scan an archive file, auto-detecting format.
pub fn scan_archive(
    path: &Path,
    detectors: &[Box<dyn Detector>],
) -> Result<Vec<Finding>, std::io::Error> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "zip" => scan_zip(path, detectors),
        "tar" => scan_tar(path, detectors),
        "gz" | "tgz" => scan_tar(path, detectors),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("unsupported archive format: {ext}"),
        )),
    }
}
