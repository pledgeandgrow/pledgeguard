//! Custom configuration file support (`pledgeguard.toml`).
//!
//! Users can define custom detector rules in a TOML file, extending
//! PledgeGuard beyond the built-in detectors without writing WASM plugins.
//!
//! ## Example `pledgeguard.toml`
//!
//! ```toml
//! [[rules]]
//! id = "custom-api-key"
//! description = "My Custom API Key"
//! severity = "high"
//! pattern = '\bMYKEY_[A-Za-z0-9]{32}\b'
//! prefilter = ["MYKEY_"]
//! entropy = 3.5
//! secretGroup = 1
//!
//! [[rules.allowlists]]
//! regexes = ['EXAMPLE$', 'test.*']
//!
//! [[rules]]
//! id = "internal-token"
//! description = "Internal Service Token"
//! severity = "critical"
//! pattern = '\bINT_[A-Fa-f0-9]{40}\b'
//! prefilter = ["INT_"]
//! path = '\.env$'
//!
//! [allowlist]
//! paths = ['vendor/.*', 'node_modules/.*']
//! ```

use crate::detector::{Allowlist, Detector, RegexDetector};
use crate::finding::Severity;
use std::path::Path;

/// A single allowlist entry within a rule or global config.
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct ConfigAllowlist {
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub stopwords: Vec<String>,
}

/// A single custom rule from the config file.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRule {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    #[serde(default)]
    pub prefilter: Vec<String>,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub secret_group: Option<usize>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub allowlists: Vec<ConfigAllowlist>,
}

/// The top-level config file structure.
#[derive(Debug, serde::Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub rules: Vec<CustomRule>,
    /// Path to another config file to extend (rules are merged).
    #[serde(default)]
    pub extend: Option<String>,
    /// Global allowlist applied to all findings.
    #[serde(default)]
    pub allowlist: Option<ConfigAllowlist>,
}

/// Errors that can occur while loading a config file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid regex in rule '{rule_id}': {error}")]
    InvalidRegex { rule_id: String, error: String },
    #[error("invalid severity '{severity}' in rule '{rule_id}'; expected low, medium, high, or critical")]
    InvalidSeverity { rule_id: String, severity: String },
    #[error("invalid path regex in rule '{rule_id}': {error}")]
    InvalidPathRegex { rule_id: String, error: String },
    #[error("invalid allowlist regex in rule '{rule_id}': {error}")]
    InvalidAllowlistRegex { rule_id: String, error: String },
}

/// Load a config file from a TOML path and return custom detectors + global allowlist.
pub fn load_config(path: &Path) -> Result<ConfigLoadResult, ConfigError> {
    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;

    // Handle config extension/inheritance.
    let mut all_rules = config.rules;
    let mut global_allowlist = config.allowlist;

    if let Some(ref extend_path) = config.extend {
        let extend_path = if Path::new(extend_path).is_absolute() {
            Path::new(extend_path).to_path_buf()
        } else {
            path.parent().unwrap_or(Path::new(".")).join(extend_path)
        };
        if extend_path.exists() {
            let parent_contents = std::fs::read_to_string(&extend_path)?;
            let parent_config: Config = toml::from_str(&parent_contents)?;
            // Parent rules come first, then child rules override by id.
            let parent_ids: std::collections::HashSet<String> =
                all_rules.iter().map(|r| r.id.clone()).collect();
            for rule in parent_config.rules {
                if !parent_ids.contains(&rule.id) {
                    all_rules.push(rule);
                }
            }
            // Inherit global allowlist if child doesn't have one.
            if global_allowlist.is_none() {
                global_allowlist = parent_config.allowlist;
            }
        }
    }

    let result = config_to_detectors_inner(&all_rules, global_allowlist)?;
    Ok(result)
}

/// Result of loading a config file: detectors + optional global allowlist.
pub struct ConfigLoadResult {
    pub detectors: Vec<Box<dyn Detector>>,
    pub global_allowlist: Option<Allowlist>,
}

/// Convert a parsed config into detectors + global allowlist.
/// Kept for backward compatibility — use `load_config` for full features.
pub fn config_to_detectors(config: &Config) -> Result<Vec<Box<dyn Detector>>, ConfigError> {
    let result = config_to_detectors_inner(&config.rules, config.allowlist.clone())?;
    Ok(result.detectors)
}

fn config_to_detectors_inner(
    rules: &[CustomRule],
    global_allowlist: Option<ConfigAllowlist>,
) -> Result<ConfigLoadResult, ConfigError> {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::new();

    for rule in rules {
        let severity = parse_severity(&rule.severity).ok_or_else(|| ConfigError::InvalidSeverity {
            rule_id: rule.id.clone(),
            severity: rule.severity.clone(),
        })?;

        let regex = regex::Regex::new(&rule.pattern).map_err(|e| ConfigError::InvalidRegex {
            rule_id: rule.id.clone(),
            error: e.to_string(),
        })?;

        let mut detector = RegexDetector::with_prefilter_owned(
            rule.id.clone(),
            rule.description.clone(),
            severity,
            regex,
            rule.prefilter.clone(),
        );

        if let Some(entropy) = rule.entropy {
            detector = detector.with_entropy(entropy);
        }

        if let Some(group) = rule.secret_group {
            detector = detector.with_secret_group(group);
        }

        if let Some(ref path_pattern) = rule.path {
            let path_re = regex::Regex::new(path_pattern).map_err(|e| ConfigError::InvalidPathRegex {
                rule_id: rule.id.clone(),
                error: e.to_string(),
            })?;
            detector = detector.with_path_filter(path_re);
        }

        // Merge all allowlists for this rule into one.
        if !rule.allowlists.is_empty() {
            let mut allowlist = Allowlist::default();
            for al in &rule.allowlists {
                for re_str in &al.regexes {
                    let re = regex::Regex::new(re_str).map_err(|e| {
                        ConfigError::InvalidAllowlistRegex {
                            rule_id: rule.id.clone(),
                            error: e.to_string(),
                        }
                    })?;
                    allowlist.regexes.push(re);
                }
                for path_str in &al.paths {
                    let re = regex::Regex::new(path_str).map_err(|e| {
                        ConfigError::InvalidAllowlistRegex {
                            rule_id: rule.id.clone(),
                            error: e.to_string(),
                        }
                    })?;
                    allowlist.paths.push(re);
                }
                allowlist.stopwords.extend(al.stopwords.iter().cloned());
            }
            detector = detector.with_allowlist(allowlist);
        }

        detectors.push(Box::new(detector));
    }

    // Build global allowlist if present.
    let global = global_allowlist.map(|al| {
        let mut allowlist = Allowlist::default();
        for re_str in &al.regexes {
            if let Ok(re) = regex::Regex::new(re_str) {
                allowlist.regexes.push(re);
            }
        }
        for path_str in &al.paths {
            if let Ok(re) = regex::Regex::new(path_str) {
                allowlist.paths.push(re);
            }
        }
        allowlist.stopwords = al.stopwords;
        allowlist
    });

    Ok(ConfigLoadResult {
        detectors,
        global_allowlist: global,
    })
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config_from_toml() {
        let toml = r#"
[[rules]]
id = "custom-api-key"
description = "My Custom API Key"
severity = "high"
pattern = '\bMYKEY_[A-Za-z0-9]{32}\b'
prefilter = ["MYKEY_"]

[[rules]]
id = "internal-token"
description = "Internal Service Token"
severity = "critical"
pattern = '\bINT_[A-Fa-f0-9]{40}\b'
prefilter = ["INT_"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let detectors = config_to_detectors(&config).unwrap();
        assert_eq!(detectors.len(), 2);

        let m = detectors[0].scan_line("key = MYKEY_abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(m.len(), 1);
        assert_eq!(detectors[0].id(), "custom-api-key");

        let m = detectors[1].scan_line("token = INT_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
        assert_eq!(m.len(), 1);
        assert_eq!(detectors[1].id(), "internal-token");
    }

    #[test]
    fn test_invalid_severity_errors() {
        let toml = r#"
[[rules]]
id = "bad-rule"
description = "Bad"
severity = "extreme"
pattern = 'foo'
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let result = config_to_detectors(&config);
        assert!(matches!(result, Err(ConfigError::InvalidSeverity { .. })));
    }

    #[test]
    fn test_invalid_regex_errors() {
        let toml = r#"
[[rules]]
id = "bad-regex"
description = "Bad Regex"
severity = "low"
pattern = '[invalid('
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let result = config_to_detectors(&config);
        assert!(matches!(result, Err(ConfigError::InvalidRegex { .. })));
    }

    #[test]
    fn test_empty_config() {
        let config = Config::default();
        let detectors = config_to_detectors(&config).unwrap();
        assert!(detectors.is_empty());
    }

    #[test]
    fn test_entropy_and_secret_group() {
        let toml = r#"
[[rules]]
id = "entropy-rule"
description = "Test entropy"
severity = "high"
pattern = 'token\s*=\s*([A-Za-z0-9]{20})'
secretGroup = 1
entropy = 3.0
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let detectors = config_to_detectors(&config).unwrap();
        assert_eq!(detectors.len(), 1);

        // High entropy match should be found.
        let m = detectors[0].scan_line("token = aB3dE5fG7hI9jK1lM3nO");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].text, "aB3dE5fG7hI9jK1lM3nO");

        // Low entropy match should be filtered out.
        let m = detectors[0].scan_line("token = aaaaaaaaaaaaaaaaaaaa");
        assert!(m.is_empty());
    }

    #[test]
    fn test_allowlist_suppresses_match() {
        let toml = r#"
[[rules]]
id = "test-rule"
description = "Test"
severity = "high"
pattern = 'KEY_[A-Za-z0-9]{20}'

[[rules.allowlists]]
regexes = ['EXAMPLE$']
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let detectors = config_to_detectors(&config).unwrap();
        assert_eq!(detectors.len(), 1);
        assert!(detectors[0].allowlist().is_some());
    }

    #[test]
    fn test_path_filter() {
        let toml = r#"
[[rules]]
id = "env-only"
description = "Env only"
severity = "high"
pattern = 'SECRET_[A-Za-z0-9]{20}'
path = '\.env$'
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let detectors = config_to_detectors(&config).unwrap();
        assert_eq!(detectors.len(), 1);
        assert!(detectors[0].path_filter().is_some());
    }
}
