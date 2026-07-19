//! PledgeGuard — Rust-native secret scanner.
//!
//! `pledgeguard-core` provides the detection engine: a [`Detector`] trait,
//! a set of built-in regex + entropy detectors for common secret formats
//! (AWS, GitHub, Slack, Stripe, Google, PEM private keys, JWTs, DB connection
//! strings, etc.), and a [`Scanner`] that walks a filesystem path (respecting
//! `.gitignore`) and applies detectors in parallel.
//!
//! # Example
//!
//! ```
//! use pledgeguard_core::{Scanner, detectors::builtin_detectors};
//!
//! let scanner = Scanner::new(builtin_detectors());
//! let findings = scanner.scan_str(
//!     std::path::Path::new("example.env"),
//!     "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
//! );
//! assert!(!findings.is_empty());
//! ```

pub mod api_scan;
pub mod archive;
pub mod ast;
pub mod baseline;
pub mod cloud_scan;
pub mod composite;
pub mod config;
pub mod context;
pub mod csv;
pub mod decode;
pub mod detector;
pub mod detectors;
pub mod docker;
pub mod entropy;
pub mod finding;
pub mod git_history;
pub mod junit;
pub mod plugin;
pub mod redact;
pub mod sarif;
pub mod file_scan;
pub mod scanner;
pub mod source_scan;
pub mod stream_scan;
pub mod template;
pub mod verify;

pub use baseline::{
    Baseline, BaselineEntry, filter as baseline_filter, from_findings as baseline_from_findings,
    load as load_baseline, save as save_baseline,
};
pub use config::{Config, ConfigAllowlist, ConfigError, ConfigLoadResult, CustomRule, load_config};
pub use detector::{Allowlist, Detector, DetectorMatch, RegexDetector};
pub use finding::{Finding, Severity, VerificationStatus};
pub use git_history::scan_git_history;
pub use plugin::{PluginError, WasmDetector, load_plugins};
pub use sarif::to_sarif;
pub use scanner::{ScanError, ScanOptions, Scanner};
pub use csv::to_csv;
pub use junit::to_junit;
pub use template::to_template;
pub use composite::{scan_composite, CompositeRule};
pub use archive::{is_archive, scan_archive};
pub use docker::{scan_docker_image, is_docker_image, DockerScanError};
pub use api_scan::{scan_github_repo, scan_gitlab_repo, GitHubScanConfig, GitLabScanConfig, ApiScanError};
pub use cloud_scan::{scan_s3_bucket, scan_gcs_bucket, scan_azure_blob, scan_alibaba_oss, S3ScanConfig, GcsScanConfig, AzureBlobScanConfig, OssScanConfig, CloudScanError};
pub use source_scan::{
    scan_confluence, scan_slack, scan_jira, scan_postman, scan_gerrit,
    scan_buildkite, scan_artifactory, scan_aws_secrets_manager,
    scan_circleci_artifacts, scan_travis_ci_logs, scan_jenkins_logs, scan_droneci_builds,
    ConfluenceScanConfig, SlackScanConfig, JiraScanConfig, PostmanScanConfig,
    GerritScanConfig, BuildkiteScanConfig, ArtifactoryScanConfig,
    AwsSecretsManagerScanConfig, CircleCiArtifactsScanConfig, TravisCiScanConfig,
    JenkinsScanConfig, DroneCiScanConfig, SourceScanError,
};
pub use file_scan::{
    scan_helm_chart, scan_terraform_state, scan_k8s_secret,
    FileScanError,
};
pub use stream_scan::{
    scan_syslog_stream, scan_syslog_file, scan_syslog_stdin,
    scan_syslog_tcp, scan_vault_tokens_in_logs,
    SyslogScanConfig, StreamScanError,
};
pub use verify::{verify_findings, verify_findings_with_options, VerifyOptions};
