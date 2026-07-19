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

pub mod ai;
pub mod ai_hooks;
pub mod api_scan;
pub mod enterprise;
pub mod archive;
pub mod ast;
pub mod ast_comments;
pub mod baseline;
pub mod bpe;
pub mod cloud_scan;
pub mod composite;
pub mod config;
pub mod context;
pub mod csv;
pub mod decode;
pub mod expr_filter;
pub mod detector;
pub mod detectors;
pub mod docker;
pub mod entropy;
pub mod finding;
pub mod git_history;
pub mod github_actions;
pub mod junit;
pub mod plugin;
pub mod redact;
pub mod sarif;
pub mod file_scan;
pub mod scanner;
pub mod source_scan;
pub mod source_scan2;
pub mod stream_scan;
pub mod template;
pub mod verify;
pub mod output_formats;
pub mod fp_filters;
pub mod extensibility;
pub mod offline;
pub mod content_decode;

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
pub use github_actions::to_github_actions;
pub use expr_filter::ExprFilter;
pub use bpe::BpeTokenizer;
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
    scan_huggingface, scan_sharepoint, scan_teams, scan_pypi,
    ConfluenceScanConfig, SlackScanConfig, JiraScanConfig, PostmanScanConfig,
    GerritScanConfig, BuildkiteScanConfig, ArtifactoryScanConfig,
    AwsSecretsManagerScanConfig, CircleCiArtifactsScanConfig, TravisCiScanConfig,
    JenkinsScanConfig, DroneCiScanConfig,
    HuggingFaceScanConfig, SharePointScanConfig, TeamsScanConfig, PyPIScanConfig,
    SourceScanError,
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
pub use verify::{verify_findings, verify_findings_with_options, verify_one, VerifyOptions};
pub use ai::{
    AiConfig, Classification, ClassificationResult, RemediationSuggestion,
    FpAssessment, RotationGuidance, RiskScore, GeneratedDescription,
    GeneratedRegex, GeneratedTests, TestCase, ConfigMigration,
    ScanSummary, ImpactAnalysis, PrioritizedFinding,
    classify_finding, remediation_suggestion, assess_false_positive,
    rotation_guidance, risk_score, generate_description, generate_regex,
    generate_tests, migrate_config, scan_summary, impact_analysis,
    prioritize_findings,
};
pub use ai_hooks::{
    AiTool, HookInstallResult, install_hooks, format_install_summary,
};
pub use enterprise::{
    AuditEntry, AuditLogger, ComplianceFramework, ComplianceReport, ComplianceStatus,
    DiffFinding, DiffStatus, DiffSummary, FindingState, FindingTracker, Permission,
    RbacConfig, Role, Suppression, TrackedFinding, WebhookConfig, WebhookType,
    diff_scans, diff_summary, generate_compliance_report, send_webhook,
};
pub use source_scan2::{
    scan_gitea, scan_bitbucket_cloud, scan_bitbucket_server, scan_azure_devops,
    scan_launchdarkly, scan_consul, scan_etcd, scan_redis, scan_elasticsearch,
    scan_aws_ssm, scan_gcp_secret_manager, scan_azure_key_vault, scan_vault,
    scan_doppler, scan_1password, scan_lastpass, scan_bitwarden,
    scan_k8s_configmaps, scan_k8s_etcd, scan_cloudflare_workers,
    scan_vercel, scan_netlify, scan_railway, scan_render, scan_fly_io,
    scan_supabase_env, scan_github_gists, scan_github_issues,
    scan_github_actions_logs, scan_gitlab_issues, scan_gitlab_ci_logs,
    scan_discord, scan_mattermost, scan_rss_feeds,
    GiteaScanConfig, BitbucketCloudScanConfig, BitbucketServerScanConfig,
    AzureDevOpsScanConfig, LaunchDarklyScanConfig, ConsulScanConfig,
    EtcdScanConfig, RedisScanConfig, ElasticsearchScanConfig,
    AwsSsmScanConfig, GcpSecretManagerScanConfig, AzureKeyVaultScanConfig,
    VaultScanConfig, DopplerScanConfig, OnePasswordScanConfig,
    LastPassScanConfig, BitwardenScanConfig, K8sConfigMapScanConfig,
    K8sEtcdScanConfig, CloudflareWorkersScanConfig, VercelScanConfig,
    NetlifyScanConfig, RailwayScanConfig, RenderScanConfig, FlyIoScanConfig,
    SupabaseEnvScanConfig, GitHubGistScanConfig, GitHubIssuesScanConfig,
    GitHubActionsLogScanConfig, GitLabIssuesScanConfig, GitLabCiLogScanConfig,
    DiscordScanConfig, MattermostScanConfig, RssFeedScanConfig,
    SourceScanError2,
};
pub use output_formats::{
    to_html, to_markdown, to_spdx, to_cyclonedx,
    to_prometheus, to_jsonl, to_xml,
};
pub use fp_filters::{
    parse_env_active_lines, is_env_file, is_documentation_path,
    is_generated_content, is_generated_path, is_vendored_path,
    is_minified_path, is_lock_file, is_binary_content, is_ca_certificate_path,
    is_example_value, is_canary_token, context_aware_entropy_threshold,
    detect_rotation, join_multiline_secrets, is_hex_blob, is_uuid,
    is_valid_jwt_structure, should_suppress_by_path, should_suppress_by_content,
    apply_path_filters, apply_content_filters, apply_all_filters,
};
pub use extensibility::{
    CustomVerifierConfig, ExprVerifierConfig, evaluate_expr_verifier,
    DetectorVersion, WasmVerifierConfig, WasmVerifyResult,
    PluginContext, PluginMarketplaceEntry, PluginType, PluginMarketplace,
    RuleProfile, RuleConditions, SeverityOverride, apply_severity_overrides,
    DetectorMetadata, CustomEntropyConfig, compute_custom_entropy,
    MultiPatternRule, LookaheadRule, CaptureTransform, Transform,
    RuleDeprecation, RuleTestCase, RuleTestResult, test_rule, run_rule_tests,
    generate_rule_docs, DocRule, ConfigError as ExtensibilityConfigError,
};
pub use offline::{
    OfflineConfig, DetectorUpdate, check_for_updates, apply_detector_update,
    VerificationCache, VerificationCacheEntry,
    get_help_topic, list_help_topics,
    TelemetryEvent, TelemetryCollector,
    redact_for_logging, sanitize_log_line,
    save_encrypted_baseline, load_encrypted_baseline,
    save_encrypted_report, load_encrypted_report,
    ZeroKnowledgeProof,
    generate_replacement_secret, rotate_secret, RotationResult,
    OfflineError,
};
pub use content_decode::{
    decode_html_entities, strip_html_tags, decode_html_content,
    url_decode, normalize_nfc, unescape_json_string,
    split_yaml_documents, extract_yaml_values,
    extract_xml_values,
    parse_csv_line, parse_csv,
    parse_ini, parse_env_file, parse_dockerfile, parse_hcl,
    extract_markdown_code_blocks, extract_jupyter_cells,
    extract_pdf_text, extract_docx_text, extract_xlsx_cells, extract_pptx_text,
    extract_image_text, is_ocr_available,
    extract_binary_strings, extract_binary_strings_min,
    detect_content_type, decode_content, scan_decoded_content, ContentType,
};
