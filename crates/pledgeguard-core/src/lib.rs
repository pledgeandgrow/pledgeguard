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
pub mod archive;
pub mod ast;
pub mod ast_comments;
pub mod baseline;
pub mod bpe;
pub mod ci_cd;
pub mod cloud_scan;
pub mod composite;
pub mod config;
pub mod content_decode;
pub mod context;
pub mod csv;
pub mod decode;
pub mod detector;
pub mod detectors;
pub mod docker;
pub mod enterprise;
pub mod entropy;
pub mod expr_filter;
pub mod extensibility;
pub mod file_scan;
pub mod finding;
pub mod fp_filters;
pub mod git_history;
pub mod github_actions;
pub mod iac_detection;
pub mod junit;
pub mod offline;
pub mod output_formats;
pub mod performance;
pub mod plugin;
pub mod redact;
pub mod sarif;
pub mod scanner;
pub mod source_scan;
pub mod source_scan2;
pub mod stream_scan;
pub mod template;
pub mod verify;

pub use ai::{
    AiConfig, Classification, ClassificationResult, ConfigMigration, FpAssessment,
    GeneratedDescription, GeneratedRegex, GeneratedTests, ImpactAnalysis, PrioritizedFinding,
    RemediationSuggestion, RiskScore, RotationGuidance, ScanSummary, TestCase,
    assess_false_positive, classify_finding, generate_description, generate_regex, generate_tests,
    impact_analysis, migrate_config, prioritize_findings, remediation_suggestion, risk_score,
    rotation_guidance, scan_summary,
};
pub use ai_hooks::{AiTool, HookInstallResult, format_install_summary, install_hooks};
pub use api_scan::{
    ApiScanError, GitHubScanConfig, GitLabScanConfig, scan_github_repo, scan_gitlab_repo,
};
pub use archive::{is_archive, scan_archive};
pub use baseline::{
    Baseline, BaselineEntry, filter as baseline_filter, from_findings as baseline_from_findings,
    load as load_baseline, save as save_baseline,
};
pub use bpe::BpeTokenizer;
pub use ci_cd::{
    BaselineCiConfig, CiError, CiPlatform, ExitCodeConfig, PrCommentConfig, ScanScope,
    append_report, azure_devops_template, bitbucket_pipe_template, circleci_orb_template,
    droneci_plugin_template, format_pr_comment, generate_junit_for_ci, gitlab_ci_template,
    husky_hook_template, jenkins_pipeline_template, lint_staged_template,
    post_azure_devops_pr_comment, post_github_pr_comment, post_gitlab_mr_comment,
    teamcity_template, upload_sarif_to_github,
};
pub use cloud_scan::{
    AzureBlobScanConfig, CloudScanError, GcsScanConfig, OssScanConfig, S3ScanConfig,
    scan_alibaba_oss, scan_azure_blob, scan_gcs_bucket, scan_s3_bucket,
};
pub use composite::{CompositeRule, scan_composite};
pub use config::{Config, ConfigAllowlist, ConfigError, ConfigLoadResult, CustomRule, load_config};
pub use content_decode::{
    ContentType, decode_content, decode_html_content, decode_html_entities, detect_content_type,
    extract_binary_strings, extract_binary_strings_min, extract_docx_text, extract_image_text,
    extract_jupyter_cells, extract_markdown_code_blocks, extract_pdf_text, extract_pptx_text,
    extract_xlsx_cells, extract_xml_values, extract_yaml_values, is_ocr_available, normalize_nfc,
    parse_csv, parse_csv_line, parse_dockerfile, parse_env_file, parse_hcl, parse_ini,
    scan_decoded_content, split_yaml_documents, strip_html_tags, unescape_json_string, url_decode,
};
pub use csv::to_csv;
pub use detector::{Allowlist, Detector, DetectorMatch, RegexDetector};
pub use docker::{DockerScanError, is_docker_image, scan_docker_image};
pub use enterprise::{
    AuditEntry, AuditLogger, ComplianceFramework, ComplianceReport, ComplianceStatus,
    CustomCategory, CustomCategoryConfig, CustomSeverity, CustomSeverityConfig, DiffFinding,
    DiffStatus, DiffSummary, EmailConfig, FindingComment, FindingEvidence, FindingState,
    FindingTracker, FindingTrackerExt, GlobalBaseline, Permission, Project, ProjectGroup,
    ProjectGroupConfig, ProjectRegistry, RbacConfig, Role, ScanSchedule, ScanScheduleConfig,
    SsoConfig, SsoProtocol, Suppression, TrackedFinding, TrackedFindingExt, WebhookConfig,
    WebhookType, diff_scans, diff_summary, generate_compliance_report, send_email_notification,
    send_webhook,
};
pub use expr_filter::ExprFilter;
pub use extensibility::{
    CaptureTransform, ConfigError as ExtensibilityConfigError, CustomEntropyConfig,
    CustomVerifierConfig, DetectorMetadata, DetectorVersion, DocRule, ExprVerifierConfig,
    LookaheadRule, MultiPatternRule, PluginContext, PluginMarketplace, PluginMarketplaceEntry,
    PluginType, RuleConditions, RuleDeprecation, RuleProfile, RuleTestCase, RuleTestResult,
    SeverityOverride, Transform, WasmVerifierConfig, WasmVerifyResult, apply_severity_overrides,
    compute_custom_entropy, evaluate_expr_verifier, generate_rule_docs, run_rule_tests, test_rule,
};
pub use file_scan::{FileScanError, scan_helm_chart, scan_k8s_secret, scan_terraform_state};
pub use finding::{Finding, Severity, VerificationStatus};
pub use fp_filters::{
    apply_all_filters, apply_content_filters, apply_path_filters, context_aware_entropy_threshold,
    detect_rotation, is_binary_content, is_ca_certificate_path, is_canary_token,
    is_documentation_path, is_env_file, is_example_value, is_generated_content, is_generated_path,
    is_hex_blob, is_lock_file, is_minified_path, is_uuid, is_valid_jwt_structure, is_vendored_path,
    join_multiline_secrets, parse_env_active_lines, should_suppress_by_content,
    should_suppress_by_path,
};
pub use git_history::{scan_git_history, scan_git_history_parallel, scan_git_history_with_scope};
pub use github_actions::to_github_actions;
pub use iac_detection::{
    IaCFileType, detect_acorn_secrets, detect_ansible_vault, detect_argocd_secrets,
    detect_aws_credentials_file, detect_cdk_secrets, detect_chef_data_bag, detect_circleci_secrets,
    detect_cloudformation_secrets, detect_cosign_secrets, detect_devspace_secrets,
    detect_docker_compose_secrets, detect_droneci_secrets, detect_env_file_secrets,
    detect_garden_secrets, detect_github_actions_secrets, detect_gitlab_ci_secrets,
    detect_helm_values_secrets, detect_iac_file_type, detect_jenkins_credentials,
    detect_k8s_pod_env_secrets, detect_kustomize_secrets, detect_okteto_secrets,
    detect_pulumi_config, detect_puppet_hiera, detect_secret_chains, detect_secret_pairs,
    detect_serverless_secrets, detect_skaffold_secrets, detect_terraform_cloud_secrets,
    detect_terraform_variable_secrets, detect_tiltfile_secrets, scan_iac_file,
};
pub use junit::to_junit;
pub use offline::{
    DetectorUpdate, OfflineConfig, OfflineError, RotationResult, TelemetryCollector,
    TelemetryEvent, VerificationCache, VerificationCacheEntry, ZeroKnowledgeProof,
    apply_detector_update, check_for_updates, generate_replacement_secret, get_help_topic,
    list_help_topics, load_encrypted_baseline, load_encrypted_report, redact_for_logging,
    rotate_secret, sanitize_log_line, save_encrypted_baseline, save_encrypted_report,
};
pub use output_formats::{
    to_cyclonedx, to_html, to_jsonl, to_markdown, to_prometheus, to_spdx, to_xml,
};
pub use performance::{
    BenchResult, FileHashEntry, IncrementalCache, MMAP_THRESHOLD, STREAMING_CHUNK_SIZE,
    STREAMING_OVERLAP, STREAMING_THRESHOLD, ScanProgress, benchmark_scan, cached_regex,
    cached_regex_with_options, clear_regex_cache, has_wasm_cache, load_ac_cache,
    read_file_optimized, regex_cache_size, save_ac_cache, stream_scan_file, wasm_cache_dir,
    wasm_cache_path, with_timeout,
};
pub use plugin::{PluginError, WasmDetector, load_plugins};
pub use sarif::to_sarif;
pub use scanner::{ScanError, ScanOptions, Scanner};
pub use source_scan::{
    ArtifactoryScanConfig, AwsSecretsManagerScanConfig, BuildkiteScanConfig,
    CircleCiArtifactsScanConfig, ConfluenceScanConfig, DroneCiScanConfig, GerritScanConfig,
    HuggingFaceScanConfig, JenkinsScanConfig, JiraScanConfig, PostmanScanConfig, PyPIScanConfig,
    SharePointScanConfig, SlackScanConfig, SourceScanError, TeamsScanConfig, TravisCiScanConfig,
    scan_artifactory, scan_aws_secrets_manager, scan_buildkite, scan_circleci_artifacts,
    scan_confluence, scan_droneci_builds, scan_gerrit, scan_huggingface, scan_jenkins_logs,
    scan_jira, scan_postman, scan_pypi, scan_sharepoint, scan_slack, scan_teams,
    scan_travis_ci_logs,
};
pub use source_scan2::{
    AwsSsmScanConfig, AzureDevOpsScanConfig, AzureKeyVaultScanConfig, BitbucketCloudScanConfig,
    BitbucketServerScanConfig, BitwardenScanConfig, CloudflareWorkersScanConfig, ConsulScanConfig,
    DiscordScanConfig, DopplerScanConfig, ElasticsearchScanConfig, EtcdScanConfig, FlyIoScanConfig,
    GcpSecretManagerScanConfig, GitHubActionsLogScanConfig, GitHubGistScanConfig,
    GitHubIssuesScanConfig, GitLabCiLogScanConfig, GitLabIssuesScanConfig, GiteaScanConfig,
    K8sConfigMapScanConfig, K8sEtcdScanConfig, LastPassScanConfig, LaunchDarklyScanConfig,
    MattermostScanConfig, NetlifyScanConfig, OnePasswordScanConfig, RailwayScanConfig,
    RedisScanConfig, RenderScanConfig, RssFeedScanConfig, SourceScanError2, SupabaseEnvScanConfig,
    VaultScanConfig, VercelScanConfig, scan_1password, scan_aws_ssm, scan_azure_devops,
    scan_azure_key_vault, scan_bitbucket_cloud, scan_bitbucket_server, scan_bitwarden,
    scan_cloudflare_workers, scan_consul, scan_discord, scan_doppler, scan_elasticsearch,
    scan_etcd, scan_fly_io, scan_gcp_secret_manager, scan_gitea, scan_github_actions_logs,
    scan_github_gists, scan_github_issues, scan_gitlab_ci_logs, scan_gitlab_issues,
    scan_k8s_configmaps, scan_k8s_etcd, scan_lastpass, scan_launchdarkly, scan_mattermost,
    scan_netlify, scan_railway, scan_redis, scan_render, scan_rss_feeds, scan_supabase_env,
    scan_vault, scan_vercel,
};
pub use stream_scan::{
    StreamScanError, SyslogScanConfig, scan_syslog_file, scan_syslog_stdin, scan_syslog_stream,
    scan_syslog_tcp, scan_vault_tokens_in_logs,
};
pub use template::to_template;
pub use verify::{VerifyOptions, verify_findings, verify_findings_with_options, verify_one};
