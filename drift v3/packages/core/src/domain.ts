export type ConventionKind =
  | "api_route_no_direct_data_access"
  | "api_route_requires_service_delegation"
  | "api_route_requires_auth_helper"
  | "test_expected_for_changed_module"
  | "custom_briefing"
  | AgentContractKind;

export type FileRole =
  | "api_route"
  | "server_module"
  | "service_module"
  | "data_access_module"
  | "component"
  | "ui_component"
  | "hook_module"
  | "schema_module"
  | "test"
  | "config"
  | "cli_command_module"
  | "core_module"
  | "query_module"
  | "factgraph_module"
  | "adapter_module"
  | "storage_module"
  | "engine_bridge_module"
  | "mcp_module"
  | "docs"
  | "package_manifest"
  | "custom";

export type CanonicalRole =
  | "route"
  | "controller"
  | "service"
  | "domain"
  | "data_access"
  | "schema"
  | "model"
  | "validation"
  | "auth"
  | "middleware"
  | "queue_worker"
  | "cron_job"
  | "event_handler"
  | "adapter"
  | "client_sdk"
  | "component"
  | "hook"
  | "test_unit"
  | "test_integration"
  | "test_e2e"
  | "config"
  | "script"
  | "migration"
  | "generated"
  | "documentation"
  | "unknown"
  | "mixed_role";

export type AgentContractKind =
  | "file_role"
  | "module_placement"
  | "import_boundary"
  | "entrypoint_flow"
  | "canonical_helper_reuse"
  | "required_change_checks";

export interface ConventionScope {
  path_globs: string[];
  package_names?: string[];
  file_roles?: FileRole[];
  include_symbols?: string[];
  exclude_path_globs?: string[];
}

export interface ConventionMatcher {
  kind: ConventionKind;
  forbidden_imports?: string[];
  forbidden_target_roles?: FileRole[];
  allowed_imports?: string[];
  required_calls?: string[];
  allowed_delegate_imports?: string[];
  applies_to_file_roles?: FileRole[];
}

export type EnforcementCapability =
  | "briefing_only"
  | "heuristic_check"
  | "deterministic_check";

export type Severity = "info" | "warning" | "error";

export type EnforcementMode = "off" | "brief" | "warn" | "block";

export interface ConventionScore {
  supporting_examples_count: number;
  counterexamples_count: number;
  scope_files_count: number;
  coverage_ratio: number;
  heuristic_id: string;
}

export interface ConventionException {
  id: string;
  reason: string;
  path_globs?: string[];
  symbols?: string[];
  imports?: string[];
  endpoint_paths?: string[];
  methods?: string[];
  resolved_modules?: string[];
  resolved_symbols?: string[];
  data_stores?: string[];
  operation_kinds?: Array<"read" | "write" | "delete" | "unknown">;
  file_roles?: FileRole[];
  contract_kinds?: AgentContractKind[];
  expires_at?: string;
  created_by: string;
  created_at: string;
}

export interface EvidenceRef {
  id: string;
  kind: "supporting" | "counterexample" | "violation" | "baseline";
  file_path: string;
  start_line?: number;
  end_line?: number;
  symbol?: string;
  import_source?: string;
  fact_ids: string[];
  scan_id: string;
  file_hash: string;
  artifact_hash?: string;
  redaction_state: "none" | "redacted" | "snippet_limited";
}

export interface RepoRecord {
  id: string;
  root_path: string;
  fingerprint: string;
  vcs_provider?: "git" | "none";
  remote_url_hash?: string | null;
  package_manager?: string;
  lockfile_hashes?: Record<string, string>;
  resolver_input_hash?: string;
  created_at: string;
  updated_at: string;
}

export interface ScanManifest {
  id: string;
  repo_id: string;
  branch: string;
  commit: string;
  dirty: boolean;
  previous_scan_id?: string;
  scanner_version: string;
  adapter_versions: Record<string, string>;
  rule_engine_version: string;
  status: "started" | "completed" | "failed";
  file_count: number;
  fact_count: number;
  finding_count: number;
  started_at: string;
  completed_at?: string;
  error_message?: string;
}

export interface FileSnapshot {
  repo_id: string;
  scan_id: string;
  file_path: string;
  content_hash: string;
  byte_size: number;
  indexed: boolean;
}

export type ScanFileChangeKind = "added" | "modified" | "deleted" | "unchanged";

export interface ScanFileChange {
  repo_id: string;
  scan_id: string;
  file_path: string;
  change_kind: ScanFileChangeKind;
  previous_hash?: string;
  current_hash?: string;
  created_at: string;
}

export interface ResolverDependency {
  repo_id: string;
  scan_id: string;
  id: string;
  source_path: string;
  dependency_path: string;
  dependency_kind: string;
}

export interface ModuleDependent {
  repo_id: string;
  scan_id: string;
  module_id: string;
  dependent_module_id: string;
  edge_id: string;
}

export interface SymbolOccurrence {
  repo_id: string;
  scan_id: string;
  id: string;
  symbol_id: string;
  occurrence_kind: "declaration" | "reference";
  file_path: string;
  start_line: number;
  end_line: number;
  evidence_id?: string;
}

export interface BackupManifest {
  id: string;
  repo_id: string;
  repo_fingerprint: string;
  schema_version: number;
  source_database_path: string;
  backup_path: string;
  checksum_sha256: string;
  size_bytes: number;
  created_at: string;
}

export type FactKind =
  | "file_detected"
  | "import_used"
  | "re_export_used"
  | "exported_symbol"
  | "symbol_called"
  | "data_operation_detected"
  | "route_declared"
  | "file_role_detected"
  | "test_declared";

export type FactEvidenceLevel = "path" | "text" | "ast" | "graph" | "heuristic";
export type FactResolutionStatus = "resolved" | "unresolved" | "partial" | "unsupported";
export type FactStalenessStatus = "fresh" | "stale" | "unknown";
export type ConfidenceLabel = "certain" | "high" | "medium" | "low" | "heuristic";

export interface SourceSpan {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
}

export interface FactRecord {
  id: string;
  repo_id: string;
  scan_id: string;
  kind: FactKind;
  file_path: string;
  name: string;
  value?: string;
  start_line: number;
  end_line: number;
  source_span: SourceSpan;
  ast_node_kind: string | null;
  extraction_method: string;
  extractor_version: string;
  parser_version: string;
  confidence: number;
  confidence_label: ConfidenceLabel;
  evidence_level: FactEvidenceLevel;
  resolution_status: FactResolutionStatus;
  staleness_status: FactStalenessStatus;
  last_seen_scan_id: string;
}

export type ParserGapKind =
  | "unresolved_import"
  | "unresolved_symbol"
  | "unknown_file_role"
  | "mixed_file_role"
  | "unsupported_framework_pattern"
  | "parser_error"
  | "partial_parse"
  | "dynamic_import_unresolved"
  | "reflection_or_magic_detected";

export type ParserGapConfidenceImpact = "none" | "lowers_file" | "lowers_flow" | "blocks_enforcement";

export interface ParserGap {
  schema_version: "drift.parser_gap.v1";
  gap_id: string;
  repo_id: string;
  scan_id: string;
  kind: ParserGapKind;
  file_path: string;
  start_line: number;
  end_line: number;
  confidence_impact: ParserGapConfidenceImpact;
  message: string;
  evidence_refs: string[];
  created_at: string;
}

export type EntrypointKind =
  | "api_route"
  | "page_route"
  | "server_action"
  | "cli_command"
  | "cron_job"
  | "queue_consumer"
  | "webhook_handler"
  | "middleware"
  | "test_entrypoint"
  | "script"
  | "migration"
  | "lambda_handler"
  | "worker";

export interface EntrypointFact {
  schema_version: "drift.entrypoint_fact.v1";
  entrypoint_id: string;
  repo_id: string;
  scan_id: string;
  kind: EntrypointKind;
  file_path: string;
  symbol?: string;
  route_pattern?: string;
  method?: string;
  adapter_id: string;
  confidence_label: ConfidenceLabel;
  evidence_refs: string[];
}

export type DataOperationFamily =
  | "orm_operation"
  | "raw_sql_operation"
  | "http_api_call"
  | "filesystem_write"
  | "cache_operation"
  | "queue_publish"
  | "queue_consume"
  | "env_secret_read"
  | "external_service_call"
  | "auth_session_read"
  | "payment_operation"
  | "email_send";

export type DataOperationEffect =
  | "read"
  | "write"
  | "delete"
  | "mutation"
  | "side_effect"
  | "external_effect"
  | "secret_access"
  | "network_effect";

export interface DataOperationRisk {
  schema_version: "drift.data_operation_risk.v1";
  operation_family: DataOperationFamily;
  effect: DataOperationEffect;
  risk: "read" | "write" | "destructive_write" | "side_effect" | "secret_access" | "external_effect" | "unknown";
  confidence_label: ConfidenceLabel;
}

export interface GraphNodeRecord {
  id: string;
  kind: "file" | "module" | "symbol" | "import" | "route" | "role" | "data_store" | "data_operation" | "endpoint" | "re_export";
  label: string;
}

export interface GraphEdgeRecord {
  id: string;
  kind:
    | "FILE_CONTAINS_SYMBOL"
    | "MODULE_IMPORTS_MODULE"
    | "FILE_HAS_ROLE"
    | "ROUTE_DECLARED_IN_FILE"
    | "ROUTE_HAS_ENDPOINT"
    | "MODULE_REEXPORTS_MODULE"
    | "REEXPORT_RESOLVES_TO_SYMBOL"
    | "IMPORT_RESOLVES_TO_MODULE"
    | "IMPORT_RESOLVES_TO_SYMBOL"
    | "DATA_OPERATION_READS_DATA_STORE"
    | "DATA_OPERATION_WRITES_DATA_STORE"
    | "DATA_OPERATION_DELETES_DATA_STORE"
    | "DATA_OPERATION_TOUCHES_DATA_STORE";
  from: string;
  to: string;
}

export interface FactGraphArtifact {
  id: string;
  repo_id: string;
  scan_id: string;
  schema_version: "factgraph.v1" | "factgraph.v2";
  graph_hash: string;
  graph: Record<string, unknown>;
  node_count: number;
  edge_count: number;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  repo_id: string;
  actor: string;
  action:
    | "repo_added"
    | "scan_started"
    | "scan_completed"
    | "scan_failed"
    | "election_accepted"
    | "election_rejected"
    | "election_edited"
    | "finding_resolved"
    | "finding_suppressed"
    | "finding_flagged_for_review"
    | "policy_changed"
    | "agent_permission_changed"
    | "backup_created"
    | "restore_completed"
    | "contract_exported"
    | "contract_imported"
    | "adapter_upgraded"
    | "scan_invalidated"
    | "baseline_created"
    | "baseline_cleared"
    | "required_check_executed";
  target_type: string;
  target_id: string;
  metadata: Record<string, unknown>;
  created_at: string;
  sequence?: number;
  previous_event_hash?: string | null;
  event_hash?: string | null;
}

export type ConventionStatus =
  | "candidate"
  | "accepted"
  | "rejected"
  | "archived"
  | "expired";

export interface ConventionCandidate {
  id: string;
  repo_id: string;
  scan_id: string;
  kind: ConventionKind;
  statement: string;
  rationale?: string;
  scope: ConventionScope;
  matcher: ConventionMatcher;
  suggested_severity: Severity;
  suggested_enforcement_mode: EnforcementMode;
  enforcement_capability: EnforcementCapability;
  confidence_label: "low" | "medium" | "high";
  scoring: ConventionScore;
  evidence_refs: EvidenceRef[];
  counterexample_refs: EvidenceRef[];
  status: ConventionStatus;
  created_at: string;
}

export interface AcceptedConvention {
  id: string;
  contract_id: string;
  kind: ConventionKind;
  statement: string;
  rationale?: string;
  scope: ConventionScope;
  matcher: ConventionMatcher;
  severity: Severity;
  enforcement_mode: EnforcementMode;
  enforcement_capability: EnforcementCapability;
  exceptions: ConventionException[];
  evidence_refs: EvidenceRef[];
  counterexample_refs: EvidenceRef[];
  accepted_by: string;
  accepted_at: string;
  updated_at: string;
  expires_at?: string;
}

export interface RejectedInference {
  candidate_id: string;
  reason: string;
  rejected_by: string;
  rejected_at: string;
}

export interface BaselineViolation {
  id: string;
  repo_id: string;
  convention_id: string;
  finding_fingerprint: string;
  file_path: string;
  first_seen_scan_id: string;
  first_seen_commit: string;
  status: "active" | "resolved";
  created_at: string;
}

export type FindingStatus =
  | "new"
  | "pre_existing"
  | "needs_review"
  | "fixed"
  | "false_positive"
  | "accepted_drift"
  | "suppressed"
  | "expired";

export type FindingDiffStatus =
  | "new_in_diff"
  | "touched_existing"
  | "outside_diff";

export type CheckRunStatus = "pass" | "fail" | "blocked";

export interface CheckRun {
  id: string;
  repo_id: string;
  repo_contract_id: string;
  contract_fingerprint: string;
  scan_id: string;
  status: CheckRunStatus;
  scope: "changed-hunks" | "changed-files" | "full";
  engine_source: "rust" | "typescript";
  fallback_used: boolean;
  stale_scan: boolean;
  capability_complete: boolean;
  findings_count: number;
  blocking_count: number;
  started_at: string;
  completed_at: string;
}

export interface Finding {
  id: string;
  repo_id: string;
  convention_id: string;
  check_id?: string;
  repo_contract_id?: string;
  fingerprint: string;
  title: string;
  message: string;
  severity: Severity;
  enforcement_result: "none" | "warn" | "block";
  status: FindingStatus;
  diff_status: FindingDiffStatus;
  evidence_refs: EvidenceRef[];
  expected_layer?: string;
  actual_layer?: string;
  graph_path?: string[];
  suggested_fix?: string;
  related_node_ids?: string[];
  created_at: string;
}

export type HelperSimilarityFeature =
  | "name_tokens"
  | "purpose_tags"
  | "parameter_shape"
  | "return_shape"
  | "call_dependencies"
  | "import_dependencies"
  | "body_operation_kinds";

export interface HelperSimilarityEvidence {
  schema_version: "drift.helper_similarity.v1";
  candidate_symbol: string;
  candidate_file_path: string;
  canonical_symbol: string;
  canonical_module: string;
  score: number;
  score_band: "low" | "medium" | "high" | "deterministic";
  matched_features: HelperSimilarityFeature[];
  missing_features: string[];
  evidence_refs: string[];
  blocking_allowed: boolean;
}

export interface EntrypointFlowProofStep {
  step_kind: "auth_helper" | "validation_helper" | "service_delegation" | "response_boundary";
  satisfied: boolean;
  evidence_refs: string[];
  graph_path: string[];
}

export interface EntrypointFlowForbiddenProofStep {
  step_kind: "direct_data_access" | "inline_business_logic";
  present: boolean;
  evidence_refs: string[];
  graph_path: string[];
}

export interface EntrypointFlowProof {
  schema_version: "drift.entrypoint_flow_proof.v1";
  entry_file_path: string;
  contract_id: string;
  required_steps: EntrypointFlowProofStep[];
  forbidden_steps: EntrypointFlowForbiddenProofStep[];
  missing_evidence: string[];
}

export interface RequiredCheckExecution {
  schema_version: "drift.required_check_execution.v1";
  execution_id: string;
  repo_id: string;
  repo_root: string;
  repo_commit: string;
  worktree_dirty: boolean;
  scan_id: string | null;
  repo_contract_id: string;
  agent_contract_id: string;
  command: string;
  argv: string[];
  command_hash: string;
  cwd: string;
  started_at: string;
  completed_at: string;
  timeout_ms: number;
  exit_code: number | null;
  status: "passed" | "failed" | "timed_out" | "blocked";
  stdout_hash: string;
  stderr_hash: string;
  stdout_preview: string;
  stderr_preview: string;
  audit_event_id: string;
}

export interface RiskArea {
  id: string;
  path_globs: string[];
  risk_kind:
    | "auth"
    | "billing"
    | "data_access"
    | "migration"
    | "secrets"
    | "external_api"
    | "generated_code";
  reason: string;
}

export interface SafeCommand {
  command: string;
  reason: string;
  requires_explicit_run: true;
}

export interface RequiredCheck {
  command: string;
  applies_to: ConventionScope;
  reason: string;
  source?: "contract" | "graph_risk";
  evidence_node_ids?: string[];
  risk_kinds?: string[];
}

export type AgentContractEnforcement = "blocking" | "advisory";

export interface FileRoleAgentContract {
  kind: "file_role";
  id: string;
  version: 1;
  roles: Array<{
    role: FileRole;
    path_globs: string[];
    required_exports?: string[];
    forbidden_imports?: string[];
    confidence: "deterministic" | "heuristic";
  }>;
}

export interface ModulePlacementAgentContract {
  kind: "module_placement";
  id: string;
  version: 1;
  statement: string;
  target_role: FileRole;
  allowed_paths: string[];
  forbidden_paths?: string[];
  required_parent_roles?: FileRole[];
  forbidden_contained_roles?: FileRole[];
  examples?: {
    good: string[];
    bad: string[];
  };
  enforcement: AgentContractEnforcement;
}

export interface ImportBoundaryAgentContract {
  kind: "import_boundary";
  id: string;
  version: 1;
  source_roles: FileRole[];
  forbidden_imports?: string[];
  forbidden_target_roles?: FileRole[];
  allowed_imports?: string[];
  allowed_delegate_imports?: string[];
  enforcement: AgentContractEnforcement;
}

export type EntrypointFlowRequiredStep =
  | { kind: "auth_helper"; imports?: string[]; calls?: string[] }
  | { kind: "validation_helper"; imports?: string[]; calls?: string[] }
  | { kind: "service_delegation"; target_roles?: FileRole[]; imports?: string[] }
  | { kind: "response_boundary"; calls?: string[] };

export type EntrypointFlowForbiddenStep =
  | { kind: "direct_data_access" }
  | { kind: "inline_business_logic" };

export interface EntrypointFlowAgentContract {
  kind: "entrypoint_flow";
  id: string;
  version: 1;
  entry_roles: FileRole[];
  required_steps: EntrypointFlowRequiredStep[];
  forbidden_steps?: EntrypointFlowForbiddenStep[];
  enforcement: AgentContractEnforcement;
}

export interface CanonicalHelperReuseAgentContract {
  kind: "canonical_helper_reuse";
  id: string;
  version: 1;
  canonical_helpers: Array<{
    helper_id: string;
    symbol: string;
    module: string;
    roles?: FileRole[];
    applies_to_roles?: FileRole[];
    purpose_tags: string[];
    avoid_new_symbols_matching?: string[];
    avoid_new_files_matching?: string[];
    suggested_import: string;
  }>;
  enforcement: AgentContractEnforcement;
}

export interface RequiredChangeChecksAgentContract {
  kind: "required_change_checks";
  id: string;
  version: 1;
  rules: Array<{
    applies_to: {
      path_globs?: string[];
      file_roles?: FileRole[];
      convention_kinds?: string[];
    };
    required_checks: Array<{
      command: string;
      reason: string;
      required_for_release?: boolean;
    }>;
  }>;
}

export type AgentContract =
  | FileRoleAgentContract
  | ModulePlacementAgentContract
  | ImportBoundaryAgentContract
  | EntrypointFlowAgentContract
  | CanonicalHelperReuseAgentContract
  | RequiredChangeChecksAgentContract;

export interface AgentContractSelection {
  schema_version: "drift.agent.contract_selection.v1";
  repo_id: string;
  scan_id: string;
  selected_contract_ids: string[];
  selected_convention_ids: string[];
  selected_helper_ids: string[];
  selected_required_checks: string[];
  selection_inputs: {
    task_text?: string;
    explicit_paths: string[];
    changed_paths: string[];
    file_roles: FileRole[];
    graph_node_ids: string[];
  };
  reasons: Array<{
    target_id: string;
    reason:
      | "path_match"
      | "role_match"
      | "task_text_match"
      | "graph_reachable"
      | "contract_dependency"
      | "active_waiver";
    evidence_refs: string[];
  }>;
}

export interface AgentPreflightPacket {
  schema_version: "drift.agent.preflight.v3";
  repo_id: string;
  scan_id: string | null;
  stale: boolean;
  task: string;
  selected_contracts: unknown[];
  selected_conventions: unknown[];
  selected_helpers: Array<{
    symbol: string;
    module: string;
    suggested_import: string;
    purpose_tags: string[];
  }>;
  placement_guidance: Array<{
    role: FileRole;
    allowed_paths: string[];
    forbidden_paths: string[];
  }>;
  import_boundaries: unknown[];
  required_flows: unknown[];
  required_checks: Array<{
    command: string;
    reason: string;
  }>;
  active_exceptions: unknown[];
  active_waivers: unknown[];
  agent_instructions: string[];
  diagnostics: string[];
}

export interface ContractFindingV2 {
  schema_version: "drift.finding.v2";
  finding_id: string;
  contract_id: string;
  convention_id?: string;
  kind: string;
  severity: Severity;
  status: "blocking" | "advisory" | "waived" | "blocked_by_missing_evidence";
  file_path: string;
  range?: {
    start_line: number;
    end_line: number;
  };
  expected: string;
  actual: string;
  evidence_refs: string[];
  graph_path?: string[];
  suggested_fix: string;
  diagnostics: string[];
}

export interface ContextEgressPolicy {
  default_mode: "local_only" | "redacted" | "approval_required";
  denied_globs: string[];
  max_snippet_chars: number;
  allow_full_file_content: boolean;
}

export interface AgentPermission {
  agent: string;
  permissions: Array<"read_context" | "request_preflight" | "propose_resolution">;
}

export interface LayerArchitectureContract {
  schema_version: "drift.layer_architecture.v1";
  architecture_id: string;
  repo_id: string;
  version: number;
  layers: Array<{
    id: string;
    role: CanonicalRole;
    position: "entrypoint" | "middle" | "terminal" | "support";
  }>;
  allowed_edges: Array<{ from_layer: string; to_layer: string; edge_kind?: string }>;
  forbidden_edges: Array<{ from_layer: string; to_layer: string; edge_kind?: string }>;
  soft_edges: Array<{ from_layer: string; to_layer: string; reason: string; edge_kind?: string }>;
}

export interface RepoContract {
  id: string;
  repo_id: string;
  contract_schema_version: number;
  repo_fingerprint: string;
  created_at: string;
  updated_at: string;
  conventions: AcceptedConvention[];
  rejected_inferences: RejectedInference[];
  waivers: ConventionException[];
  risky_areas: RiskArea[];
  agent_contracts?: AgentContract[];
  layer_architecture?: LayerArchitectureContract;
  safe_commands: SafeCommand[];
  required_checks: RequiredCheck[];
  context_egress: ContextEgressPolicy;
  agent_permissions: AgentPermission[];
}

export interface PolicyDecision {
  allowed: boolean;
  surface: "cli-preflight" | "cli-check" | "mcp" | "contract-export" | "artifact" | "log" | "ui";
  mode: "local_only" | "redacted" | "approval_required" | "denied";
  reason: string;
  max_snippet_chars: number;
  approved_snippet_chars: number;
}
