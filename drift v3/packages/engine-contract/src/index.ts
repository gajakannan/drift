import { z } from "zod";
import {
  GraphEdgeSchema,
  GraphEvidenceSchema,
  GraphNodeSchema
} from "@drift/factgraph";

export const ENGINE_SCAN_REQUEST_SCHEMA_VERSION = "engine.scan.request.v1";
export const ENGINE_SCAN_RESULT_SCHEMA_VERSION = "engine.scan.result.v1";
export const ENGINE_CHECK_REQUEST_SCHEMA_VERSION = "engine.check.request.v1";
export const ENGINE_CHECK_RESULT_SCHEMA_VERSION = "engine.check.result.v1";
export const ENGINE_CANDIDATES_RESULT_SCHEMA_VERSION = "engine.candidates.result.v1";
export const ENGINE_STREAM_EVENT_SCHEMA_VERSION = "engine.stream.event.v1";
export const ENGINE_SECURITY_PROOF_EVENT_SCHEMA_VERSION = "engine.security.proof/v1";

const DiagnosticSeveritySchema = z.enum(["info", "warning", "error"]);
const DiffModeSchema = z.enum(["changed-hunks", "changed-files", "full"]);
const CompletenessScopeSchema = z.enum(["repo", "changed-files", "changed-hunks", "route-flow", "file"]);

export const EngineLimitsSchema = z.object({
  max_files_seen: z.number().int().positive(),
  max_files_parsed: z.number().int().positive(),
  max_file_bytes: z.number().int().positive(),
  max_facts: z.number().int().positive(),
  max_graph_nodes: z.number().int().nonnegative(),
  max_graph_edges: z.number().int().nonnegative(),
  max_diagnostics: z.number().int().nonnegative(),
  max_duration_ms: z.number().int().positive().optional(),
  follow_symlinks: z.literal(false)
});

export const EngineCapabilityStatsSchema = z.object({
  certified: z.array(z.string().min(1)),
  required: z.array(z.string().min(1)),
  missing: z.array(z.string().min(1))
});

export const EngineStatsSchema = z.object({
  files_seen: z.number().int().nonnegative(),
  files_skipped: z.number().int().nonnegative(),
  files_parsed: z.number().int().nonnegative(),
  files_reused: z.number().int().nonnegative().optional(),
  reuse_applied: z.boolean().optional(),
  reuse_blocked_reasons: z.array(z.string().min(1)).optional(),
  facts_emitted: z.number().int().nonnegative(),
  graph_nodes: z.number().int().nonnegative(),
  graph_edges: z.number().int().nonnegative(),
  diagnostics_emitted: z.number().int().nonnegative(),
  duration_ms: z.number().int().nonnegative(),
  peak_rss_bytes: z.number().int().nonnegative().optional(),
  batch_count: z.number().int().nonnegative().optional(),
  spill_artifacts_written: z.number().int().nonnegative().optional(),
  truncated: z.boolean(),
  truncation_reason: z.string().min(1).optional(),
  capabilities: EngineCapabilityStatsSchema.optional()
});

export const EngineDiagnosticSchema = z.object({
  severity: DiagnosticSeveritySchema,
  code: z.string().min(1),
  message: z.string().min(1),
  file_path: z.string().min(1).optional(),
  evidence_id: z.string().min(1).optional()
});

export const EngineCompletenessSchema = z.object({
  scope: CompletenessScopeSchema,
  rule_id: z.string().min(1).optional(),
  complete: z.boolean(),
  required_capabilities: z.array(z.string().min(1)),
  missing_capabilities: z.array(z.string().min(1)),
  truncated: z.boolean(),
  can_block: z.boolean(),
  reasons: z.array(z.string())
});

export const EngineFileSnapshotSchema = z.object({
  file_path: z.string().min(1),
  content_hash: z.string().min(1),
  byte_size: z.number().int().nonnegative(),
  indexed: z.boolean()
});

export const EngineFactSchema = z.object({
  kind: z.enum([
    "file_detected",
    "import_used",
    "re_export_used",
    "exported_symbol",
    "symbol_called",
    "data_operation_detected",
    "route_declared",
    "file_role_detected",
    "test_declared",
    "auth_guard_called",
    "route_returns_response",
    "callback_boundary_detected",
    "middleware_declared",
    "middleware_matcher_declared",
    "middleware_protects_route",
    "request_input_read",
    "request_validation_called",
    "validated_input_used",
    "sensitive_field_declared",
    "response_emits_field",
    "serializer_called",
    "secret_read"
  ]),
  file_path: z.string().min(1),
  name: z.string().min(1),
  value: z.string().optional(),
  imported_name: z.string().optional(),
  start_line: z.number().int().positive(),
  end_line: z.number().int().positive()
});

export const EngineRepoContextSchema = z.object({
  repo_id: z.string().min(1),
  repo_root: z.string().min(1),
  branch: z.string().min(1),
  commit: z.string().min(1),
  dirty: z.boolean()
});

export const EngineScanRequestSchema = z.object({
  schema_version: z.literal(ENGINE_SCAN_REQUEST_SCHEMA_VERSION),
  repo: EngineRepoContextSchema,
  limits: EngineLimitsSchema,
  adapters: z.object({
    enabled: z.array(z.string().min(1)),
    disabled: z.array(z.string().min(1)),
    required_capabilities: z.array(z.string().min(1))
  }),
  policy: z.object({
    denied_globs: z.array(z.string().min(1)),
    max_snippet_chars: z.number().int().nonnegative(),
    allow_full_file_content: z.literal(false)
  })
});

export const EngineScanResultSchema = z.object({
  schema_version: z.literal(ENGINE_SCAN_RESULT_SCHEMA_VERSION),
  repo_id: z.string().min(1),
  scan_id: z.string().min(1),
  engine_version: z.string().min(1),
  adapter_versions: z.record(z.string().min(1)),
  file_snapshots: z.array(EngineFileSnapshotSchema),
  facts: z.array(EngineFactSchema),
  graph: z.unknown().optional(),
  diagnostics: z.array(EngineDiagnosticSchema),
  stats: EngineStatsSchema,
  completeness: z.array(EngineCompletenessSchema)
});

const Phase5EngineSensitiveFieldSchema = z.object({
  field_path: z.string().min(1),
  classification: z.enum(["pii", "credential", "token", "tenant_secret", "internal"]),
  source: z.enum(["contract", "schema", "candidate"])
});

const Phase5EngineResponseSerializerSchema = z.object({
  serializer_id: z.string().min(1),
  import_source: z.string().min(1),
  imported_name: z.string().min(1).optional(),
  local_name: z.string().min(1).optional(),
  policy: z.enum(["allowlist", "denylist"], {
    errorMap: () => ({ message: "serializer policy must be allowlist or denylist" })
  }),
  filtered_fields: z.array(z.string().min(1))
});

const Phase5EngineSensitiveResponseRequiresSchema = z.object({
  sensitive_response_fields: z.array(Phase5EngineSensitiveFieldSchema).optional(),
  response_serializers: z.array(Phase5EngineResponseSerializerSchema).optional()
}).strict();

const Phase5EngineSecretExposureRequiresSchema = z.object({
  secret_sources: z.array(z.enum(["env", "config", "secret_manager"])).optional(),
  log_sinks: z.array(z.string().min(1)).optional()
}).strict();

function containsEngineSourceValue(payload: unknown): boolean {
  if (!payload || typeof payload !== "object") {
    return false;
  }

  if (Array.isArray(payload)) {
    return payload.some(containsEngineSourceValue);
  }

  return Object.entries(payload).some(([key, value]) =>
    [
      "source_value",
      "secret_value",
      "env_value",
      "token_value",
      "cookie_value",
      "header_value",
      "request_payload"
    ].includes(key) || containsEngineSourceValue(value)
  );
}

const EngineConventionSchema = z.object({
  id: z.string().min(1),
  rule_id: z.string().min(1),
  rule_version: z.string().min(1).optional(),
  kind: z.string().min(1),
  matcher: z.record(z.unknown()),
  scope: z.record(z.unknown()).optional(),
  requires: z.record(z.unknown()).optional(),
  exceptions: z.array(z.record(z.unknown())).optional(),
  governance: z.record(z.unknown()).optional(),
  severity: z.enum(["info", "warning", "error"]),
  enforcement_mode: z.enum(["off", "brief", "warn", "block"]),
  enforcement_capability: z.enum(["briefing_only", "heuristic_check", "deterministic_check"])
}).superRefine((convention, context) => {
  if (
    convention.kind !== "api_route_forbids_sensitive_response_fields" &&
    convention.kind !== "api_route_forbids_secret_exposure"
  ) {
    return;
  }

  if (containsEngineSourceValue(convention.requires)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "source values are not allowed in Phase 5 security contracts",
      path: ["requires"]
    });
  }

  const requiresResult = convention.kind === "api_route_forbids_sensitive_response_fields"
    ? Phase5EngineSensitiveResponseRequiresSchema.safeParse(convention.requires ?? {})
    : Phase5EngineSecretExposureRequiresSchema.safeParse(convention.requires ?? {});

  if (!requiresResult.success) {
    for (const issue of requiresResult.error.issues) {
      context.addIssue({
        ...issue,
        path: ["requires", ...issue.path]
      });
    }
    return;
  }

  if (
    convention.enforcement_mode === "block" &&
    convention.kind === "api_route_forbids_sensitive_response_fields"
  ) {
    const fields = Phase5EngineSensitiveResponseRequiresSchema.parse(convention.requires ?? {})
      .sensitive_response_fields ?? [];
    if (fields.some((field) => field.source === "candidate")) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "candidate sensitive fields cannot back blocking enforcement",
        path: ["requires", "sensitive_response_fields"]
      });
    }
  }
});

const EngineWaiverSchema = z.object({
  id: z.string().min(1),
  convention_id: z.string().min(1).optional(),
  finding_fingerprint: z.string().min(1).optional(),
  path_globs: z.array(z.string().min(1)).optional(),
  reason: z.string().min(1)
});

const EngineBaselineViolationSchema = z.object({
  convention_id: z.string().min(1),
  finding_fingerprint: z.string().min(1),
  status: z.enum(["active", "resolved"])
});

export const EngineCheckRequestSchema = z.object({
  schema_version: z.literal(ENGINE_CHECK_REQUEST_SCHEMA_VERSION),
  repo: EngineRepoContextSchema,
  graph: z.object({
    graph_id: z.string().min(1).optional(),
    scan_id: z.string().min(1).optional(),
    require_fresh: z.boolean(),
    graph_nodes: z.array(GraphNodeSchema).default([]),
    graph_edges: z.array(GraphEdgeSchema).default([]),
    graph_evidence: z.array(GraphEvidenceSchema).default([]),
    graph_diagnostics: z.array(EngineDiagnosticSchema).default([])
  }),
  scan: z.object({
    scan_id: z.string().min(1),
    file_snapshots: z.array(EngineFileSnapshotSchema),
    facts: z.array(EngineFactSchema)
  }),
  contract: z.object({
    contract_id: z.string().min(1),
    contract_schema_version: z.number().int().positive(),
    conventions: z.array(EngineConventionSchema),
    waivers: z.array(EngineWaiverSchema),
    exceptions: z.array(z.record(z.unknown()))
  }),
  baseline: z.array(EngineBaselineViolationSchema),
  diff: z.object({
    mode: DiffModeSchema,
    range: z.string().min(1).optional(),
    patch: z.string().optional(),
    files: z.array(z.object({
      path: z.string().min(1),
      changed_lines: z.array(z.number().int().positive())
    })).optional(),
    deleted_files: z.array(z.string().min(1)).optional()
  }),
  limits: EngineLimitsSchema
});

export const EngineEvidenceRefSchema = z.object({
  file_path: z.string().min(1),
  start_line: z.number().int().positive().optional(),
  end_line: z.number().int().positive().optional(),
  evidence_id: z.string().min(1).optional()
});

export const EngineCandidateEvidenceRefSchema = z.object({
  id: z.string().min(1),
  kind: z.enum(["supporting", "counterexample", "violation", "baseline"]),
  file_path: z.string().min(1),
  start_line: z.number().int().positive().optional(),
  end_line: z.number().int().positive().optional(),
  symbol: z.string().min(1).optional(),
  import_source: z.string().min(1).optional(),
  fact_ids: z.array(z.string().min(1)),
  scan_id: z.string().min(1),
  file_hash: z.string().min(1),
  artifact_hash: z.string().min(1).optional(),
  redaction_state: z.enum(["none", "redacted", "snippet_limited"])
});

export const EngineCandidateScoringSchema = z.object({
  supporting_examples_count: z.number().int().nonnegative(),
  counterexamples_count: z.number().int().nonnegative(),
  scope_files_count: z.number().int().nonnegative(),
  coverage_ratio: z.number().min(0).max(1),
  heuristic_id: z.string().min(1)
});

export const EngineCandidateSchema = z.object({
  candidate_id: z.string().min(1),
  candidate_version: z.number().int().positive(),
  kind: z.enum([
    "api_route_no_direct_data_access",
    "api_route_requires_service_delegation",
    "api_route_requires_auth_helper",
    "test_expected_for_changed_module",
    "custom_briefing"
  ]),
  rule_id: z.string().min(1),
  rule_version: z.string().min(1),
  matcher_schema_version: z.string().min(1),
  matcher_fingerprint: z.string().min(1),
  scope_fingerprint: z.string().min(1),
  graph_fingerprint: z.string().min(1),
  statement: z.string().min(1),
  rationale: z.string().min(1).optional(),
  scope: z.record(z.unknown()),
  matcher: z.record(z.unknown()),
  suggested_severity: z.enum(["info", "warning", "error"]),
  suggested_enforcement_mode: z.enum(["off", "brief", "warn", "block"]),
  enforcement_capability: z.enum(["briefing_only", "heuristic_check", "deterministic_check"]),
  confidence_label: z.enum(["low", "medium", "high"]),
  scoring: EngineCandidateScoringSchema,
  required_capabilities: z.array(z.string().min(1)),
  evidence_refs: z.array(EngineCandidateEvidenceRefSchema),
  counterexample_refs: z.array(EngineCandidateEvidenceRefSchema),
  supersedes_candidate_id: z.string().min(1).optional()
});

export const EngineFindingSchema = z.object({
  id: z.string().min(1),
  fingerprint: z.string().min(1),
  convention_id: z.string().min(1),
  rule_id: z.string().min(1),
  title: z.string().min(1),
  message: z.string().min(1),
  severity: z.enum(["info", "warning", "error"]),
  enforcement_result: z.enum(["none", "warn", "block"]),
  status_hint: z.enum(["new", "pre_existing"]),
  diff_status: z.enum(["new_in_diff", "touched_existing", "outside_diff"]),
  evidence: z.array(EngineEvidenceRefSchema),
  related_node_ids: z.array(z.string())
});

const EngineSecurityMissingProofCodeSchema = z.enum([
  "missing_auth_guard",
  "auth_guard_not_dominating_sink",
  "middleware_not_covering_route",
  "middleware_dynamic_matcher",
  "request_input_not_validated",
  "validation_result_not_used",
  "unknown_validator",
  "sensitive_response_field_unfiltered",
  "dynamic_response_shape_missing_proof",
  "secret_exposure_not_excluded",
  "unsupported_callback_boundary",
  "unsupported_dynamic_control_flow",
  "route_binding_unresolved",
  "handler_unresolved"
]);

const EngineSecurityParserGapSchema = z.object({
  parser_gap_id: z.string().min(1),
  capability: z.string().min(1),
  code: z.enum([
    "route_binding_unresolved",
    "handler_unresolved",
    "unsupported_dynamic_control_flow",
    "unsupported_dynamic_middleware_matcher",
    "unsupported_request_input_spread",
    "unsupported_request_input_destructure",
    "dynamic_response_shape",
    "unsupported_destructuring_or_spread",
    "unsupported_callback_boundary"
  ]),
  file_path: z.string().min(1),
  start_line: z.number().int().positive().optional(),
  end_line: z.number().int().positive().optional(),
  reason: z.string().min(1),
  affected_contract_kinds: z.array(z.string().min(1)),
  affected_route_ids: z.array(z.string().min(1)),
  missing_proof_ids: z.array(z.string().min(1)),
  blocks_enforcement: z.boolean()
});

const EngineSecurityBoundaryProofSchema = z.object({
  proof_id: z.string().min(1),
  proof_version: z.literal("security-boundary-proof/v1"),
  route: z.object({
    route_id: z.string().min(1),
    file_path: z.string().min(1),
    file_role: z.literal("api_route")
  }),
  contracts: z.array(z.object({
    contract_id: z.string().min(1),
    kind: z.string().min(1),
    enforcement_mode: z.enum(["off", "brief", "warn", "block"]),
    capability: z.enum(["briefing_only", "heuristic_check", "deterministic_check"]),
    matched: z.boolean()
  })),
  capability_status: z.array(z.object({
    name: z.string().min(1),
    status: z.enum(["complete", "partial", "unsupported", "failed"]),
    can_block: z.boolean(),
    parser_gap_ids: z.array(z.string().min(1)),
    missing_proof_ids: z.array(z.string().min(1))
  })),
  auth: z.object({
    required: z.boolean(),
    proven: z.boolean(),
    proof_kind: z.enum(["handler_guard", "middleware_guard", "both", "none"]),
    trusted_guard_calls: z.array(z.object({
      fact_id: z.string().min(1),
      guard_id: z.string().min(1),
      symbol: z.string().min(1)
    }).passthrough()),
    dominated_sinks: z.array(z.object({
      sink_id: z.string().min(1),
      sink_kind: z.enum(["data_operation", "response", "outbound_request", "raw_sql", "secret_log"]),
      edge_id: z.string().min(1)
    })),
    undominated_sinks: z.array(z.object({
      sink_id: z.string().min(1),
      sink_kind: z.string().min(1),
      reason: z.enum([
        "guard_after_sink",
        "guard_only_in_one_branch",
        "callback_boundary",
        "unsupported_dynamic_control_flow",
        "no_guard_call"
      ]),
      fact_ids: z.array(z.string().min(1))
    }))
  }),
  middleware: z.object({
    required: z.boolean(),
    proven: z.boolean(),
    matched_middleware: z.array(z.object({
      middleware_id: z.string().min(1),
      matcher_fact_id: z.string().min(1),
      protects_route_edge_id: z.string().min(1),
      protection_kind: z.enum(["auth", "csrf", "rate_limit", "cors", "unknown"])
    })),
    mismatches: z.array(z.object({
      middleware_id: z.string().min(1).optional(),
      reason: z.enum(["path_not_matched", "method_not_matched", "dynamic_matcher", "unknown_framework"]),
      parser_gap_id: z.string().min(1).optional()
    }))
  }).optional().default({
    required: false,
    proven: false,
    matched_middleware: [],
    mismatches: []
  }),
  request_validation: z.object({
    required: z.boolean(),
    proven: z.boolean(),
    input_reads: z.array(z.object({
      fact_id: z.string().min(1),
      source: z.enum(["body", "query", "params", "headers", "cookies", "formData"]),
      variable: z.string().min(1).optional(),
      key: z.string().min(1).optional()
    })),
    validations: z.array(z.object({
      fact_id: z.string().min(1),
      validator_symbol: z.string().min(1),
      schema_symbol: z.string().min(1).optional(),
      input_var: z.string().min(1).optional(),
      result_var: z.string().min(1).optional()
    })),
    validated_uses: z.array(z.object({
      fact_id: z.string().min(1).optional(),
      source_input_var: z.string().min(1),
      validated_var: z.string().min(1),
      sink_fact_id: z.string().min(1),
      sink_kind: z.enum(["data_operation", "response", "outbound_request", "raw_sql"])
    })),
    unvalidated_uses: z.array(z.object({
      input_fact_id: z.string().min(1),
      sink_fact_id: z.string().min(1),
      sink_kind: z.enum(["data_operation", "response", "outbound_request", "raw_sql"]),
      reason: z.enum(["request_input_not_validated", "validation_result_not_used", "unknown_validator"])
    }))
  }).optional().default({
    required: false,
    proven: false,
    input_reads: [],
    validations: [],
    validated_uses: [],
    unvalidated_uses: []
  }),
  response_shape: z.object({
    required: z.boolean(),
    proven: z.boolean(),
    sensitive_leaks: z.array(z.object({
      field_fact_id: z.string().min(1),
      field_path: z.string().min(1),
      reason: z.enum(["sensitive_field_without_serializer"])
    }))
  }).optional().default({
    required: false,
    proven: false,
    sensitive_leaks: []
  }),
  sinks: z.object({
    secrets: z.array(z.object({
      secret_fact_id: z.string().min(1),
      secret_class: z.enum(["api_key", "token", "password", "private_key", "unknown"]),
      sink_kind: z.enum(["response", "log"]),
      sink_line: z.number().int().positive(),
      reason: z.enum(["secret_reaches_sink"])
    }))
  }).optional().default({
    secrets: []
  }),
  missing_proof: z.array(z.object({
    id: z.string().min(1),
    capability: z.string().min(1),
    code: EngineSecurityMissingProofCodeSchema,
    blocks_enforcement: z.boolean(),
    fact_ids: z.array(z.string().min(1)),
    graph_edge_ids: z.array(z.string().min(1))
  })),
  parser_gaps: z.array(EngineSecurityParserGapSchema),
  result: z.object({
    proof_status: z.enum(["proven", "violated", "missing_proof", "parser_gap", "advisory_only"]),
    enforcement_result: z.enum(["pass", "brief", "warn", "block"]),
    can_block: z.boolean(),
    finding_ids: z.array(z.string().min(1))
  })
}).superRefine((proof, context) => {
  const requestValidationMissingProof = proof.missing_proof.filter((entry) =>
    entry.capability === "request_validation_facts" ||
    ["request_input_not_validated", "validation_result_not_used", "unknown_validator"].includes(entry.code)
  );
  const blockingRequestValidationParserGaps = proof.parser_gaps.filter((gap) =>
    gap.blocks_enforcement &&
    (gap.capability === "request_validation_facts" ||
      gap.affected_contract_kinds.includes("api_route_requires_request_validation"))
  );

  if (proof.request_validation.required && proof.request_validation.proven) {
    if (
      proof.request_validation.unvalidated_uses.length > 0 ||
      requestValidationMissingProof.length > 0 ||
      blockingRequestValidationParserGaps.length > 0 ||
      proof.request_validation.validated_uses.length === 0 ||
      proof.result.proof_status !== "proven" ||
      proof.result.enforcement_result !== "pass"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "request validation proven proof cannot include missing proof, parser gaps, or unvalidated uses"
      });
    }
  }

  if (
    proof.request_validation.unvalidated_uses.length > 0 &&
    (proof.request_validation.proven || proof.result.proof_status === "proven")
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "request validation unvalidated uses require a non-proven proof status"
    });
  }

  const matchedSensitiveResponseContract = proof.contracts.some((contract) =>
    contract.matched && contract.kind === "api_route_forbids_sensitive_response_fields"
  );
  if (matchedSensitiveResponseContract && !proof.response_shape.required) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "matched sensitive response contracts require response_shape proof"
    });
  }

  const matchedSecretExposureContract = proof.contracts.some((contract) =>
    contract.matched && contract.kind === "api_route_forbids_secret_exposure"
  );
  if (
    matchedSecretExposureContract &&
    !proof.capability_status.some((status) => status.name === "secret_exposure")
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "matched secret exposure contracts require secret_exposure capability status"
    });
  }
});

export const EngineSecurityProofEventSchema = z.object({
  event: z.literal("SecurityProof"),
  schema_version: z.literal(ENGINE_SECURITY_PROOF_EVENT_SCHEMA_VERSION),
  proofs: z.array(EngineSecurityBoundaryProofSchema)
});

export const EngineCheckResultSchema = z.object({
  schema_version: z.literal(ENGINE_CHECK_RESULT_SCHEMA_VERSION),
  repo_id: z.string().min(1),
  scan_id: z.string().min(1),
  graph_id: z.string().min(1).optional(),
  engine_version: z.string().min(1),
  rule_engine_version: z.string().min(1),
  adapter_versions: z.record(z.string().min(1)),
  diff_mode: DiffModeSchema,
  findings: z.array(EngineFindingSchema),
  security_boundary_proofs: z.array(EngineSecurityBoundaryProofSchema).default([]),
  diagnostics: z.array(EngineDiagnosticSchema),
  stats: EngineStatsSchema,
  completeness: z.array(EngineCompletenessSchema)
}).superRefine((result, context) => {
  const hasBlockingFinding = result.findings.some((finding) =>
    finding.enforcement_result === "block"
  );
  if (!hasBlockingFinding) {
    return;
  }

  const hasCompleteBlockingCoverage = result.completeness.some((completeness) =>
    completeness.can_block &&
    completeness.complete &&
    !completeness.truncated &&
    completeness.missing_capabilities.length === 0
  );
  const statsMissing = result.stats.capabilities?.missing ?? [];
  if (!hasCompleteBlockingCoverage || statsMissing.length > 0) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "blocking findings require complete capability coverage"
    });
  }
});

export const EngineCandidatesResultSchema = z.object({
  schema_version: z.literal(ENGINE_CANDIDATES_RESULT_SCHEMA_VERSION),
  repo_id: z.string().min(1),
  scan_id: z.string().min(1),
  graph_id: z.string().min(1).optional(),
  engine_version: z.string().min(1),
  rule_engine_version: z.string().min(1),
  adapter_versions: z.record(z.string().min(1)),
  candidates: z.array(EngineCandidateSchema),
  diagnostics: z.array(EngineDiagnosticSchema),
  stats: EngineStatsSchema,
  completeness: z.array(EngineCompletenessSchema)
});

export const EngineStreamEventSchema = z.discriminatedUnion("event", [
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("scan_started"),
    repo_id: z.string().min(1).optional(),
    scan_id: z.string().min(1).optional(),
    engine_version: z.string().min(1)
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("file_snapshot_batch"),
    file_snapshots: z.array(EngineFileSnapshotSchema)
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("fact_batch"),
    facts: z.array(EngineFactSchema)
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("graph_node_batch"),
    graph_nodes: z.array(GraphNodeSchema)
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("graph_edge_batch"),
    graph_edges: z.array(GraphEdgeSchema)
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("graph_evidence_batch"),
    graph_evidence: z.array(GraphEvidenceSchema)
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("diagnostic_batch"),
    diagnostics: z.array(EngineDiagnosticSchema)
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("stats_delta"),
    stats: EngineStatsSchema.partial()
  }),
  z.object({
    schema_version: z.literal(ENGINE_STREAM_EVENT_SCHEMA_VERSION),
    event: z.literal("scan_completed"),
    stats: EngineStatsSchema,
    completeness: z.array(EngineCompletenessSchema)
  })
]);

export type EngineLimits = z.infer<typeof EngineLimitsSchema>;
export type EngineStats = z.infer<typeof EngineStatsSchema>;
export type EngineCapabilityStats = z.infer<typeof EngineCapabilityStatsSchema>;
export type EngineDiagnostic = z.infer<typeof EngineDiagnosticSchema>;
export type EngineCompleteness = z.infer<typeof EngineCompletenessSchema>;
export type EngineFileSnapshot = z.infer<typeof EngineFileSnapshotSchema>;
export type EngineFact = z.infer<typeof EngineFactSchema>;
export type EngineScanRequest = z.infer<typeof EngineScanRequestSchema>;
export type EngineScanResult = z.infer<typeof EngineScanResultSchema>;
export type EngineCheckRequest = z.infer<typeof EngineCheckRequestSchema>;
export type EngineCheckResult = z.infer<typeof EngineCheckResultSchema>;
export type EngineCandidateEvidenceRef = z.infer<typeof EngineCandidateEvidenceRefSchema>;
export type EngineCandidateScoring = z.infer<typeof EngineCandidateScoringSchema>;
export type EngineCandidate = z.infer<typeof EngineCandidateSchema>;
export type EngineCandidatesResult = z.infer<typeof EngineCandidatesResultSchema>;
export type EngineStreamEvent = z.infer<typeof EngineStreamEventSchema>;
export type EngineSecurityProofEvent = z.infer<typeof EngineSecurityProofEventSchema>;

export function parseEngineScanResult(value: unknown): EngineScanResult {
  return parseWithMessage(EngineScanResultSchema, value, "Invalid Drift engine scan result");
}

export function parseEngineStreamEvent(value: unknown): EngineStreamEvent {
  return parseWithMessage(EngineStreamEventSchema, value, "Invalid Drift engine stream event");
}

export function parseEngineCheckResult(value: unknown): EngineCheckResult {
  return parseWithMessage(EngineCheckResultSchema, value, "Invalid Drift engine check result");
}

export function parseEngineCandidatesResult(value: unknown): EngineCandidatesResult {
  return parseWithMessage(EngineCandidatesResultSchema, value, "Invalid Drift engine candidates result");
}

export function parseEngineSecurityProofEvent(value: unknown): EngineSecurityProofEvent {
  return parseWithMessage(EngineSecurityProofEventSchema, value, "Invalid Drift engine security proof event");
}

function parseWithMessage<S extends z.ZodTypeAny>(schema: S, value: unknown, message: string): z.output<S> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new Error(`${message}: ${parsed.error.issues.map((issue) => issue.message).join("; ")}`);
  }
  return parsed.data;
}
