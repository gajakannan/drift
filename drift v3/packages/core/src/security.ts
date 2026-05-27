import { z } from "zod";

export const SecurityCapabilityNameSchema = z.enum([
  "security_facts",
  "auth_boundary_facts",
  "control_flow_guard_dominance",
  "middleware_coverage",
  "request_validation_facts",
  "outbound_request_facts",
  "raw_sql_facts",
  "cors_policy_facts",
  "csrf_facts",
  "rate_limit_facts"
]);

export const SecurityMissingProofCodeSchema = z.enum([
  "missing_auth_guard",
  "auth_guard_not_dominating_sink",
  "middleware_not_covering_route",
  "middleware_dynamic_matcher",
  "request_input_not_validated",
  "validation_result_not_used",
  "unknown_validator",
  "request_controlled_url",
  "raw_sql_unparameterized",
  "wildcard_origin_with_credentials",
  "disallowed_origin",
  "credentials_not_allowed",
  "unsupported_dynamic_outbound_url",
  "unsupported_dynamic_cors_origin",
  "missing_csrf_guard",
  "csrf_guard_not_dominating_sink",
  "missing_rate_limit_guard",
  "rate_limit_guard_not_dominating_sink",
  "unsupported_callback_boundary",
  "unsupported_dynamic_control_flow",
  "route_binding_unresolved",
  "handler_unresolved"
]);

export const SecurityParserGapCodeSchema = z.enum([
  "route_binding_unresolved",
  "handler_unresolved",
  "unsupported_dynamic_control_flow",
  "unsupported_dynamic_middleware_matcher",
  "unsupported_request_input_spread",
  "unsupported_request_input_destructure",
  "unsupported_callback_boundary",
  "unsupported_dynamic_outbound_url",
  "unsupported_dynamic_cors_origin"
]);

const SecurityContractKindSchema = z.enum([
  "api_route_requires_auth_helper",
  "middleware_must_cover_routes",
  "api_route_requires_request_validation",
  "api_route_forbids_untrusted_ssrf",
  "api_route_forbids_raw_sql_without_params",
  "api_route_cors_must_match_policy",
  "api_route_requires_csrf_for_mutation",
  "api_route_requires_rate_limit"
]);

export const SecurityConventionSchema = z.object({
  contract_id: z.string().min(1),
  kind: SecurityContractKindSchema,
  capability: z.enum(["briefing_only", "heuristic_check", "deterministic_check"]),
  enforcement_mode: z.enum(["off", "brief", "warn", "block"]),
  matcher: z.object({
    file_roles: z.array(z.literal("api_route")).optional(),
    path_globs: z.array(z.string().min(1)).optional(),
    route_paths: z.array(z.string().min(1)).optional(),
    route_path_patterns: z.array(z.string().min(1)).optional(),
    methods: z.array(z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])).optional(),
    frameworks: z.array(z.string().min(1)).optional(),
    package_names: z.array(z.string().min(1)).optional(),
    tags: z.array(z.string().min(1)).optional()
  }),
  scope: z.object({
    check_scope: z.enum(["changed-hunks", "changed-files", "full"]),
    diff_status: z.array(z.enum(["added", "modified", "renamed"])).optional(),
    applies_to: z.enum(["route", "handler", "middleware", "data_operation", "response"]),
    include_pre_existing: z.boolean().optional()
  }),
  requires: z.record(z.unknown()).optional(),
  forbids: z.record(z.unknown()).optional(),
  exceptions: z.array(z.record(z.unknown())).optional(),
  governance: z.object({
    accepted_by: z.string().min(1).optional(),
    accepted_at: z.string().datetime().optional(),
    updated_at: z.string().datetime().optional(),
    expires_at: z.string().datetime().optional(),
    rationale: z.string().min(1).optional(),
    evidence_refs: z.array(z.string().min(1)).optional(),
    counterexample_refs: z.array(z.string().min(1)).optional()
  }).optional()
}).superRefine((contract, context) => {
  if (contract.enforcement_mode === "block" && contract.capability !== "deterministic_check") {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "blocking security contracts require deterministic capability"
    });
  }
});

const SecurityContractMatchSchema = z.object({
  contract_id: z.string().min(1),
  kind: SecurityContractKindSchema,
  enforcement_mode: z.enum(["off", "brief", "warn", "block"]),
  capability: z.enum(["briefing_only", "heuristic_check", "deterministic_check"]),
  matched: z.boolean()
});

const SecurityCapabilityStatusSchema = z.object({
  name: z.string().min(1),
  status: z.enum(["complete", "partial", "unsupported", "failed"]),
  can_block: z.boolean(),
  parser_gap_ids: z.array(z.string().min(1)),
  missing_proof_ids: z.array(z.string().min(1))
});

const SecurityAuthProofSchema = z.object({
  required: z.boolean(),
  proven: z.boolean(),
  proof_kind: z.enum(["handler_guard", "middleware_guard", "both", "none"]),
  trusted_guard_calls: z.array(z.object({
    fact_id: z.string().min(1),
    guard_id: z.string().min(1),
    symbol: z.string().min(1),
    start_line: z.number().int().positive().optional(),
    end_line: z.number().int().positive().optional(),
    result_var: z.string().min(1).optional()
  })),
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
});

const SecurityMiddlewareProofSchema = z.object({
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
});

const SecurityRequestValidationProofSchema = z.object({
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
});

const SecurityPhase6MissingProofSchema = z.object({
  code: SecurityMissingProofCodeSchema,
  fact_ids: z.array(z.string().min(1))
});

const SecurityPhase6HelperProofSchema = z.object({
  fact_id: z.string().min(1),
  helper_id: z.string().min(1),
  symbol: z.string().min(1).optional(),
  edge_id: z.string().min(1),
  start_line: z.number().int().positive().optional(),
  end_line: z.number().int().positive().optional()
});

const SecuritySsrfProofSchema = z.object({
  required: z.boolean(),
  proven: z.boolean(),
  outbound_requests: z.array(z.object({
    fact_id: z.string().min(1),
    sink_id: z.string().min(1),
    api: z.string().min(1),
    url_source: z.enum(["constant", "request_input", "validated_input", "allowlisted", "unknown"])
  })),
  allowlist_proofs: z.array(SecurityPhase6HelperProofSchema),
  missing_proof: z.array(SecurityPhase6MissingProofSchema)
});

const SecurityRawSqlProofSchema = z.object({
  required: z.boolean(),
  proven: z.boolean(),
  raw_sql_calls: z.array(z.object({
    fact_id: z.string().min(1),
    sink_id: z.string().min(1),
    query_shape: z.enum(["raw_string", "template", "concat", "query_builder", "unknown"]),
    uses_untrusted_input: z.boolean()
  })),
  parameterized_sql: z.array(z.object({
    fact_id: z.string().min(1),
    sink_id: z.string().min(1),
    parameterization: z.string().min(1)
  })),
  missing_proof: z.array(SecurityPhase6MissingProofSchema)
});

const SecurityCorsProofSchema = z.object({
  required: z.boolean(),
  proven: z.boolean(),
  policies: z.array(z.object({
    fact_id: z.string().min(1),
    origin: z.string().min(1).nullable().optional(),
    credentials: z.boolean(),
    dynamic_origin: z.boolean()
  })),
  missing_proof: z.array(SecurityPhase6MissingProofSchema)
});

const SecurityPhase6GuardProofSchema = z.object({
  required: z.boolean(),
  proven: z.boolean(),
  guard_calls: z.array(SecurityPhase6HelperProofSchema),
  missing_proof: z.array(SecurityPhase6MissingProofSchema)
});

const SecurityMissingProofSchema = z.object({
  id: z.string().min(1),
  capability: z.string().min(1),
  code: SecurityMissingProofCodeSchema,
  blocks_enforcement: z.boolean(),
  fact_ids: z.array(z.string().min(1)),
  graph_edge_ids: z.array(z.string().min(1))
});

const SecurityParserGapSchema = z.object({
  parser_gap_id: z.string().min(1),
  capability: z.string().min(1),
  code: SecurityParserGapCodeSchema,
  file_path: z.string().min(1),
  start_line: z.number().int().positive().optional(),
  end_line: z.number().int().positive().optional(),
  reason: z.string().min(1),
  affected_contract_kinds: z.array(z.string().min(1)),
  affected_route_ids: z.array(z.string().min(1)),
  missing_proof_ids: z.array(z.string().min(1)),
  blocks_enforcement: z.boolean()
});

export const SecurityBoundaryProofSchema = z.object({
  proof_id: z.string().min(1),
  proof_version: z.literal("security-boundary-proof/v1"),
  route: z.object({
    route_id: z.string().min(1),
    file_path: z.string().min(1),
    file_role: z.literal("api_route"),
    endpoint: z.object({
      path: z.string().min(1).optional(),
      method: z.string().min(1).optional(),
      framework: z.string().min(1).optional()
    }).optional(),
    handler_symbol: z.string().min(1).optional(),
    start_line: z.number().int().positive().optional(),
    end_line: z.number().int().positive().optional(),
    diff_status: z.enum(["unchanged", "added", "modified", "deleted", "renamed"]).optional()
  }),
  contracts: z.array(SecurityContractMatchSchema),
  capability_status: z.array(SecurityCapabilityStatusSchema),
  auth: SecurityAuthProofSchema,
  middleware: SecurityMiddlewareProofSchema.optional().default({
    required: false,
    proven: false,
    matched_middleware: [],
    mismatches: []
  }),
  request_validation: SecurityRequestValidationProofSchema.optional().default({
    required: false,
    proven: false,
    input_reads: [],
    validations: [],
    validated_uses: [],
    unvalidated_uses: []
  }),
  ssrf: SecuritySsrfProofSchema.optional().default({
    required: false,
    proven: false,
    outbound_requests: [],
    allowlist_proofs: [],
    missing_proof: []
  }),
  raw_sql: SecurityRawSqlProofSchema.optional().default({
    required: false,
    proven: false,
    raw_sql_calls: [],
    parameterized_sql: [],
    missing_proof: []
  }),
  cors: SecurityCorsProofSchema.optional().default({
    required: false,
    proven: false,
    policies: [],
    missing_proof: []
  }),
  csrf: SecurityPhase6GuardProofSchema.optional().default({
    required: false,
    proven: false,
    guard_calls: [],
    missing_proof: []
  }),
  rate_limit: SecurityPhase6GuardProofSchema.optional().default({
    required: false,
    proven: false,
    guard_calls: [],
    missing_proof: []
  }),
  missing_proof: z.array(SecurityMissingProofSchema),
  parser_gaps: z.array(SecurityParserGapSchema),
  result: z.object({
    proof_status: z.enum(["proven", "violated", "missing_proof", "parser_gap", "advisory_only"]),
    enforcement_result: z.enum(["pass", "brief", "warn", "block"]),
    can_block: z.boolean(),
    finding_ids: z.array(z.string().min(1))
  })
}).superRefine((proof, context) => {
  const phase6MissingCodes = new Set([
    "request_controlled_url",
    "raw_sql_unparameterized",
    "wildcard_origin_with_credentials",
    "disallowed_origin",
    "credentials_not_allowed",
    "unsupported_dynamic_outbound_url",
    "unsupported_dynamic_cors_origin",
    "missing_csrf_guard",
    "csrf_guard_not_dominating_sink",
    "missing_rate_limit_guard",
    "rate_limit_guard_not_dominating_sink"
  ]);
  const phase6ParserGapCodes = new Set([
    "unsupported_dynamic_outbound_url",
    "unsupported_dynamic_cors_origin"
  ]);
  const phase6MissingProof = proof.missing_proof.filter((entry) => phase6MissingCodes.has(entry.code));
  const phase6ParserGaps = proof.parser_gaps.filter((gap) => phase6ParserGapCodes.has(gap.code));

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

  if (
    proof.result.proof_status === "proven" &&
    (phase6MissingProof.length > 0 || phase6ParserGaps.length > 0)
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "proven Phase 6 proof cannot include Phase 6 missing proof or parser gaps"
    });
  }

  if (proof.ssrf.required && proof.ssrf.proven) {
    const unsafeOutbound = proof.ssrf.outbound_requests.some((request) =>
      request.url_source === "request_input" || request.url_source === "unknown"
    );
    if (unsafeOutbound || proof.ssrf.missing_proof.length > 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "proven SSRF proof cannot include untrusted outbound URLs or missing proof"
      });
    }
  }

  if (proof.raw_sql.required && proof.raw_sql.proven) {
    const parameterizedSinkIds = new Set(proof.raw_sql.parameterized_sql.map((entry) => entry.sink_id));
    const unsafeRawSql = proof.raw_sql.raw_sql_calls.some((call) =>
      !parameterizedSinkIds.has(call.sink_id)
    );
    if (unsafeRawSql || proof.raw_sql.missing_proof.length > 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "proven raw SQL proof cannot include unparameterized raw SQL calls or missing proof"
      });
    }
  }

  if (proof.cors.required && proof.cors.proven) {
    const unsafeCorsPolicy = proof.cors.policies.some((policy) =>
      policy.dynamic_origin ||
      (policy.origin === "*" && policy.credentials)
    );
    if (unsafeCorsPolicy || proof.cors.missing_proof.length > 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "proven CORS proof cannot include dynamic or unsafe CORS policy evidence"
      });
    }
  }

  if (
    proof.csrf.required &&
    proof.csrf.proven &&
    (proof.csrf.guard_calls.length === 0 || proof.csrf.missing_proof.length > 0)
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "proven CSRF proof requires trusted guard calls and no missing proof"
    });
  }

  if (
    proof.rate_limit.required &&
    proof.rate_limit.proven &&
    (proof.rate_limit.guard_calls.length === 0 || proof.rate_limit.missing_proof.length > 0)
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "proven rate-limit proof requires trusted guard calls and no missing proof"
    });
  }
});

export type SecurityConvention = z.infer<typeof SecurityConventionSchema>;
export type SecurityBoundaryProof = z.infer<typeof SecurityBoundaryProofSchema>;
