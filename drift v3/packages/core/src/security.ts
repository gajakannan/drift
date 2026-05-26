import { z } from "zod";

export const SecurityCapabilityNameSchema = z.enum([
  "security_facts",
  "auth_boundary_facts",
  "control_flow_guard_dominance",
  "middleware_coverage",
  "request_validation_facts"
]);

export const SecurityMissingProofCodeSchema = z.enum([
  "missing_auth_guard",
  "auth_guard_not_dominating_sink",
  "middleware_not_covering_route",
  "middleware_dynamic_matcher",
  "request_input_not_validated",
  "validation_result_not_used",
  "unknown_validator",
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
  "unsupported_callback_boundary"
]);

const SecurityContractKindSchema = z.enum([
  "api_route_requires_auth_helper",
  "middleware_must_cover_routes",
  "api_route_requires_request_validation"
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
  kind: z.string().min(1),
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
  missing_proof: z.array(SecurityMissingProofSchema),
  parser_gaps: z.array(SecurityParserGapSchema),
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
});

export type SecurityConvention = z.infer<typeof SecurityConventionSchema>;
export type SecurityBoundaryProof = z.infer<typeof SecurityBoundaryProofSchema>;
