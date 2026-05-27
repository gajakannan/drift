import type { AcceptedConvention, SecurityBoundaryProof } from "@drift/core";

export interface SecurityFindingSummaryInput {
  finding_id: string;
  title: string;
  lifecycle: string;
}

export interface BuildSecurityBoundaryProofReadModelInput {
  proofs: SecurityBoundaryProof[];
  findings: SecurityFindingSummaryInput[];
}

export interface SecurityBoundaryProofRouteSummary {
  route_id: string;
  file_path: string;
  auth_required: boolean;
  auth_proven: boolean;
  middleware_required: boolean;
  middleware_proven: boolean;
  middleware_protection_kinds: string[];
  middleware_mismatch_reasons: string[];
  request_validation_required: boolean;
  request_validation_proven: boolean;
  request_validation_unvalidated_reasons: string[];
  phase6: {
    ssrf: {
      required: boolean;
      proven: boolean;
      outbound_request_count: number;
      allowlist_proof_count: number;
    };
    raw_sql: {
      required: boolean;
      proven: boolean;
      raw_sql_call_count: number;
      parameterized_sql_count: number;
    };
    cors: {
      required: boolean;
      proven: boolean;
      policy_count: number;
    };
    csrf: {
      required: boolean;
      proven: boolean;
      guard_call_count: number;
    };
    rate_limit: {
      required: boolean;
      proven: boolean;
      guard_call_count: number;
    };
  };
  response_shape_required: boolean;
  response_shape_proven: boolean;
  sensitive_response_leak_reasons: string[];
  secret_exposure_count: number;
  secret_exposure_sink_kinds: string[];
  session_trust_required: boolean;
  session_trust_proven: boolean;
  session_missing_trust_reasons: string[];
  authorization_required: boolean;
  authorization_proven: boolean;
  authorization_missing_reasons: string[];
  tenant_required: boolean;
  tenant_proven: boolean;
  tenant_missing_reasons: string[];
  proof_status: string;
  enforcement_result: string;
  missing_proof_codes: string[];
  parser_gap_codes: string[];
  finding_ids: string[];
  lifecycle: string[];
}

export interface SecurityBoundaryProofReadModel {
  routes: SecurityBoundaryProofRouteSummary[];
}

export interface BuildSecurityPhase8ReadModelInput {
  repo_id: string;
  scan_id: string | null;
  check_id: string | null;
  proofs: SecurityBoundaryProof[];
  findings: SecurityFindingSummaryInput[];
  accepted_conventions: AcceptedConvention[];
  changed_files?: string[];
}

export interface SecurityCapabilitySummary {
  name: string;
  capability: "deterministic_check" | "heuristic_check" | "briefing_only";
  status: "complete" | "partial" | "missing" | "unsupported";
  can_block: boolean;
  parser_gap_count: number;
  missing_proof_count: number;
  affected_files: string[];
}

export interface SecurityPhase8Route {
  route_id: string;
  path: string | null;
  method: string | null;
  file_path: string;
  security: {
    public_or_protected: "public" | "protected" | "unknown";
    auth_proven: boolean | "not_required" | "missing_proof" | "parser_gap" | "unknown";
    middleware_proven: boolean | "not_required" | "missing_proof" | "parser_gap" | "unknown";
    tenant_scope: ProofState;
    request_validation: ProofState;
    sensitive_response: ProofState;
    phase6: {
      ssrf: ProofState;
      raw_sql: ProofState;
      cors: ProofState;
      csrf: ProofState;
      rate_limit: ProofState;
    };
    proof_status: SecurityBoundaryProof["result"]["proof_status"] | "unknown";
    enforcement_result: SecurityBoundaryProof["result"]["enforcement_result"] | "unknown";
    missing_proof_codes: string[];
    parser_gap_codes: string[];
    finding_ids: string[];
    next_command: string;
  };
}

type ProofState = "proven" | "not_required" | "missing_proof" | "parser_gap" | "unknown";

const SECURITY_CAPABILITIES = [
  "control_flow_guard_dominance",
  "middleware_coverage",
  "request_validation_facts",
  "session_trust",
  "authorization",
  "tenant_scope",
  "sensitive_response",
  "secret_exposure",
  "ssrf",
  "raw_sql",
  "cors_policy",
  "csrf",
  "rate_limit"
] as const;

const CAPABILITY_ALIASES: Record<string, string> = {
  response_shape_facts: "sensitive_response",
  outbound_request_facts: "ssrf",
  raw_sql_facts: "raw_sql",
  cors_policy_facts: "cors_policy",
  csrf_facts: "csrf",
  rate_limit_facts: "rate_limit"
};

export function buildSecurityPhase8ReadModel(input: BuildSecurityPhase8ReadModelInput) {
  const changedFiles = new Set(input.changed_files ?? input.proofs.map((proof) => proof.route.file_path));
  const routes = input.proofs.map((proof) => phase8Route(input.repo_id, proof));
  return {
    response_schema: "drift.security.phase8.read-model.v1",
    repo_id: input.repo_id,
    scan_id: input.scan_id,
    check_id: input.check_id,
    security_capabilities: securityCapabilities(input.proofs, input.accepted_conventions),
    routes,
    repo_security_contracts: input.accepted_conventions
      .filter((convention) => isSecurityConventionKind(convention.kind))
      .map(acceptedSecurityConventionSummary),
    changed_route_security: routes
      .filter((route) => changedFiles.has(route.file_path))
      .map((route) => {
        const proof = input.proofs.find((candidate) => candidate.route.route_id === route.route_id);
        return {
          route_id: route.route_id,
          path: route.path,
          method: route.method,
          file_path: route.file_path,
          required_proofs: proof ? requiredProofSummaries(proof) : [],
          current_proof_status: route.security.proof_status,
          enforcement_result: route.security.enforcement_result,
          missing_proof: (proof?.missing_proof ?? []).map((missing) => ({
            id: missing.id,
            capability: normalizedCapability(missing.capability),
            code: missing.code,
            blocks_enforcement: missing.blocks_enforcement
          })),
          parser_gaps: (proof?.parser_gaps ?? []).map((gap) => ({
            parser_gap_id: gap.parser_gap_id,
            capability: normalizedCapability(gap.capability),
            code: gap.code,
            file_path: gap.file_path,
            ...(gap.start_line ? { start_line: gap.start_line } : {}),
            ...(gap.end_line ? { end_line: gap.end_line } : {}),
            blocks_enforcement: gap.blocks_enforcement
          })),
          next_command: route.security.next_command
        };
      }),
    do_not_include: [
      "source snippets",
      "secret values",
      "raw request payload examples",
      "headers",
      "cookies",
      "raw SQL",
      "raw URLs",
      "env values",
      "tokens",
      "user IDs",
      "tenant IDs"
    ] as const
  };
}

export function buildSecurityBoundaryProofReadModel(
  input: BuildSecurityBoundaryProofReadModelInput
): SecurityBoundaryProofReadModel {
  const findingLifecycle = new Map(input.findings.map((finding) => [
    finding.finding_id,
    finding.lifecycle
  ]));

  return {
    routes: input.proofs.map((proof) => {
      const middleware = proof.middleware ?? {
        required: false,
        proven: false,
        matched_middleware: [],
        mismatches: []
      };
      const requestValidation = proof.request_validation ?? {
        required: false,
        proven: false,
        input_reads: [],
        validations: [],
        validated_uses: [],
        unvalidated_uses: []
      };
      const ssrf = proof.ssrf ?? {
        required: false,
        proven: false,
        outbound_requests: [],
        allowlist_proofs: [],
        missing_proof: []
      };
      const rawSql = proof.raw_sql ?? {
        required: false,
        proven: false,
        raw_sql_calls: [],
        parameterized_sql: [],
        missing_proof: []
      };
      const cors = proof.cors ?? {
        required: false,
        proven: false,
        policies: [],
        missing_proof: []
      };
      const csrf = proof.csrf ?? {
        required: false,
        proven: false,
        guard_calls: [],
        missing_proof: []
      };
      const rateLimit = proof.rate_limit ?? {
        required: false,
        proven: false,
        guard_calls: [],
        missing_proof: []
      };
      const responseShape = proof.response_shape ?? {
        required: false,
        proven: false,
        sensitive_leaks: []
      };
      const secretSinks = proof.sinks?.secrets ?? [];
      const sessionTrust = proof.session_trust ?? {
        required: false,
        proven: false,
        trusted_sessions: [],
        missing_trust: []
      };
      const authorization = proof.authorization ?? {
        required: false,
        proven: false,
        role_or_policy_guards: [],
        missing: []
      };
      const tenant = proof.tenant ?? {
        required: false,
        proven: false,
        tenant_sources: [],
        predicates: [],
        missing: []
      };
      return {
      route_id: proof.route.route_id,
      file_path: proof.route.file_path,
      auth_required: proof.auth.required,
      auth_proven: proof.auth.proven,
      middleware_required: middleware.required,
      middleware_proven: middleware.proven,
      middleware_protection_kinds: [...new Set(middleware.matched_middleware
        .map((middleware) => middleware.protection_kind))].sort(),
      middleware_mismatch_reasons: [...new Set(middleware.mismatches
        .map((mismatch) => mismatch.reason))].sort(),
      request_validation_required: requestValidation.required,
      request_validation_proven: requestValidation.proven,
      request_validation_unvalidated_reasons: [...new Set(requestValidation.unvalidated_uses
        .map((unvalidated) => unvalidated.reason))].sort(),
      phase6: {
        ssrf: {
          required: ssrf.required,
          proven: ssrf.proven,
          outbound_request_count: ssrf.outbound_requests.length,
          allowlist_proof_count: ssrf.allowlist_proofs.length
        },
        raw_sql: {
          required: rawSql.required,
          proven: rawSql.proven,
          raw_sql_call_count: rawSql.raw_sql_calls.length,
          parameterized_sql_count: rawSql.parameterized_sql.length
        },
        cors: {
          required: cors.required,
          proven: cors.proven,
          policy_count: cors.policies.length
        },
        csrf: {
          required: csrf.required,
          proven: csrf.proven,
          guard_call_count: csrf.guard_calls.length
        },
        rate_limit: {
          required: rateLimit.required,
          proven: rateLimit.proven,
          guard_call_count: rateLimit.guard_calls.length
        }
      },
      response_shape_required: responseShape.required,
      response_shape_proven: responseShape.proven,
      sensitive_response_leak_reasons: [...new Set(responseShape.sensitive_leaks
        .map((leak) => leak.reason))].sort(),
      secret_exposure_count: secretSinks.length,
      secret_exposure_sink_kinds: [...new Set(secretSinks.map((secret) => secret.sink_kind))].sort(),
      session_trust_required: sessionTrust.required,
      session_trust_proven: sessionTrust.proven,
      session_missing_trust_reasons: [...new Set(sessionTrust.missing_trust
        .map((missing) => missing.reason))].sort(),
      authorization_required: authorization.required,
      authorization_proven: authorization.proven,
      authorization_missing_reasons: [...new Set(authorization.missing
        .map((missing) => missing.reason))].sort(),
      tenant_required: tenant.required,
      tenant_proven: tenant.proven,
      tenant_missing_reasons: [...new Set(tenant.missing
        .map((missing) => missing.reason))].sort(),
      proof_status: proof.result.proof_status,
      enforcement_result: proof.result.enforcement_result,
      missing_proof_codes: proof.missing_proof.map((missing) => missing.code),
      parser_gap_codes: proof.parser_gaps.map((gap) => gap.code),
      finding_ids: proof.result.finding_ids,
      lifecycle: proof.result.finding_ids
        .map((findingId) => findingLifecycle.get(findingId))
        .filter((value): value is string => value !== undefined)
      };
    })
  };
}

function phase8Route(repoId: string, proof: SecurityBoundaryProof): SecurityPhase8Route {
  const middleware = proof.middleware ?? {
    required: false,
    proven: false,
    matched_middleware: [],
    mismatches: []
  };
  const requestValidation = proof.request_validation ?? {
    required: false,
    proven: false,
    input_reads: [],
    validations: [],
    validated_uses: [],
    unvalidated_uses: []
  };
  const tenant = proof.tenant ?? {
    required: false,
    proven: false,
    tenant_sources: [],
    predicates: [],
    missing: []
  };
  const responseShape = proof.response_shape ?? {
    required: false,
    proven: false,
    sensitive_leaks: []
  };
  const ssrf = proof.ssrf ?? {
    required: false,
    proven: false,
    outbound_requests: [],
    allowlist_proofs: [],
    missing_proof: []
  };
  const rawSql = proof.raw_sql ?? {
    required: false,
    proven: false,
    raw_sql_calls: [],
    parameterized_sql: [],
    missing_proof: []
  };
  const cors = proof.cors ?? {
    required: false,
    proven: false,
    policies: [],
    missing_proof: []
  };
  const csrf = proof.csrf ?? {
    required: false,
    proven: false,
    guard_calls: [],
    missing_proof: []
  };
  const rateLimit = proof.rate_limit ?? {
    required: false,
    proven: false,
    guard_calls: [],
    missing_proof: []
  };
  return {
    route_id: proof.route.route_id,
    path: proof.route.endpoint?.path ?? null,
    method: proof.route.endpoint?.method ?? null,
    file_path: proof.route.file_path,
    security: {
      public_or_protected: proof.auth.required || proof.auth.proven ? "protected" : "unknown",
      auth_proven: booleanSecurityState(proof.auth.required, proof.auth.proven, proof, "control_flow_guard_dominance"),
      middleware_proven: booleanSecurityState(middleware.required, middleware.proven, proof, "middleware_coverage"),
      tenant_scope: proofState(tenant.required, tenant.proven, proof, "tenant_scope"),
      request_validation: proofState(requestValidation.required, requestValidation.proven, proof, "request_validation_facts"),
      sensitive_response: proofState(responseShape.required, responseShape.proven, proof, "sensitive_response"),
      phase6: {
        ssrf: proofState(ssrf.required, ssrf.proven, proof, "ssrf"),
        raw_sql: proofState(rawSql.required, rawSql.proven, proof, "raw_sql"),
        cors: proofState(cors.required, cors.proven, proof, "cors_policy"),
        csrf: proofState(csrf.required, csrf.proven, proof, "csrf"),
        rate_limit: proofState(rateLimit.required, rateLimit.proven, proof, "rate_limit")
      },
      proof_status: proof.result.proof_status,
      enforcement_result: proof.result.enforcement_result,
      missing_proof_codes: proof.missing_proof.map((missing) => missing.code),
      parser_gap_codes: proof.parser_gaps.map((gap) => gap.code),
      finding_ids: proof.result.finding_ids,
      next_command: `drift repo map --repo ${repoId} --path ${proof.route.file_path} --json`
    }
  };
}

function booleanSecurityState(
  required: boolean,
  proven: boolean,
  proof: SecurityBoundaryProof,
  capability: string
): boolean | "not_required" | "missing_proof" | "parser_gap" | "unknown" {
  const state = proofState(required, proven, proof, capability);
  if (state === "proven") {
    return true;
  }
  return state;
}

function proofState(
  required: boolean,
  proven: boolean,
  proof: SecurityBoundaryProof,
  capability: string
): ProofState {
  if (!required) {
    return "not_required";
  }
  if (proven) {
    return "proven";
  }
  if (proof.parser_gaps.some((gap) => normalizedCapability(gap.capability) === capability)) {
    return "parser_gap";
  }
  if (proof.missing_proof.some((missing) => normalizedCapability(missing.capability) === capability)) {
    return "missing_proof";
  }
  if (proof.result.proof_status === "parser_gap") {
    return "parser_gap";
  }
  if (proof.result.proof_status === "missing_proof" || proof.result.proof_status === "violated") {
    return "missing_proof";
  }
  return "unknown";
}

function securityCapabilities(
  proofs: SecurityBoundaryProof[],
  acceptedConventions: AcceptedConvention[]
): SecurityCapabilitySummary[] {
  return SECURITY_CAPABILITIES.map((name) => {
    const matchingProofs = proofs.filter((proof) =>
      proof.capability_status.some((status) => normalizedCapability(status.name) === name) ||
      proof.missing_proof.some((missing) => normalizedCapability(missing.capability) === name) ||
      proof.parser_gaps.some((gap) => normalizedCapability(gap.capability) === name)
    );
    const parserGapCount = matchingProofs.reduce((count, proof) =>
      count + proof.parser_gaps.filter((gap) => normalizedCapability(gap.capability) === name).length, 0);
    const missingProofCount = matchingProofs.reduce((count, proof) =>
      count + proof.missing_proof.filter((missing) => normalizedCapability(missing.capability) === name).length, 0);
    const affectedFiles = [...new Set(matchingProofs.flatMap((proof) => [
      proof.route.file_path,
      ...proof.parser_gaps
        .filter((gap) => normalizedCapability(gap.capability) === name)
        .map((gap) => gap.file_path)
    ]))].sort();
    const requiredByContract = acceptedConventions.some((convention) =>
      securityConventionCapability(convention.kind) === name &&
      ["warn", "block"].includes(convention.enforcement_mode)
    );
    const complete = matchingProofs.length > 0 &&
      matchingProofs.every((proof) => proof.result.proof_status === "proven") &&
      parserGapCount === 0 &&
      missingProofCount === 0;
    return {
      name,
      capability: "deterministic_check",
      status: complete
        ? "complete"
        : matchingProofs.length > 0
          ? "partial"
          : requiredByContract
            ? "missing"
            : "unsupported",
      can_block: true,
      parser_gap_count: parserGapCount,
      missing_proof_count: missingProofCount,
      affected_files: affectedFiles
    };
  });
}

function normalizedCapability(capability: string): string {
  return CAPABILITY_ALIASES[capability] ?? capability;
}

function isSecurityConventionKind(kind: string): boolean {
  return securityConventionCapability(kind) !== null;
}

function securityConventionCapability(kind: string): string | null {
  switch (kind) {
    case "api_route_requires_auth_helper":
      return "control_flow_guard_dominance";
    case "middleware_must_cover_routes":
      return "middleware_coverage";
    case "api_route_requires_request_validation":
      return "request_validation_facts";
    case "session_object_must_come_from_trusted_helper":
      return "session_trust";
    case "api_route_requires_authorization":
      return "authorization";
    case "api_route_requires_tenant_scope":
      return "tenant_scope";
    case "api_route_forbids_sensitive_response_fields":
      return "sensitive_response";
    case "api_route_forbids_secret_exposure":
      return "secret_exposure";
    case "api_route_forbids_untrusted_ssrf":
      return "ssrf";
    case "api_route_forbids_raw_sql_without_params":
      return "raw_sql";
    case "api_route_cors_must_match_policy":
      return "cors_policy";
    case "api_route_requires_csrf_for_mutation":
      return "csrf";
    case "api_route_requires_rate_limit":
      return "rate_limit";
    default:
      return null;
  }
}

function acceptedSecurityConventionSummary(convention: AcceptedConvention) {
  const matcher = convention.matcher as unknown as Record<string, unknown>;
  return {
    convention_id: convention.id,
    kind: convention.kind,
    enforcement_mode: convention.enforcement_mode,
    capability: convention.enforcement_capability,
    matcher_summary: matcherSummary(convention.matcher),
    route_scope: {
      file_roles: stringArray(matcher.file_roles ?? matcher.applies_to_file_roles),
      paths: stringArray(matcher.paths ?? matcher.route_paths ?? convention.scope.path_globs),
      methods: stringArray(matcher.methods)
    },
    trusted_helpers: trustedHelpers(convention.requires),
    requires_summary: requiredProofSummariesForKind(convention.kind),
    accepted_by: convention.accepted_by,
    accepted_at: convention.accepted_at,
    updated_at: convention.updated_at,
    expires_at: convention.expires_at
  };
}

function matcherSummary(matcher: AcceptedConvention["matcher"]): string {
  const record = matcher as unknown as Record<string, unknown>;
  const roles = stringArray(record.file_roles ?? record.applies_to_file_roles);
  const methods = stringArray(record.methods);
  const paths = stringArray(record.paths ?? record.route_paths ?? record.path_globs);
  return [
    roles.length > 0 ? `file roles ${roles.join(",")}` : null,
    methods.length > 0 ? `methods ${methods.join(",")}` : null,
    paths.length > 0 ? `paths ${paths.join(",")}` : null
  ].filter((value): value is string => Boolean(value)).join("; ") || "security convention matcher";
}

function trustedHelpers(requires: Record<string, unknown> | undefined) {
  if (!requires) {
    return [];
  }
  const helpers = [
    ...helperStrings(requires.auth_helpers, "auth"),
    ...helperStrings(requires.authorization_helpers, "authorization"),
    ...helperStrings(requires.tenant_helpers, "tenant"),
    ...helperStrings(requires.validators, "validator"),
    ...helperObjects(requires.outbound_url_allowlist_helpers),
    ...helperObjects(requires.csrf_helpers),
    ...helperObjects(requires.rate_limit_helpers),
    ...helperObjects(requires.response_serializers)
  ];
  return helpers.sort((left, right) => left.helper_id.localeCompare(right.helper_id));
}

function helperStrings(value: unknown, prefix: string) {
  return stringArray(value).map((symbol) => ({ helper_id: `${prefix}:${symbol}`, symbol }));
}

function helperObjects(value: unknown) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((entry): entry is Record<string, unknown> => entry !== null && typeof entry === "object")
    .map((entry) => ({
      helper_id: String(entry.helper_id ?? entry.serializer_id ?? entry.symbol ?? "helper"),
      symbol: String(entry.symbol ?? entry.imported_name ?? entry.local_name ?? entry.serializer_id ?? "helper"),
      ...(typeof entry.module === "string" ? { module: entry.module } : {}),
      ...(typeof entry.import_source === "string" ? { import: entry.import_source } : {})
    }));
}

function requiredProofSummaries(proof: SecurityBoundaryProof): string[] {
  return proof.contracts.flatMap((contract) => requiredProofSummariesForKind(contract.kind));
}

function requiredProofSummariesForKind(kind: string): string[] {
  switch (kind) {
    case "api_route_requires_auth_helper":
      return ["auth helper must dominate data and response sinks"];
    case "middleware_must_cover_routes":
      return ["middleware must cover matched route and method"];
    case "api_route_requires_request_validation":
      return ["request input must be validated before trusted sinks"];
    case "session_object_must_come_from_trusted_helper":
      return ["session object must come from trusted helper"];
    case "api_route_requires_authorization":
      return ["authorization guard must dominate protected operations"];
    case "api_route_requires_tenant_scope":
      return ["tenant predicate must bind trusted tenant source to data operation"];
    case "api_route_forbids_sensitive_response_fields":
      return ["sensitive response fields must be filtered by accepted serializer"];
    case "api_route_forbids_secret_exposure":
      return ["secret values must not reach response or log sinks"];
    case "api_route_forbids_untrusted_ssrf":
      return ["outbound URL must be constant or accepted allowlisted value"];
    case "api_route_forbids_raw_sql_without_params":
      return ["raw SQL must be parameterized"];
    case "api_route_cors_must_match_policy":
      return ["CORS policy must match accepted origin and credential policy"];
    case "api_route_requires_csrf_for_mutation":
      return ["CSRF guard must dominate mutation route sinks"];
    case "api_route_requires_rate_limit":
      return ["rate-limit guard must dominate matched route sinks"];
    default:
      return [];
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string").sort()
    : [];
}
