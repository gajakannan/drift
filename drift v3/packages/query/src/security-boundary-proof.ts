import type { SecurityBoundaryProof } from "@drift/core";

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
