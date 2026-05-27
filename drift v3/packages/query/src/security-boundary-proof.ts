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
