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
