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
