import type { SecurityBoundaryProof } from "@drift/core";

export interface SecurityCheckFindingInput {
  finding_id: string;
  title: string;
  file_path: string;
  enforcement_result: "pass" | "brief" | "warn" | "block";
}

export interface BuildSecurityCheckJsonInput {
  repo_id: string;
  scope: "changed-hunks" | "changed-files" | "full";
  changed_files: string[];
  proofs: SecurityBoundaryProof[];
  findings: SecurityCheckFindingInput[];
}

export interface SecurityCheckJson {
  repo_id: string;
  scope: "changed-hunks" | "changed-files" | "full";
  security_boundary_proofs: SecurityBoundaryProof[];
  security_findings: SecurityCheckFindingInput[];
  summary: {
    security_findings_count: number;
    security_blocking_count: number;
    middleware_coverage_proven_count: number;
  };
}

export function buildSecurityCheckJson(input: BuildSecurityCheckJsonInput): SecurityCheckJson {
  const changedFiles = new Set(input.changed_files);
  const scopedFindings = input.findings.filter((finding) =>
    input.scope === "full" || changedFiles.has(finding.file_path)
  );

  return {
    repo_id: input.repo_id,
    scope: input.scope,
    security_boundary_proofs: input.proofs,
    security_findings: scopedFindings,
    summary: {
      security_findings_count: scopedFindings.length,
      security_blocking_count: scopedFindings.filter((finding) =>
        finding.enforcement_result === "block"
      ).length,
      middleware_coverage_proven_count: input.proofs.filter((proof) => {
        const middleware = proof.middleware;
        return Boolean(middleware && middleware.required && middleware.proven);
      }).length
    }
  };
}
