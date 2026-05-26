import { describe, expect, it } from "vitest";
import { buildSecurityBoundaryProofReadModel } from "../src/index.js";

describe("security boundary proof read model", () => {
  it("renders proof, findings, and parser gaps without snippets", () => {
    const model = buildSecurityBoundaryProofReadModel({
      proofs: [{
        proof_id: "proof_route_projects_get",
        proof_version: "security-boundary-proof/v1",
        route: {
          route_id: "route_projects_get",
          file_path: "app/api/projects/route.ts",
          file_role: "api_route"
        },
        contracts: [{
          contract_id: "security_api_auth_require_user",
          kind: "api_route_requires_auth_helper",
          enforcement_mode: "block",
          capability: "deterministic_check",
          matched: true
        }],
        capability_status: [{
          name: "control_flow_guard_dominance",
          status: "complete",
          can_block: true,
          parser_gap_ids: ["parser_gap_dynamic"],
          missing_proof_ids: ["missing_proof_auth"]
        }],
        auth: {
          required: true,
          proven: false,
          proof_kind: "none",
          trusted_guard_calls: [],
          dominated_sinks: [],
          undominated_sinks: [{
            sink_id: "sink_projects_read",
            sink_kind: "data_operation",
            reason: "no_guard_call",
            fact_ids: ["fact_projects_read"]
          }]
        },
        missing_proof: [{
          id: "missing_proof_auth",
          capability: "control_flow_guard_dominance",
          code: "missing_auth_guard",
          blocks_enforcement: true,
          fact_ids: ["fact_projects_read"],
          graph_edge_ids: []
        }],
        parser_gaps: [{
          parser_gap_id: "parser_gap_dynamic",
          capability: "control_flow_guard_dominance",
          code: "unsupported_dynamic_control_flow",
          file_path: "app/api/projects/route.ts",
          reason: "Unsupported dynamic control flow",
          affected_contract_kinds: ["api_route_requires_auth_helper"],
          affected_route_ids: ["route_projects_get"],
          missing_proof_ids: ["missing_proof_auth"],
          blocks_enforcement: true
        }],
        result: {
          proof_status: "parser_gap",
          enforcement_result: "block",
          can_block: true,
          finding_ids: ["finding_auth"]
        }
      }],
      findings: [{
        finding_id: "finding_auth",
        title: "API route missing required auth proof",
        lifecycle: "new"
      }]
    });

    expect(model.routes).toEqual([{
      route_id: "route_projects_get",
      file_path: "app/api/projects/route.ts",
      auth_required: true,
      auth_proven: false,
      proof_status: "parser_gap",
      enforcement_result: "block",
      missing_proof_codes: ["missing_auth_guard"],
      parser_gap_codes: ["unsupported_dynamic_control_flow"],
      finding_ids: ["finding_auth"],
      lifecycle: ["new"]
    }]);
    expect(JSON.stringify(model)).not.toContain("const projects");
    expect(JSON.stringify(model)).not.toContain("requireUser()");
  });
});
