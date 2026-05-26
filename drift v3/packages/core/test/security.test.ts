import { describe, expect, it } from "vitest";
import {
  SecurityBoundaryProofSchema,
  SecurityConventionSchema,
  SecurityMissingProofCodeSchema
} from "../src/index.js";

describe("security domain schemas", () => {
  it("validates api_route_requires_auth_helper contracts and missing proof codes", () => {
    expect(SecurityMissingProofCodeSchema.parse("missing_auth_guard")).toBe("missing_auth_guard");

    const contract = SecurityConventionSchema.parse({
      contract_id: "security_api_auth_require_user",
      kind: "api_route_requires_auth_helper",
      capability: "deterministic_check",
      enforcement_mode: "block",
      matcher: {
        file_roles: ["api_route"],
        path_globs: ["**/app/api/**/route.ts"],
        methods: ["GET", "POST"]
      },
      scope: {
        check_scope: "changed-files",
        applies_to: "route",
        diff_status: ["added", "modified", "renamed"]
      },
      requires: {
        auth_helpers: ["requireUser"],
        dominates: ["data_operation", "response"]
      },
      exceptions: [],
      governance: {
        accepted_by: "test",
        accepted_at: "2026-05-25T00:00:00.000Z",
        rationale: "API routes require accepted auth helper dominance"
      }
    });

    expect(contract.kind).toBe("api_route_requires_auth_helper");
  });

  it("rejects blocking heuristic security contracts", () => {
    expect(() => SecurityConventionSchema.parse({
      contract_id: "security_api_auth_require_user",
      kind: "api_route_requires_auth_helper",
      capability: "heuristic_check",
      enforcement_mode: "block",
      matcher: { file_roles: ["api_route"] },
      scope: { check_scope: "changed-files", applies_to: "route" },
      requires: { auth_helpers: ["requireUser"] }
    })).toThrow(/blocking security contracts require deterministic capability/);
  });

  it("validates SecurityBoundaryProof.auth without snippets", () => {
    const proof = SecurityBoundaryProofSchema.parse({
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
        parser_gap_ids: [],
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
      parser_gaps: [],
      result: {
        proof_status: "missing_proof",
        enforcement_result: "block",
        can_block: true,
        finding_ids: ["finding_auth"]
      }
    });

    expect(JSON.stringify(proof)).not.toContain("const projects");
    expect(proof.auth.required).toBe(true);
  });
});
