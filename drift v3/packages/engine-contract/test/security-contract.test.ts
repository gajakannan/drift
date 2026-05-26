import { describe, expect, it } from "vitest";
import {
  EngineSecurityProofEventSchema,
  parseEngineSecurityProofEvent
} from "../src/index.js";

describe("engine security contract schemas", () => {
  it("validates versioned security proof events", () => {
    const event = parseEngineSecurityProofEvent({
      event: "SecurityProof",
      schema_version: "engine.security.proof/v1",
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
        capability_status: [],
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
      }]
    });

    expect(event.schema_version).toBe("engine.security.proof/v1");
    expect(EngineSecurityProofEventSchema.safeParse(event).success).toBe(true);
    expect(JSON.stringify(event)).not.toContain("requireUser()");
  });

  it("rejects unknown security proof event versions", () => {
    expect(() => parseEngineSecurityProofEvent({
      event: "SecurityProof",
      schema_version: "engine.security.proof/v2",
      proofs: []
    })).toThrow(/Invalid Drift engine security proof event/);
  });
});
