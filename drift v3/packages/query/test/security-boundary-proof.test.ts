import { describe, expect, it } from "vitest";
import { buildSecurityBoundaryProofReadModel, fallbackFactRepoMapFiles } from "../src/index.js";

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
      middleware_required: false,
      middleware_proven: false,
      middleware_protection_kinds: [],
      middleware_mismatch_reasons: [],
      request_validation_required: false,
      request_validation_proven: false,
      request_validation_unvalidated_reasons: [],
      session_trust_required: false,
      session_trust_proven: false,
      session_missing_trust_reasons: [],
      authorization_required: false,
      authorization_proven: false,
      authorization_missing_reasons: [],
      tenant_required: false,
      tenant_proven: false,
      tenant_missing_reasons: [],
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

  it("summarizes request validation proof without snippets", () => {
    const model = buildSecurityBoundaryProofReadModel({
      proofs: [{
        proof_id: "proof_route_projects_post_validation",
        proof_version: "security-boundary-proof/v1",
        route: {
          route_id: "route_projects_post",
          file_path: "app/api/projects/route.ts",
          file_role: "api_route"
        },
        contracts: [{
          contract_id: "security_api_request_validation",
          kind: "api_route_requires_request_validation",
          enforcement_mode: "block",
          capability: "deterministic_check",
          matched: true
        }],
        capability_status: [{
          name: "request_validation_facts",
          status: "complete",
          can_block: true,
          parser_gap_ids: [],
          missing_proof_ids: ["missing_validation"]
        }],
        auth: {
          required: false,
          proven: false,
          proof_kind: "none",
          trusted_guard_calls: [],
          dominated_sinks: [],
          undominated_sinks: []
        },
        request_validation: {
          required: true,
          proven: false,
          input_reads: [{ fact_id: "fact_body", source: "body", variable: "body" }],
          validations: [],
          validated_uses: [],
          unvalidated_uses: [{
            input_fact_id: "fact_body",
            sink_fact_id: "sink_create",
            sink_kind: "data_operation",
            reason: "request_input_not_validated"
          }]
        },
        missing_proof: [{
          id: "missing_validation",
          capability: "request_validation_facts",
          code: "request_input_not_validated",
          blocks_enforcement: true,
          fact_ids: ["fact_body"],
          graph_edge_ids: []
        }],
        parser_gaps: [],
        result: {
          proof_status: "missing_proof",
          enforcement_result: "block",
          can_block: true,
          finding_ids: ["finding_validation"]
        }
      }],
      findings: []
    });

    expect(model.routes[0]).toMatchObject({
      route_id: "route_projects_post",
      request_validation_required: true,
      request_validation_proven: false,
      request_validation_unvalidated_reasons: ["request_input_not_validated"]
    });
    expect(JSON.stringify(model)).not.toContain("request.json()");
  });

  it("summarizes phase4 proof without synthesizing trust from raw facts", () => {
    const model = buildSecurityBoundaryProofReadModel({
      proofs: [{
        proof_id: "proof_phase4",
        proof_version: "security-boundary-proof/v1",
        route: {
          route_id: "route_projects_delete",
          file_path: "app/api/projects/route.ts",
          file_role: "api_route"
        },
        contracts: [{
          contract_id: "security_api_authorization",
          kind: "api_route_requires_authorization",
          enforcement_mode: "block",
          capability: "deterministic_check",
          matched: true
        }],
        capability_status: [{
          name: "authorization",
          status: "partial",
          can_block: true,
          parser_gap_ids: [],
          missing_proof_ids: ["missing_authz"]
        }],
        auth: {
          required: false,
          proven: false,
          proof_kind: "none",
          trusted_guard_calls: [],
          dominated_sinks: [],
          undominated_sinks: []
        },
        session_trust: {
          required: true,
          proven: false,
          trusted_sessions: [],
          missing_trust: [{ fact_id: "fact_session", variable: "session", reason: "derived_from_request" }]
        },
        authorization: {
          required: true,
          proven: false,
          role_or_policy_guards: [],
          missing: [{ reason: "session_not_trusted", sink_fact_id: "sink_delete" }]
        },
        tenant: {
          required: true,
          proven: false,
          tenant_sources: [{ fact_id: "fact_tenant", source: "body", key: "tenantId", trusted: false }],
          predicates: [],
          missing: [{ data_operation_fact_id: "fact_delete", reason: "tenant_source_untrusted" }]
        },
        missing_proof: [{
          id: "missing_authz",
          capability: "authorization",
          code: "session_not_trusted",
          blocks_enforcement: true,
          fact_ids: ["fact_session"],
          graph_edge_ids: []
        }],
        parser_gaps: [],
        result: {
          proof_status: "missing_proof",
          enforcement_result: "block",
          can_block: true,
          finding_ids: ["finding_authz"]
        }
      }],
      findings: [{ finding_id: "finding_authz", title: "missing", lifecycle: "new" }]
    });

    expect(model.routes[0]).toMatchObject({
      session_trust_required: true,
      session_trust_proven: false,
      authorization_required: true,
      authorization_proven: false,
      authorization_missing_reasons: ["session_not_trusted"],
      tenant_required: true,
      tenant_proven: false,
      tenant_missing_reasons: ["tenant_source_untrusted"]
    });
    expect(JSON.stringify(model)).not.toContain("tenant-");
    expect(JSON.stringify(model)).not.toContain("session=");
  });

  it("does not report request validation proven from raw scan facts", () => {
    const files = fallbackFactRepoMapFiles([{
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      file_path: "app/api/projects/route.ts",
      content_hash: "hash_projects_route",
      byte_size: 120,
      indexed: true
    }], [{
      id: "fact_request_body",
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      kind: "request_input_read",
      file_path: "app/api/projects/route.ts",
      name: "body",
      value: JSON.stringify({
        route_id: "route:app/api/projects/route.ts:POST",
        source: "body",
        variable: "body"
      }),
      start_line: 3,
      end_line: 3
    }, {
      id: "fact_validated_use",
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      kind: "validated_input_used",
      file_path: "app/api/projects/route.ts",
      name: "input",
      value: JSON.stringify({
        route_id: "route:app/api/projects/route.ts:POST",
        sink_kind: "data_operation"
      }),
      start_line: 5,
      end_line: 5
    }] as never);

    expect(files[0]?.route_security?.request_validation).toMatchObject({
      status: "not_evaluated",
      input_sources: ["body"]
    });
  });

  it("summarizes middleware coverage proof without snippets", () => {
    const model = buildSecurityBoundaryProofReadModel({
      proofs: [{
        proof_id: "proof_route_projects_get_middleware",
        proof_version: "security-boundary-proof/v1",
        route: {
          route_id: "route_projects_get",
          file_path: "app/api/projects/route.ts",
          file_role: "api_route"
        },
        contracts: [{
          contract_id: "security_middleware_api_coverage",
          kind: "middleware_must_cover_routes",
          enforcement_mode: "block",
          capability: "deterministic_check",
          matched: true
        }],
        capability_status: [{
          name: "middleware_coverage",
          status: "complete",
          can_block: true,
          parser_gap_ids: [],
          missing_proof_ids: []
        }],
        auth: {
          required: true,
          proven: true,
          proof_kind: "middleware_guard",
          trusted_guard_calls: [],
          dominated_sinks: [],
          undominated_sinks: []
        },
        middleware: {
          required: true,
          proven: true,
          matched_middleware: [{
            middleware_id: "middleware:middleware.ts",
            matcher_fact_id: "fact_middleware_matcher",
            protects_route_edge_id: "edge_middleware_projects",
            protection_kind: "auth"
          }],
          mismatches: []
        },
        missing_proof: [],
        parser_gaps: [],
        result: {
          proof_status: "proven",
          enforcement_result: "pass",
          can_block: false,
          finding_ids: []
        }
      }],
      findings: []
    });

    expect(model.routes).toEqual([expect.objectContaining({
      route_id: "route_projects_get",
      middleware_required: true,
      middleware_proven: true,
      middleware_protection_kinds: ["auth"],
      middleware_mismatch_reasons: [],
      request_validation_required: false,
      request_validation_proven: false,
      request_validation_unvalidated_reasons: []
    })]);
    expect(JSON.stringify(model)).not.toContain("requireUser()");
  });
});
