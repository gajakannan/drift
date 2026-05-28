import { describe, expect, it } from "vitest";
import {
  BUILTIN_SEMANTIC_CAPABILITIES,
  ArchitectureContractV1Schema,
  ConventionElectionContractV2Schema,
  ConventionRuleContractSchema,
  ParserGapV2Schema,
  RepoContractSchema,
  SemanticCoverageContractSchema,
  SemanticCapabilityContractSchema,
  validateConventionRuleCapabilities
} from "../src/index.js";

describe("semantic capabilities", () => {
  it("rejects blocking semantic capabilities without deterministic certification", () => {
    expect(() => SemanticCapabilityContractSchema.parse({
      schema_version: "drift.semantic_capability.v1",
      capability_id: "ts.computed_calls.v1",
      display_name: "Computed call resolution",
      language: "typescript",
      support: "partial",
      certification: "experimental",
      can_block: true,
      evidence_classes: ["heuristic"],
      emitted_fact_kinds: [],
      emitted_node_kinds: [],
      emitted_edge_kinds: [],
      parser_gap_kinds: ["computed_call_unresolved"],
      fixture_suites: ["ts-computed-calls"],
      required_for_beta_claims: [],
      owner: "rust_engine"
    })).toThrow("blocking semantic capabilities require certified deterministic evidence");
  });

  it("requires active convention rules to reference known semantic capabilities", () => {
    const result = validateConventionRuleCapabilities({
      rule: {
        rule_id: "api_route_no_direct_data_access",
        requires_capabilities: ["ts.static_imports.v1", "ts.missing.v1"]
      },
      capabilities: BUILTIN_SEMANTIC_CAPABILITIES
    });

    expect(result).toEqual({
      valid: false,
      missing_capabilities: ["ts.missing.v1"]
    });
  });

  it("marks the V1 route-layering capability set as blocking-safe", () => {
    const result = validateConventionRuleCapabilities({
      rule: {
        rule_id: "api_route_no_direct_data_access",
        requires_capabilities: [
          "ts.file_discovery.v1",
          "ts.syntax_facts.v1",
          "ts.static_imports.v1",
          "ts.import_resolution.v1",
          "ts.data_operations.v1",
          "ts.route_flow.v1"
        ]
      },
      capabilities: BUILTIN_SEMANTIC_CAPABILITIES
    });

    expect(result).toEqual({
      valid: true,
      missing_capabilities: []
    });
  });

  it("validates parser gap v2 semantic capability impact", () => {
    expect(ParserGapV2Schema.parse({
      schema_version: "drift.parser_gap.v2",
      parser_gap_id: "gap_dynamic_import_route_1",
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      file_path: "app/api/users/route.ts",
      start_line: 4,
      end_line: 4,
      kind: "dynamic_import_unresolved",
      message: "Dynamic import target is not statically resolvable.",
      affected_capabilities: ["ts.dynamic_imports.v1", "ts.route_flow.v1"],
      affected_contract_kinds: ["api_route_no_direct_data_access"],
      confidence_impact: "blocks_enforcement",
      suggested_action: "rewrite_static",
      evidence_refs: ["evidence_graph_1"]
    })).toMatchObject({
      kind: "dynamic_import_unresolved",
      affected_capabilities: ["ts.dynamic_imports.v1", "ts.route_flow.v1"],
      confidence_impact: "blocks_enforcement"
    });
  });

  it("validates semantic coverage decisions for blocking-safe checks", () => {
    expect(SemanticCoverageContractSchema.parse({
      schema_version: "drift.semantic_coverage.v1",
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      scope: "check",
      scope_id: "check_route_no_db",
      required_capabilities: ["ts.static_imports.v1", "ts.import_resolution.v1"],
      complete_capabilities: ["ts.static_imports.v1", "ts.import_resolution.v1"],
      partial_capabilities: [],
      missing_capabilities: [],
      unsupported_capabilities: [],
      parser_gap_ids: [],
      unsupported_pattern_ids: [],
      confidence: 1,
      decision: "blocking_allowed",
      reasons: [],
      generated_at: "2026-05-28T00:00:00.000Z"
    })).toMatchObject({
      decision: "blocking_allowed",
      confidence: 1
    });
  });

  it("validates architecture role edge policies", () => {
    expect(ArchitectureContractV1Schema.parse({
      schema_version: "drift.architecture.v1",
      architecture_id: "default_ts_architecture_v1",
      repo_id: "repo_abc",
      version: "1",
      source: "default",
      roles: [{
        role: "route",
        description: "HTTP route entrypoint",
        detection: "path",
        confidence_required_for_blocking: "high"
      }],
      edge_policies: [{
        from_role: "route",
        to_role: "data_access",
        edge_kind: "imports",
        policy: "forbidden",
        required_capabilities: ["ts.import_resolution.v1"]
      }]
    })).toMatchObject({
      architecture_id: "default_ts_architecture_v1",
      edge_policies: [expect.objectContaining({ policy: "forbidden" })]
    });
  });

  it("validates convention rules bound to semantic capabilities and architecture", () => {
    expect(ConventionRuleContractSchema.parse({
      schema_version: "drift.convention_rule.v2",
      rule_id: "api_route_no_direct_data_access",
      rule_version: "1",
      convention_kind: "api_route_no_direct_data_access",
      statement: "API routes must not directly access data stores.",
      applies_to: {
        path_globs: ["app/api/**/route.ts"],
        file_roles: ["route"],
        entrypoint_kinds: ["api_route"],
        methods: ["GET"]
      },
      requires_capabilities: ["ts.static_imports.v1", "ts.import_resolution.v1", "ts.route_flow.v1"],
      architecture_contract_id: "default_ts_architecture_v1",
      matcher: { forbidden_target_roles: ["data_access"] },
      can_block_when: {
        convention_status: "active",
        coverage_decision: "blocking_allowed",
        capability_certification: "certified_deterministic"
      },
      advisory_when: ["parser_gap_lowers_flow"],
      refuse_when: ["required_capability_missing"]
    })).toMatchObject({
      schema_version: "drift.convention_rule.v2",
      can_block_when: { coverage_decision: "blocking_allowed" }
    });
  });

  it("validates audited active convention elections", () => {
    expect(ConventionElectionContractV2Schema.parse({
      schema_version: "drift.convention_election.v2",
      election_id: "election_abc",
      repo_id: "repo_abc",
      candidate_id: "candidate_abc",
      convention_id: "convention_abc",
      previous_state: "candidate",
      next_state: "active",
      decision: "activate",
      human_actor: "local-user",
      reason: "Accepted deterministic route-layering convention.",
      evidence_refs: ["evidence_1"],
      counterexample_refs: [],
      required_capabilities: ["ts.route_flow.v1"],
      semantic_coverage_id: "coverage_abc",
      architecture_contract_id: "default_ts_architecture_v1",
      convention_rule_id: "api_route_no_direct_data_access",
      contract_fingerprint_before: "0".repeat(64),
      contract_fingerprint_after: "1".repeat(64),
      audit_event_id: "audit_abc",
      can_block: true,
      created_at: "2026-05-28T00:00:00.000Z"
    })).toMatchObject({
      next_state: "active",
      can_block: true
    });
  });

  it("allows repo contracts to bind semantic and architecture contract versions", () => {
    expect(RepoContractSchema.parse({
      id: "contract_abc",
      repo_id: "repo_abc",
      contract_schema_version: 1,
      repo_fingerprint: "repo-fingerprint",
      created_at: "2026-05-28T00:00:00.000Z",
      updated_at: "2026-05-28T00:00:00.000Z",
      conventions: [],
      rejected_inferences: [],
      waivers: [],
      risky_areas: [],
      safe_commands: [],
      required_checks: [],
      context_egress: {
        default_mode: "local_only",
        denied_globs: [],
        max_snippet_chars: 1200,
        allow_full_file_content: false
      },
      agent_permissions: [],
      semantic_capability_contract_version: "drift.semantic_capability.v1",
      architecture_contract_id: "default_ts_architecture_v1",
      architecture_contract_fingerprint: "a".repeat(64),
      active_convention_rule_ids: ["api_route_no_direct_data_access"],
      active_semantic_capability_ids: ["ts.route_flow.v1"],
      beta_claim_profile: "narrow_route_layering",
      enforcement_policy: {
        block_on_parser_gaps: false,
        refuse_on_required_capability_missing: true,
        advisory_on_heuristic_capability: true
      }
    })).toMatchObject({
      semantic_capability_contract_version: "drift.semantic_capability.v1",
      beta_claim_profile: "narrow_route_layering"
    });
  });
});
