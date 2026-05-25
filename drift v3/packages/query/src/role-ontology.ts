import type { CanonicalRole } from "@drift/core";

export type RoleEdgeKind = "imports" | "calls" | "depends_on";

export interface RoleEdgeInput {
  from_role: CanonicalRole | string;
  to_role: CanonicalRole | string;
  edge_kind: RoleEdgeKind | string;
  rules?: RoleOntologyRule[];
}

export interface RoleEdgeDecision {
  allowed: boolean;
  severity: "allowed" | "advisory" | "warning" | "blocking";
  reason_code: string;
  reason: string;
  source?: "built_in" | "repo_contract";
  rule_id?: string;
}

export interface RoleOntologyRule {
  rule_id: string;
  from_role: CanonicalRole | string;
  to_role: CanonicalRole | string;
  edge_kind?: RoleEdgeKind | string;
  allowed: boolean;
  severity: "allowed" | "advisory" | "warning" | "blocking";
  reason_code: string;
  reason: string;
  source: "repo_contract";
}

export function evaluateRoleEdge(input: RoleEdgeInput): RoleEdgeDecision {
  const configuredRule = input.rules?.find((rule) =>
    rule.from_role === input.from_role &&
    rule.to_role === input.to_role &&
    (!rule.edge_kind || rule.edge_kind === input.edge_kind)
  );
  if (configuredRule) {
    return {
      allowed: configuredRule.allowed,
      severity: configuredRule.severity,
      reason_code: configuredRule.reason_code,
      reason: configuredRule.reason,
      source: configuredRule.source,
      rule_id: configuredRule.rule_id
    };
  }

  if (input.from_role === "route" && input.to_role === "data_access") {
    return {
      allowed: false,
      severity: "blocking",
      reason_code: "route_must_not_import_data_access",
      reason: "Routes must delegate data access through a service layer.",
      source: "built_in"
    };
  }

  if (input.from_role === "service" && input.to_role === "data_access") {
    return allowed("service_may_use_data_access", "Services may own data-access orchestration.");
  }

  if (input.from_role === "route" && input.to_role === "service") {
    return allowed("route_may_delegate_to_service", "Routes may delegate work to services.");
  }

  if (input.from_role === "component" && input.to_role === "data_access") {
    return {
      allowed: false,
      severity: "blocking",
      reason_code: "component_must_not_import_data_access",
      reason: "Components must not import server-side data-access modules.",
      source: "built_in"
    };
  }

  if (input.from_role.startsWith("test_")) {
    return allowed("test_dependency_allowed_by_scope", "Tests may depend on scoped subjects.");
  }

  if (input.from_role === "migration" && input.to_role === "data_access") {
    return allowed("migration_may_use_data_access", "Migrations may use data-access primitives.");
  }

  if (input.from_role === "script" && input.to_role === "data_access") {
    return {
      allowed: true,
      severity: "warning",
      reason_code: "script_data_access_allowed_with_risk",
      reason: "Scripts may use data access, but should be treated as side-effecting.",
      source: "built_in"
    };
  }

  if (input.from_role === "generated" || input.to_role === "generated") {
    return {
      allowed: true,
      severity: "advisory",
      reason_code: "generated_edges_ignored_by_default",
      reason: "Generated-code edges are ignored by default.",
      source: "built_in"
    };
  }

  if (input.from_role === "unknown" || input.to_role === "unknown") {
    return {
      allowed: true,
      severity: "advisory",
      reason_code: "unknown_role_lowers_confidence",
      reason: "Unknown roles lower graph confidence and must not create blocking findings by themselves.",
      source: "built_in"
    };
  }

  return allowed("role_edge_unspecified_allowed", "No canonical role rule forbids this edge.");
}

function allowed(reasonCode: string, reason: string): RoleEdgeDecision {
  return {
    allowed: true,
    severity: "allowed",
    reason_code: reasonCode,
    reason,
    source: "built_in"
  };
}
