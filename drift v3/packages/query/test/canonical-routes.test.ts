import { describe, expect, it } from "vitest";
import { buildCanonicalRouteReadModel } from "../src/canonical-routes.js";

describe("buildCanonicalRouteReadModel", () => {
  it("uses normalized entrypoints as the route source of truth", () => {
    const model = buildCanonicalRouteReadModel({
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      entrypoints: [{
        schema_version: "drift.normalized_entrypoint.v1",
        entrypoint_id: "entrypoint:next_app:apps/web/app/(admin)/api/projects/route.ts:GET",
        repo_id: "repo_abc",
        scan_id: "scan_abc",
        adapter_id: "framework_adapter_next_v1",
        framework: "next_app",
        kind: "api_route",
        file_path: "apps/web/app/(admin)/api/projects/route.ts",
        handler_symbol: "GET",
        route_pattern: "/api/projects",
        method: "GET",
        middleware_refs: [],
        request_source_refs: [],
        response_sink_refs: [],
        data_operation_refs: [],
        confidence_label: "high",
        evidence_refs: ["fact:apps/web/app/(admin)/api/projects/route.ts:route_declared:GET:1-3"],
        parser_gap_ids: []
      }],
      proofs: [],
      fallback_fact_routes: [{
        route_id: "route:apps/web/app/(admin)/api/projects/route.ts:GET",
        file_path: "apps/web/app/(admin)/api/projects/route.ts",
        path: "/api/wrong",
        method: "GET",
        file_role: "api_route"
      }]
    });

    expect(model.routes).toEqual([expect.objectContaining({
      route_id: "route:apps/web/app/(admin)/api/projects/route.ts:GET",
      normalized_entrypoint_id: "entrypoint:next_app:apps/web/app/(admin)/api/projects/route.ts:GET",
      path: "/api/projects",
      method: "GET",
      source: "normalized_entrypoint"
    })]);
    expect(model.fallback.used).toBe(false);
  });

  it("marks legacy fact fallback explicitly when entrypoints are absent", () => {
    const model = buildCanonicalRouteReadModel({
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      entrypoints: [],
      proofs: [],
      fallback_fact_routes: [{
        route_id: "route:apps/web/app/api/projects/route.ts:GET",
        file_path: "apps/web/app/api/projects/route.ts",
        path: "/api/projects",
        method: "GET",
        file_role: "api_route"
      }]
    });

    expect(model.fallback).toMatchObject({
      used: true,
      reason: "normalized_entrypoints_missing"
    });
    expect(model.routes[0]).toMatchObject({ source: "legacy_fact_fallback" });
  });

  it("uses legacy fact fallback when no API route entrypoints exist", () => {
    const model = buildCanonicalRouteReadModel({
      repo_id: "repo_abc",
      scan_id: "scan_abc",
      entrypoints: [{
        schema_version: "drift.normalized_entrypoint.v1",
        entrypoint_id: "entrypoint:cron:apps/web/jobs/sync.ts:runSync",
        repo_id: "repo_abc",
        scan_id: "scan_abc",
        adapter_id: "framework_adapter_worker_v1",
        framework: "generic",
        kind: "background_job",
        file_path: "apps/web/jobs/sync.ts",
        handler_symbol: "runSync",
        middleware_refs: [],
        request_source_refs: [],
        response_sink_refs: [],
        data_operation_refs: [],
        confidence_label: "medium",
        evidence_refs: [],
        parser_gap_ids: []
      }],
      proofs: [],
      fallback_fact_routes: [{
        route_id: "route:apps/web/app/api/projects/route.ts:GET",
        file_path: "apps/web/app/api/projects/route.ts",
        path: "/api/projects",
        method: "GET",
        file_role: "api_route"
      }]
    });

    expect(model.fallback.used).toBe(true);
    expect(model.routes[0]).toMatchObject({ source: "legacy_fact_fallback" });
  });

  it("marks proof-only routes and scan mismatches explicitly", () => {
    const model = buildCanonicalRouteReadModel({
      repo_id: "repo_abc",
      scan_id: "scan_new",
      entrypoints: [],
      proofs: [{
        proof_scan_id: "scan_old",
        route_id: "route:apps/web/app/api/projects/route.ts:GET",
        file_path: "apps/web/app/api/projects/route.ts",
        path: "/api/projects",
        method: "GET"
      }],
      fallback_fact_routes: []
    });

    expect(model.routes[0]).toMatchObject({
      source: "security_proof",
      freshness: "stale"
    });
    expect(model.proof_freshness).toBe("stale");
  });
});
