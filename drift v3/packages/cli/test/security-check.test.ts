import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach } from "vitest";
import { openDriftStorage } from "@drift/storage";
import { runCheck } from "../src/check/run-check.js";
import { runEngineCheck } from "../src/engine/engine-check.js";
import { buildSecurityCheckJson } from "../src/check/security-check.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs.length = 0;
});

describe("security check bridge", () => {
  it("includes security proofs and blocks only changed-scope security findings", () => {
    const payload = buildSecurityCheckJson({
      repo_id: "repo_abc",
      scope: "changed-files",
      changed_files: ["app/api/projects/route.ts"],
      proofs: [
        securityProof("proof_changed", "app/api/projects/route.ts", "finding_changed"),
        securityProof("proof_unchanged", "app/api/archive/route.ts", "finding_unchanged")
      ],
      findings: [{
        finding_id: "finding_changed",
        title: "API route missing required auth proof",
        file_path: "app/api/projects/route.ts",
        enforcement_result: "block"
      }, {
        finding_id: "finding_unchanged",
        title: "API route missing required auth proof",
        file_path: "app/api/archive/route.ts",
        enforcement_result: "block"
      }]
    });

    expect(payload.security_boundary_proofs).toHaveLength(2);
    expect(payload.security_findings).toEqual([{
      finding_id: "finding_changed",
      title: "API route missing required auth proof",
      file_path: "app/api/projects/route.ts",
      enforcement_result: "block"
    }]);
    expect(payload.summary.security_blocking_count).toBe(1);
    expect(JSON.stringify(payload)).not.toContain("requireUser()");
  });

  it("receives SecurityBoundaryProof.auth from engine-owned auth checks", async () => {
    const result = await runEngineCheck({
      repoId: "repo_abc",
      repoRoot: process.cwd(),
      scanId: "scan_security_auth",
      snapshots: [{
        repo_id: "repo_abc",
        scan_id: "scan_security_auth",
        file_path: "app/api/projects/route.ts",
        content_hash: "a".repeat(64),
        byte_size: 100,
        indexed: true
      }],
      facts: [
        fact("file_role_detected", "api_route", 1),
        fact("route_declared", "GET", 4),
        fact("data_operation_detected", "findMany", 5, "db.project"),
        fact("route_returns_response", "json", 6, "Response")
      ],
      conventions: [{
        id: "security_api_auth_require_user",
        repo_id: "repo_abc",
        contract_id: "contract_abc",
        kind: "api_route_requires_auth_helper",
        statement: "API routes require accepted auth helper dominance.",
        scope: { path_globs: ["app/api/**/route.ts"], file_roles: ["api_route"] },
        matcher: {
          kind: "api_route_requires_auth_helper",
          required_calls: ["requireUser"],
          applies_to_file_roles: ["api_route"]
        },
        severity: "error",
        enforcement_mode: "block",
        enforcement_capability: "deterministic_check",
        exceptions: [],
        evidence_refs: [],
        counterexample_refs: [],
        accepted_by: "test",
        accepted_at: "2026-05-25T00:00:00.000Z",
        updated_at: "2026-05-25T00:00:00.000Z"
      }],
      baseline: [],
      diff: {
        files: [{ path: "app/api/projects/route.ts", changedLines: new Set([5]) }],
        deletedFiles: []
      },
      scope: "changed-files"
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      convention_id: "security_api_auth_require_user",
      rule_id: "api_route_requires_auth_helper",
      enforcement_result: "block"
    });
    expect(result.security_boundary_proofs).toHaveLength(1);
    expect(result.security_boundary_proofs[0].auth).toMatchObject({
      required: true,
      proven: false,
      proof_kind: "none"
    });
  });

  it("returns SecurityBoundaryProof.auth in drift check JSON output", async () => {
    const { databasePath, repoRoot, diffPath } = await seedAuthCheckDatabase();
    const storage = openDriftStorage({ databasePath });
    storage.migrate();

    const result = await runCheck(storage, {
      positional: ["check"],
      flags: new Map<string, string | true>([
        ["repo", "repo_abc"],
        ["scope", "changed-hunks"],
        ["diff-file", diffPath],
        ["now", "2026-05-25T00:00:00.000Z"],
        ["json", true]
      ])
    });
    storage.close();

    expect(result.exitCode).toBe(1);
    const payload = result.payload as {
      security_boundary_proofs?: Array<{ auth?: { required: boolean; proven: boolean; proof_kind: string } }>;
      findings?: Array<{ convention_id: string; enforcement_result: string }>;
    };
    expect(payload.security_boundary_proofs).toHaveLength(1);
    expect(payload.security_boundary_proofs?.[0]?.auth).toMatchObject({
      required: true,
      proven: false,
      proof_kind: "none"
    });
    expect(payload.findings).toContainEqual(expect.objectContaining({
      convention_id: "security_api_auth_require_user",
      enforcement_result: "block"
    }));
    expect(JSON.stringify(payload)).not.toContain("requireUser()");
    expect(JSON.stringify(payload)).not.toContain("await db.project.findMany()");
    expect(repoRoot).toContain("drift-security-auth-check-");
  });
});

function fact(kind: string, name: string, line: number, value?: string) {
  return {
    id: `fact_${kind}_${line}`,
    repo_id: "repo_abc",
    scan_id: "scan_security_auth",
    kind,
    file_path: "app/api/projects/route.ts",
    name,
    value,
    start_line: line,
    end_line: line
  } as const;
}

function securityProof(proofId: string, filePath: string, findingId: string) {
  return {
    proof_id: proofId,
    proof_version: "security-boundary-proof/v1",
    route: {
      route_id: proofId.replace("proof", "route"),
      file_path: filePath,
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
        sink_id: `${proofId}_sink`,
        sink_kind: "data_operation",
        reason: "no_guard_call",
        fact_ids: [`${proofId}_fact`]
      }]
    },
    missing_proof: [{
      id: `${proofId}_missing`,
      capability: "control_flow_guard_dominance",
      code: "missing_auth_guard",
      blocks_enforcement: true,
      fact_ids: [`${proofId}_fact`],
      graph_edge_ids: []
    }],
    parser_gaps: [],
    result: {
      proof_status: "missing_proof",
      enforcement_result: "block",
      can_block: true,
      finding_ids: [findingId]
    }
  } as const;
}

async function seedAuthCheckDatabase(): Promise<{
  databasePath: string;
  repoRoot: string;
  diffPath: string;
}> {
  const dir = await mkdtemp(join(tmpdir(), "drift-security-auth-check-"));
  tempDirs.push(dir);
  const repoRoot = join(dir, "repo");
  const routePath = "app/api/projects/route.ts";
  await mkdir(join(repoRoot, "app/api/projects"), { recursive: true });
  await writeFile(join(repoRoot, routePath), [
    "const db = { project: { findMany: async () => [] } };",
    "",
    "export async function GET() {",
    "  const projects = await db.project.findMany();",
    "  return Response.json(projects);",
    "}",
    ""
  ].join("\n"));
  const diffPath = join(dir, "diff.patch");
  await writeFile(diffPath, [
    "diff --git a/app/api/projects/route.ts b/app/api/projects/route.ts",
    "--- a/app/api/projects/route.ts",
    "+++ b/app/api/projects/route.ts",
    "@@ -0,0 +1,6 @@",
    "+const db = { project: { findMany: async () => [] } };",
    "+",
    "+export async function GET() {",
    "+  const projects = await db.project.findMany();",
    "+  return Response.json(projects);",
    "+}",
    ""
  ].join("\n"));
  const databasePath = join(dir, "drift.sqlite");
  const storage = openDriftStorage({ databasePath });
  storage.migrate();
  storage.upsertRepo({
    id: "repo_abc",
    root_path: repoRoot,
    fingerprint: "repo-fp",
    created_at: "2026-05-25T00:00:00.000Z",
    updated_at: "2026-05-25T00:00:00.000Z"
  });
  storage.upsertAcceptedConvention("repo_abc", {
    id: "security_api_auth_require_user",
    contract_id: "contract_abc",
    kind: "api_route_requires_auth_helper",
    statement: "API routes require accepted auth helper dominance.",
    scope: { path_globs: ["app/api/**/route.ts"], file_roles: ["api_route"] },
    matcher: {
      kind: "api_route_requires_auth_helper",
      required_calls: ["requireUser"],
      applies_to_file_roles: ["api_route"]
    },
    severity: "error",
    enforcement_mode: "block",
    enforcement_capability: "deterministic_check",
    exceptions: [],
    evidence_refs: [],
    counterexample_refs: [],
    accepted_by: "test",
    accepted_at: "2026-05-25T00:00:00.000Z",
    updated_at: "2026-05-25T00:00:00.000Z"
  });
  storage.upsertRepoContract({
    id: "contract_abc",
    repo_id: "repo_abc",
    contract_schema_version: 1,
    repo_fingerprint: "repo-fp",
    created_at: "2026-05-25T00:00:00.000Z",
    updated_at: "2026-05-25T00:00:00.000Z",
    conventions: storage.listAcceptedConventions("repo_abc"),
    rejected_inferences: [],
    waivers: [],
    risky_areas: [],
    layer_architecture: {
      schema_version: "drift.layer_architecture.v1",
      architecture_id: "architecture_security_auth",
      repo_id: "repo_abc",
      version: 1,
      layers: [
        { id: "route", role: "route", position: "entrypoint" },
        { id: "auth", role: "auth", position: "middle" },
        { id: "data_access", role: "data_access", position: "terminal" }
      ],
      allowed_edges: [],
      forbidden_edges: [],
      soft_edges: []
    },
    safe_commands: [],
    required_checks: [],
    context_egress: {
      default_mode: "local_only",
      denied_globs: [".env*", "**/*.pem"],
      max_snippet_chars: 1200,
      allow_full_file_content: false
    },
    agent_permissions: []
  });
  storage.close();
  return { databasePath, repoRoot, diffPath };
}
