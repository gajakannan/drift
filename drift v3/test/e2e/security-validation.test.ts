import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCli } from "../../packages/cli/src/index.js";
import { openDriftStorage } from "../../packages/storage/src/index.js";

const tempDirs: string[] = [];
let originalEngineBin: string | undefined;

async function fixtureRepo(name: string): Promise<{ repoRoot: string; stateRoot: string; diffPath: string }> {
  const dir = await mkdtemp(join(tmpdir(), "drift-security-validation-"));
  tempDirs.push(dir);
  const repoRoot = join(dir, "repo");
  const stateRoot = join(dir, "state");
  await cp(resolve("test/fixtures", name), repoRoot, { recursive: true });
  const route = await readFile(join(repoRoot, "app/api/projects/route.ts"), "utf8");
  const diffPath = join(dir, "change.patch");
  await writeFile(diffPath, [
    "diff --git a/app/api/projects/route.ts b/app/api/projects/route.ts",
    "--- /dev/null",
    "+++ b/app/api/projects/route.ts",
    `@@ -0,0 +1,${route.split(/\r?\n/).filter(Boolean).length} @@`,
    ...route.trimEnd().split(/\r?\n/).map((line) => `+${line}`),
    ""
  ].join("\n"));
  return { repoRoot, stateRoot, diffPath };
}

beforeEach(() => {
  originalEngineBin = process.env.DRIFT_ENGINE_BIN;
  process.env.DRIFT_ENGINE_BIN = resolve("target/debug/drift-engine");
});

afterEach(async () => {
  if (originalEngineBin === undefined) {
    delete process.env.DRIFT_ENGINE_BIN;
  } else {
    process.env.DRIFT_ENGINE_BIN = originalEngineBin;
  }
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("security validation fixture matrix", () => {
  it("security validation fixture matrix proves request input validation and gaps", async () => {
    const cases = [
      {
        name: "security-validation-missing",
        exitCode: 1,
        proven: false,
        parserGap: false,
        missingReason: "request_input_not_validated"
      },
      {
        name: "security-validation-result-unused",
        exitCode: 1,
        proven: false,
        parserGap: false,
        missingReason: "request_input_not_validated"
      },
      {
        name: "security-validation-before-data",
        exitCode: 0,
        proven: true,
        parserGap: false
      },
      {
        name: "security-validation-dynamic-body-parser-gap",
        exitCode: 1,
        proven: false,
        parserGap: true,
        missingReason: "unsupported_request_input_spread"
      }
    ];

    for (const entry of cases) {
      const { repoRoot, stateRoot, diffPath } = await fixtureRepo(entry.name);
      const scan = await runCli([
        "scan",
        "--repo-root", repoRoot,
        "--state-root", stateRoot,
        "--now", "2026-05-25T00:00:00.000Z",
        "--json"
      ]);
      expect(scan.exitCode, `${entry.name} scan stderr:\n${scan.stderr}`).toBe(0);
      const scanPayload = JSON.parse(scan.stdout);

      const storage = openDriftStorage({ databasePath: scanPayload.database_path });
      storage.migrate();
      const convention = {
        id: "security_api_request_validation",
        contract_id: "contract_security_validation",
        kind: "api_route_requires_request_validation" as const,
        statement: "API request input must be validated before protected sinks.",
        scope: { path_globs: ["app/api/**/route.ts"], file_roles: ["api_route" as const] },
        matcher: {
          kind: "api_route_requires_request_validation" as const,
          applies_to_file_roles: ["api_route" as const]
        },
        requires: {
          schemas: ["ProjectInputSchema"],
          validators: ["validateProjectInput"]
        },
        severity: "error" as const,
        enforcement_mode: "block" as const,
        enforcement_capability: "deterministic_check" as const,
        exceptions: [],
        evidence_refs: [],
        counterexample_refs: [],
        accepted_by: "test",
        accepted_at: "2026-05-25T00:00:00.000Z",
        updated_at: "2026-05-25T00:00:00.000Z"
      };
      storage.upsertAcceptedConvention(scanPayload.repo.id, convention);
      storage.upsertRepoContract({
        id: "contract_security_validation",
        repo_id: scanPayload.repo.id,
        contract_schema_version: 1,
        repo_fingerprint: scanPayload.repo.fingerprint,
        created_at: "2026-05-25T00:00:00.000Z",
        updated_at: "2026-05-25T00:00:00.000Z",
        conventions: [convention],
        rejected_inferences: [],
        waivers: [],
        risky_areas: [],
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

      const check = await runCli([
        "--db", scanPayload.database_path,
        "check",
        "--repo", scanPayload.repo.id,
        "--scope", "changed-hunks",
        "--diff-file", diffPath,
        "--now", "2026-05-25T00:00:01.000Z",
        "--json"
      ]);
      expect(check.exitCode, `${entry.name} check stderr:\n${check.stderr}\nstdout:\n${check.stdout}`).toBe(entry.exitCode);
      const payload = JSON.parse(check.stdout);
      const proof = payload.security_boundary_proofs?.[0];
      expect(proof?.request_validation, `${entry.name} payload:\n${JSON.stringify(payload)}`).toMatchObject({
        required: true,
        proven: entry.proven
      });
      if (entry.missingReason) {
        expect(JSON.stringify(proof)).toContain(entry.missingReason);
      }
      const hasParserGap = (proof?.parser_gaps ?? []).some((gap: { code?: string; blocks_enforcement?: boolean }) =>
        gap.code === "unsupported_request_input_spread" &&
        gap.blocks_enforcement === true
      );
      expect(hasParserGap, `${entry.name} parser gap`).toBe(entry.parserGap);
      expect(JSON.stringify(payload)).not.toContain("request.json()");
      expect(JSON.stringify(payload)).not.toContain("SECRET_VALUE");
    }
  }, 30_000);
});
