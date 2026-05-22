import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createDriftCapabilities } from "../../packages/core/src/capabilities";
import { describe, expect, it } from "vitest";

describe("release hygiene", () => {
  it("keeps the root package release gate explicit", async () => {
    const manifest = JSON.parse(await readFile("package.json", "utf8"));

    expect(manifest.private).toBe(true);
    expect(manifest.packageManager).toBe("pnpm@10.28.0");
    expect(manifest.engines?.node).toBe(">=20.0.0");
    expect(manifest.scripts.verify).toBe("pnpm build && pnpm typecheck && pnpm test && pnpm test:e2e");
    expect(manifest.scripts["format:engine"]).toBe("cargo fmt --all");
    expect(manifest.scripts["format:engine:check"]).toBe("cargo fmt --all -- --check");
    expect(manifest.scripts["lint:engine"]).toBe("cargo clippy -p drift-engine --all-targets -- -D warnings");
    expect(manifest.scripts["check:boundaries"]).toBe("node packages/cli/scripts/check-boundaries.mjs");
    expect(manifest.scripts["validate:release-matrix"]).toBe("node scripts/validate-engine-release-matrix.mjs");
    expect(manifest.scripts["release:proof"]).toBe("node scripts/generate-release-proof.mjs");
    expect(manifest.scripts["verify:ci"]).toBe(
      "pnpm verify && pnpm format:engine:check && pnpm lint:engine && pnpm check:boundaries && pnpm validate:release-matrix && git diff --check",
    );
  });

  it("runs the production verification gate in CI with least repository permissions", async () => {
    const workflow = await readFile(".github/workflows/ci.yml", "utf8");

    expect(workflow).toContain("permissions:");
    expect(workflow).toContain("contents: read");
    expect(workflow).toContain("concurrency:");
    expect(workflow).toContain("cancel-in-progress: true");
    expect(workflow).toContain("node-version: 22");
    expect(workflow).toContain("pnpm install --frozen-lockfile");
    expect(workflow).toContain("pnpm verify:ci");
  });

  it("defines a guarded engine binary release matrix", async () => {
    const workflow = await readFile(".github/workflows/engine-binary-release.yml", "utf8");

    for (const expected of [
      "name: Engine Binary Release",
      "workflow_dispatch:",
      "dry_run:",
      "permissions:",
      "contents: write",
      "id-token: write",
      "cancel-in-progress: false",
      "aarch64-apple-darwin",
      "x86_64-apple-darwin",
      "x86_64-unknown-linux-gnu",
      "aarch64-unknown-linux-gnu",
      "x86_64-pc-windows-msvc",
      "@drift/engine-darwin-arm64",
      "@drift/engine-darwin-x64",
      "@drift/engine-linux-x64-gnu",
      "@drift/engine-linux-arm64-gnu",
      "@drift/engine-win32-x64",
      "SHA256SUMS",
      "npm publish",
      "npm_config_provenance=true",
      "packages/factgraph",
      "packages/query",
      "drift-factgraph-*.tgz",
      "drift-query-*.tgz",
      "node scripts/validate-engine-release-matrix.mjs"
    ]) {
      expect(workflow).toContain(expected);
    }
    expect(workflow).toContain("node scripts/generate-release-proof.mjs --require-clean --require-built-cli --output release-proof.json");
    expect(workflow).toContain("if: ${{ inputs.dry_run == false || startsWith(github.ref, 'refs/tags/v') }}");
  });

  it("generates a release proof artifact with source and built schema fields", () => {
    const output = execFileSync("node", ["scripts/generate-release-proof.mjs"], {
      encoding: "utf8"
    });
    const proof = JSON.parse(output);

    expect(proof.schema_version).toBe("drift.release.proof.v1");
    expect(proof.release_version).toBe("0.1.0");
    expect(proof.source_schema_version).toBe(11);
    expect(proof.built_schema_version === null || proof.built_schema_version === 11).toBe(true);
    expect(proof.dirty_state).toEqual(expect.any(Boolean));
    expect(proof.engine_targets).toHaveLength(5);
    expect(proof.beta_proof).toMatchObject({
      clean_git: expect.any(Boolean),
      verify_ci_passed: expect.any(Boolean),
      rust_engine_required: true,
      fallback_absent: expect.any(Boolean),
      good_route_passed: null,
      bad_route_blocked: null,
      finding_evidence_complete: null,
      mcp_cli_parity_verified: false,
      audit_verified: null
    });
    expect(proof.verification).toMatchObject({
      source_build_schema_match: expect.any(Boolean),
      release_ready: expect.any(Boolean),
      beta_ready: false,
      beta_missing: expect.arrayContaining([
        "verify_ci_passed",
        "rust_engine_no_fallback",
        "good_route_passed",
        "bad_route_blocked",
        "finding_evidence_complete",
        "mcp_cli_parity_verified",
        "audit_verified"
      ])
    });
  });

  it("validates the engine release matrix against package manifests", () => {
    const output = execFileSync("node", ["scripts/validate-engine-release-matrix.mjs"], {
      encoding: "utf8"
    });

    expect(output).toContain("Validated 5 engine release targets");
  });

  it("keeps engine binary package versions exact and workspace-free for publication", async () => {
    const cliManifest = JSON.parse(await readFile("packages/cli/package.json", "utf8"));
    const assertReleaseVersionsScript = await readFile("scripts/assert-release-versions.mjs", "utf8");
    const preparePublishManifestsScript = await readFile("scripts/prepare-npm-publish-manifests.mjs", "utf8");
    const enginePackages = [
      "engine-darwin-arm64",
      "engine-darwin-x64",
      "engine-linux-x64-gnu",
      "engine-linux-arm64-gnu",
      "engine-win32-x64"
    ];

    for (const packageName of enginePackages) {
      const manifest = JSON.parse(await readFile(`packages/${packageName}/package.json`, "utf8"));
      expect(manifest.name).toBe(`@drift/${packageName}`);
      expect(manifest.version).toBe(cliManifest.version);
      expect(cliManifest.optionalDependencies?.[`@drift/${packageName}`]).toBe("workspace:*");
    }
    for (const runtimePackage of ["factgraph", "query"]) {
      expect(assertReleaseVersionsScript).toContain(`packages/${runtimePackage}/package.json`);
      expect(preparePublishManifestsScript).toContain(`packages/${runtimePackage}/package.json`);
    }
  });

  it("documents every installed-package smoke surface that release tests execute", async () => {
    const readme = await readFile("README.md", "utf8");

    for (const expected of [
      "installed `drift doctor`",
      "installed `drift scan`",
      "installed `drift start --accept-defaults`",
      "installed `drift prepare`",
      "installed `drift baseline status`",
      "installed `drift contract show`",
      "installed `drift check`",
      "installed `drift findings list`",
      "installed `drift findings mark-needs-review --confirm`",
      "installed `drift findings mark-fixed --confirm`",
      "installed `drift audit list`",
      "installed `drift audit verify`",
      "installed `drift backup create --confirm`",
      "installed `drift backup list`",
      "installed `drift backup verify`",
      "installed `drift restore --dry-run`",
      "installed `drift restore --confirm`",
      "installed `drift version --json`",
      "installed `drift capabilities --json`",
      "installed MCP `get_runtime_info`",
      "installed MCP `get_capabilities`",
      "installed MCP `get_audit_status`",
      "installed `drift-mcp`"
    ]) {
      expect(readme).toContain(expected);
    }
    expect(readme).toContain("pnpm verify:ci");
  });

  it("documents every human-confirmed CLI capability in the governance section", async () => {
    const readme = await readFile("README.md", "utf8");
    const governanceSection = readme.slice(
      readme.indexOf("Governance changes require explicit human intent:"),
      readme.indexOf("## Architecture")
    );
    const capabilities = createDriftCapabilities();

    for (const command of capabilities.human_confirmed_cli) {
      const baseCommand = command.replace(" --confirm", "");
      const matchingLines = governanceSection
        .split("\n")
        .filter((line) => line.includes(`drift ${baseCommand}`));

      expect(matchingLines.length).toBeGreaterThan(0);
      expect(matchingLines.some((line) => line.includes("--confirm"))).toBe(true);
    }
  });

  it("documents every read-only MCP capability in package smoke", async () => {
    const readme = await readFile("README.md", "utf8");
    const capabilities = createDriftCapabilities();

    for (const tool of capabilities.mcp_read_only_tools) {
      expect(readme).toContain(`installed MCP \`${tool}\``);
    }
    expect(capabilities.mcp_mutation_tools).toEqual([]);
  });

  it("documents the V1 support matrix and deferred surfaces without overpromising", async () => {
    const readme = await readFile("README.md", "utf8");

    for (const expected of [
      "## V1 Support Matrix",
      "| Surface | V1 status |",
      "| TypeScript/JavaScript API route layering | Supported |",
      "| Python adapter | Deferred |",
      "| Desktop UI | Deferred |",
      "| Cloud sync | Deferred |",
      "| Duplicate helper detection | Deferred |",
      "Drift V1 does not mutate source code.",
      "drift capabilities --json",
      "contract_fingerprint",
      "scan_fingerprint",
      "audit verify",
      "get_audit_status"
    ]) {
      expect(readme).toContain(expected);
    }
  });

  it("ignores local Drift state and release artifacts that should never be committed", async () => {
    const gitignore = await readFile(".gitignore", "utf8");

    for (const expected of [
      ".drift/",
      "*.sqlite",
      "*.drift-backup.sqlite",
      "*.tgz",
      "coverage/"
    ]) {
      expect(gitignore).toContain(expected);
    }
  });

  it("keeps adapter internals behind the public adapter registry package", async () => {
    const boundaryScript = await readFile("packages/cli/scripts/check-boundaries.mjs", "utf8");

    expect(boundaryScript).toContain("adapters: join(repoRoot, \"packages/adapters/src\")");
    expect(boundaryScript).toContain("@drift\\/adapters\\/");
    expect(boundaryScript).toContain("imports adapter internals directly");
  });

  it("keeps OSS trust and contribution rails in place", async () => {
    const license = await readFile("LICENSE", "utf8");
    const security = await readFile("SECURITY.md", "utf8");
    const contributing = await readFile("CONTRIBUTING.md", "utf8");
    const prTemplate = await readFile(".github/PULL_REQUEST_TEMPLATE.md", "utf8");
    const bugTemplate = await readFile(".github/ISSUE_TEMPLATE/bug_report.yml", "utf8");
    const featureTemplate = await readFile(".github/ISSUE_TEMPLATE/feature_request.yml", "utf8");

    expect(license).toContain("MIT License");
    expect(security).toContain("local-first");
    expect(security).toContain("Do not include private source code");
    expect(contributing).toContain("pnpm verify:ci");
    expect(contributing).toContain("Rust owns deterministic parser and rule authority");
    expect(prTemplate).toContain("No source snippets or secrets are added to outputs");
    expect(bugTemplate).toContain("Drift version");
    expect(featureTemplate).toContain("V1 wedge");
  });

  it("keeps the beta intelligence gate honest about supported and deferred scope", async () => {
    const gate = await readFile("docs/architecture/beta-intelligence-gate.md", "utf8");

    for (const expected of [
      "Drift is a local-first TypeScript/JavaScript repo intelligence guardrail",
      "pnpm verify:ci",
      "docs/dogfood/drift-on-drift.md",
      "Rust owns parser and deterministic rule authority",
      "Blocking enforcement is allowed only when parser completeness permits it",
      "MCP must not accept, reject, edit, suppress, import, export",
      "full platform engine binary publishing",
      "Python and additional language adapters",
      "Desktop review UI",
      "Cloud or team sync",
      "Duplicate-helper detection",
      "Write-capable MCP tools"
    ]) {
      expect(gate).toContain(expected);
    }
  });
});
