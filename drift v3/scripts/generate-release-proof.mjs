#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const args = new Set(process.argv.slice(2).filter((arg) => arg.startsWith("--")));
const outputPath = valueFlag("--output");
const requireClean = args.has("--require-clean");
const requireBuiltCli = args.has("--require-built-cli");
const requireComplete = args.has("--require-complete");

const root = process.cwd();
const rootManifest = readJson("package.json");
const cliManifest = readJson("packages/cli/package.json");
const engineTargets = engineReleaseTargets();
const sourceSchemaVersion = migrationIds().length;
const builtVersion = builtCliVersion();
const builtSchemaVersion = builtVersion?.runtime?.supported_sqlite_schema_version ?? null;
const dirtyState = gitStatusPorcelain().length > 0;
const sourceBuildSchemaMatch = builtSchemaVersion !== null && builtSchemaVersion === sourceSchemaVersion;
const packageVersions = packageVersionMap([
  "packages/core",
  "packages/engine-contract",
  "packages/factgraph",
  "packages/query",
  "packages/storage",
  "packages/cli",
  "packages/mcp",
  ...engineTargets.map((target) => `packages/${target.package_dir}`)
]);
const npmTarballs = listFiles(".release/npm", ".tgz").map((path) => ({
  path,
  sha256: sha256File(path),
  size_bytes: statSync(path).size
}));
const engineArtifactSha256 = listEngineChecksums();
const installedCliSmokeResults = {
  version_json: Boolean(builtVersion),
  schema_version: builtSchemaVersion,
  engine_status: builtVersion?.engine?.status ?? null,
  engine_source: builtVersion?.engine?.source ?? null
};
const installedMcpSmokeResults = {
  present: existsSync("packages/mcp/dist/index.js")
};
const releaseReady = !dirtyState &&
  sourceBuildSchemaMatch &&
  npmTarballs.length > 0 &&
  engineArtifactSha256.length === engineTargets.length;

const proof = {
  schema_version: "drift.release.proof.v1",
  release_version: rootManifest.version,
  git_ref: process.env.GITHUB_REF ?? gitOutput(["rev-parse", "--abbrev-ref", "HEAD"]) ?? "unknown",
  git_sha: process.env.GITHUB_SHA ?? gitOutput(["rev-parse", "HEAD"]) ?? "unknown",
  workflow_run_id: process.env.GITHUB_RUN_ID ?? null,
  dirty_state: dirtyState,
  verify_ci_status: process.env.DRIFT_VERIFY_CI_STATUS ?? null,
  node_version: process.version,
  pnpm_version: packageManagerVersion(rootManifest.packageManager),
  cargo_version: gitOutput(["--version"], "cargo") ?? null,
  package_versions: packageVersions,
  source_schema_version: sourceSchemaVersion,
  built_schema_version: builtSchemaVersion,
  engine_targets: engineTargets,
  engine_artifact_sha256: engineArtifactSha256,
  npm_tarballs: npmTarballs,
  installed_cli_smoke_results: installedCliSmokeResults,
  installed_mcp_smoke_results: installedMcpSmokeResults,
  dogfood_or_fixture_repo_id: process.env.DRIFT_RELEASE_REPO_ID ?? null,
  scan_id: process.env.DRIFT_RELEASE_SCAN_ID ?? null,
  repo_contract_id: process.env.DRIFT_RELEASE_REPO_CONTRACT_ID ?? null,
  check_id: process.env.DRIFT_RELEASE_CHECK_ID ?? null,
  mcp_cli_parity_hash: process.env.DRIFT_RELEASE_MCP_CLI_PARITY_HASH ?? null,
  audit_head_hash: process.env.DRIFT_RELEASE_AUDIT_HEAD_HASH ?? null,
  created_at: new Date().toISOString(),
  verification: {
    source_build_schema_match: sourceBuildSchemaMatch,
    release_ready: releaseReady,
    missing: missingProofFields({
      built_schema_version: builtSchemaVersion,
      npm_tarballs: npmTarballs,
      engine_artifact_sha256: engineArtifactSha256
    })
  }
};

if (outputPath) {
  writeFileSync(resolve(outputPath), `${JSON.stringify(proof, null, 2)}\n`);
}

process.stdout.write(`${JSON.stringify(proof, null, 2)}\n`);

if (requireClean && dirtyState) {
  console.error("Release proof failed: git worktree is dirty.");
  process.exit(1);
}
if (requireBuiltCli && !sourceBuildSchemaMatch) {
  console.error("Release proof failed: built CLI schema version is missing or does not match source migrations.");
  process.exit(1);
}
if (requireComplete && !releaseReady) {
  console.error(`Release proof failed: incomplete proof (${proof.verification.missing.join(", ") || "unknown"}).`);
  process.exit(1);
}

function valueFlag(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) {
    return null;
  }
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value.`);
  }
  return value;
}

function readJson(path) {
  return JSON.parse(readFileSync(resolve(path), "utf8"));
}

function migrationIds() {
  const source = readFileSync(resolve("packages/storage/src/migrations.ts"), "utf8");
  return [...source.matchAll(/id:\s*"([^"]+)"/g)].map((match) => match[1]);
}

function builtCliVersion() {
  const entrypoint = resolve("packages/cli/dist/main.js");
  if (!existsSync(entrypoint)) {
    return null;
  }
  try {
    return JSON.parse(execFileSync(process.execPath, [entrypoint, "version", "--json"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }));
  } catch {
    return null;
  }
}

function gitStatusPorcelain() {
  return gitOutput(["status", "--porcelain"]) ?? "";
}

function gitOutput(args, command = "git") {
  try {
    return execFileSync(command, args, {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return null;
  }
}

function engineReleaseTargets() {
  return [
    target("aarch64-apple-darwin", "engine-darwin-arm64"),
    target("x86_64-apple-darwin", "engine-darwin-x64"),
    target("x86_64-unknown-linux-gnu", "engine-linux-x64-gnu"),
    target("aarch64-unknown-linux-gnu", "engine-linux-arm64-gnu"),
    target("x86_64-pc-windows-msvc", "engine-win32-x64")
  ];
}

function target(targetTriple, packageDir) {
  const manifest = readJson(`packages/${packageDir}/package.json`);
  return {
    target: targetTriple,
    package_dir: packageDir,
    package_name: manifest.name,
    package_version: manifest.version,
    os: manifest.os?.[0] ?? null,
    cpu: manifest.cpu?.[0] ?? null,
    libc: manifest.libc?.[0] ?? null
  };
}

function packageVersionMap(packageDirs) {
  return Object.fromEntries(packageDirs.map((packageDir) => {
    const manifest = readJson(`${packageDir}/package.json`);
    return [manifest.name, manifest.version];
  }));
}

function packageManagerVersion(value) {
  return typeof value === "string" && value.includes("@") ? value.split("@").at(-1) ?? null : null;
}

function listEngineChecksums() {
  const checksumPath = resolve("SHA256SUMS");
  if (!existsSync(checksumPath)) {
    return [];
  }
  return readFileSync(checksumPath, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      const [sha256, path] = line.trim().split(/\s+/, 2);
      return { path, sha256 };
    });
}

function listFiles(dir, suffix) {
  const absolute = resolve(dir);
  if (!existsSync(absolute)) {
    return [];
  }
  return readdirSync(absolute)
    .filter((entry) => entry.endsWith(suffix))
    .sort()
    .map((entry) => join(dir, entry));
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(resolve(path))).digest("hex");
}

function missingProofFields(fields) {
  const missing = [];
  if (fields.built_schema_version === null) {
    missing.push("built_schema_version");
  }
  if (fields.npm_tarballs.length === 0) {
    missing.push("npm_tarballs");
  }
  if (fields.engine_artifact_sha256.length !== engineTargets.length) {
    missing.push("engine_artifact_sha256");
  }
  return missing;
}
