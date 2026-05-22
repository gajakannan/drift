#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = process.cwd();
const claimsPath = join(repoRoot, "docs", "architecture", "beta-claims.json");
const claims = JSON.parse(readFileSync(claimsPath, "utf8"));

const requiredAllowed = [
  "local_first_cli",
  "typescript_api_route_layering",
  "sqlite_local_state",
  "human_confirmed_governance",
  "read_only_mcp",
  "accepted_contract_blocks_direct_data_access"
];
const requiredBlocked = [
  "incremental_reuse",
  "cloud_sync",
  "desktop_ui",
  "python_adapter",
  "duplicate_helper_detection",
  "mutation_capable_mcp",
  "general_ai_code_review",
  "broad_language_support"
];

const failures = [];
if (claims.schema_version !== "drift.production.claims.v1") {
  failures.push("schema_version must be drift.production.claims.v1");
}
if (claims.source_of_truth !== "createDriftCapabilities") {
  failures.push("source_of_truth must be createDriftCapabilities");
}
for (const claim of requiredAllowed) {
  if (!claims.allowed_claims?.includes(claim)) {
    failures.push(`allowed_claims missing ${claim}`);
  }
}
for (const claim of requiredBlocked) {
  if (!claims.blocked_claims?.includes(claim)) {
    failures.push(`blocked_claims missing ${claim}`);
  }
}
for (const claim of claims.blocked_claims ?? []) {
  if (claims.allowed_claims?.includes(claim)) {
    failures.push(`claim cannot be both allowed and blocked: ${claim}`);
  }
}

const docsToCheck = [
  "README.md",
  join("docs", "architecture", "canonical-contracts.md")
];
const forbiddenPhrases = new Map([
  ["incremental_reuse", /incremental scan performance is supported|incremental reuse is implemented/i],
  ["cloud_sync", /cloud sync is supported|cloud-backed enforcement is supported/i],
  ["mutation_capable_mcp", /MCP mutation tools are supported|mutation-capable MCP is supported/i],
  ["broad_language_support", /all languages are supported|broad language support is supported/i]
]);
for (const docPath of docsToCheck) {
  const text = readFileSync(join(repoRoot, docPath), "utf8");
  for (const [claim, pattern] of forbiddenPhrases) {
    if (pattern.test(text)) {
      failures.push(`${docPath} appears to overclaim blocked capability ${claim}`);
    }
  }
}

if (failures.length > 0) {
  console.error(`Product claims validation failed:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}

console.log(`Validated Drift production claims manifest at ${claimsPath}.`);
