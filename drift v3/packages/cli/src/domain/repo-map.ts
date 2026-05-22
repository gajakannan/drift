import { authorizeContextExport,type FileRole,type PolicyDecision,type RepoContract } from "@drift/core";
import {
  buildRepoMapReadModel,
  createGraphQueryService,
  fallbackFactRepoMapFiles,
  repoMapConventionIds,
  repoMapOpenFindingIds,
  repoMapRiskyAreaIds,
  type RepoMapFile
} from "@drift/query";
import type { SqliteDriftStorage } from "@drift/storage";
import { agentEnvelopeForScan } from "./agent-envelope.js";
import { preflightGovernance } from "./governance.js";
import { scanFingerprint } from "./identifiers.js";
import { repoContractOrDefault } from "./repo-paths.js";
import { assertFreshScanIfRequired,freshnessRequirement,latestIndexedScan,scanStatusPayload } from "./scan-status.js";

export function policyFileContext(
  storage: SqliteDriftStorage,
  repoId: string,
  filePath: string,
  contract: RepoContract
): {
  path: string;
  indexed: boolean;
  roles: string[];
  convention_ids: string[];
  risky_area_ids: string[];
  open_finding_ids: string[];
} {
  const latestScan = latestIndexedScan(storage.listScanManifests(repoId));
  const snapshots = latestScan ? storage.listFileSnapshots(repoId, latestScan.id) : [];
  const facts = latestScan ? storage.listFacts(latestScan.id) : [];
  const findings = storage.listFindings(repoId);
  const graphMap = latestScan ? createGraphQueryService(storage).repoMap({ repoId, scanId: latestScan.id }) : null;
  const readModel = buildRepoMapReadModel({
    graphFiles: graphMap?.files ?? [],
    factFiles: fallbackFactRepoMapFiles(snapshots, facts),
    contract,
    findings
  });
  const file = readModel.all_files.find((entry) => entry.path === filePath);
  if (!file) {
    return {
      path: filePath,
      indexed: false,
      roles: [],
      convention_ids: repoMapConventionIds(contract, filePath),
      risky_area_ids: repoMapRiskyAreaIds(contract, filePath),
      open_finding_ids: repoMapOpenFindingIds(findings, filePath)
    };
  }
  return {
    path: file.path,
    indexed: true,
    roles: file.roles,
    convention_ids: file.convention_ids,
    risky_area_ids: file.risky_area_ids,
    open_finding_ids: file.open_finding_ids
  };
}

export function repoMapPayload(
  storage: SqliteDriftStorage,
  repoId: string,
  options: {
    surface: PolicyDecision["surface"];
    role?: FileRole;
    path?: string;
    requireFresh?: boolean;
    limit?: number;
    offset?: number;
  }
) {
  const repo = storage.getRepo(repoId);
  if (!repo) {
    throw new Error(`Unknown repo ${repoId}. Run drift scan --repo-root <path> first.`);
  }
  const contract = repoContractOrDefault(storage, repoId);
  const policy = authorizeContextExport(contract, options.surface);
  if (!policy.allowed) {
    throw new Error(`Policy denied repo map output: ${policy.reason}`);
  }
  const latestScan = latestIndexedScan(storage.listScanManifests(repoId));
  const snapshots = latestScan ? storage.listFileSnapshots(repoId, latestScan.id) : [];
  const facts = latestScan ? storage.listFacts(latestScan.id) : [];
  const findings = storage.listFindings(repoId);
  const graphMap = latestScan ? createGraphQueryService(storage).repoMap({ repoId, scanId: latestScan.id }) : null;
  const readModel = buildRepoMapReadModel({
    graphFiles: graphMap?.files ?? [],
    factFiles: fallbackFactRepoMapFiles(snapshots, facts),
    contract,
    findings,
    filters: {
      role: options.role,
      path: options.path
    },
    limit: options.limit,
    offset: options.offset ?? 0
  });
  const offset = options.offset ?? 0;
  const scanStatus = scanStatusPayload(storage, repoId);
  assertFreshScanIfRequired(repoId, scanStatus, Boolean(options.requireFresh));
  return {
    response_schema: "drift.repo.map.v1",
    repo_id: repoId,
    repo_root: repo.root_path,
    generated_at: new Date().toISOString(),
    agent_envelope: agentEnvelopeForScan({
      surface: options.surface,
      policy,
      scanStatus,
      requireFresh: Boolean(options.requireFresh)
    }),
    policy,
    governance: preflightGovernance(),
    latest_scan: latestScan ?? null,
    scan_fingerprint: latestScan ? scanFingerprint(latestScan, snapshots) : null,
    scan_status: scanStatus,
    filters: {
      role: options.role ?? null,
      path: options.path ?? null
    },
    summary: readModel.summary,
    impact_summary: readModel.impact_summary,
    pagination: readModel.pagination,
    freshness_requirement: freshnessRequirement(Boolean(options.requireFresh), scanStatus),
    files: readModel.listed_files,
    redactions: {
      denied_globs: contract.context_egress.denied_globs,
      snippets_included: false,
      source_content_included: false,
      graph_context_included: Boolean(graphMap),
      context_truncated: false
    },
    next_commands: [
      `drift prepare "task" --repo ${repoId} --json`,
      `drift scan status --repo ${repoId} --json`
    ]
  };
}

export type { RepoMapFile };
