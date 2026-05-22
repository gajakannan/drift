import { authorizeContextExport,type FactRecord,type FileRole,type FileSnapshot,type Finding,type PolicyDecision,type RepoContract } from "@drift/core";
import type { SqliteDriftStorage } from "@drift/storage";
import { uniqueSorted } from "./contract-materialization.js";
import { isOpenPreflightFinding } from "./findings.js";
import { preflightGovernance } from "./governance.js";
import { scanFingerprint } from "./identifiers.js";
import { paginationSummary } from "./pagination.js";
import { matchesGlob,requiredRepoContract } from "./repo-paths.js";
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
  const file = repoMapFiles(snapshots, facts, contract, storage.listFindings(repoId))
    .find((entry) => entry.path === filePath);
  if (!file) {
    return {
      path: filePath,
      indexed: false,
      roles: [],
      convention_ids: repoMapConventionIds(contract, filePath),
      risky_area_ids: repoMapRiskyAreaIds(contract, filePath),
      open_finding_ids: repoMapOpenFindingIds(storage.listFindings(repoId), filePath)
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
  const contract = requiredRepoContract(storage, repoId);
  const policy = authorizeContextExport(contract, options.surface);
  if (!policy.allowed) {
    throw new Error(`Policy denied repo map output: ${policy.reason}`);
  }
  const latestScan = latestIndexedScan(storage.listScanManifests(repoId));
  const snapshots = latestScan ? storage.listFileSnapshots(repoId, latestScan.id) : [];
  const facts = latestScan ? storage.listFacts(latestScan.id) : [];
  const findings = storage.listFindings(repoId);
  const allFiles = repoMapFiles(snapshots, facts, contract, findings);
  const files = allFiles.filter((file) =>
    (!options.role || file.roles.includes(options.role)) &&
    (!options.path || file.path === options.path || matchesGlob(file.path, options.path))
  );
  const offset = options.offset ?? 0;
  const listedFiles = paginateRepoMapFiles(files, options.limit, offset);
  const scanStatus = scanStatusPayload(storage, repoId);
  assertFreshScanIfRequired(repoId, scanStatus, Boolean(options.requireFresh));
  return {
    repo_id: repoId,
    repo_root: repo.root_path,
    generated_at: new Date().toISOString(),
    policy,
    governance: preflightGovernance(),
    latest_scan: latestScan ?? null,
    scan_fingerprint: latestScan ? scanFingerprint(latestScan, snapshots) : null,
    scan_status: scanStatus,
    filters: {
      role: options.role ?? null,
      path: options.path ?? null
    },
    summary: repoMapSummary(allFiles, files, listedFiles),
    impact_summary: repoMapImpactSummary(listedFiles),
    pagination: paginationSummary(files.length, listedFiles.length, options.limit, offset),
    freshness_requirement: freshnessRequirement(Boolean(options.requireFresh), scanStatus),
    files: listedFiles,
    redactions: {
      denied_globs: contract.context_egress.denied_globs,
      snippets_included: false
    },
    next_commands: [
      `drift prepare "task" --repo ${repoId} --json`,
      `drift scan status --repo ${repoId} --json`
    ]
  };
}

export function repoMapFiles(
  snapshots: FileSnapshot[],
  facts: FactRecord[],
  contract: RepoContract,
  findings: Finding[]
): RepoMapFile[] {
  const factsByFile = new Map<string, FactRecord[]>();
  for (const fact of facts) {
    const existing = factsByFile.get(fact.file_path) ?? [];
    existing.push(fact);
    factsByFile.set(fact.file_path, existing);
  }

  return snapshots
    .filter((snapshot) => snapshot.indexed)
    .map((snapshot) => {
      const fileFacts = factsByFile.get(snapshot.file_path) ?? [];
      return {
        path: snapshot.file_path,
        content_hash: snapshot.content_hash,
        byte_size: snapshot.byte_size,
        indexed: snapshot.indexed,
        roles: uniqueSorted(fileFacts
          .filter((fact) => fact.kind === "file_role_detected")
          .map((fact) => fact.name)),
        imports: uniqueSorted(fileFacts
          .filter((fact) => fact.kind === "import_used")
          .map((fact) => fact.value ?? fact.name)),
        exported_symbols: uniqueSorted(fileFacts
          .filter((fact) => fact.kind === "exported_symbol")
          .map((fact) => fact.name)),
        calls: uniqueSorted(fileFacts
          .filter((fact) => fact.kind === "symbol_called")
          .map((fact) => fact.name)),
        convention_ids: repoMapConventionIds(contract, snapshot.file_path),
        risky_area_ids: repoMapRiskyAreaIds(contract, snapshot.file_path),
        open_finding_ids: repoMapOpenFindingIds(findings, snapshot.file_path),
        fact_count: fileFacts.length
      };
    })
    .sort((left, right) => left.path.localeCompare(right.path));
}

export function paginateRepoMapFiles(files: RepoMapFile[], limit: number | undefined, offset: number): RepoMapFile[] {
  return limit === undefined
    ? files.slice(offset)
    : files.slice(offset, offset + limit);
}

export function repoMapConventionIds(contract: RepoContract, filePath: string): string[] {
  return uniqueSorted(contract.conventions
    .filter((convention) =>
      convention.scope.path_globs.some((glob) => matchesGlob(filePath, glob)) &&
      !(convention.scope.exclude_path_globs ?? []).some((glob) => matchesGlob(filePath, glob))
    )
    .map((convention) => convention.id));
}

export function repoMapRiskyAreaIds(contract: RepoContract, filePath: string): string[] {
  return uniqueSorted(contract.risky_areas
    .filter((area) => area.path_globs.some((glob) => matchesGlob(filePath, glob)))
    .map((area) => area.id));
}

export function repoMapOpenFindingIds(findings: Finding[], filePath: string): string[] {
  return uniqueSorted(findings
    .filter((finding) =>
      isOpenPreflightFinding(finding) &&
      finding.evidence_refs.some((ref) => ref.file_path === filePath)
    )
    .map((finding) => finding.id));
}

export function repoMapImpactSummary(files: RepoMapFile[]): {
  convention_coverage_count: number;
  risky_file_count: number;
  open_finding_count: number;
} {
  return {
    convention_coverage_count: files.filter((file) => file.convention_ids.length > 0).length,
    risky_file_count: files.filter((file) => file.risky_area_ids.length > 0).length,
    open_finding_count: files.reduce((count, file) => count + file.open_finding_ids.length, 0)
  };
}

export function repoMapSummary(allFiles: RepoMapFile[], filteredFiles: RepoMapFile[], listedFiles: RepoMapFile[]): {
  indexed_file_count: number;
  filtered_file_count: number;
  listed_file_count: number;
  role_counts: Record<string, number>;
  import_count: number;
  export_count: number;
  call_count: number;
} {
  const roleCounts: Record<string, number> = {};
  for (const file of listedFiles) {
    for (const role of file.roles) {
      roleCounts[role] = (roleCounts[role] ?? 0) + 1;
    }
  }
  return {
    indexed_file_count: allFiles.length,
    filtered_file_count: filteredFiles.length,
    listed_file_count: listedFiles.length,
    role_counts: roleCounts,
    import_count: listedFiles.reduce((count, file) => count + file.imports.length, 0),
    export_count: listedFiles.reduce((count, file) => count + file.exported_symbols.length, 0),
    call_count: listedFiles.reduce((count, file) => count + file.calls.length, 0)
  };
}

export interface RepoMapFile {
  path: string;
  content_hash: string;
  byte_size: number;
  indexed: boolean;
  roles: string[];
  imports: string[];
  exported_symbols: string[];
  calls: string[];
  convention_ids: string[];
  risky_area_ids: string[];
  open_finding_ids: string[];
  fact_count: number;
}
