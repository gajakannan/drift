import { authorizeContextExport,type Finding,type RepoContract } from "@drift/core";
import type { SqliteDriftStorage } from "@drift/storage";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CommandPayload,ParsedArgs } from "../app/command-types.js";
import { actorFlag,stringFlag } from "../args/flag-readers.js";
import { resolveRepoId } from "../args/repo-flags.js";
import { isClosedFindingStatus,preservedGovernanceStatus,reviewFinding } from "../domain/findings.js";
import { auditEvent,preflightGovernance } from "../domain/governance.js";
import { hashStable } from "../domain/identifiers.js";
import { WaivedFinding } from "../domain/preflight.js";
import { isApiRoutePath } from "../domain/repo-paths.js";
import { collectScanData } from "../engine/collect-scan-data.js";
import { extractImports,importFactsForFile } from "../engine/fact-extraction.js";
import { walkIndexableFiles } from "../engine/ts-fallback-scanner.js";
import { formatCheckText } from "../formatters/checks.js";
import { fileContentHash } from "../io/file-hash.js";
import { diffStatusFor,filesForConvention,fullRepoDiff,loadDiff,parseUnifiedDiff } from "./diff.js";
import { findingFingerprint } from "./finding-fingerprint.js";
import { enforcementResultFor,isActiveConvention,isForbiddenImport } from "./rule-evaluation.js";
import { findContractWaiverForImport,isExceptedImport,isExceptedPath } from "./waivers.js";

export function runCheck(storage: SqliteDriftStorage, parsed: ParsedArgs): CommandPayload {
  const repoId = resolveRepoId(parsed);
  const repo = storage.getRepo(repoId);
  if (!repo) {
    throw new Error(`Unknown repo ${repoId}.`);
  }
  const contract = storage.getRepoContract(repoId);
  if (!contract) {
    throw new Error(`No repo contract exists for ${repoId}.`);
  }
  const policy = authorizeContextExport(contract, "cli-check");
  if (!policy.allowed) {
    throw new Error(`Policy denied check output: ${policy.reason}`);
  }

  const scope = stringFlag(parsed, "scope") ?? "changed-hunks";
  if (!["changed-hunks", "changed-files", "full"].includes(scope)) {
    throw new Error("--scope must be changed-hunks, changed-files, or full.");
  }

  const now = stringFlag(parsed, "now") ?? new Date().toISOString();
  const parsedDiff = scope === "full"
    ? fullRepoDiff(repo.root_path)
    : parseUnifiedDiff(loadDiff(repo.root_path, parsed));
  const baseline = storage.listBaselineViolations(repoId);
  const existingFindings = new Map(
    storage.listFindings(repoId).map((finding) => [finding.fingerprint, finding])
  );
  const expiredFindingsCount = expireFindingsForExpiredConventions(storage, parsed, repoId, contract, now);
  const checkData = collectScanData({
    repoId,
    scanId: `scan_check_${hashStable(`${repoId}:${now}`).slice(0, 16)}`,
    repoRoot: repo.root_path
  });
  const snapshotsByPath = new Map(checkData.snapshots.map((snapshot) => [snapshot.file_path, snapshot]));
  const findings: Finding[] = [];
  const waivedFindings: WaivedFinding[] = [];
  let waivedFindingsCount = 0;

  for (const convention of contract.conventions) {
    if (
      convention.kind !== "api_route_no_direct_data_access" ||
      convention.enforcement_mode === "off" ||
      convention.enforcement_capability !== "deterministic_check" ||
      !isActiveConvention(convention, now)
    ) {
      continue;
    }

    const files = filesForConvention(parsedDiff, convention, scope);
    for (const filePath of files) {
      if (!isApiRoutePath(filePath) || isExceptedPath(filePath, convention, now)) {
        continue;
      }

      for (const importUsed of importFactsForFile(checkData.facts, filePath)) {
        if (!isForbiddenImport(importUsed.value, convention.matcher.forbidden_imports ?? [])) {
          continue;
        }
        if (isExceptedImport(filePath, importUsed.name, importUsed.value, convention, now)) {
          continue;
        }
        const waiver = findContractWaiverForImport(filePath, importUsed.name, importUsed.value, contract, now);
        if (waiver) {
          waivedFindingsCount += 1;
          waivedFindings.push({
            waiver_id: waiver.id,
            convention_id: convention.id,
            file_path: filePath,
            symbol: importUsed.name,
            import_source: importUsed.value,
            line: importUsed.start_line,
            reason: waiver.reason
          });
          continue;
        }

        const diffStatus = diffStatusFor(filePath, importUsed.start_line, parsedDiff, scope);
        const fingerprint = findingFingerprint(
          convention.id,
          filePath,
          importUsed.name,
          importUsed.value
        );
        const status = baseline.some((entry) =>
          entry.status === "active" &&
          entry.convention_id === convention.id &&
          entry.finding_fingerprint === fingerprint
        ) ? "pre_existing" : preservedGovernanceStatus(existingFindings.get(fingerprint)) ?? "new";
        const snapshot = snapshotsByPath.get(filePath);
        const finding: Finding = {
          id: `finding_${fingerprint.slice(0, 16)}`,
          repo_id: repoId,
          convention_id: convention.id,
          fingerprint,
          title: "API route imports data access directly",
          message: `${filePath} imports ${importUsed.name} from ${importUsed.value} directly; route modules should delegate through the accepted service/data-access layer.`,
          severity: convention.severity,
          enforcement_result: enforcementResultFor(convention.enforcement_mode),
          status,
          diff_status: diffStatus,
          evidence_refs: [{
            id: `evidence_${fingerprint.slice(0, 16)}`,
            kind: "violation",
            file_path: filePath,
            start_line: importUsed.start_line,
            end_line: importUsed.start_line,
            symbol: importUsed.name,
            import_source: importUsed.value,
            fact_ids: importUsed.fact_id ? [importUsed.fact_id] : [],
            scan_id: checkData.snapshots[0]?.scan_id ?? `scan_check_${hashStable(`${repoId}:${now}`).slice(0, 16)}`,
            file_hash: snapshot?.content_hash ?? "",
            redaction_state: "none"
          }],
          created_at: now
        };
        storage.upsertFinding(finding);
        findings.push(finding);
      }
    }
  }

  const blockingCount = findings.filter((finding) =>
    finding.status === "new" &&
    finding.diff_status === "new_in_diff" &&
    finding.enforcement_result === "block"
  ).length;
  const openNewCount = findings.filter((finding) => finding.status === "new").length;
  const payload = {
    policy,
    governance: preflightGovernance(),
    audit_integrity: storage.verifyAuditChain(repoId),
    summary: {
      repo_id: repoId,
      scope,
      findings_count: findings.length,
      blocking_count: blockingCount,
      waived_findings_count: waivedFindingsCount,
      expired_findings_count: expiredFindingsCount,
      skipped_deleted_files: parsedDiff.deletedFiles,
      engine_source: checkData.engineSource
    },
    review_items: findings.map(reviewFinding),
    waived_findings: waivedFindings,
    next_commands: checkNextCommands(repoId, {
      findingCount: findings.length,
      openNewCount,
      blockingCount
    }),
    findings
  };

  return {
    exitCode: blockingCount > 0 ? 1 : 0,
    payload: parsed.flags.has("json") ? payload : formatCheckText(payload)
  };
}

export function expireFindingsForExpiredConventions(
  storage: SqliteDriftStorage,
  parsed: ParsedArgs,
  repoId: string,
  contract: RepoContract,
  now: string
): number {
  const expiredConventionIds = new Set(
    contract.conventions
      .filter((convention) => convention.expires_at && convention.expires_at <= now)
      .map((convention) => convention.id)
  );
  if (expiredConventionIds.size === 0) {
    return 0;
  }

  let expiredCount = 0;
  const actor = actorFlag(parsed);
  for (const finding of storage.listFindings(repoId)) {
    if (!expiredConventionIds.has(finding.convention_id) || isClosedFindingStatus(finding.status)) {
      continue;
    }

    const updated: Finding = {
      ...finding,
      status: "expired"
    };
    storage.upsertFinding(updated);
    storage.appendAuditEvent(auditEvent({
      id: `audit_event_finding_expired_${repoId}_${finding.id}_${now}`,
      repoId,
      actor,
      action: "finding_resolved",
      targetType: "finding",
      targetId: finding.id,
      metadata: {
        status: "expired",
        reason: "convention_expired",
        convention_id: finding.convention_id
      },
      createdAt: now
    }));
    expiredCount += 1;
  }
  return expiredCount;
}

export function runFullRepoCheck(
  storage: SqliteDriftStorage,
  parsed: ParsedArgs,
  repoId: string,
  now: string
): Finding[] {
  const repo = storage.getRepo(repoId);
  if (!repo) {
    return [];
  }

  const files = walkIndexableFiles(repo.root_path).filter(isApiRoutePath);
  const diff = {
    files: files.map((path) => ({ path, changedLines: new Set<number>() })),
    deletedFiles: []
  };
  const contract = storage.getRepoContract(repoId);
  if (!contract) {
    return [];
  }
  const latestScan = storage.listScanManifests(repoId).find((scan) => scan.status === "completed");
  const snapshotsByPath = new Map(
    latestScan
      ? storage.listFileSnapshots(repoId, latestScan.id).map((snapshot) => [snapshot.file_path, snapshot])
      : []
  );

  const findings: Finding[] = [];
  for (const convention of contract.conventions) {
    if (convention.kind !== "api_route_no_direct_data_access") {
      continue;
    }

    for (const filePath of filesForConvention(diff, convention, "full")) {
      if (isExceptedPath(filePath, convention, now)) {
        continue;
      }
      const source = readFileSync(join(repo.root_path, filePath), "utf8");
      for (const importUsed of extractImports(source)) {
        if (!isForbiddenImport(importUsed.source, convention.matcher.forbidden_imports ?? [])) {
          continue;
        }
        if (isExceptedImport(filePath, importUsed.name, importUsed.source, convention, now)) {
          continue;
        }
        if (findContractWaiverForImport(filePath, importUsed.name, importUsed.source, contract, now)) {
          continue;
        }

        const fingerprint = findingFingerprint(convention.id, filePath, importUsed.name, importUsed.source);
        const snapshot = snapshotsByPath.get(filePath);
        const finding: Finding = {
          id: `finding_${fingerprint.slice(0, 16)}`,
          repo_id: repoId,
          convention_id: convention.id,
          fingerprint,
          title: "API route imports data access directly",
          message: `${filePath} imports ${importUsed.name} from ${importUsed.source} directly; route modules should delegate through the accepted service/data-access layer.`,
          severity: convention.severity,
          enforcement_result: enforcementResultFor(convention.enforcement_mode),
          status: "new",
          diff_status: "touched_existing",
          evidence_refs: [{
            id: `evidence_${fingerprint.slice(0, 16)}`,
            kind: "violation",
            file_path: filePath,
            start_line: importUsed.line,
            end_line: importUsed.end_line,
            symbol: importUsed.name,
            import_source: importUsed.source,
            fact_ids: [],
            scan_id: latestScan?.id ?? `scan_check_${hashStable(`${repoId}:${now}`).slice(0, 16)}`,
            file_hash: snapshot?.content_hash ?? fileContentHash(join(repo.root_path, filePath)),
            redaction_state: "none"
          }],
          created_at: now
        };
        storage.upsertFinding(finding);
        findings.push(finding);
      }
    }
  }

  return findings;
}

export function checkNextCommands(
  repoId: string,
  summary: { findingCount: number; openNewCount: number; blockingCount: number }
): string[] {
  const commands = [
    summary.openNewCount > 0
      ? `drift findings list --repo ${repoId} --status new --json`
      : `drift findings list --repo ${repoId} --json`,
    `drift prepare "task" --repo ${repoId} --json`
  ];
  if (summary.findingCount > 0) {
    commands.push(`drift baseline create --repo ${repoId} --from main --confirm --json`);
  }
  if (summary.blockingCount > 0) {
    commands.push(`drift audit list --repo ${repoId} --action finding_resolved --json`);
  }
  return commands;
}
