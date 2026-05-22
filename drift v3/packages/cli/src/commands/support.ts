import type { SqliteDriftStorage } from "@drift/storage";
import type { ParsedArgs } from "../app/command-types.js";
import { stringFlag } from "../args/flag-readers.js";
import { engineProvenance } from "../domain/engine-provenance.js";
import { preflightGovernance } from "../domain/governance.js";
import { requiredRepo } from "../domain/repo-paths.js";
import { doctorRuntime,sqliteSchemaCompatibility } from "../domain/versions.js";

export function supportBundle(storage: SqliteDriftStorage, parsed: ParsedArgs) {
  const repoId = stringFlag(parsed, "repo") ?? "repo_abc";
  const dryRun = parsed.flags.has("dry-run");
  if (!dryRun) {
    throw new Error("support bundle requires --dry-run in V1.");
  }
  const repo = requiredRepo(storage, repoId);
  const appliedMigrations = storage.getAppliedMigrations();
  const audit = storage.verifyAuditChain(repoId);
  const latestScan = storage.listScanManifests(repoId).find((scan) => scan.status === "completed") ?? null;
  const backups = storage.listBackupManifests(repoId);

  return {
    response_schema: "drift.support.bundle.v1",
    repo_id: repoId,
    mode: "dry_run",
    governance: preflightGovernance(),
    contents: {
      includes_source_text: false,
      includes_sqlite_database: false,
      includes_backup_files: false,
      includes_environment: false,
      includes_absolute_paths: false,
      includes_contract_json: false,
      includes_finding_evidence: false
    },
    manifest: {
      runtime: doctorRuntime(),
      engine: engineProvenance(),
      repo_identity: {
        repo_id: repo.id,
        fingerprint: repo.fingerprint,
        vcs_provider: repo.vcs_provider ?? "none",
        remote_url_hash: repo.remote_url_hash ?? null,
        package_manager: repo.package_manager ?? "unknown",
        lockfile_hash_count: Object.keys(repo.lockfile_hashes ?? {}).length,
        resolver_input_hash: repo.resolver_input_hash ?? null
      },
      migrations: {
        applied_count: appliedMigrations.length,
        compatibility: sqliteSchemaCompatibility(appliedMigrations)
      },
      scan: latestScan
        ? {
          latest_scan_id: latestScan.id,
          branch: latestScan.branch,
          commit: latestScan.commit,
          dirty: latestScan.dirty,
          file_count: latestScan.file_count,
          fact_count: latestScan.fact_count,
          finding_count: latestScan.finding_count
        }
        : null,
      audit: {
        valid: audit.valid,
        event_count: audit.event_count,
        head_event_hash: audit.head_event_hash
      },
      backups: {
        count: backups.length
      }
    },
    next_commands: [
      `drift doctor --repo ${repoId} --json`,
      `drift audit verify --repo ${repoId} --json`,
      `drift backup list --repo ${repoId} --json`
    ]
  };
}
