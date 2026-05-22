import { authorizeContextExport,type AcceptedConvention,type ConventionCandidate,type ConventionException,type ConventionScope,ConventionScopeSchema,type ConventionStatus,type RepoContract } from "@drift/core";
import type { SqliteDriftStorage } from "@drift/storage";
import { existsSync,statSync } from "node:fs";
import { CommandPayload,ParsedArgs } from "../app/command-types.js";
import { actorFlag,hasAnyFlag,optionalConventionKindFlag,optionalConventionStatusFlag,optionalEnforcementCapabilityFlag,optionalEnforcementModeFlag,optionalNonEmptyFlag,optionalNonNegativeIntegerFlag,optionalPositiveIntegerFlag,optionalSeverityFlag,requiredFlag,requiredNonEmptyFlag,stringFlag } from "../args/flag-readers.js";
import { assertCandidateRepoMatchesParsed,resolveRepoId } from "../args/repo-flags.js";
import { contractSummary,materializeRepoContract } from "../domain/contract-materialization.js";
import { acceptConventionCandidate,conventionCandidateEditNextCommands,conventionCandidateListNextCommands,conventionCandidateReviewItem,conventionCandidateShowNextCommands,conventionCandidateSummary,exceptionNextCommands,rejectedConventionNextCommands } from "../domain/convention-candidates.js";
import { auditEvent,mutationGovernance,preflightGovernance } from "../domain/governance.js";
import { exceptionIdForConvention,hashStable } from "../domain/identifiers.js";
import { orderConventionCandidatesForReview,paginateConventionCandidates,paginationSummary } from "../domain/pagination.js";
import { isRepoRelativePolicyPattern,requiredCandidate,requiredRepo,requiredRepoContract } from "../domain/repo-paths.js";
import { formatConventionCandidateText,formatConventionCandidatesText } from "../formatters/conventions.js";
import { parseJsonFile } from "../io/json-file.js";

export function acceptCandidate(
  storage: SqliteDriftStorage,
  parsed: ParsedArgs,
  candidateId: string
) {
  return acceptConventionCandidate(storage, {
    candidateId,
    repoId: stringFlag(parsed, "repo"),
    now: stringFlag(parsed, "now") ?? new Date().toISOString(),
    actor: actorFlag(parsed),
    severity: optionalSeverityFlag(parsed, "severity"),
    mode: optionalEnforcementModeFlag(parsed, "mode"),
    confirmed: parsed.flags.has("confirm"),
    dryRun: parsed.flags.has("dry-run")
  });
}

export function listConventionCandidates(storage: SqliteDriftStorage, parsed: ParsedArgs): CommandPayload {
  const repoId = resolveRepoId(parsed);
  requiredRepo(storage, repoId);
  const status = optionalConventionStatusFlag(parsed, "status");
  const kind = optionalConventionKindFlag(parsed, "kind");
  const capability = optionalEnforcementCapabilityFlag(parsed, "capability");
  const limit = optionalPositiveIntegerFlag(parsed, "limit");
  const offset = optionalNonNegativeIntegerFlag(parsed, "offset") ?? 0;
  const allCandidates = storage.listConventionCandidates(repoId);
  const filteredCandidates = orderConventionCandidatesForReview(allCandidates.filter((candidate) =>
    (!status || candidate.status === status) &&
    (!kind || candidate.kind === kind) &&
    (!capability || candidate.enforcement_capability === capability)
  ));
  const candidates = paginateConventionCandidates(filteredCandidates, limit, offset);
  const listedStatus: ConventionStatus | "all" = status ?? "all";
  const payload = {
    repo_id: repoId,
    status: listedStatus,
    filters: {
      status: status ?? null,
      kind: kind ?? null,
      capability: capability ?? null
    },
    governance: preflightGovernance(),
    summary: conventionCandidateSummary(allCandidates, filteredCandidates, candidates),
    pagination: paginationSummary(filteredCandidates.length, candidates.length, limit, offset),
    review_items: candidates.map(conventionCandidateReviewItem),
    next_commands: conventionCandidateListNextCommands(repoId, candidates),
    candidates
  };
  return {
    payload: parsed.flags.has("json")
      ? payload
      : formatConventionCandidatesText(payload)
  };
}

export function listAcceptedConventions(storage: SqliteDriftStorage, parsed: ParsedArgs): CommandPayload {
  const repoId = resolveRepoId(parsed);
  requiredRepo(storage, repoId);
  const contract = requiredRepoContract(storage, repoId);
  const policy = authorizeContextExport(contract, "cli-preflight");
  if (!policy.allowed) {
    throw new Error(`Policy denied accepted convention output: ${policy.reason}`);
  }
  const kind = optionalConventionKindFlag(parsed, "kind");
  const capability = optionalEnforcementCapabilityFlag(parsed, "capability");
  const limit = optionalPositiveIntegerFlag(parsed, "limit");
  const offset = optionalNonNegativeIntegerFlag(parsed, "offset") ?? 0;
  const allConventions = storage.listAcceptedConventions(repoId);
  const filteredConventions = orderAcceptedConventionsForReview(allConventions.filter((convention) =>
    (!kind || convention.kind === kind) &&
    (!capability || convention.enforcement_capability === capability)
  ));
  const conventions = paginateAcceptedConventions(filteredConventions, limit, offset);
  const payload = {
    response_schema: "drift.conventions.accepted.v1",
    repo_id: repoId,
    policy,
    filters: {
      kind: kind ?? null,
      capability: capability ?? null
    },
    governance: preflightGovernance(),
    summary: acceptedConventionSummary(allConventions, filteredConventions, conventions),
    pagination: paginationSummary(filteredConventions.length, conventions.length, limit, offset),
    conventions
  };
  return {
    payload
  };
}

export function showConventionCandidate(
  storage: SqliteDriftStorage,
  parsed: ParsedArgs,
  id: string
): CommandPayload {
  const candidate = requiredCandidate(storage, id);
  const repoId = stringFlag(parsed, "repo");
  if (repoId) {
    requiredRepo(storage, repoId);
    if (candidate.repo_id !== repoId) {
      throw new Error(`Convention candidate ${candidate.id} belongs to repo ${candidate.repo_id}, not ${repoId}.`);
    }
  }
  const payload = {
    candidate,
    governance: preflightGovernance(),
    review_item: conventionCandidateReviewItem(candidate),
    next_commands: conventionCandidateShowNextCommands(candidate)
  };
  return {
    payload: parsed.flags.has("json")
      ? payload
      : formatConventionCandidateText(payload)
  };
}

export function rejectCandidate(
  storage: SqliteDriftStorage,
  parsed: ParsedArgs,
  candidateId: string
): {
  candidate: ConventionCandidate;
  changed: boolean;
  governance: ReturnType<typeof mutationGovernance>;
  review_item: ReturnType<typeof conventionCandidateReviewItem>;
  next_commands: string[];
} {
  const candidate = requiredCandidate(storage, candidateId);
  assertCandidateRepoMatchesParsed(storage, parsed, candidate);
  const now = stringFlag(parsed, "now") ?? new Date().toISOString();
  const actor = actorFlag(parsed);
  const reason = requiredNonEmptyFlag(parsed, "reason");
  const dryRun = parsed.flags.has("dry-run");
  const confirmed = parsed.flags.has("confirm");
  if (dryRun && confirmed) {
    throw new Error("Use either --dry-run or --confirm, not both.");
  }
  if (!confirmed && !dryRun) {
    throw new Error("Convention rejection requires --confirm.");
  }
  if (dryRun) {
    const rejected = { ...candidate, status: "rejected" as const };
    return {
      candidate: rejected,
      changed: candidate.status !== "rejected",
      governance: preflightGovernance() as never,
      review_item: conventionCandidateReviewItem(rejected),
      next_commands: [
        `drift conventions reject ${candidate.id} --repo ${candidate.repo_id} --reason "${reason}" --confirm --json`
      ],
      dry_run: true,
      write_intent: false,
      would_reject: candidate.status !== "rejected"
    } as never;
  }
  if (candidate.status === "rejected") {
    return {
      candidate,
      changed: false,
      governance: mutationGovernance(),
      review_item: conventionCandidateReviewItem(candidate),
      next_commands: rejectedConventionNextCommands(candidate.repo_id)
    };
  }

  const rejected = { ...candidate, status: "rejected" as const };

  storage.upsertConventionCandidate(rejected);
  storage.appendAuditEvent(auditEvent({
    id: `audit_event_reject_${candidate.id}_${now}`,
    repoId: candidate.repo_id,
    actor,
    action: "election_rejected",
    targetType: "candidate",
    targetId: candidate.id,
    metadata: { reason },
    createdAt: now
  }));

  return {
    candidate: rejected,
    changed: true,
    governance: mutationGovernance(),
    review_item: conventionCandidateReviewItem(rejected),
    next_commands: rejectedConventionNextCommands(candidate.repo_id)
  };
}

export function editCandidate(
  storage: SqliteDriftStorage,
  parsed: ParsedArgs,
  candidateId: string
): {
  candidate: ConventionCandidate;
  changed_fields: string[];
  governance: ReturnType<typeof mutationGovernance>;
  review_item: ReturnType<typeof conventionCandidateReviewItem>;
  next_commands: string[];
} {
  const candidate = requiredCandidate(storage, candidateId);
  assertCandidateRepoMatchesParsed(storage, parsed, candidate);
  if (!hasAnyFlag(parsed, ["statement", "scope-file"])) {
    throw new Error("Convention edits require --statement or --scope-file.");
  }
  const statement = optionalNonEmptyFlag(parsed, "statement");
  const scopeFile = optionalNonEmptyFlag(parsed, "scope-file");
  const dryRun = parsed.flags.has("dry-run");
  const confirmed = parsed.flags.has("confirm");
  if (dryRun && confirmed) {
    throw new Error("Use either --dry-run or --confirm, not both.");
  }
  if (!confirmed && !dryRun) {
    throw new Error("Convention edits require --confirm.");
  }
  const now = stringFlag(parsed, "now") ?? new Date().toISOString();
  const actor = actorFlag(parsed);
  const nextScope = scopeFile ? readConventionScopeFile(scopeFile) : candidate.scope;
  const changedFields = [
    statement && statement !== candidate.statement ? "statement" : undefined,
    scopeFile && hashStable(JSON.stringify(nextScope)) !== hashStable(JSON.stringify(candidate.scope)) ? "scope" : undefined
  ].filter((field): field is string => Boolean(field));
  const updated = {
    ...candidate,
    statement: statement ?? candidate.statement,
    scope: nextScope
  };
  if (dryRun) {
    return {
      candidate: updated,
      changed_fields: changedFields,
      governance: preflightGovernance() as never,
      review_item: conventionCandidateReviewItem(updated),
      next_commands: [
        `drift conventions edit ${candidate.id} --repo ${candidate.repo_id} --confirm --json`
      ],
      dry_run: true,
      write_intent: false,
      would_edit: changedFields.length > 0
    } as never;
  }
  if (changedFields.length === 0) {
    return {
      candidate: updated,
      changed_fields: changedFields,
      governance: mutationGovernance(),
      review_item: conventionCandidateReviewItem(updated),
      next_commands: conventionCandidateEditNextCommands(updated)
    };
  }

  storage.upsertConventionCandidate(updated);
  storage.appendAuditEvent(auditEvent({
    id: `audit_event_edit_${candidate.id}_${now}`,
    repoId: candidate.repo_id,
    actor,
    action: "election_edited",
    targetType: "candidate",
    targetId: candidate.id,
    metadata: { changed_fields: changedFields },
    createdAt: now
  }));
  return {
    candidate: updated,
    changed_fields: changedFields,
    governance: mutationGovernance(),
    review_item: conventionCandidateReviewItem(updated),
    next_commands: conventionCandidateEditNextCommands(updated)
  };
}

export function readConventionScopeFile(scopeFile: string): ConventionScope {
  if (!existsSync(scopeFile)) {
    throw new Error(`--scope-file not found: ${scopeFile}`);
  }
  if (!statSync(scopeFile).isFile()) {
    throw new Error(`--scope-file must be a file: ${scopeFile}`);
  }
  const rawScope = parseJsonFile(scopeFile, "--scope-file") as {
    path_globs?: unknown;
    exclude_path_globs?: unknown;
  };
  const pathGlobs = Array.isArray(rawScope.path_globs) ? rawScope.path_globs : [];
  const excludePathGlobs = Array.isArray(rawScope.exclude_path_globs) ? rawScope.exclude_path_globs : [];
  const unsafeGlob = [...pathGlobs, ...excludePathGlobs].some((glob) =>
    typeof glob !== "string" || !isRepoRelativePolicyPattern(glob)
  );
  if (unsafeGlob) {
    throw new Error("--scope-file path_globs and exclude_path_globs must be repo-relative.");
  }
  const parsedScope = ConventionScopeSchema.safeParse(rawScope);
  if (!parsedScope.success) {
    throw new Error("--scope-file does not match the Drift scope schema.");
  }
  return parsedScope.data;
}

function orderAcceptedConventionsForReview(conventions: AcceptedConvention[]): AcceptedConvention[] {
  return [...conventions].sort((left, right) =>
    left.accepted_at.localeCompare(right.accepted_at) ||
    left.id.localeCompare(right.id)
  );
}

function paginateAcceptedConventions(
  conventions: AcceptedConvention[],
  limit: number | undefined,
  offset: number
): AcceptedConvention[] {
  return limit === undefined
    ? conventions.slice(offset)
    : conventions.slice(offset, offset + limit);
}

function acceptedConventionSummary(
  allConventions: AcceptedConvention[],
  filteredConventions: AcceptedConvention[],
  listedConventions: AcceptedConvention[]
): {
  total_count: number;
  filtered_count: number;
  listed_count: number;
  deterministic_count: number;
  heuristic_count: number;
  briefing_only_count: number;
  blocking_count: number;
} {
  return {
    total_count: allConventions.length,
    filtered_count: filteredConventions.length,
    listed_count: listedConventions.length,
    deterministic_count: allConventions.filter((convention) =>
      convention.enforcement_capability === "deterministic_check"
    ).length,
    heuristic_count: allConventions.filter((convention) =>
      convention.enforcement_capability === "heuristic_check"
    ).length,
    briefing_only_count: allConventions.filter((convention) =>
      convention.enforcement_capability === "briefing_only"
    ).length,
    blocking_count: allConventions.filter((convention) =>
      convention.enforcement_mode === "block"
    ).length
  };
}

export function addConventionException(
  storage: SqliteDriftStorage,
  parsed: ParsedArgs,
  conventionId: string
): {
  convention: AcceptedConvention;
  contract: RepoContract;
  changed: boolean;
  governance: ReturnType<typeof mutationGovernance>;
  contract_summary: ReturnType<typeof contractSummary>;
  next_commands: string[];
} {
  const repoId = resolveRepoId(parsed);
  requiredRepo(storage, repoId);
  const path = stringFlag(parsed, "path");
  if (path && !isRepoRelativePolicyPattern(path)) {
    throw new Error("--path must be repo-relative.");
  }
  const endpoint = stringFlag(parsed, "endpoint");
  if (endpoint && !endpoint.startsWith("/")) {
    throw new Error("--endpoint must start with /.");
  }
  const method = stringFlag(parsed, "method")?.toUpperCase();
  const resolvedModule = stringFlag(parsed, "resolved-module");
  if (resolvedModule && !isRepoRelativePolicyPattern(resolvedModule)) {
    throw new Error("--resolved-module must be repo-relative.");
  }
  const resolvedSymbol = stringFlag(parsed, "resolved-symbol");
  const dataStore = stringFlag(parsed, "data-store");
  const operationKind = optionalOperationKindFlag(parsed);
  if (!path && !endpoint && !method && !resolvedModule && !resolvedSymbol && !dataStore && !operationKind) {
    throw new Error("Convention exception requires at least one selector.");
  }
  const reason = requiredNonEmptyFlag(parsed, "reason");
  const dryRun = parsed.flags.has("dry-run");
  const confirmed = parsed.flags.has("confirm");
  if (dryRun && confirmed) {
    throw new Error("Use either --dry-run or --confirm, not both.");
  }
  if (!confirmed && !dryRun) {
    throw new Error("Convention exception changes require --confirm.");
  }
  const now = stringFlag(parsed, "now") ?? new Date().toISOString();
  const actor = actorFlag(parsed);
  const convention = storage
    .listAcceptedConventions(repoId)
    .find((accepted) => accepted.id === conventionId);
  if (!convention) {
    throw new Error(`Accepted convention not found: ${conventionId}`);
  }
  const exception: ConventionException = {
    id: exceptionIdForConvention(conventionId, exceptionSelectorKey({
      path,
      endpoint,
      method,
      resolvedModule,
      resolvedSymbol,
      dataStore,
      operationKind
    })),
    reason,
    ...(path ? { path_globs: [path] } : {}),
    ...(endpoint ? { endpoint_paths: [endpoint] } : {}),
    ...(method ? { methods: [method] } : {}),
    ...(resolvedModule ? { resolved_modules: [resolvedModule] } : {}),
    ...(resolvedSymbol ? { resolved_symbols: [resolvedSymbol] } : {}),
    ...(dataStore ? { data_stores: [dataStore] } : {}),
    ...(operationKind ? { operation_kinds: [operationKind] } : {}),
    created_by: actor,
    created_at: now
  };
  const duplicate = convention.exceptions.some((entry) =>
    exceptionSelectorKeyFromException(entry) === exceptionSelectorKeyFromException(exception)
  );
  if (duplicate) {
    const contract = requiredRepoContract(storage, repoId);
    return {
      convention,
      contract,
      changed: false,
      governance: dryRun ? preflightGovernance() as never : mutationGovernance(),
      contract_summary: contractSummary(contract),
      next_commands: dryRun
        ? [`drift conventions exception add ${conventionId} --repo ${repoId} --confirm --json`]
        : exceptionNextCommands(repoId),
      ...(dryRun
        ? {
            dry_run: true,
            write_intent: false,
            would_add_exception: false
          }
        : {})
    } as never;
  }

  const updated: AcceptedConvention = {
    ...convention,
    exceptions: [
      ...convention.exceptions,
      {
        ...exception
      }
    ],
    updated_at: now
  };

  if (dryRun) {
    const existingContract = requiredRepoContract(storage, repoId);
    const previewContract: RepoContract = {
      ...existingContract,
      updated_at: now,
      conventions: existingContract.conventions.map((entry) =>
        entry.id === updated.id ? updated : entry
      )
    };
    return {
      convention: updated,
      contract: previewContract,
      changed: true,
      governance: preflightGovernance() as never,
      contract_summary: contractSummary(previewContract),
      next_commands: [
        `drift conventions exception add ${conventionId} --repo ${repoId} --confirm --json`
      ],
      dry_run: true,
      write_intent: false,
      would_add_exception: true
    } as never;
  }

  const contract = storage.transaction(() => {
    storage.upsertAcceptedConvention(repoId, updated);
    const materializedContract = materializeRepoContract(storage, repoId, updated.contract_id, now);
    storage.upsertRepoContract(materializedContract);
    storage.appendAuditEvent(auditEvent({
      id: `audit_event_exception_${conventionId}_${now}`,
      repoId,
      actor,
      action: "policy_changed",
      targetType: "convention_exception",
      targetId: updated.exceptions.at(-1)?.id ?? conventionId,
      metadata: { convention_id: conventionId, selectors: exceptionSelectorKeyFromException(exception), reason },
      createdAt: now
    }));
    return materializedContract;
  });

  return {
    convention: updated,
    contract,
    changed: true,
    governance: mutationGovernance(),
    contract_summary: contractSummary(contract),
    next_commands: exceptionNextCommands(repoId)
  };
}

function optionalOperationKindFlag(
  parsed: ParsedArgs
): NonNullable<ConventionException["operation_kinds"]>[number] | undefined {
  const value = stringFlag(parsed, "operation-kind");
  if (!value) {
    return undefined;
  }
  if (value === "read" || value === "write" || value === "delete" || value === "unknown") {
    return value;
  }
  throw new Error("--operation-kind must be read, write, delete, or unknown.");
}

function exceptionSelectorKey(input: {
  path?: string;
  endpoint?: string;
  method?: string;
  resolvedModule?: string;
  resolvedSymbol?: string;
  dataStore?: string;
  operationKind?: NonNullable<ConventionException["operation_kinds"]>[number];
}): string {
  return [
    `path=${input.path ?? ""}`,
    `endpoint=${input.endpoint ?? ""}`,
    `method=${input.method ?? ""}`,
    `resolved_module=${input.resolvedModule ?? ""}`,
    `resolved_symbol=${input.resolvedSymbol ?? ""}`,
    `data_store=${input.dataStore ?? ""}`,
    `operation_kind=${input.operationKind ?? ""}`
  ].join("|");
}

function exceptionSelectorKeyFromException(exception: ConventionException): string {
  return [
    `path=${[...(exception.path_globs ?? [])].sort().join(",")}`,
    `endpoint=${[...(exception.endpoint_paths ?? [])].sort().join(",")}`,
    `method=${[...(exception.methods ?? [])].sort().join(",")}`,
    `resolved_module=${[...(exception.resolved_modules ?? [])].sort().join(",")}`,
    `resolved_symbol=${[...(exception.resolved_symbols ?? [])].sort().join(",")}`,
    `data_store=${[...(exception.data_stores ?? [])].sort().join(",")}`,
    `operation_kind=${[...(exception.operation_kinds ?? [])].sort().join(",")}`
  ].join("|");
}
