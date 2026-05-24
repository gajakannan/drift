import { FileRoleSchema,authorizeContextExport,createAgentPreflightPacket,type FileRole } from "@drift/core";
import { buildChangeImpact,selectRelevantTests,type ChangeImpactRouteFlow } from "@drift/query";
import type { SqliteDriftStorage } from "@drift/storage";
import { CommandPayload,ParsedArgs } from "../app/command-types.js";
import { optionalRepoRelativeFlag,requiredValue,stringFlag } from "../args/flag-readers.js";
import { resolveRepoId } from "../args/repo-flags.js";
import { isActiveConvention } from "../check/rule-evaluation.js";
import { agentEnvelopeForScan } from "../domain/agent-envelope.js";
import { baselineSummary } from "../domain/baselines.js";
import { isOpenPreflightFinding } from "../domain/findings.js";
import { graphPreflightContext } from "../domain/graph-preflight.js";
import { requiredChecksFromGraphRisk } from "../domain/graph-risk-checks.js";
import { preflightGovernance } from "../domain/governance.js";
import { countDeniedFiles,preflightSummary,preparedConvention,relevantFilesForTask,requiredChecksForFiles,riskyAreasForFiles,waiversForFiles } from "../domain/preflight.js";
import { repoContractOrDefault } from "../domain/repo-paths.js";
import { assertFreshScanIfRequired,freshnessRequirement,scanStatusPayload } from "../domain/scan-status.js";
import { formatPrepareText } from "../formatters/preflight.js";

export function prepareTask(storage: SqliteDriftStorage, parsed: ParsedArgs): CommandPayload {
  const repoId = resolveRepoId(parsed);
  const task = requiredValue(parsed.positional.slice(1).join(" ").trim(), "task");
  const targetPath = optionalRepoRelativeFlag(parsed, "path");
  const now = stringFlag(parsed, "now") ?? new Date().toISOString();
  const repo = storage.getRepo(repoId);
  if (!repo) {
    throw new Error(`Unknown repo ${repoId}.`);
  }
  const storedContract = storage.getRepoContract(repoId);
  const contract = storedContract ?? repoContractOrDefault(storage, repoId);
  const contractReady = Boolean(storedContract);
  const candidateCount = storage.listConventionCandidates(repoId, { status: "candidate" }).length;

  const policy = authorizeContextExport(contract, "cli-preflight");
  if (!policy.allowed) {
    throw new Error(`Policy denied prepare output: ${policy.reason}`);
  }

  const activeConventions = contract.conventions.filter((convention) =>
    isActiveConvention(convention, now)
  );
  const conventions = activeConventions.map(preparedConvention);
  const findings = storage
    .listFindings(repoId)
    .filter(isOpenPreflightFinding)
    .map((finding) => ({
      id: finding.id,
      convention_id: finding.convention_id,
      title: finding.title,
      severity: finding.severity,
      status: finding.status,
      diff_status: finding.diff_status,
      enforcement_result: finding.enforcement_result
    }));
  const baseline = baselineSummary(storage, repoId);
  const relevantFiles = relevantFilesForTask({
    repoRoot: repo.root_path,
    task,
    contract: { ...contract, conventions: activeConventions },
    targetPath
  });
  const riskyAreas = riskyAreasForFiles(contract, relevantFiles);
  const waivers = waiversForFiles(contract, relevantFiles, now);
  const scanStatus = scanStatusPayload(storage, repoId);
  const requireFresh = parsed.flags.has("require-fresh");
  assertFreshScanIfRequired(repoId, scanStatus, requireFresh);
  const graphContext = graphPreflightContext({
    storage,
    repoId,
    scanStatus,
    targetPath,
    relevantFiles
  });
  const requiredChecks = [
    ...requiredChecksForFiles(contract, relevantFiles),
    ...requiredChecksFromGraphRisk({
      repoRoot: repo.root_path,
      graphContext,
      relevantFiles,
      safeCommands: contract.safe_commands
    })
  ];
  const changeImpactRouteFlows = routeFlowsForChangeImpact(graphContext);
  const testFiles = scanStatus.latest_scan
    ? storage.listFileSnapshots(repoId, scanStatus.latest_scan.id)
        .filter((snapshot) => /(\.test|\.spec)\.[tj]sx?$/.test(snapshot.file_path))
        .map((snapshot) => snapshot.file_path)
    : [];
  const changeImpact = buildChangeImpact({
    repo_id: repoId,
    scan_id: scanStatus.latest_scan?.id ?? "scan_missing",
    changed_files: relevantFiles.map((file) => file.path),
    route_flows: changeImpactRouteFlows,
    test_files: testFiles
  });
  const testSelection = selectRelevantTests({
    changed_file: relevantFiles[0]?.path ?? targetPath ?? "",
    route_flow: changeImpactRouteFlows[0],
    test_files: testFiles
  });
  const agentContractPacket = createAgentPreflightPacket({
    repoContract: { ...contract, conventions: activeConventions },
    task,
    scan_id: scanStatus.latest_scan?.id ?? null,
    stale: scanStatus.stale,
    explicit_paths: targetPath ? [targetPath] : [],
    changed_paths: relevantFiles.map((file) => file.path),
    file_roles: uniqueFileRoles(relevantFiles),
    graph_node_ids: graphNodeIdsForPreflight(graphContext, relevantFiles)
  });
  const auditIntegrity = scanStatus.audit_integrity;
  const redactions = {
    denied_globs: contract.context_egress.denied_globs,
    excluded_file_count: countDeniedFiles(repo.root_path, contract.context_egress.denied_globs),
    snippets_included: false,
    source_content_included: false,
    graph_context_included: graphContext.available,
    context_truncated: false
  };
  const payload = {
    response_schema: "drift.task.preflight.v1",
    repo_id: repoId,
    task,
    target_path: targetPath ?? null,
    generated_at: now,
    agent_envelope: agentEnvelopeForScan({
      surface: "cli-preflight",
      policy,
      scanStatus,
      requireFresh,
      diagnostics: graphContext.diagnostics
    }),
    policy,
    contract: {
      id: storedContract?.id ?? null,
      schema_version: contract.contract_schema_version,
      updated_at: storedContract?.updated_at ?? null,
      ready: contractReady,
      source: contractReady ? "accepted_contract" : "default_local_policy"
    },
    summary: {
      ...preflightSummary({
      conventions,
      relevantFiles,
      riskyAreas,
      waivers,
      findings,
      requiredChecks,
      safeCommands: contract.safe_commands,
      baseline,
      scanStatus
      }),
      contract_ready: contractReady,
      candidate_count: candidateCount
    },
    conventions,
    audit_integrity: auditIntegrity,
    scan_status: scanStatus,
    freshness_requirement: freshnessRequirement(requireFresh, scanStatus),
    graph_context: graphContext,
    change_impact: changeImpact,
    test_intelligence: testSelection.test_intelligence,
    agent_contract_packet: agentContractPacket,
    baseline,
    findings,
    relevant_files: relevantFiles,
    risky_areas: riskyAreas,
    waivers,
    required_checks: requiredChecks,
    safe_commands: contract.safe_commands,
    governance: preflightGovernance(),
    redactions,
    next_commands: contractReady
      ? [
        `drift check --repo ${repoId} --diff main...HEAD --scope changed-hunks --json`,
        `drift findings list --repo ${repoId} --json`
      ]
      : [
        `drift conventions list --repo ${repoId} --status candidate --json`,
        `drift repo map --repo ${repoId} --json`,
        `drift scan status --repo ${repoId} --json`
      ]
  };

  return {
    payload: parsed.flags.has("json") ? payload : formatPrepareText(payload)
  };
}

function routeFlowsForChangeImpact(
  graphContext: ReturnType<typeof graphPreflightContext>
): ChangeImpactRouteFlow[] {
  return graphContext.route_flows.map((flow) => {
    const route = [flow.method, flow.route_pattern].filter(Boolean).join(" ");
    return {
      route: route || flow.path || "unknown route",
      service_file: flow.module_path.find((path) => path.includes("service")),
      data_access_file: flow.module_path.find((path) => path.includes("repositories") || path.includes("data") || path.includes("db")),
      data_operation: graphContext.reachable_data_access
        .flatMap((access) => access.data_operations)
        .map((operation) => [operation.receiver_name, operation.operation_name].filter(Boolean).join("."))
        .find(Boolean)
    };
  });
}

function uniqueFileRoles(relevantFiles: Array<{ roles: string[] }>): FileRole[] {
  return [...new Set(relevantFiles.flatMap((file) => file.roles))]
    .sort()
    .filter(isFileRole);
}

function isFileRole(value: string): value is FileRole {
  return FileRoleSchema.safeParse(value).success;
}

function graphNodeIdsForPreflight(
  graphContext: ReturnType<typeof graphPreflightContext>,
  relevantFiles: Array<{ path: string }>
): string[] {
  return [...new Set([
    ...relevantFiles.map((file) => `file:${file.path}`),
    ...graphContext.route_flows.flatMap((flow) => [
      flow.route_module_id,
      ...flow.route_handler_symbol_ids,
      ...flow.service_module_ids,
      ...flow.data_access_module_ids,
      ...flow.module_path
    ]),
    ...graphContext.reachable_data_access.flatMap((access) => [
      ...access.data_access_module_ids,
      ...access.module_path,
      ...access.data_operations.flatMap((operation) => [
        operation.operation_node_id,
        operation.data_store_node_id
      ])
    ])
  ].filter((id): id is string => Boolean(id)))].sort();
}
