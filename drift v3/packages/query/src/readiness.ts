import type { ParserGap } from "@drift/core";

export type DriftReadinessSurface =
  | "scan_status"
  | "repo_map"
  | "prepare"
  | "allowed_context"
  | "check"
  | "mcp";

export type DriftReadinessDecision = "blocking_allowed" | "advisory_only" | "refuse";

export interface DriftReadiness {
  schema_version: "drift.readiness.v1";
  repo_id: string;
  scan_id: string | null;
  surface: DriftReadinessSurface;
  graph_available: boolean;
  graph_complete: boolean;
  parser_gap_count: number;
  parser_gaps_by_kind: Record<string, number>;
  confidence: number;
  decision: DriftReadinessDecision;
  reasons: string[];
  required_capabilities: string[];
  missing_capabilities: string[];
}

export interface BuildReadinessInput {
  repo_id: string;
  scan_id: string | null;
  surface: DriftReadinessSurface;
  graph_available: boolean;
  graph_complete: boolean;
  parser_gaps?: ParserGap[];
  completeness_reasons?: string[];
  required_capabilities?: string[];
  missing_capabilities?: string[];
}

export function buildReadiness(input: BuildReadinessInput): DriftReadiness {
  const parserGaps = input.parser_gaps ?? [];
  const parserGapsByKind = countBy(parserGaps, (gap) => gap.kind);
  const parserGapReasons = parserGaps.length > 0 ? ["parser_gaps_present"] : [];
  const graphReasons = [
    ...(!input.graph_available ? ["graph_unavailable"] : []),
    ...(!input.graph_complete ? ["graph_incomplete"] : [])
  ];
  const missingCapabilityReasons = (input.missing_capabilities ?? [])
    .map((capability) => `missing_capability:${capability}`);
  const reasons = uniqueSorted([
    ...graphReasons,
    ...(input.completeness_reasons ?? []),
    ...parserGapReasons,
    ...blockingParserGapReasons(parserGaps),
    ...missingCapabilityReasons
  ]);
  const decision = readinessDecision({
    graphAvailable: input.graph_available,
    graphComplete: input.graph_complete,
    parserGaps,
    missingCapabilities: input.missing_capabilities ?? []
  });

  return {
    schema_version: "drift.readiness.v1",
    repo_id: input.repo_id,
    scan_id: input.scan_id,
    surface: input.surface,
    graph_available: input.graph_available,
    graph_complete: input.graph_complete,
    parser_gap_count: parserGaps.length,
    parser_gaps_by_kind: parserGapsByKind,
    confidence: readinessConfidence({
      graphAvailable: input.graph_available,
      graphComplete: input.graph_complete,
      parserGaps
    }),
    decision,
    reasons,
    required_capabilities: uniqueSorted(input.required_capabilities ?? []),
    missing_capabilities: uniqueSorted(input.missing_capabilities ?? [])
  };
}

function readinessDecision(input: {
  graphAvailable: boolean;
  graphComplete: boolean;
  parserGaps: ParserGap[];
  missingCapabilities: string[];
}): DriftReadinessDecision {
  if (!input.graphAvailable || !input.graphComplete || input.missingCapabilities.length > 0) {
    return "refuse";
  }
  if (input.parserGaps.some((gap) => gap.confidence_impact === "blocks_enforcement")) {
    return "refuse";
  }
  if (input.parserGaps.length > 0) {
    return "advisory_only";
  }
  return "blocking_allowed";
}

function readinessConfidence(input: {
  graphAvailable: boolean;
  graphComplete: boolean;
  parserGaps: ParserGap[];
}): number {
  if (!input.graphAvailable) {
    return 0;
  }
  if (!input.graphComplete) {
    return 0.6;
  }
  if (input.parserGaps.some((gap) => gap.confidence_impact === "blocks_enforcement")) {
    return 0.4;
  }
  if (input.parserGaps.length > 0) {
    return 0.82;
  }
  return 1;
}

function blockingParserGapReasons(parserGaps: ParserGap[]): string[] {
  return parserGaps.some((gap) => gap.confidence_impact === "blocks_enforcement")
    ? ["parser_gap_blocks_enforcement"]
    : [];
}

function countBy<T>(items: T[], keyFor: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const key = keyFor(item);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}
