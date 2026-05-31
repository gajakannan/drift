import { SemanticCoverageContractSchema, type ParserGap, type ParserGapV2, type SemanticCoverageContract, type SemanticCoverageScope } from "@drift/core";
import type { DriftReadiness } from "./readiness.js";

export interface BuildSemanticCoverageInput {
  repo_id: string;
  scan_id: string;
  scope: SemanticCoverageScope;
  scope_id: string;
  required_capabilities: string[];
  certified_capabilities: string[];
  missing_capabilities: string[];
  unsupported_capabilities?: string[];
  readiness: DriftReadiness;
  parser_gaps?: Array<ParserGap | ParserGapV2>;
  unsupported_pattern_ids?: string[];
  generated_at: string;
}

export function buildSemanticCoverage(input: BuildSemanticCoverageInput): SemanticCoverageContract {
  const parserGaps = input.parser_gaps ?? [];
  const requiredCapabilities = uniqueSorted(input.required_capabilities);
  const certifiedCapabilities = new Set(input.certified_capabilities);
  const missingCapabilities = new Set(input.missing_capabilities);
  const unsupportedCapabilities = new Set(input.unsupported_capabilities ?? []);
  const gapAffectedCapabilities = new Set(parserGaps.flatMap((gap) =>
    "affected_capabilities" in gap ? gap.affected_capabilities : []
  ));

  const completeCapabilities = requiredCapabilities.filter((capability) =>
    certifiedCapabilities.has(capability) &&
    !missingCapabilities.has(capability) &&
    !unsupportedCapabilities.has(capability) &&
    !gapAffectedCapabilities.has(capability)
  );
  const partialCapabilities = requiredCapabilities.filter((capability) =>
    gapAffectedCapabilities.has(capability) &&
    !missingCapabilities.has(capability) &&
    !unsupportedCapabilities.has(capability)
  );

  return SemanticCoverageContractSchema.parse({
    schema_version: "drift.semantic_coverage.v1",
    repo_id: input.repo_id,
    scan_id: input.scan_id,
    scope: input.scope,
    scope_id: input.scope_id,
    required_capabilities: requiredCapabilities,
    complete_capabilities: completeCapabilities,
    partial_capabilities: partialCapabilities,
    missing_capabilities: uniqueSorted([...missingCapabilities]),
    unsupported_capabilities: uniqueSorted([...unsupportedCapabilities]),
    parser_gap_ids: uniqueSorted(parserGaps.map(parserGapId)),
    unsupported_pattern_ids: uniqueSorted(input.unsupported_pattern_ids ?? []),
    confidence: input.readiness.confidence,
    decision: input.readiness.decision,
    reasons: input.readiness.reasons,
    generated_at: input.generated_at
  });
}

function parserGapId(gap: ParserGap | ParserGapV2): string {
  return "parser_gap_id" in gap ? gap.parser_gap_id : gap.gap_id;
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}
