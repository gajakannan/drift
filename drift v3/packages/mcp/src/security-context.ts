import type { AcceptedConvention, FactRecord, ParserGap, RepoContract, ScanManifest } from "@drift/core";
import type { openDriftStorage } from "@drift/storage";

type DriftStorage = ReturnType<typeof openDriftStorage>;

interface MiddlewareCoverageValue {
  route_id?: string;
  middleware_id?: string;
  protection_kind?: string;
}

interface RequestInputReadValue {
  route_id?: string;
  source?: string;
}

interface ValidatedInputUsedValue {
  route_id?: string;
  sink_kind?: string;
}

export function buildSecurityContextPayload(storage: DriftStorage, repoId: string, contract: RepoContract) {
  const latestScan = latestSecurityScan(storage.listScanManifests(repoId));
  const facts = latestScan ? storage.listFacts(latestScan.id, { kind: "middleware_protects_route" }) : [];
  const requestInputFacts = latestScan ? storage.listFacts(latestScan.id, { kind: "request_input_read" }) : [];
  const validatedUseFacts = latestScan ? storage.listFacts(latestScan.id, { kind: "validated_input_used" }) : [];
  const parserGaps = latestScan ? storage.listParserGaps(repoId, latestScan.id) : [];

  return {
    response_schema: "drift.security.context.v1",
    repo_id: repoId,
    scan_id: latestScan?.id ?? null,
    accepted_contracts: securityConventions(contract.conventions),
    middleware_coverage: {
      routes: middlewareCoverageRoutes(facts),
      parser_gaps: middlewareParserGaps(parserGaps)
    },
    request_validation: {
      routes: requestValidationRoutes(requestInputFacts, validatedUseFacts),
      parser_gaps: requestValidationParserGaps(parserGaps)
    },
    redactions: {
      snippets_included: false,
      source_content_included: false,
      request_payloads_included: false,
      secret_values_included: false
    }
  };
}

function latestSecurityScan(scans: ScanManifest[]): ScanManifest | undefined {
  return scans.find((scan) =>
    scan.status === "completed" &&
    !scan.id.startsWith("scan_baseline_") &&
    !scan.id.startsWith("scan_check_")
  ) ?? scans.find((scan) => scan.status === "completed") ?? scans[0];
}

function securityConventions(conventions: AcceptedConvention[]) {
  return conventions
    .filter((convention) =>
      convention.kind === "middleware_must_cover_routes" ||
      convention.kind === "api_route_requires_auth_helper" ||
      convention.kind === "api_route_requires_request_validation"
    )
    .map((convention) => ({
      id: convention.id,
      kind: convention.kind,
      enforcement_mode: convention.enforcement_mode,
      enforcement_capability: convention.enforcement_capability,
      severity: convention.severity
    }));
}

function requestValidationRoutes(inputFacts: FactRecord[], validatedUseFacts: FactRecord[]) {
  const byRoute = new Map<string, {
    route_id: string;
    file_path: string;
    input_sources: Set<string>;
    validated_sink_kinds: Set<string>;
  }>();

  for (const fact of inputFacts) {
    const value = parseRequestInputReadValue(fact.value);
    const routeId = value.route_id ?? `route:${fact.file_path}:unknown`;
    const entry = byRoute.get(routeId) ?? {
      route_id: routeId,
      file_path: fact.file_path,
      input_sources: new Set<string>(),
      validated_sink_kinds: new Set<string>()
    };
    if (value.source) {
      entry.input_sources.add(value.source);
    }
    byRoute.set(routeId, entry);
  }

  for (const fact of validatedUseFacts) {
    const value = parseValidatedInputUsedValue(fact.value);
    const routeId = value.route_id ?? `route:${fact.file_path}:unknown`;
    const entry = byRoute.get(routeId) ?? {
      route_id: routeId,
      file_path: fact.file_path,
      input_sources: new Set<string>(),
      validated_sink_kinds: new Set<string>()
    };
    if (value.sink_kind) {
      entry.validated_sink_kinds.add(value.sink_kind);
    }
    byRoute.set(routeId, entry);
  }

  return [...byRoute.values()]
    .sort((left, right) => left.route_id.localeCompare(right.route_id))
    .map((entry) => ({
      route_id: entry.route_id,
      file_path: entry.file_path,
      proof_status: entry.input_sources.size > 0 && entry.validated_sink_kinds.size > 0
        ? "proven"
        : "missing_proof",
      input_sources: [...entry.input_sources].sort(),
      validated_sink_kinds: [...entry.validated_sink_kinds].sort()
    }));
}

function parseRequestInputReadValue(value: string | undefined): RequestInputReadValue {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value) as RequestInputReadValue;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function parseValidatedInputUsedValue(value: string | undefined): ValidatedInputUsedValue {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value) as ValidatedInputUsedValue;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function middlewareCoverageRoutes(facts: FactRecord[]) {
  const byPath = new Map<string, {
    file_path: string;
    proven: true;
    protection_kinds: Set<string>;
    middleware_ids: Set<string>;
  }>();

  for (const fact of facts) {
    const value = parseMiddlewareCoverageValue(fact.value);
    const entry = byPath.get(fact.file_path) ?? {
      file_path: fact.file_path,
      proven: true,
      protection_kinds: new Set<string>(),
      middleware_ids: new Set<string>()
    };
    if (value.protection_kind) {
      entry.protection_kinds.add(value.protection_kind);
    }
    if (value.middleware_id) {
      entry.middleware_ids.add(value.middleware_id);
    }
    byPath.set(fact.file_path, entry);
  }

  return [...byPath.values()]
    .sort((left, right) => left.file_path.localeCompare(right.file_path))
    .map((entry) => ({
      file_path: entry.file_path,
      proven: entry.proven,
      protection_kinds: [...entry.protection_kinds].sort(),
      middleware_ids: [...entry.middleware_ids].sort()
    }));
}

function parseMiddlewareCoverageValue(value: string | undefined): MiddlewareCoverageValue {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value) as MiddlewareCoverageValue;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function middlewareParserGaps(parserGaps: ParserGap[]) {
  return parserGaps
    .filter((gap) => gap.message === "unsupported_dynamic_middleware_matcher")
    .map((gap) => ({
      reason: gap.message,
      blocking: gap.confidence_impact === "blocks_enforcement"
    }));
}

function requestValidationParserGaps(parserGaps: ParserGap[]) {
  return parserGaps
    .filter((gap) => gap.message === "unsupported_request_input_spread")
    .map((gap) => ({
      reason: gap.message,
      blocking: gap.confidence_impact === "blocks_enforcement"
    }));
}
