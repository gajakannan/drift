# Dogfood Transcript: Drift On Drift

Date: 2026-05-22
Repo: `/Users/geoffreyfernald/Downloads/driftv3/drift v3`
Commit: `af3acb65e061366463d25f7c13974b58b3d522fa`
Branch: `codex/drift-sprints-15-25`
Drift version: `0.1.0`
State root: `output/dogfood/drift-state`
Artifacts: `output/dogfood/artifacts`

## Purpose

This run checks whether Drift is useful on its own repo using the current graph-backed engine and agent envelopes. The repo has no accepted Drift contract, so the useful behavior is honest local metadata, safe refusals, and clear next steps rather than invented conventions.

## Commands Run

```bash
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js doctor --repo-root . --state-root output/dogfood/drift-state --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js start --repo-root . --state-root output/dogfood/drift-state --accept-defaults --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js --db <db> scan status --repo <repo> --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js --db <db> repo map --repo <repo> --limit 10 --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js --db <db> audit verify --repo <repo> --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js --db <db> backup create --repo <repo> --confirm --output-dir output/dogfood/artifacts --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js --db <db> prepare "Add graph-backed policy metadata" --repo <repo> --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js --db <db> ask "what should I know before changing the checker or engine?" --repo <repo> --json
DRIFT_ENGINE_BIN=target/debug/drift-engine node packages/cli/dist/main.js --db <db> check --repo <repo> --scope full --json
```

## Doctor

Status: `warn`

Reason: local state did not exist yet.

Database path:

```text
output/dogfood/drift-state/repo_8e87fba3c58ea49b/drift.sqlite
```

## Start / Onboarding

Repo: `repo_8e87fba3c58ea49b`
Scan: `scan_b8d311289fd1298e`
Files indexed: `144`
Facts emitted: `15945`
Diagnostics emitted: `672`
Candidates emitted: `0`
Engine source: `rust`

Onboarding result:

```json
{
  "status": "needs_more_signal",
  "accepted_default": false,
  "baselined_count": 0,
  "candidate_count": 0
}
```

Correct behavior: Drift did not infer a repo contract from its own test fixtures.

## Scan Status

```json
{
  "latest_scan_id": "scan_b8d311289fd1298e",
  "scan_count": 1,
  "indexed_file_count": 144,
  "source_change_count": 0,
  "stale": false,
  "invalidation_count": 0,
  "audit_valid": true
}
```

## Repo Map

Repo map worked without an accepted contract through the default local-only policy.

```json
{
  "indexed_file_count": 144,
  "filtered_file_count": 144,
  "listed_file_count": 10,
  "role_counts": {
    "test": 1
  },
  "import_count": 43,
  "export_count": 48,
  "call_count": 178
}
```

Agent envelope action: `safe_to_edit`

Redaction metadata confirmed:

```json
{
  "snippets_included": false,
  "source_content_included": false,
  "graph_context_included": true,
  "context_truncated": false
}
```

## Audit / Backup

Audit verification:

```json
{
  "valid": true,
  "event_count": 2,
  "verified_count": 2,
  "broken_at_event_id": null,
  "reason_count": 0
}
```

Backup creation:

```json
{
  "write_intent": true,
  "artifact_exists": true,
  "schema_version": 10,
  "size_bytes": 67203072
}
```

## Prepare / Ask

Prepare now returns a no-contract local packet instead of failing:

```json
{
  "convention_count": 0,
  "relevant_file_count": 4,
  "finding_count": 0,
  "contract_ready": false,
  "candidate_count": 0
}
```

Agent envelope action: `safe_to_edit`

Ask also returns deterministic local context without inventing conventions:

```json
{
  "matched_convention_count": 0,
  "open_finding_count": 0,
  "relevant_file_count": 13,
  "scan_stale": false,
  "contract_ready": false,
  "candidate_count": 0
}
```

## Check / MCP Limitation

`drift check --scope full` refused because no repo contract exists:

```text
No repo contract exists for repo_8e87fba3c58ea49b.
```

The JSON refusal included an agent envelope with action `blocked_by_policy`.

Read-only MCP `get_task_preflight` also currently requires an accepted contract, so Drift-on-Drift MCP preflight refuses on a no-contract repo. That is honest, but it now lags the CLI no-contract prepare behavior.

## Product Notes

What worked:

- First scan is local-only and deterministic.
- Fixture routes do not pollute onboarding.
- Repo map, scan status, audit, backup, prepare, and ask are useful before a contract exists.
- Agent envelope V2 is present on CLI agent-facing outputs.
- Graph-derived payloads explicitly say no snippets/source content are included.

What was confusing:

- MCP preflight still refuses without a contract while CLI prepare now returns a no-contract packet.
- The repo map sees mostly low-level file facts for Drift itself; richer package/CLI roles would make dogfood more useful.
- Diagnostics count is high on Drift itself, but the surfaced summary does not group why.

What should change before beta:

- Bring MCP no-contract preflight to parity with CLI prepare.
- Add diagnostic grouping to scan status and dogfood output.
- Add richer CLI/package role detection beyond the API-route wedge.
- Keep no-contract behavior explicit: useful repo metadata is okay, invented conventions are not.
