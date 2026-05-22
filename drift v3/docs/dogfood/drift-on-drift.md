# Dogfood Transcript: Drift On Drift

Date: 2026-05-21
Repo: `/Users/geoffreyfernald/Downloads/driftv3`
Commit: record before running
Drift version: record from `drift version --json`
Machine: local developer machine

## Purpose

This transcript should prove whether Drift is useful on its own codebase.

Do not polish this into marketing copy. The point is to capture what worked, what was confusing, what context was missing, and what needs to improve before beta.

## Rules

- Run commands against the real Drift checkout.
- Keep source code private/local.
- Record summaries, not full source snippets.
- Preserve command JSON artifacts where useful under a local ignored output directory.
- Call out false positives and missing intelligence honestly.
- If a command fails, record the failure and the next command Drift suggested.

## 1. Doctor

Command:

```bash
drift doctor --repo-root . --json
```

Record:

- status:
- database path:
- repo id:
- migration compatibility:
- contract compatibility:
- scan freshness:
- audit integrity:
- backup artifact health:
- next commands:

Observation:

- What was clear:
- What was confusing:
- What should change:

## 2. Start / Onboarding

Command:

```bash
drift start --repo-root . --accept-defaults --json
```

Record:

- scan id:
- repo id:
- accepted default convention:
- baseline count:
- next commands:

Observation:

- Did `--accept-defaults` feel explicit enough?
- Was the resulting contract understandable?
- Were candidates overbroad or too narrow?

## 3. Scan

Command:

```bash
drift scan --repo-root . --json
```

Record:

- files indexed:
- facts emitted:
- candidates emitted:
- engine source:
- diagnostics:
- scan fingerprint:

Observation:

- Were important files skipped?
- Were generated/vendor files skipped correctly?
- Did the scan stats explain enough?

## 4. Convention Review

Command:

```bash
drift conventions list --repo <repo_id> --status candidate --json
drift conventions show <candidate_id> --repo <repo_id> --json
```

Record:

- candidate count:
- deterministic candidates:
- heuristic candidates:
- best candidate:
- rejected/noisy candidate:

Observation:

- Are candidates machine-checkable?
- Is evidence understandable?
- Are counterexamples shown?

## 5. Contract

Command:

```bash
drift contract show --repo <repo_id> --json
drift contract validate --repo <repo_id> --json
```

Record:

- contract id:
- contract fingerprint:
- accepted conventions:
- waivers:
- risky areas:
- required checks:
- safe commands:

Observation:

- Does the contract explain the repo's real patterns?
- Is anything missing for an agent about to edit Drift?

## 6. Prepare

Task:

```text
Add engine-owned direct data-access checks.
```

Command:

```bash
drift prepare "Add engine-owned direct data-access checks" --repo <repo_id> --json
```

Record:

- matched conventions:
- relevant files:
- risky areas:
- open findings:
- required checks:
- policy result:
- scan freshness:

Observation:

- Did this give useful guidance?
- Did it mention the right files?
- What graph context was missing?
- Would an agent avoid bad code after reading it?

## 7. Ask

Command:

```bash
drift ask "what should I know before changing the checker or engine?" --repo <repo_id> --json
```

Record:

- answer summary:
- conventions referenced:
- findings referenced:
- files referenced:

Observation:

- Was the answer concrete?
- Did it feel like repo intelligence or generic advice?

## 8. Repo Map

Command:

```bash
drift repo map --repo <repo_id> --limit 50 --offset 0 --json
```

Record:

- files returned:
- roles detected:
- imports/exports/calls quality:
- impact summary:

Observation:

- Could this map help someone navigate Drift?
- What relationships were missing?
- Did lack of true graph edges show up?

## 9. Check

Command:

```bash
drift check --repo <repo_id> --diff main...HEAD --scope changed-hunks --json
```

Record:

- findings count:
- blocking count:
- waived count:
- expired count:
- diagnostics:
- exit code:

Observation:

- Were findings actionable?
- Were there false positives?
- Did baseline behavior work?
- Was diff classification intuitive?

## 10. Findings

Command:

```bash
drift findings list --repo <repo_id> --json
drift findings show <finding_id> --repo <repo_id> --json
```

Record:

- new:
- pre-existing:
- needs review:
- suppressed:
- fixed:

Observation:

- Is evidence enough to resolve the finding?
- Are next commands clear?

## 11. MCP

Tool calls:

```text
get_runtime_info
get_capabilities
get_scan_status
get_repo_contract
get_task_preflight
get_repo_map
get_findings
get_allowed_context
get_audit_status
```

Record:

- CLI/MCP parity:
- policy metadata:
- missing fields:
- oversized responses:

Observation:

- Would an agent have enough context?
- Did MCP stay safely read-only?

## 12. Audit

Command:

```bash
drift audit verify --repo <repo_id> --json
drift audit list --repo <repo_id> --limit 20 --offset 0 --json
```

Record:

- valid:
- event count:
- head hash:
- recent events:

Observation:

- Is governance history clear?
- Are mutation events complete?

## 13. Backup

Command:

```bash
drift backup create --repo <repo_id> --confirm --json
drift backup list --repo <repo_id> --json
```

Record:

- backup path:
- checksum:
- size:
- verify command:
- restore dry-run command:

Observation:

- Is recovery guidance clear?
- Does backup avoid source code?

## 14. Product Notes

What felt strong:

-

What was confusing:

-

What intelligence was missing:

-

What was too noisy:

-

What should change before beta:

-

## 15. Beta Readiness Checklist

- [ ] First run is understandable without reading docs.
- [ ] `doctor` gives useful next commands.
- [ ] `prepare` gives task-relevant guidance.
- [ ] `repo map` helps navigate the repo.
- [ ] `check` produces actionable findings.
- [ ] Findings have enough evidence to resolve.
- [ ] Baselines prevent legacy noise.
- [ ] Audit chain verifies.
- [ ] Backup/restore guidance is clear.
- [ ] MCP responses are safe and useful.
- [ ] Missing graph intelligence is documented.
