use std::{
    io::Write,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

#[test]
fn infer_candidates_emits_governance_free_candidate_proposals() {
    let request = json!({
        "repo": { "repo_id": "repo_abc" },
        "graph": {
            "graph_nodes": [{
                "id": "module:app/api/users/route.ts",
                "kind": "module",
                "label": "app/api/users/route.ts",
                "stable": true,
                "evidence_ids": [],
                "metadata": { "file_path": "app/api/users/route.ts" }
            }],
            "graph_edges": [],
            "graph_evidence": []
        },
        "scan": {
            "scan_id": "scan_abc",
            "file_snapshots": [{
                "file_path": "app/api/users/route.ts",
                "content_hash": "a".repeat(64),
                "byte_size": 120,
                "indexed": true
            }],
            "facts": [
                {
                    "kind": "file_role_detected",
                    "file_path": "app/api/users/route.ts",
                    "name": "api_route",
                    "start_line": 1,
                    "end_line": 5
                },
                {
                    "kind": "import_used",
                    "file_path": "app/api/users/route.ts",
                    "name": "db",
                    "value": "@/lib/db",
                    "start_line": 1,
                    "end_line": 1
                }
            ]
        }
    });
    let payload = run_infer_candidates(request);
    let candidates = payload["candidates"].as_array().expect("candidates");

    assert_eq!(payload["schema_version"], "engine.candidates.result.v1");
    assert_eq!(candidates.len(), 2, "{payload:#?}");
    assert!(candidates.iter().any(|candidate| {
        candidate["kind"] == "api_route_no_direct_data_access"
            && candidate["enforcement_capability"] == "deterministic_check"
            && candidate["suggested_enforcement_mode"] == "warn"
            && candidate.get("status").is_none()
    }));
    assert!(candidates.iter().any(|candidate| {
        candidate["kind"] == "api_route_requires_service_delegation"
            && candidate["enforcement_capability"] == "heuristic_check"
            && candidate["suggested_enforcement_mode"] == "warn"
            && candidate["counterexample_refs"]
                .as_array()
                .is_some_and(|refs| refs.len() == 1)
    }));
    assert_eq!(payload["completeness"][0]["can_block"], false);
}

#[test]
fn infer_candidates_uses_resolved_import_targets_for_data_access_modules() {
    let request = json!({
        "repo": { "repo_id": "repo_abc" },
        "graph": {
            "graph_nodes": [{
                "id": "import:app/api/users/route.ts:client",
                "kind": "import_decl",
                "label": "client from @/lib/client",
                "stable": false,
                "evidence_ids": [],
                "metadata": {
                    "file_path": "app/api/users/route.ts",
                    "local_name": "client",
                    "source": "@/lib/client",
                    "resolved_file_path": "src/lib/client.ts"
                }
            }],
            "graph_edges": [],
            "graph_evidence": []
        },
        "scan": {
            "scan_id": "scan_abc",
            "file_snapshots": [
                {
                    "file_path": "app/api/users/route.ts",
                    "content_hash": "a".repeat(64),
                    "byte_size": 120,
                    "indexed": true
                },
                {
                    "file_path": "src/lib/client.ts",
                    "content_hash": "b".repeat(64),
                    "byte_size": 80,
                    "indexed": true
                }
            ],
            "facts": [
                {
                    "kind": "file_role_detected",
                    "file_path": "app/api/users/route.ts",
                    "name": "api_route",
                    "start_line": 1,
                    "end_line": 5
                },
                {
                    "kind": "import_used",
                    "file_path": "app/api/users/route.ts",
                    "name": "client",
                    "value": "@/lib/client",
                    "start_line": 1,
                    "end_line": 1
                },
                {
                    "kind": "import_used",
                    "file_path": "src/lib/client.ts",
                    "name": "PrismaClient",
                    "value": "@prisma/client",
                    "start_line": 1,
                    "end_line": 1
                }
            ]
        }
    });
    let payload = run_infer_candidates(request);
    let candidates = payload["candidates"].as_array().expect("candidates");
    let direct = candidates
        .iter()
        .find(|candidate| candidate["kind"] == "api_route_no_direct_data_access")
        .expect("direct data-access candidate");

    assert_eq!(
        direct["matcher"]["forbidden_imports"],
        json!(["@/lib/client"])
    );
    assert_eq!(direct["evidence_refs"][0]["symbol"], "client");
}

#[test]
fn infer_candidates_uses_graph_evidence_without_raw_import_facts() {
    let request = json!({
        "repo": { "repo_id": "repo_abc" },
        "graph": {
            "graph_nodes": [
                graph_node("file:app/api/users/route.ts", "file", "app/api/users/route.ts", json!({ "path": "app/api/users/route.ts" })),
                graph_node("file:src/lib/db.ts", "file", "src/lib/db.ts", json!({ "path": "src/lib/db.ts" })),
                graph_node("file_role:api_route", "file_role", "api_route", json!({ "role": "api_route" })),
                graph_node("file_role:data_access_module", "file_role", "data_access_module", json!({ "role": "data_access_module" })),
                graph_node("module:app/api/users/route.ts", "module", "app/api/users/route.ts", json!({ "file_path": "app/api/users/route.ts" })),
                graph_node("module:src/lib/db.ts", "module", "src/lib/db.ts", json!({ "file_path": "src/lib/db.ts" })),
                {
                    "id": "import_decl:app/api/users/route.ts:aaaaaaaaaaaa:@/lib/db:db:1-1",
                    "kind": "import_decl",
                    "label": "db from @/lib/db",
                    "stable": false,
                    "evidence_ids": ["evidence_import"],
                    "metadata": {
                        "file_path": "app/api/users/route.ts",
                        "source": "@/lib/db",
                        "local_name": "db",
                        "imported_name": "db",
                        "resolved_file_path": "src/lib/db.ts",
                        "resolved_module_id": "module:src/lib/db.ts"
                    }
                }
            ],
            "graph_edges": [
                graph_edge("FILE_HAS_ROLE", "file:app/api/users/route.ts", "file_role:api_route"),
                graph_edge("FILE_HAS_ROLE", "file:src/lib/db.ts", "file_role:data_access_module"),
                graph_edge("FILE_DEFINES_MODULE", "file:app/api/users/route.ts", "module:app/api/users/route.ts"),
                graph_edge("FILE_DEFINES_MODULE", "file:src/lib/db.ts", "module:src/lib/db.ts"),
                graph_edge_with_evidence("IMPORT_DECL_REFERENCES_MODULE", "import_decl:app/api/users/route.ts:aaaaaaaaaaaa:@/lib/db:db:1-1", "module:app/api/users/route.ts", "evidence_import"),
                graph_edge_with_evidence("IMPORT_RESOLVES_TO_MODULE", "import_decl:app/api/users/route.ts:aaaaaaaaaaaa:@/lib/db:db:1-1", "module:src/lib/db.ts", "evidence_import")
            ],
            "graph_evidence": [{
                "id": "evidence_import",
                "repo_id": "repo_abc",
                "scan_id": "scan_abc",
                "artifact_id": "file_version:app/api/users/route.ts:aaaaaaaaaaaa",
                "file_path": "app/api/users/route.ts",
                "file_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "start_line": 1,
                "end_line": 1,
                "adapter_id": "typescript",
                "adapter_version": "0.1.0",
                "fact_ids": ["fact_graph_import"],
                "redaction_state": "none"
            }]
        },
        "scan": {
            "scan_id": "scan_abc",
            "file_snapshots": [
                {
                    "file_path": "app/api/users/route.ts",
                    "content_hash": "a".repeat(64),
                    "byte_size": 120,
                    "indexed": true
                },
                {
                    "file_path": "src/lib/db.ts",
                    "content_hash": "b".repeat(64),
                    "byte_size": 80,
                    "indexed": true
                }
            ],
            "facts": []
        }
    });
    let payload = run_infer_candidates(request);
    let candidates = payload["candidates"].as_array().expect("candidates");
    let direct = candidates
        .iter()
        .find(|candidate| candidate["kind"] == "api_route_no_direct_data_access")
        .expect("direct data-access candidate");

    assert_eq!(direct["matcher"]["forbidden_imports"], json!(["@/lib/db"]));
    assert_eq!(direct["evidence_refs"][0]["id"], "evidence_import");
    assert_eq!(
        direct["evidence_refs"][0]["fact_ids"],
        json!(["fact_graph_import"])
    );
    assert_eq!(
        direct["required_capabilities"],
        json!(["syntax_facts", "import_resolution", "route_detection"])
    );
}

#[test]
fn infer_candidates_ignores_repo_fixture_routes_when_repo_root_is_not_the_fixture() {
    let request = json!({
        "repo": { "repo_id": "repo_abc" },
        "graph": {
            "graph_nodes": [],
            "graph_edges": [],
            "graph_evidence": []
        },
        "scan": {
            "scan_id": "scan_abc",
            "file_snapshots": [{
                "file_path": "test/fixtures/next-api-direct-db/apps/web/app/api/users/route.ts",
                "content_hash": "a".repeat(64),
                "byte_size": 120,
                "indexed": true
            }],
            "facts": [
                {
                    "kind": "file_role_detected",
                    "file_path": "test/fixtures/next-api-direct-db/apps/web/app/api/users/route.ts",
                    "name": "api_route",
                    "start_line": 1,
                    "end_line": 5
                },
                {
                    "kind": "import_used",
                    "file_path": "test/fixtures/next-api-direct-db/apps/web/app/api/users/route.ts",
                    "name": "prisma",
                    "value": "@/lib/prisma",
                    "start_line": 1,
                    "end_line": 1
                }
            ]
        }
    });
    let payload = run_infer_candidates(request);

    assert_eq!(
        payload["candidates"].as_array().expect("candidates").len(),
        0
    );
}

#[test]
fn infer_candidates_emits_security_phase_candidates_as_non_blocking_elections() {
    let route_a = "app/api/users/route.ts";
    let route_b = "app/api/projects/route.ts";
    let facts = json!([
        { "kind": "file_role_detected", "file_path": route_a, "name": "api_route", "start_line": 1, "end_line": 5 },
        { "kind": "file_role_detected", "file_path": route_b, "name": "api_route", "start_line": 1, "end_line": 5 },
        { "kind": "import_used", "file_path": route_a, "name": "requireUser", "value": "@/auth", "start_line": 1, "end_line": 1 },
        { "kind": "import_used", "file_path": route_b, "name": "requireUser", "value": "@/auth", "start_line": 1, "end_line": 1 },
        { "kind": "symbol_called", "file_path": route_a, "name": "requireUser", "start_line": 4, "end_line": 4 },
        { "kind": "symbol_called", "file_path": route_b, "name": "requireUser", "start_line": 4, "end_line": 4 },
        { "kind": "request_validation_called", "file_path": route_a, "name": "validateBody", "start_line": 5, "end_line": 5 },
        { "kind": "request_validation_called", "file_path": route_b, "name": "validateBody", "start_line": 5, "end_line": 5 },
        { "kind": "authorization_guard_called", "file_path": route_a, "name": "requireRole", "start_line": 6, "end_line": 6 },
        { "kind": "authorization_guard_called", "file_path": route_b, "name": "requireRole", "start_line": 6, "end_line": 6 },
        { "kind": "tenant_guard_called", "file_path": route_a, "name": "scopeTenant", "start_line": 7, "end_line": 7 },
        { "kind": "tenant_guard_called", "file_path": route_b, "name": "scopeTenant", "start_line": 7, "end_line": 7 },
        { "kind": "serializer_called", "file_path": route_a, "name": "serializeUser", "start_line": 8, "end_line": 8 },
        { "kind": "serializer_called", "file_path": route_b, "name": "serializeUser", "start_line": 8, "end_line": 8 },
        { "kind": "parameterized_sql_used", "file_path": route_a, "name": "safeQuery", "start_line": 9, "end_line": 9 },
        { "kind": "parameterized_sql_used", "file_path": route_b, "name": "safeQuery", "start_line": 9, "end_line": 9 },
        { "kind": "symbol_called", "file_path": route_a, "name": "allowlistedUrl", "start_line": 9, "end_line": 9 },
        { "kind": "symbol_called", "file_path": route_b, "name": "allowlistedUrl", "start_line": 9, "end_line": 9 },
        { "kind": "csrf_guard_called", "file_path": route_a, "name": "requireCsrf", "start_line": 10, "end_line": 10 },
        { "kind": "csrf_guard_called", "file_path": route_b, "name": "requireCsrf", "start_line": 10, "end_line": 10 },
        { "kind": "rate_limit_guard_called", "file_path": route_a, "name": "rateLimit", "start_line": 11, "end_line": 11 },
        { "kind": "rate_limit_guard_called", "file_path": route_b, "name": "rateLimit", "start_line": 11, "end_line": 11 },
        { "kind": "cors_policy_declared", "file_path": route_a, "name": "cors", "value": "{\"origin\":\"https://app.example.com\",\"allow_credentials\":true}", "start_line": 12, "end_line": 12 },
        { "kind": "sensitive_field_declared", "file_path": route_a, "name": "password", "value": "{\"field_path\":\"password\",\"classification\":\"credential\"}", "start_line": 13, "end_line": 13 }
    ]);
    let request = json!({
        "repo": { "repo_id": "repo_abc" },
        "graph": { "graph_nodes": [], "graph_edges": [], "graph_evidence": [] },
        "scan": {
            "scan_id": "scan_abc",
            "file_snapshots": [
                { "file_path": route_a, "content_hash": "a".repeat(64), "byte_size": 120, "indexed": true },
                { "file_path": route_b, "content_hash": "b".repeat(64), "byte_size": 120, "indexed": true }
            ],
            "facts": facts
        }
    });

    let payload = run_infer_candidates(request);
    let candidates = payload["candidates"].as_array().expect("candidates");
    for expected in [
        "api_route_requires_auth_helper",
        "api_route_requires_request_validation",
        "api_route_requires_authorization",
        "api_route_requires_tenant_scope",
        "api_route_forbids_sensitive_response_fields",
        "api_route_forbids_raw_sql_without_params",
        "api_route_forbids_untrusted_ssrf",
        "api_route_requires_csrf_for_mutation",
        "api_route_requires_rate_limit",
        "api_route_cors_must_match_policy",
    ] {
        let candidate = candidates
            .iter()
            .find(|candidate| candidate["kind"] == expected)
            .unwrap_or_else(|| panic!("missing {expected}: {payload:#?}"));
        assert_eq!(candidate["suggested_enforcement_mode"], "warn");
        assert_eq!(candidate["reason_not_blocking"], "candidate_not_accepted");
        assert!(
            candidate["requires"].is_object(),
            "missing requires for {expected}"
        );
        assert!(
            candidate["evidence_fingerprint"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "missing evidence fingerprint for {expected}: {candidate:#?}"
        );
    }
}

fn run_infer_candidates(request: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_drift-engine"))
        .arg("infer-candidates")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn drift-engine");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(request.to_string().as_bytes())
        .expect("write request");
    let output = child.wait_with_output().expect("wait output");
    assert!(
        output.status.success(),
        "engine failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json output")
}

fn graph_node(id: &str, kind: &str, label: &str, metadata: Value) -> Value {
    json!({
        "id": id,
        "kind": kind,
        "label": label,
        "stable": true,
        "evidence_ids": [],
        "metadata": metadata
    })
}

fn graph_edge(kind: &str, from: &str, to: &str) -> Value {
    graph_edge_with_evidence(kind, from, to, "")
}

fn graph_edge_with_evidence(kind: &str, from: &str, to: &str, evidence_id: &str) -> Value {
    let evidence_ids = if evidence_id.is_empty() {
        Vec::<String>::new()
    } else {
        vec![evidence_id.to_string()]
    };
    json!({
        "id": format!("edge:{from}:{kind}:{to}"),
        "kind": kind,
        "from": from,
        "to": to,
        "evidence_ids": evidence_ids,
        "metadata": {}
    })
}
