use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

use serde_json::{Value, json};

#[test]
fn check_repo_blocks_phase6_ssrf_with_trusted_proof() {
    let source = [
        "export async function GET(request: Request) {",
        r#"  const target = request.nextUrl.searchParams.get("target");"#,
        "  await fetch(target);",
        "  return Response.json({ ok: true });",
        "}",
        "",
    ]
    .join("\n");
    let payload = run_phase6_fixture(
        "ssrf",
        "app/api/proxy/route.ts",
        &source,
        json!({
            "id": "security_api_no_ssrf",
            "kind": "api_route_forbids_untrusted_ssrf",
            "matcher": {
                "applies_to_file_roles": ["api_route"],
                "methods": ["GET"]
            },
            "requires": {
                "outbound_url_allowlist_helpers": [{
                    "helper_id": "outbound_allowlist",
                    "module": "@/security/outbound",
                    "symbol": "requireAllowedOutboundUrl"
                }]
            },
            "severity": "error",
            "enforcement_mode": "block",
            "enforcement_capability": "deterministic_check"
        }),
    );

    assert_eq!(
        payload["findings"][0]["rule_id"],
        "api_route_forbids_untrusted_ssrf"
    );
    assert_eq!(payload["findings"][0]["enforcement_result"], "block");
    assert_eq!(
        payload["security_boundary_proofs"][0]["ssrf"]["required"],
        json!(true)
    );
    assert_eq!(
        payload["security_boundary_proofs"][0]["result"]["proof_status"],
        "missing_proof"
    );
}

fn run_phase6_fixture(name: &str, file_path: &str, source: &str, convention: Value) -> Value {
    let repo_root = temp_repo(name);
    let route_path = repo_root.join(file_path);
    fs::create_dir_all(route_path.parent().expect("route parent")).expect("create route parent");
    fs::write(&route_path, source).expect("write route");
    fs::write(repo_root.join("package.json"), "{}").expect("write package");
    let scan = run_scan_repo(&repo_root);
    run_check_repo(json!({
        "repo": {
            "repo_id": "repo_phase6",
            "repo_root": repo_root.to_string_lossy()
        },
        "scan": {
            "scan_id": "scan_phase6",
            "facts": scan["facts"]
        },
        "contract": {
            "contract_id": "contract_phase6",
            "contract_schema_version": 1,
            "conventions": [convention]
        },
        "baseline": [],
        "diff": { "mode": "full", "files": [] }
    }))
}

fn run_scan_repo(repo_root: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_drift-engine"))
        .args([
            "scan-repo",
            repo_root.to_str().expect("repo root"),
            "--format",
            "json",
            "--repo-id",
            "repo_phase6",
            "--scan-id",
            "scan_phase6",
        ])
        .output()
        .expect("run scan-repo");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("scan json")
}

fn run_check_repo(request: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_drift-engine"))
        .arg("check-repo")
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

fn temp_repo(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "drift-security-check-phase6-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create temp repo");
    path
}
