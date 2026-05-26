use drift_engine::{
    AcceptedAuthHelper, AuthGuardBehavior, SecurityAuthContract, SecurityEnforcementMode,
    SecurityFindingResult, evaluate_api_route_requires_auth_helper,
};

#[test]
fn accepted_auth_helper_contract_blocks_missing_auth() {
    let source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let findings = evaluate_api_route_requires_auth_helper(
        "app/api/projects/route.ts",
        source,
        &SecurityAuthContract {
            contract_id: "security_api_auth_require_user".to_string(),
            enforcement_mode: SecurityEnforcementMode::Block,
            accepted_auth_helpers: vec![AcceptedAuthHelper {
                guard_id: "auth_require_user".to_string(),
                symbol: "requireUser".to_string(),
                behavior: AuthGuardBehavior::ReturnsUser,
            }],
        },
    )
    .expect("security findings");

    assert_eq!(findings.len(), 1, "expected one finding: {findings:#?}");
    assert_eq!(findings[0].contract_id, "security_api_auth_require_user");
    assert_eq!(findings[0].title, "API route missing required auth proof");
    assert_eq!(findings[0].enforcement_result, SecurityFindingResult::Block);
    assert_eq!(findings[0].drift_category, "missing_proof");
    assert_eq!(findings[0].confidence_label, "certain");
}

#[test]
fn auth_like_helper_without_accepted_contract_does_not_block() {
    let source = r#"
import { auth } from "@/server/auth";
import { db } from "@/server/db";

export async function GET() {
  await auth();
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let findings = evaluate_api_route_requires_auth_helper(
        "app/api/projects/route.ts",
        source,
        &SecurityAuthContract {
            contract_id: "security_api_auth_require_user".to_string(),
            enforcement_mode: SecurityEnforcementMode::Block,
            accepted_auth_helpers: Vec::new(),
        },
    )
    .expect("security findings");

    assert!(
        findings.is_empty(),
        "auth-looking names without accepted contract must not block: {findings:#?}"
    );
}
