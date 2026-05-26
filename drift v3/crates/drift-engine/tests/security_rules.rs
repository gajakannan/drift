use drift_engine::{
    AcceptedAuthHelper, AuthGuardBehavior, SecurityAuthContract, SecurityContractCapability,
    SecurityEnforcementMode, SecurityFindingResult, SecurityMiddlewareContract,
    evaluate_api_route_requires_auth_helper,
    evaluate_api_route_requires_auth_helper_with_middleware, evaluate_middleware_must_cover_routes,
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

#[test]
fn middleware_path_mismatch_blocks_covered_route_contract() {
    let middleware_source = r#"
import { NextResponse } from "next/server";
import { requireUser } from "@/server/auth";

export async function middleware(request: Request) {
  await requireUser();
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/admin/:path*"],
};
"#;
    let route_source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let findings = evaluate_middleware_must_cover_routes(
        "middleware.ts",
        middleware_source,
        "app/api/projects/route.ts",
        route_source,
        &SecurityMiddlewareContract {
            contract_id: "security_middleware_api_coverage".to_string(),
            capability: SecurityContractCapability::DeterministicCheck,
            enforcement_mode: SecurityEnforcementMode::Block,
            route_paths: vec!["/api/projects".to_string()],
            methods: Vec::new(),
            accepted_auth_helpers: vec![AcceptedAuthHelper {
                guard_id: "auth_require_user".to_string(),
                symbol: "requireUser".to_string(),
                behavior: AuthGuardBehavior::ReturnsUser,
            }],
        },
    )
    .expect("security findings");

    assert_eq!(findings.len(), 1, "expected one finding: {findings:#?}");
    assert_eq!(findings[0].contract_id, "security_middleware_api_coverage");
    assert_eq!(
        findings[0].title,
        "Middleware does not cover required route"
    );
    assert_eq!(findings[0].actual_layer, "path_not_matched");
    assert_eq!(findings[0].enforcement_result, SecurityFindingResult::Block);
    assert_eq!(findings[0].drift_category, "missing_proof");
}

#[test]
fn middleware_method_mismatch_blocks_when_contract_requires_method() {
    let middleware_source = r##"
import { NextResponse } from "next/server";
import { requireUser } from "@/server/auth";

export async function middleware(request: Request) {
  await requireUser();
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/projects/:path*#POST"],
};
"##;
    let route_source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let findings = evaluate_middleware_must_cover_routes(
        "middleware.ts",
        middleware_source,
        "app/api/projects/route.ts",
        route_source,
        &SecurityMiddlewareContract {
            contract_id: "security_middleware_api_coverage".to_string(),
            capability: SecurityContractCapability::DeterministicCheck,
            enforcement_mode: SecurityEnforcementMode::Block,
            route_paths: vec!["/api/projects".to_string()],
            methods: vec!["GET".to_string()],
            accepted_auth_helpers: vec![AcceptedAuthHelper {
                guard_id: "auth_require_user".to_string(),
                symbol: "requireUser".to_string(),
                behavior: AuthGuardBehavior::ReturnsUser,
            }],
        },
    )
    .expect("security findings");

    assert_eq!(findings.len(), 1, "expected one finding: {findings:#?}");
    assert_eq!(findings[0].actual_layer, "method_not_matched");
    assert_eq!(findings[0].enforcement_result, SecurityFindingResult::Block);
}

#[test]
fn middleware_excludes_matched_route_blocks() {
    let middleware_source = r#"
import { NextResponse } from "next/server";
import { requireUser } from "@/server/auth";

export async function middleware(request: Request) {
  await requireUser();
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/:path*", "!/api/projects/:path*"],
};
"#;
    let route_source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let findings = evaluate_middleware_must_cover_routes(
        "middleware.ts",
        middleware_source,
        "app/api/projects/route.ts",
        route_source,
        &SecurityMiddlewareContract {
            contract_id: "security_middleware_api_coverage".to_string(),
            capability: SecurityContractCapability::DeterministicCheck,
            enforcement_mode: SecurityEnforcementMode::Block,
            route_paths: vec!["/api/projects".to_string()],
            methods: vec!["GET".to_string()],
            accepted_auth_helpers: vec![AcceptedAuthHelper {
                guard_id: "auth_require_user".to_string(),
                symbol: "requireUser".to_string(),
                behavior: AuthGuardBehavior::ReturnsUser,
            }],
        },
    )
    .expect("security findings");

    assert_eq!(findings.len(), 1, "expected one finding: {findings:#?}");
    assert_eq!(findings[0].actual_layer, "path_not_matched");
    assert_eq!(findings[0].drift_category, "missing_proof");
}

#[test]
fn auth_contract_accepts_static_middleware_proof_but_not_middleware_existence() {
    let covered_middleware_source = r#"
import { NextResponse } from "next/server";
import { requireUser } from "@/server/auth";

export async function middleware(request: Request) {
  await requireUser();
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/projects/:path*"],
};
"#;
    let middleware_without_matcher_source = r#"
import { NextResponse } from "next/server";
import { requireUser } from "@/server/auth";

export async function middleware(request: Request) {
  await requireUser();
  return NextResponse.next();
}
"#;
    let route_source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;
    let contract = SecurityAuthContract {
        contract_id: "security_api_auth_require_user".to_string(),
        enforcement_mode: SecurityEnforcementMode::Block,
        accepted_auth_helpers: vec![AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    };

    let covered_findings = evaluate_api_route_requires_auth_helper_with_middleware(
        "app/api/projects/route.ts",
        route_source,
        "middleware.ts",
        covered_middleware_source,
        &contract,
    )
    .expect("covered security findings");
    assert!(
        covered_findings.is_empty(),
        "deterministic middleware proof should satisfy auth: {covered_findings:#?}"
    );

    let existence_only_findings = evaluate_api_route_requires_auth_helper_with_middleware(
        "app/api/projects/route.ts",
        route_source,
        "middleware.ts",
        middleware_without_matcher_source,
        &contract,
    )
    .expect("existence-only security findings");
    assert_eq!(
        existence_only_findings.len(),
        1,
        "middleware existence alone must not satisfy auth: {existence_only_findings:#?}"
    );
    assert_eq!(
        existence_only_findings[0].actual_layer,
        "missing_auth_guard"
    );
    assert_eq!(
        existence_only_findings[0].enforcement_result,
        SecurityFindingResult::Block
    );
}

#[test]
fn candidate_only_middleware_evidence_does_not_block() {
    let middleware_source = r#"
import { NextResponse } from "next/server";
import { requireUser } from "@/server/auth";

export async function middleware(request: Request) {
  await requireUser();
  return NextResponse.next();
}

export const config = {
  matcher: ["/api/admin/:path*"],
};
"#;
    let route_source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let findings = evaluate_middleware_must_cover_routes(
        "middleware.ts",
        middleware_source,
        "app/api/projects/route.ts",
        route_source,
        &SecurityMiddlewareContract {
            contract_id: "candidate_middleware_api_coverage".to_string(),
            capability: SecurityContractCapability::HeuristicCheck,
            enforcement_mode: SecurityEnforcementMode::Block,
            route_paths: vec!["/api/projects".to_string()],
            methods: vec!["GET".to_string()],
            accepted_auth_helpers: vec![AcceptedAuthHelper {
                guard_id: "auth_require_user".to_string(),
                symbol: "requireUser".to_string(),
                behavior: AuthGuardBehavior::ReturnsUser,
            }],
        },
    )
    .expect("security findings");

    assert!(
        findings.is_empty(),
        "candidate-only heuristic middleware evidence must not block: {findings:#?}"
    );
}
