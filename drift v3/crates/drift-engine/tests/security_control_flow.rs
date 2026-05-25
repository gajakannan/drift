use drift_engine::{
    AcceptedAuthHelper, AuthGuardBehavior, FactKind, SecurityProofStatus,
    build_auth_boundary_proof, build_middleware_coverage_proof, extract_security_facts,
};

#[test]
fn auth_guard_before_all_sinks_passes() {
    let source = r#"
import { requireUser } from "@/server/auth";
import { db } from "@/server/db";

export async function GET() {
  const user = await requireUser();
  const projects = await db.project.findMany({ where: { ownerId: user.id } });
  return Response.json({ projects });
}
"#;

    let proof = build_auth_boundary_proof(
        "app/api/projects/route.ts",
        source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("auth proof");

    assert!(proof.auth.required);
    assert!(proof.auth.proven, "proof should prove auth: {proof:#?}");
    assert_eq!(proof.auth.undominated_sinks, Vec::<String>::new());
    assert!(
        proof
            .auth
            .dominated_sinks
            .iter()
            .any(|sink| sink.sink_kind == "data_operation"),
        "missing dominated data sink: {proof:#?}"
    );
    assert!(
        proof
            .auth
            .dominated_sinks
            .iter()
            .any(|sink| sink.sink_kind == "response"),
        "missing dominated response sink: {proof:#?}"
    );
    assert_eq!(proof.result.proof_status, SecurityProofStatus::Proven);
}

#[test]
fn auth_after_data_operation_blocks() {
    let source = r#"
import { requireUser } from "@/server/auth";
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  const user = await requireUser();
  return Response.json({ projects, user });
}
"#;

    let proof = build_auth_boundary_proof(
        "app/api/projects/route.ts",
        source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("auth proof");

    assert!(!proof.auth.proven, "auth should not be proven: {proof:#?}");
    assert!(
        proof
            .auth
            .undominated_sinks
            .contains(&"guard_after_sink".to_string()),
        "missing guard_after_sink reason: {proof:#?}"
    );
    assert_eq!(proof.result.proof_status, SecurityProofStatus::MissingProof);
}

#[test]
fn auth_in_one_branch_does_not_dominate_other_branch() {
    let source = r#"
import { requireUser } from "@/server/auth";
import { db } from "@/server/db";

export async function GET(request: Request) {
  if (request.headers.get("x-auth") === "yes") {
    await requireUser();
  } else {
    const projects = await db.project.findMany();
    return Response.json({ projects });
  }
  return Response.json({ ok: true });
}
"#;

    let proof = build_auth_boundary_proof(
        "app/api/projects/route.ts",
        source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("auth proof");

    assert!(!proof.auth.proven, "branch bypass should fail: {proof:#?}");
    assert!(
        proof
            .auth
            .undominated_sinks
            .contains(&"guard_only_in_one_branch".to_string()),
        "missing guard_only_in_one_branch reason: {proof:#?}"
    );
}

#[test]
fn callback_auth_does_not_dominate_outer_sink() {
    let source = r#"
import { requireUser } from "@/server/auth";
import { db } from "@/server/db";

export async function GET() {
  ["auth"].forEach(async () => {
    await requireUser();
  });
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let proof = build_auth_boundary_proof(
        "app/api/projects/route.ts",
        source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("auth proof");

    assert!(!proof.auth.proven, "callback guard should fail: {proof:#?}");
    assert!(
        proof
            .auth
            .undominated_sinks
            .contains(&"callback_boundary".to_string()),
        "missing callback_boundary reason: {proof:#?}"
    );

    let facts = extract_security_facts(
        "app/api/projects/route.ts",
        source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("security facts");
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::CallbackBoundaryDetected),
        "missing callback boundary fact: {facts:#?}"
    );
}

#[test]
fn unsupported_dynamic_control_flow_emits_parser_gap_and_blocks() {
    let source = r#"
import { requireUser } from "@/server/auth";
import { db } from "@/server/db";

const guards = { requireUser };

export async function GET(request: Request) {
  const guard = guards[request.headers.get("x-guard") as keyof typeof guards];
  await guard();
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let proof = build_auth_boundary_proof(
        "app/api/projects/route.ts",
        source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("auth proof");

    assert!(
        !proof.auth.proven,
        "dynamic control flow should fail: {proof:#?}"
    );
    assert!(
        proof
            .auth
            .undominated_sinks
            .contains(&"unsupported_dynamic_control_flow".to_string()),
        "missing unsupported_dynamic_control_flow reason: {proof:#?}"
    );
    assert!(
        proof
            .parser_gaps
            .iter()
            .any(|gap| gap.code == "unsupported_dynamic_control_flow" && gap.blocks_enforcement),
        "missing parser gap: {proof:#?}"
    );
    assert_eq!(proof.result.proof_status, SecurityProofStatus::ParserGap);
}

#[test]
fn static_middleware_matcher_protects_route() {
    let middleware_source = r#"
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
    let route_source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let proof = build_middleware_coverage_proof(
        "middleware.ts",
        middleware_source,
        "app/api/projects/route.ts",
        route_source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("middleware proof");

    assert!(proof.middleware.required);
    assert!(
        proof.middleware.proven,
        "static matcher should prove middleware coverage: {proof:#?}"
    );
    assert_eq!(proof.result.proof_status, SecurityProofStatus::Proven);
    assert!(
        proof
            .middleware
            .matched_middleware
            .iter()
            .any(|middleware| middleware.protection_kind == "auth"
                && middleware
                    .protects_route_edge_id
                    .contains("middleware-protects")),
        "missing matched middleware proof: {proof:#?}"
    );
}

#[test]
fn dynamic_middleware_matcher_emits_parser_gap_and_blocks() {
    let middleware_source = r#"
import { NextResponse } from "next/server";
import { requireUser } from "@/server/auth";

const protectedPaths = ["/api/projects/:path*"];

export async function middleware(request: Request) {
  await requireUser();
  return NextResponse.next();
}

export const config = {
  matcher: protectedPaths,
};
"#;
    let route_source = r#"
import { db } from "@/server/db";

export async function GET() {
  const projects = await db.project.findMany();
  return Response.json({ projects });
}
"#;

    let proof = build_middleware_coverage_proof(
        "middleware.ts",
        middleware_source,
        "app/api/projects/route.ts",
        route_source,
        &[AcceptedAuthHelper {
            guard_id: "auth_require_user".to_string(),
            symbol: "requireUser".to_string(),
            behavior: AuthGuardBehavior::ReturnsUser,
        }],
    )
    .expect("middleware proof");

    assert!(
        !proof.middleware.proven,
        "dynamic matcher should not prove coverage: {proof:#?}"
    );
    assert!(
        proof
            .parser_gaps
            .iter()
            .any(|gap| gap.code == "unsupported_dynamic_middleware_matcher"
                && gap.blocks_enforcement),
        "missing dynamic middleware parser gap: {proof:#?}"
    );
    assert_eq!(proof.result.proof_status, SecurityProofStatus::ParserGap);
}
