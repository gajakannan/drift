use drift_engine::{
    AcceptedAuthHelper, AcceptedRequestValidator, AuthGuardBehavior, FactKind,
    RequestValidatorBehavior, RequestValidatorKind, SecurityProofStatus, build_auth_boundary_proof,
    build_middleware_coverage_proof, build_request_validation_proof, extract_security_facts,
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

#[test]
fn safe_parse_data_is_validated_only_after_success_guard() {
    let unguarded_source = r#"
import { ProjectInputSchema } from "@/server/validation";
import { db } from "@/server/db";

export async function POST(request: Request) {
  const body = await request.json();
  const result = ProjectInputSchema.safeParse(body);
  await db.project.create({ data: result.data });
  return Response.json({ ok: true });
}
"#;
    let guarded_source = r#"
import { ProjectInputSchema } from "@/server/validation";
import { db } from "@/server/db";

export async function POST(request: Request) {
  const body = await request.json();
  const result = ProjectInputSchema.safeParse(body);
  if (!result.success) {
    return Response.json({ ok: false }, { status: 400 });
  }
  await db.project.create({ data: result.data });
  return Response.json({ ok: true });
}
"#;
    let validators = vec![AcceptedRequestValidator {
        validator_id: "schema_project_input".to_string(),
        symbol: "ProjectInputSchema".to_string(),
        kind: RequestValidatorKind::Schema,
        behavior: RequestValidatorBehavior::ReturnsParsed,
    }];

    let unguarded =
        build_request_validation_proof("app/api/projects/route.ts", unguarded_source, &validators)
            .expect("unguarded request validation proof");
    assert!(
        !unguarded.request_validation.proven,
        "safeParse data without success guard must not prove validation: {unguarded:#?}"
    );

    let guarded =
        build_request_validation_proof("app/api/projects/route.ts", guarded_source, &validators)
            .expect("guarded request validation proof");
    assert!(
        guarded.request_validation.proven,
        "safeParse data after success guard should prove validation: {guarded:#?}"
    );
}

#[test]
fn safe_parse_bare_result_is_not_validated_input() {
    let source = r#"
const db = { project: { create: async (input) => input } };
export async function POST(request: Request) {
  const body = await request.json();
  const result = ProjectInputSchema.safeParse(body);
  if (!result.success) {
    return Response.json({ ok: false }, { status: 400 });
  }
  await db.project.create({ data: result });
  return Response.json({ ok: true });
}
"#;
    let validators = vec![AcceptedRequestValidator {
        validator_id: "schema_project_input".to_string(),
        symbol: "ProjectInputSchema".to_string(),
        kind: RequestValidatorKind::Schema,
        behavior: RequestValidatorBehavior::ReturnsParsed,
    }];
    let proof = build_request_validation_proof("app/api/projects/route.ts", source, &validators)
        .expect("request validation proof");

    assert!(
        !proof.request_validation.proven,
        "bare safeParse result must not prove validation"
    );
    assert!(
        proof
            .request_validation
            .unvalidated_uses
            .iter()
            .any(|use_proof| use_proof.reason == "validation_result_not_used"
                || use_proof.reason == "request_input_not_validated")
    );
}

#[test]
fn safe_parse_guard_must_exit_not_contain_return_string() {
    let source = r#"
const db = { project: { create: async (input) => input } };
export async function POST(request: Request) {
  const body = await request.json();
  const result = ProjectInputSchema.safeParse(body);
  if (!result.success) {
    console.log("return later");
  }
  await db.project.create({ data: result.data });
  return Response.json({ ok: true });
}
"#;
    let validators = vec![AcceptedRequestValidator {
        validator_id: "schema_project_input".to_string(),
        symbol: "ProjectInputSchema".to_string(),
        kind: RequestValidatorKind::Schema,
        behavior: RequestValidatorBehavior::ReturnsParsed,
    }];
    let proof = build_request_validation_proof("app/api/projects/route.ts", source, &validators)
        .expect("request validation proof");

    assert!(
        !proof.request_validation.proven,
        "fake success guard must not prove validation"
    );
}

#[test]
fn safe_parse_data_alias_after_exit_guard_is_validated_input() {
    let source = r#"
const db = { project: { create: async (input) => input } };
export async function POST(request: Request) {
  const body = await request.json();
  const result = ProjectInputSchema.safeParse(body);
  if (!result.success) {
    throw new Error("bad input");
  }
  const input = result.data;
  await db.project.create({ data: input });
  return Response.json({ ok: true });
}
"#;
    let validators = vec![AcceptedRequestValidator {
        validator_id: "schema_project_input".to_string(),
        symbol: "ProjectInputSchema".to_string(),
        kind: RequestValidatorKind::Schema,
        behavior: RequestValidatorBehavior::ReturnsParsed,
    }];
    let proof = build_request_validation_proof("app/api/projects/route.ts", source, &validators)
        .expect("request validation proof");

    assert!(
        proof.request_validation.proven,
        "guarded safeParse .data alias should prove validation"
    );
}

#[test]
fn multiline_sink_with_validated_and_raw_values_blocks() {
    let source = r#"
const db = { project: { create: async (input) => input } };
export async function POST(request: Request) {
  const body = await request.json();
  const input = ProjectInputSchema.parse(body);
  await db.project.create({
    data: input,
    audit: body
  });
  return Response.json({ ok: true });
}
"#;
    let validators = vec![AcceptedRequestValidator {
        validator_id: "schema_project_input".to_string(),
        symbol: "ProjectInputSchema".to_string(),
        kind: RequestValidatorKind::Schema,
        behavior: RequestValidatorBehavior::ReturnsParsed,
    }];
    let proof = build_request_validation_proof("app/api/projects/route.ts", source, &validators)
        .expect("request validation proof");

    assert!(
        !proof.request_validation.proven,
        "raw body in multi-line sink must block"
    );
    assert!(
        proof
            .request_validation
            .unvalidated_uses
            .iter()
            .any(|use_proof| use_proof.reason == "request_input_not_validated")
    );
}

#[test]
fn destructured_body_input_emits_parser_gap() {
    let source = r#"
const db = { project: { create: async (input) => input } };
export async function POST(request: Request) {
  const body = await request.json();
  const { name } = body;
  await db.project.create({ data: { name } });
  return Response.json({ ok: true });
}
"#;
    let proof = build_request_validation_proof("app/api/projects/route.ts", source, &[])
        .expect("request validation proof");

    assert_eq!(proof.result.proof_status, SecurityProofStatus::ParserGap);
    assert!(proof.parser_gaps.iter().any(|gap| {
        gap.code == "unsupported_request_input_destructure" && gap.blocks_enforcement
    }));
}

#[test]
fn request_input_spread_emits_parser_gap_and_blocks() {
    let source = r#"
import { ProjectInputSchema } from "@/server/validation";
import { db } from "@/server/db";

export async function POST(request: Request) {
  const body = await request.json();
  const input = ProjectInputSchema.parse(body);
  await db.project.create({ data: { ...body, ownerId: input.ownerId } });
  return Response.json({ ok: true });
}
"#;
    let validators = vec![AcceptedRequestValidator {
        validator_id: "schema_project_input".to_string(),
        symbol: "ProjectInputSchema".to_string(),
        kind: RequestValidatorKind::Schema,
        behavior: RequestValidatorBehavior::ReturnsParsed,
    }];

    let proof = build_request_validation_proof("app/api/projects/route.ts", source, &validators)
        .expect("request validation proof");

    assert!(
        proof.parser_gaps.iter().any(|gap| {
            gap.code == "unsupported_request_input_spread" && gap.blocks_enforcement
        }),
        "missing unsupported request input spread parser gap: {proof:#?}"
    );
    assert_eq!(proof.result.proof_status, SecurityProofStatus::ParserGap);
}
