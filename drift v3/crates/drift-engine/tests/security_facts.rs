use drift_engine::{
    AcceptedAuthHelper, AcceptedRequestValidator, AuthGuardBehavior, FactKind,
    RequestValidatorBehavior, RequestValidatorKind, extract_security_facts,
    extract_security_facts_with_validation,
};

#[test]
fn extracts_request_input_read_facts() {
    let source = r#"
export async function POST(request: Request, { params }: { params: { projectId: string } }) {
  const body = await request.json();
  const projectId = request.nextUrl.searchParams.get("projectId");
  const routeProjectId = params.projectId;
  return Response.json({ ok: true, body, projectId, routeProjectId });
}
"#;

    let facts =
        extract_security_facts("app/api/projects/route.ts", source, &[]).expect("security facts");

    assert!(
        facts
            .iter()
            .any(|fact| format!("{:?}", fact.kind) == "RequestInputRead"
                && fact.name == "body"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"source\":\"body\"")
                        && value.contains("\"variable\":\"body\"")
                        && value.contains("\"route_id\":\"route:app/api/projects/route.ts:POST\"")
                })
                && fact.start_line == 3),
        "missing body request input read fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| format!("{:?}", fact.kind) == "RequestInputRead"
                && fact.name == "projectId"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"source\":\"query\"")
                        && value.contains("\"variable\":\"projectId\"")
                        && value.contains("\"key\":\"projectId\"")
                })
                && fact.start_line == 4),
        "missing query request input read fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| format!("{:?}", fact.kind) == "RequestInputRead"
                && fact.name == "routeProjectId"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"source\":\"params\"")
                        && value.contains("\"variable\":\"routeProjectId\"")
                        && value.contains("\"key\":\"projectId\"")
                })
                && fact.start_line == 5),
        "missing params request input read fact: {facts:#?}"
    );
}

#[test]
fn extracts_request_validation_called_for_accepted_schema_and_helper() {
    let source = r#"
import { ProjectInputSchema } from "@/server/validation";
import { validateProjectInput as validateInput } from "@/server/validation";

export async function POST(request: Request) {
  const body = await request.json();
  const parsed = ProjectInputSchema.parse(body);
  const safe = ProjectInputSchema.safeParse(body);
  const checked = validateProjectInput(body);
  const aliased = validateInput(body);
  return Response.json({ parsed, safe, checked, aliased });
}
"#;

    let validators = vec![
        AcceptedRequestValidator {
            validator_id: "schema_project_input".to_string(),
            symbol: "ProjectInputSchema".to_string(),
            kind: RequestValidatorKind::Schema,
            behavior: RequestValidatorBehavior::ReturnsParsed,
        },
        AcceptedRequestValidator {
            validator_id: "helper_project_input".to_string(),
            symbol: "validateProjectInput".to_string(),
            kind: RequestValidatorKind::Helper,
            behavior: RequestValidatorBehavior::ReturnsParsed,
        },
    ];
    let facts = extract_security_facts_with_validation(
        "app/api/projects/route.ts",
        source,
        &[],
        &validators,
    )
    .expect("security facts");

    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::RequestValidationCalled
                && fact.name == "parse"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"schema_symbol\":\"ProjectInputSchema\"")
                        && value.contains("\"input_var\":\"body\"")
                        && value.contains("\"result_var\":\"parsed\"")
                })
                && fact.start_line == 7),
        "missing accepted schema parse validation fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::RequestValidationCalled
                && fact.name == "safeParse"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"schema_symbol\":\"ProjectInputSchema\"")
                        && value.contains("\"input_var\":\"body\"")
                        && value.contains("\"result_var\":\"safe\"")
                })
                && fact.start_line == 8),
        "missing accepted schema safeParse validation fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::RequestValidationCalled
                && fact.name == "validateProjectInput"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"validator_symbol\":\"validateProjectInput\"")
                        && value.contains("\"input_var\":\"body\"")
                        && value.contains("\"result_var\":\"checked\"")
                })
                && fact.start_line == 9),
        "missing accepted helper validation fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::RequestValidationCalled
                && fact.name == "validateInput"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"validator_symbol\":\"validateProjectInput\"")
                        && value.contains("\"input_var\":\"body\"")
                        && value.contains("\"result_var\":\"aliased\"")
                })
                && fact.start_line == 10),
        "missing accepted helper alias validation fact: {facts:#?}"
    );
}

#[test]
fn extracts_validated_input_used_when_parsed_result_reaches_sink() {
    let source = r#"
import { ProjectInputSchema } from "@/server/validation";
import { db } from "@/server/db";

export async function POST(request: Request) {
  const body = await request.json();
  const input = ProjectInputSchema.parse(body);
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
    let facts = extract_security_facts_with_validation(
        "app/api/projects/route.ts",
        source,
        &[],
        &validators,
    )
    .expect("security facts");

    assert!(
        facts
            .iter()
            .any(|fact| format!("{:?}", fact.kind) == "ValidatedInputUsed"
                && fact.name == "input"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"source_input_var\":\"body\"")
                        && value.contains("\"validated_var\":\"input\"")
                        && value.contains("\"sink_kind\":\"data_operation\"")
                })
                && fact.start_line == 8),
        "missing validated input use fact: {facts:#?}"
    );
}

#[test]
fn extracts_auth_guard_called_fact() {
    let source = r#"
import { requireUser } from "@/server/auth";
import { db } from "@/server/db";

export async function GET() {
  const user = await requireUser();
  const projects = await db.project.findMany({ where: { ownerId: user.id } });
  return Response.json({ projects });
}
"#;

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
            .any(|fact| fact.kind == FactKind::AuthGuardCalled
                && fact.name == "requireUser"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"guard_id\":\"auth_require_user\"")
                        && value.contains("\"route_id\":\"route:app/api/projects/route.ts:GET\"")
                        && value.contains("\"behavior\":\"returns_user\"")
                })
                && fact.start_line == 6
                && fact.end_line == 6),
        "missing accepted auth call fact: {facts:#?}"
    );
}

#[test]
fn extracts_route_returns_response_fact() {
    let next_response_source = r#"
import { NextResponse } from "next/server";

export async function GET() {
  return Response.json({ ok: true });
}

export async function POST() {
  return NextResponse.json({ ok: true }, { status: 201 });
}
"#;
    let pages_response_source = r#"
export default async function handler(req, res) {
  return res.json({ ok: true });
}
"#;

    let next_facts = extract_security_facts("app/api/projects/route.ts", next_response_source, &[])
        .expect("next route security facts");
    let pages_facts = extract_security_facts("pages/api/projects.ts", pages_response_source, &[])
        .expect("pages route security facts");

    assert!(
        next_facts
            .iter()
            .any(|fact| fact.kind == FactKind::RouteReturnsResponse
                && fact.name == "json"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"response_kind\":\"json\"")
                        && value.contains("\"route_id\":\"route:app/api/projects/route.ts:GET\"")
                })
                && fact.start_line == 5),
        "missing Response.json sink: {next_facts:#?}"
    );
    assert!(
        next_facts
            .iter()
            .any(|fact| fact.kind == FactKind::RouteReturnsResponse
                && fact.name == "json"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"response_kind\":\"json\"")
                        && value.contains("\"route_id\":\"route:app/api/projects/route.ts:POST\"")
                })
                && fact.start_line == 9),
        "missing NextResponse.json sink: {next_facts:#?}"
    );
    assert!(
        pages_facts
            .iter()
            .any(|fact| fact.kind == FactKind::RouteReturnsResponse
                && fact.name == "json"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"response_kind\":\"json\"")
                        && value.contains("\"route_id\":\"route:pages/api/projects.ts:default\"")
                })
                && fact.start_line == 3),
        "missing res.json sink: {pages_facts:#?}"
    );
}

#[test]
fn extracts_static_middleware_matcher_fact() {
    let source = r#"
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

    let facts = extract_security_facts(
        "middleware.ts",
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
            .any(|fact| fact.kind == FactKind::MiddlewareDeclared
                && fact.name == "middleware"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"middleware_id\":\"middleware:middleware.ts\"")
                        && value.contains("\"protection_kind\":\"auth\"")
                })
                && fact.start_line == 5),
        "missing middleware declaration fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::MiddlewareMatcherDeclared
                && fact.name == "/api/projects/:path*"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"middleware_id\":\"middleware:middleware.ts\"")
                        && value.contains("\"matcher_kind\":\"static_path\"")
                        && value.contains("\"path_pattern\":\"/api/projects/:path*\"")
                })
                && fact.start_line == 11),
        "missing static middleware matcher fact: {facts:#?}"
    );
}
