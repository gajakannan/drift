use drift_engine::{AcceptedAuthHelper, AuthGuardBehavior, FactKind, extract_security_facts};

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
