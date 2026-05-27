use drift_engine::{
    AcceptedAuthHelper, AcceptedPhase5Contract, AcceptedRequestValidator,
    AcceptedResponseSerializer, AcceptedSensitiveResponseField, AuthGuardBehavior, FactKind,
    RequestValidatorBehavior, RequestValidatorKind, ResponseSerializerPolicy,
    extract_security_facts, extract_security_facts_with_phase5,
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
fn security_phase5_secret_read_ignores_unknown_public_config_unless_explicitly_accepted() {
    let source = r#"
export async function GET() {
  const publicName = config.publicName;
  return Response.json({ ok: true });
}
"#;
    let phase5 = AcceptedPhase5Contract {
        sensitive_response_fields: Vec::new(),
        response_serializers: Vec::new(),
        secret_sources: vec!["config".to_string()],
        log_sinks: Vec::new(),
    };
    let facts = extract_security_facts_with_phase5(
        "app/api/config/route.ts",
        source,
        &[],
        &[],
        Some(&phase5),
    )
    .expect("facts");
    assert!(
        facts.iter().all(|fact| fact.kind != FactKind::SecretRead),
        "{facts:#?}"
    );
}

#[test]
fn security_phase5_secret_read_fact_name_does_not_leak_env_key_shaped_variable() {
    let source = r#"
export async function GET() {
  const API_KEY = process.env.API_KEY;
  return Response.json({ ok: true });
}
"#;
    let phase5 = AcceptedPhase5Contract {
        sensitive_response_fields: Vec::new(),
        response_serializers: Vec::new(),
        secret_sources: vec!["env".to_string()],
        log_sinks: Vec::new(),
    };
    let facts = extract_security_facts_with_phase5(
        "app/api/config/route.ts",
        source,
        &[],
        &[],
        Some(&phase5),
    )
    .expect("facts");
    let serialized = format!("{facts:#?}");
    assert!(!serialized.contains("API_KEY"), "{serialized}");
}

#[test]
fn security_phase5_sensitive_field_facts_from_contract_schema_and_candidates() {
    let source = r#"
const UserSchema = z.object({
  email: z.string().meta({ driftSensitive: "pii" }),
  password: z.string(),
});

export async function GET() {
  const user = { email: "SECRET_VALUE_SHOULD_NOT_LEAK", password: "sk_live_should_not_leak" };
  return Response.json({ ok: true });
}
"#;
    let phase5 = AcceptedPhase5Contract {
        sensitive_response_fields: vec![AcceptedSensitiveResponseField {
            field_path: "user.email".to_string(),
            classification: "pii".to_string(),
            source: "contract".to_string(),
        }],
        response_serializers: Vec::new(),
        secret_sources: Vec::new(),
        log_sinks: Vec::new(),
    };

    let facts = extract_security_facts_with_phase5(
        "app/api/users/route.ts",
        source,
        &[],
        &[],
        Some(&phase5),
    )
    .expect("security facts");

    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::SensitiveFieldDeclared
                && fact.name == "user.email"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"field_path\":\"user.email\"")
                        && value.contains("\"classification\":\"pii\"")
                        && value.contains("\"source\":\"contract\"")
                })),
        "missing contract sensitive field fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::SensitiveFieldDeclared
                && fact.name == "email"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"field_path\":\"email\"")
                        && value.contains("\"classification\":\"pii\"")
                        && value.contains("\"source\":\"schema\"")
                })),
        "missing schema sensitive field fact: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::SensitiveFieldDeclared
                && fact.name == "password"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"field_path\":\"password\"")
                        && value.contains("\"classification\":\"credential\"")
                        && value.contains("\"source\":\"candidate\"")
                })),
        "missing candidate sensitive field fact: {facts:#?}"
    );

    let serialized = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::SensitiveFieldDeclared)
        .filter_map(|fact| fact.value.as_deref())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!serialized.contains("SECRET_VALUE_SHOULD_NOT_LEAK"));
    assert!(!serialized.contains("sk_live_should_not_leak"));
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
fn extracts_request_validation_called_for_namespace_imported_schema() {
    let source = r#"
import * as validation from "@/server/validation";
export async function POST(request: Request) {
  const body = await request.json();
  const input = validation.ProjectInputSchema.parse(body);
  return Response.json(input);
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
            .any(|fact| fact.kind == FactKind::RequestValidationCalled),
        "missing namespace-imported schema validation fact: {facts:#?}"
    );
}

#[test]
fn extracts_destructured_params_as_request_input_read() {
    let source = r#"
export async function GET(_request: Request, { params }: { params: { projectId: string } }) {
  const { projectId } = params;
  return Response.json({ projectId });
}
"#;
    let facts =
        extract_security_facts("app/api/projects/route.ts", source, &[]).expect("security facts");

    assert!(
        facts.iter().any(|fact| {
            fact.kind == FactKind::RequestInputRead
                && fact.name == "projectId"
                && fact
                    .value
                    .as_deref()
                    .is_some_and(|value| value.contains("\"source\":\"params\""))
        }),
        "missing destructured params request input read: {facts:#?}"
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
fn security_phase5_response_shape_facts_for_static_json_shapes() {
    let source = r#"
import { NextResponse } from "next/server";

export async function GET() {
  const email = "redacted@example.test";
  return Response.json({ user: { email } });
}

export async function POST() {
  const token = "redacted";
  return NextResponse.json({ token });
}

export default async function handler(req, res) {
  const user = { id: "u1" };
  return res.json({ user });
}

export async function PUT() {
  const email = "redacted@example.test";
  const payload = { user: { email } };
  return Response.json(payload);
}

export async function PATCH() {
  const user = { email: "redacted@example.test" };
  return Response.json({ ...user });
}
"#;
    let facts =
        extract_security_facts("app/api/users/route.ts", source, &[]).expect("security facts");

    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::ResponseEmitsField
                && fact.name == "user.email"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"field_path\":\"user.email\"")
                        && value.contains("\"response_kind\":\"json\"")
                        && value.contains("\"classification\":\"unknown\"")
                })),
        "missing nested Response.json field: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::ResponseEmitsField
                && fact.name == "token"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"field_path\":\"token\"")
                        && value.contains("\"route_id\":\"route:app/api/users/route.ts:POST\"")
                })),
        "missing NextResponse.json field: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::ResponseEmitsField
                && fact.name == "user"
                && fact
                    .value
                    .as_deref()
                    .is_some_and(|value| { value.contains("\"field_path\":\"user\"") })),
        "missing res.json field: {facts:#?}"
    );
    assert!(
        facts
            .iter()
            .any(|fact| fact.kind == FactKind::ResponseEmitsField
                && fact.name == "user.email"
                && fact.value.as_deref().is_some_and(|value| {
                    value.contains("\"source_var\":\"payload\"")
                        && value.contains("\"route_id\":\"route:app/api/users/route.ts:PUT\"")
                })),
        "missing response variable field: {facts:#?}"
    );
    assert!(
        !facts
            .iter()
            .any(|fact| fact.kind == FactKind::ResponseEmitsField && fact.start_line == 26),
        "object spread must not emit known-safe response fields: {facts:#?}"
    );
}

#[test]
fn security_phase5_serializer_facts_require_accepted_import_identity() {
    let source = r#"
import { serializePublicUser as publicUser } from "@/lib/serializers/user";
import { serializePublicUser as unsafePublicUser } from "@/lib/unsafe-serializers";

export async function GET() {
  const user = { email: "redacted@example.test" };
  const serialized = publicUser(user);
  const unsafeSerialized = unsafePublicUser(user);
  const localSerialized = serializePublicUser(user);
  return Response.json({ serialized, unsafeSerialized, localSerialized });
}
"#;
    let phase5 = AcceptedPhase5Contract {
        sensitive_response_fields: Vec::new(),
        response_serializers: vec![AcceptedResponseSerializer {
            serializer_id: "serializePublicUser".to_string(),
            import_source: "@/lib/serializers/user".to_string(),
            imported_name: "serializePublicUser".to_string(),
            local_name: Some("publicUser".to_string()),
            policy: ResponseSerializerPolicy::Denylist,
            filtered_fields: vec!["user.email".to_string()],
        }],
        secret_sources: Vec::new(),
        log_sinks: Vec::new(),
    };
    let facts = extract_security_facts_with_phase5(
        "app/api/users/route.ts",
        source,
        &[],
        &[],
        Some(&phase5),
    )
    .expect("security facts");

    let serializer_facts = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::SerializerCalled)
        .collect::<Vec<_>>();
    assert_eq!(
        serializer_facts.len(),
        1,
        "only the accepted import alias should produce serializer_called: {facts:#?}"
    );
    let fact = serializer_facts[0];
    assert_eq!(fact.name, "publicUser");
    assert!(
        fact.value.as_deref().is_some_and(|value| {
            value.contains("\"serializer_id\":\"serializePublicUser\"")
                && value.contains("\"input_var\":\"user\"")
                && value.contains("\"output_var\":\"serialized\"")
                && value.contains("\"policy\":\"denylist\"")
                && value.contains("\"filtered_fields\":[\"user.email\"]")
        }),
        "serializer fact did not preserve policy and filtered fields: {fact:#?}"
    );
}

#[test]
fn security_phase5_secret_read_facts_are_redacted() {
    let source = r#"
const config = { password: "SECRET_VALUE_SHOULD_NOT_LEAK" };
const secretManager = { get: (key: string) => key };

export async function GET() {
  const apiKey = process.env.API_KEY;
  const token = process.env["TOKEN"];
  const password = config.password;
  const privateKey = secretManager.get("PRIVATE_KEY");
  return Response.json({ ok: true });
}
"#;
    let phase5 = AcceptedPhase5Contract {
        sensitive_response_fields: Vec::new(),
        response_serializers: Vec::new(),
        secret_sources: vec![
            "env".to_string(),
            "config".to_string(),
            "secret_manager".to_string(),
        ],
        log_sinks: Vec::new(),
    };
    let facts = extract_security_facts_with_phase5(
        "app/api/secrets/route.ts",
        source,
        &[],
        &[],
        Some(&phase5),
    )
    .expect("security facts");
    let secret_facts = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::SecretRead)
        .collect::<Vec<_>>();

    assert_eq!(
        secret_facts.len(),
        4,
        "missing secret_read facts: {facts:#?}"
    );
    let serialized = secret_facts
        .iter()
        .filter_map(|fact| fact.value.as_deref())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(serialized.contains("\"source\":\"env\""));
    assert!(serialized.contains("\"source\":\"config\""));
    assert!(serialized.contains("\"source\":\"secret_manager\""));
    assert!(serialized.contains("\"secret_class\":\"api_key\""));
    assert!(serialized.contains("\"secret_class\":\"token\""));
    assert!(serialized.contains("\"secret_class\":\"password\""));
    assert!(serialized.contains("\"secret_class\":\"private_key\""));
    assert!(serialized.contains("\"env_key_hash\""));
    assert!(!serialized.contains("API_KEY"));
    assert!(!serialized.contains("TOKEN"));
    assert!(!serialized.contains("PRIVATE_KEY"));
    assert!(!serialized.contains("SECRET_VALUE_SHOULD_NOT_LEAK"));
    assert!(!serialized.contains("sk_live_should_not_leak"));
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
