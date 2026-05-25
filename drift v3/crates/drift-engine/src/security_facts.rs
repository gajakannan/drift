use serde_json::json;

use crate::security_patterns::{
    AcceptedAuthHelper, accepted_auth_helper_for_call, static_middleware_matchers,
};
use crate::{Fact, FactExtractError, FactKind, extract_typescript_facts};

pub fn extract_security_facts(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_auth_helpers: &[AcceptedAuthHelper],
) -> Result<Vec<Fact>, FactExtractError> {
    let normalized_file_path = file_path.as_ref().to_string_lossy().replace('\\', "/");
    let facts = extract_typescript_facts(file_path, source)?;
    let source_lines: Vec<&str> = source.lines().collect();
    let mut security_facts = Vec::new();
    for fact in facts
        .iter()
        .filter(|fact| fact.kind == FactKind::SymbolCalled)
    {
        let route = route_for_line(&facts, fact.start_line).unwrap_or("unknown");
        if let Some(helper) = accepted_auth_helper_for_call(fact, &facts, accepted_auth_helpers) {
            let route_id = format!("route:{}:{route}", fact.file_path);
            security_facts.push(Fact {
                kind: FactKind::AuthGuardCalled,
                file_path: fact.file_path.clone(),
                name: fact.name.clone(),
                value: Some(
                    json!({
                        "guard_id": helper.guard_id,
                        "route_id": route_id,
                        "handler_symbol": route,
                        "behavior": helper.behavior.as_str(),
                    })
                    .to_string(),
                ),
                imported_name: Some(helper.symbol.clone()),
                start_line: fact.start_line,
                end_line: fact.end_line,
            });
            if line_is_inside_callback(&source_lines, fact.start_line) {
                security_facts.push(Fact {
                    kind: FactKind::CallbackBoundaryDetected,
                    file_path: fact.file_path.clone(),
                    name: "callback".to_string(),
                    value: Some(
                        json!({
                            "route_id": route_id,
                            "boundary_kind": "callback",
                            "contains_guard": true,
                            "contains_sink": protected_sink_after_line(&facts, fact.start_line),
                        })
                        .to_string(),
                    ),
                    imported_name: None,
                    start_line: fact.start_line,
                    end_line: fact.end_line,
                });
            }
        }
        if is_json_response_call(fact) {
            let route_id = format!("route:{}:{route}", fact.file_path);
            security_facts.push(Fact {
                kind: FactKind::RouteReturnsResponse,
                file_path: fact.file_path.clone(),
                name: fact.name.clone(),
                value: Some(
                    json!({
                        "route_id": route_id,
                        "handler_symbol": route,
                        "response_id": format!("response:{}:{}", fact.file_path, fact.start_line),
                        "response_kind": "json",
                    })
                    .to_string(),
                ),
                imported_name: None,
                start_line: fact.start_line,
                end_line: fact.end_line,
            });
        }
    }
    if is_middleware_file(
        facts
            .first()
            .map(|fact| fact.file_path.as_str())
            .unwrap_or_default(),
    ) && let Some(middleware_line) = middleware_declaration_line(&source_lines)
    {
        let file_path = facts
            .first()
            .map(|fact| fact.file_path.clone())
            .unwrap_or_else(|| normalized_file_path.clone());
        let middleware_id = format!("middleware:{file_path}");
        let protection_kind = if security_facts
            .iter()
            .any(|fact| fact.kind == FactKind::AuthGuardCalled)
        {
            "auth"
        } else {
            "unknown"
        };
        security_facts.push(Fact {
            kind: FactKind::MiddlewareDeclared,
            file_path: file_path.clone(),
            name: "middleware".to_string(),
            value: Some(
                json!({
                    "middleware_id": middleware_id,
                    "protection_kind": protection_kind,
                })
                .to_string(),
            ),
            imported_name: None,
            start_line: middleware_line,
            end_line: middleware_line,
        });
        for matcher in static_middleware_matchers(source) {
            security_facts.push(Fact {
                kind: FactKind::MiddlewareMatcherDeclared,
                file_path: file_path.clone(),
                name: matcher.path_pattern.clone(),
                value: Some(
                    json!({
                        "middleware_id": middleware_id,
                        "matcher_kind": if matcher.excluded { "excluded_path" } else { "static_path" },
                        "path_pattern": matcher.path_pattern,
                    })
                    .to_string(),
                ),
                imported_name: None,
                start_line: matcher.start_line,
                end_line: matcher.end_line,
            });
        }
    }

    Ok(security_facts)
}

fn is_middleware_file(file_path: &str) -> bool {
    file_path == "middleware.ts"
        || file_path == "middleware.js"
        || file_path.ends_with("/middleware.ts")
        || file_path.ends_with("/middleware.js")
}

fn middleware_declaration_line(lines: &[&str]) -> Option<usize> {
    lines
        .iter()
        .position(|line| line.contains("function middleware") || line.contains("middleware ="))
        .map(|index| index + 1)
}

fn protected_sink_after_line(facts: &[Fact], line: usize) -> bool {
    facts.iter().any(|fact| {
        matches!(
            fact.kind,
            FactKind::DataOperationDetected | FactKind::RouteReturnsResponse
        ) && fact.start_line > line
    })
}

fn line_is_inside_callback(lines: &[&str], line_number: usize) -> bool {
    lines
        .iter()
        .take(line_number.saturating_sub(1))
        .rev()
        .take_while(|line| !line.contains("export "))
        .any(|line| {
            (line.contains("=>") && line.contains('{'))
                || line.contains(".then(")
                || line.contains(".catch(")
                || line.contains(".forEach(")
                || line.contains(".map(")
        })
}

fn route_for_line(facts: &[Fact], line: usize) -> Option<&str> {
    facts
        .iter()
        .filter(|fact| fact.kind == FactKind::RouteDeclared)
        .find(|fact| fact.start_line <= line && line <= fact.end_line)
        .or_else(|| {
            facts
                .iter()
                .find(|fact| fact.kind == FactKind::RouteDeclared)
        })
        .map(|fact| fact.name.as_str())
}

fn is_json_response_call(fact: &Fact) -> bool {
    fact.name == "json"
        && matches!(
            fact.value.as_deref(),
            Some("Response") | Some("NextResponse") | Some("res")
        )
}
