use serde_json::json;

use crate::security_control_flow::validated_input_uses;
use crate::security_patterns::{
    AcceptedAuthHelper, AcceptedRequestValidator, RequestValidatorKind,
    accepted_auth_helper_for_call, accepted_request_validator_for_call, static_middleware_matchers,
};
use crate::{Fact, FactExtractError, FactKind, extract_typescript_facts};

pub fn extract_security_facts(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_auth_helpers: &[AcceptedAuthHelper],
) -> Result<Vec<Fact>, FactExtractError> {
    extract_security_facts_with_validation(file_path, source, accepted_auth_helpers, &[])
}

pub fn extract_security_facts_with_validation(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_auth_helpers: &[AcceptedAuthHelper],
    accepted_validators: &[AcceptedRequestValidator],
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
        if let Some(validator) =
            accepted_request_validator_for_call(fact, &facts, accepted_validators)
            && let Some(line) = source_lines.get(fact.start_line.saturating_sub(1))
            && let Some(input_var) = call_first_argument(line, &fact.name)
        {
            let route_id = format!("route:{}:{route}", fact.file_path);
            let result_var = assigned_variable(line);
            let schema_symbol =
                (validator.kind == RequestValidatorKind::Schema).then(|| validator.symbol.clone());
            security_facts.push(Fact {
                kind: FactKind::RequestValidationCalled,
                file_path: fact.file_path.clone(),
                name: fact.name.clone(),
                value: Some(
                    json!({
                        "validator_id": validator.validator_id,
                        "route_id": route_id,
                        "validator_symbol": validator.symbol,
                        "schema_symbol": schema_symbol,
                        "input_var": input_var,
                        "result_var": result_var,
                        "behavior": validator.behavior.as_str(),
                        "kind": validator.kind.as_str(),
                    })
                    .to_string(),
                ),
                imported_name: Some(validator.symbol.clone()),
                start_line: fact.start_line,
                end_line: fact.end_line,
            });
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
        if is_outbound_request_call(fact) {
            let route_id = format!("route:{}:{route}", fact.file_path);
            let line = source_lines
                .get(fact.start_line.saturating_sub(1))
                .copied()
                .unwrap_or_default();
            let url_var = call_first_argument(line, &fact.name);
            let url_source = outbound_url_source(line, url_var.as_deref(), &security_facts);
            security_facts.push(Fact {
                kind: FactKind::OutboundRequestCalled,
                file_path: fact.file_path.clone(),
                name: fact.name.clone(),
                value: Some(
                    json!({
                        "route_id": route_id,
                        "api": outbound_request_api(fact),
                        "url_var": url_var,
                        "url_source": url_source,
                    })
                    .to_string(),
                ),
                imported_name: None,
                start_line: fact.start_line,
                end_line: fact.end_line,
            });
        }
    }
    security_facts.extend(request_input_read_facts(
        &normalized_file_path,
        &facts,
        &source_lines,
    ));
    security_facts.extend(raw_sql_facts(&normalized_file_path, &facts, &source_lines));
    security_facts.extend(cors_policy_facts(
        &normalized_file_path,
        &facts,
        &source_lines,
    ));
    let combined_facts = facts
        .iter()
        .cloned()
        .chain(security_facts.iter().cloned())
        .collect::<Vec<_>>();
    for validated_use in validated_input_uses(&combined_facts, &source_lines) {
        security_facts.push(Fact {
            kind: FactKind::ValidatedInputUsed,
            file_path: normalized_file_path.clone(),
            name: validated_use.validated_var.clone(),
            value: Some(
                json!({
                    "source_input_var": validated_use.source_input_var,
                    "validated_var": validated_use.validated_var,
                    "sink_kind": validated_use.sink_kind,
                    "sink_fact_id": validated_use.sink_fact_id,
                })
                .to_string(),
            ),
            imported_name: None,
            start_line: validated_use.start_line,
            end_line: validated_use.end_line,
        });
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

fn call_first_argument(line: &str, call_name: &str) -> Option<String> {
    let marker = format!("{call_name}(");
    let after_marker = line.split(&marker).nth(1)?;
    let argument = after_marker.split_once(')')?.0.split(',').next()?.trim();
    (!argument.is_empty() && argument.chars().all(is_identifier_char)).then(|| argument.to_string())
}

fn request_input_read_facts(file_path: &str, facts: &[Fact], lines: &[&str]) -> Vec<Fact> {
    let mut request_facts = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let route = route_for_line(facts, line_number).unwrap_or("unknown");
        let route_id = format!("route:{file_path}:{route}");
        if line.contains("await request.json()") {
            if let Some(variable) = assigned_variable(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id,
                    "body",
                    variable,
                    None,
                ));
            }
        } else if line.contains("await request.formData()") {
            if let Some(variable) = assigned_variable(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id,
                    "formData",
                    variable,
                    None,
                ));
            }
        } else if line.contains("await request.text()") {
            if let Some(variable) = assigned_variable(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id,
                    "body",
                    variable,
                    None,
                ));
            }
        } else if line.contains("request.nextUrl.searchParams.get(")
            || line.contains("new URL(request.url).searchParams.get(")
        {
            if let Some(variable) = assigned_variable(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id,
                    "query",
                    variable,
                    quoted_argument(line, "searchParams.get("),
                ));
            }
        } else if line.contains("request.headers.get(") {
            if let Some(variable) = assigned_variable(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id,
                    "headers",
                    variable,
                    quoted_argument(line, "headers.get("),
                ));
            }
        } else if line.contains("cookies().get(") {
            if let Some(variable) = assigned_variable(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id,
                    "cookies",
                    variable,
                    quoted_argument(line, "cookies().get("),
                ));
            }
        } else if (line.contains("params.") || line.contains("context.params."))
            && let Some(variable) = assigned_variable(line)
        {
            let key = line
                .split("params.")
                .nth(1)
                .map(|value| identifier_prefix(value).to_string());
            request_facts.push(request_input_fact(
                file_path,
                line_number,
                route_id,
                "params",
                variable,
                key,
            ));
        } else if line.contains("} = params") {
            for variable in destructured_names(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id.clone(),
                    "params",
                    variable.clone(),
                    Some(variable),
                ));
            }
        }
    }
    request_facts
}

fn request_input_fact(
    file_path: &str,
    line_number: usize,
    route_id: String,
    source: &str,
    variable: String,
    key: Option<String>,
) -> Fact {
    Fact {
        kind: FactKind::RequestInputRead,
        file_path: file_path.to_string(),
        name: variable.clone(),
        value: Some(
            json!({
                "route_id": route_id,
                "source": source,
                "variable": variable,
                "key": key,
                "taint": "untrusted",
            })
            .to_string(),
        ),
        imported_name: None,
        start_line: line_number,
        end_line: line_number,
    }
}

fn assigned_variable(line: &str) -> Option<String> {
    let before_equals = line.split_once('=')?.0.trim();
    let variable = before_equals
        .strip_prefix("const ")
        .or_else(|| before_equals.strip_prefix("let "))
        .or_else(|| before_equals.strip_prefix("var "))
        .unwrap_or(before_equals)
        .trim();
    (!variable.is_empty() && variable.chars().all(is_identifier_char)).then(|| variable.to_string())
}

fn quoted_argument(line: &str, marker: &str) -> Option<String> {
    let after_marker = line.split(marker).nth(1)?;
    let quote = after_marker
        .chars()
        .find(|value| *value == '"' || *value == '\'')?;
    let after_quote = after_marker.split_once(quote)?.1;
    let value = after_quote.split_once(quote)?.0.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn identifier_prefix(value: &str) -> &str {
    value
        .split(|character: char| !is_identifier_char(character))
        .next()
        .unwrap_or("")
}

fn destructured_names(line: &str) -> Vec<String> {
    let Some(start) = line.find('{') else {
        return Vec::new();
    };
    let Some(end) = line[start + 1..].find('}') else {
        return Vec::new();
    };
    line[start + 1..start + 1 + end]
        .split(',')
        .filter_map(|part| {
            let name = part
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches("...")
                .trim();
            (!name.is_empty() && name.chars().all(is_identifier_char)).then(|| name.to_string())
        })
        .collect()
}

fn is_identifier_char(value: char) -> bool {
    value == '_' || value == '$' || value.is_ascii_alphanumeric()
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
            FactKind::DataOperationDetected
                | FactKind::RouteReturnsResponse
                | FactKind::OutboundRequestCalled
                | FactKind::RawSqlCalled
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

fn is_outbound_request_call(fact: &Fact) -> bool {
    fact.name == "fetch"
        || matches!(
            (fact.value.as_deref(), fact.name.as_str()),
            (
                Some("axios"),
                "get" | "post" | "put" | "patch" | "delete" | "request"
            ) | (Some("http"), "get" | "request")
                | (Some("https"), "get" | "request")
        )
}

fn outbound_request_api(fact: &Fact) -> &'static str {
    if fact.name == "fetch" {
        "fetch"
    } else if matches!(fact.value.as_deref(), Some("axios")) {
        "axios"
    } else if matches!(fact.value.as_deref(), Some("http")) {
        "http"
    } else if matches!(fact.value.as_deref(), Some("https")) {
        "https"
    } else {
        "request"
    }
}

fn outbound_url_source(line: &str, url_var: Option<&str>, security_facts: &[Fact]) -> &'static str {
    if first_call_argument_text(line).is_some_and(|argument| {
        argument.starts_with('"') || argument.starts_with('\'') || argument.starts_with('`')
    }) {
        return "constant";
    }
    if let Some(url_var) = url_var
        && security_facts
            .iter()
            .any(|fact| fact.kind == FactKind::RequestInputRead && fact.name == url_var)
    {
        return "request_input";
    }
    "unknown"
}

fn first_call_argument_text(line: &str) -> Option<&str> {
    let after_open = line.split_once('(')?.1;
    let argument = after_open.split_once(')')?.0.split(',').next()?.trim();
    (!argument.is_empty()).then_some(argument)
}

fn raw_sql_facts(file_path: &str, facts: &[Fact], lines: &[&str]) -> Vec<Fact> {
    let mut raw_sql_facts = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let route = route_for_line(facts, line_number).unwrap_or("unknown");
        let route_id = format!("route:{file_path}:{route}");
        if line.contains("$queryRawUnsafe") || line.contains("$executeRawUnsafe") {
            raw_sql_facts.push(Fact {
                kind: FactKind::RawSqlCalled,
                file_path: file_path.to_string(),
                name: "raw_sql".to_string(),
                value: Some(
                    json!({
                        "route_id": route_id,
                        "sink_id": format!("raw_sql:{}:{}", file_path, line_number),
                        "query_shape": raw_sql_query_shape(line),
                        "uses_untrusted_input": true,
                    })
                    .to_string(),
                ),
                imported_name: None,
                start_line: line_number,
                end_line: line_number,
            });
        } else if line.contains("$queryRaw`")
            || line.contains("$executeRaw`")
            || (line.contains(".query(") && line.contains('['))
        {
            raw_sql_facts.push(Fact {
                kind: FactKind::ParameterizedSqlUsed,
                file_path: file_path.to_string(),
                name: "parameterized_sql".to_string(),
                value: Some(
                    json!({
                        "route_id": route_id,
                        "sink_id": format!("raw_sql:{}:{}", file_path, line_number),
                        "parameterization": if line.contains(".query(") { "placeholder_array" } else { "tagged_template_safe" },
                    })
                    .to_string(),
                ),
                imported_name: None,
                start_line: line_number,
                end_line: line_number,
            });
        }
    }
    raw_sql_facts
}

fn raw_sql_query_shape(line: &str) -> &'static str {
    if line.contains('`') && line.contains("${") {
        "template"
    } else if line.contains(" + ") {
        "concat"
    } else {
        "raw_string"
    }
}

fn cors_policy_facts(file_path: &str, facts: &[Fact], lines: &[&str]) -> Vec<Fact> {
    let Some((origin_line, origin)) = header_literal(lines, "Access-Control-Allow-Origin") else {
        return Vec::new();
    };
    let credentials = header_literal(lines, "Access-Control-Allow-Credentials")
        .is_some_and(|(_, value)| value.eq_ignore_ascii_case("true"));
    let route = route_for_line(facts, origin_line).unwrap_or("unknown");
    vec![Fact {
        kind: FactKind::CorsPolicyDeclared,
        file_path: file_path.to_string(),
        name: "cors_policy".to_string(),
        value: Some(
            json!({
                "route_id": format!("route:{file_path}:{route}"),
                "origins": origin,
                "credentials": credentials,
                "source": "route",
            })
            .to_string(),
        ),
        imported_name: None,
        start_line: origin_line,
        end_line: origin_line,
    }]
}

fn header_literal(lines: &[&str], header: &str) -> Option<(usize, String)> {
    let header_marker = format!("\"{header}\"");
    lines.iter().enumerate().find_map(|(index, line)| {
        if !line.contains(&header_marker) {
            return None;
        }
        let after_colon = line.split_once(':')?.1.trim();
        let quote = after_colon
            .chars()
            .find(|value| *value == '"' || *value == '\'')?;
        let after_quote = after_colon.split_once(quote)?.1;
        let value = after_quote.split_once(quote)?.0.trim();
        (!value.is_empty()).then(|| (index + 1, value.to_string()))
    })
}
