use serde_json::json;

use crate::security_control_flow::validated_input_uses;
use crate::security_patterns::{
    AcceptedAuthHelper, AcceptedRequestValidator, Phase4SecurityPolicy, RequestValidatorKind,
    accepted_auth_helper_for_call, accepted_authorization_helper_for_call,
    accepted_phase4_auth_helper_for_call, accepted_request_validator_for_call,
    static_middleware_matchers,
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
    extract_security_facts_with_policy(
        file_path,
        source,
        &Phase4SecurityPolicy::from_auth_helpers(accepted_auth_helpers),
        accepted_validators,
    )
}

pub fn extract_security_facts_with_policy(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    phase4_policy: &Phase4SecurityPolicy,
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
        let route_id = format!("route:{}:{route}", fact.file_path);
        if let Some(helper) = accepted_phase4_auth_helper_for_call(fact, &facts, phase4_policy)
            .or_else(|| {
                phase4_policy
                    .auth_helper_imports
                    .is_empty()
                    .then(|| {
                        accepted_auth_helper_for_call(
                            fact,
                            &facts,
                            &phase4_policy.accepted_auth_helpers,
                        )
                    })
                    .flatten()
            })
        {
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
            if matches!(
                helper.behavior,
                crate::security_patterns::AuthGuardBehavior::ReturnsSession
                    | crate::security_patterns::AuthGuardBehavior::ReturnsUser
            ) && let Some(line) = source_lines.get(fact.start_line.saturating_sub(1))
                && let Some(variable) = assigned_variable(line)
            {
                security_facts.push(Fact {
                    kind: FactKind::SessionRead,
                    file_path: fact.file_path.clone(),
                    name: variable.clone(),
                    value: Some(
                        json!({
                            "route_id": route_id,
                            "source": "auth_result",
                            "trust": "unknown",
                            "variable": variable,
                            "helper_id": helper.guard_id,
                        })
                        .to_string(),
                    ),
                    imported_name: Some(helper.symbol.clone()),
                    start_line: fact.start_line,
                    end_line: fact.end_line,
                });
            }
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
        } else if let Some(line) = source_lines.get(fact.start_line.saturating_sub(1))
            && let Some(variable) = assigned_variable(line)
            && is_session_like_variable(&variable)
            && line.contains("await")
            && line.contains('(')
            && !line.contains("await request.json()")
            && !line.contains("await request.formData()")
            && !line.contains("await request.text()")
        {
            security_facts.push(Fact {
                kind: FactKind::SessionRead,
                file_path: fact.file_path.clone(),
                name: variable.clone(),
                value: Some(
                    json!({
                        "route_id": route_id,
                        "source": "unknown_helper",
                        "trust": "untrusted",
                        "variable": variable,
                    })
                    .to_string(),
                ),
                imported_name: Some(fact.name.clone()),
                start_line: fact.start_line,
                end_line: fact.end_line,
            });
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
        if let Some(helper) = accepted_authorization_helper_for_call(
            fact,
            &facts,
            &phase4_policy.authorization_helpers,
        ) && let Some(line) = source_lines.get(fact.start_line.saturating_sub(1))
        {
            if helper.behavior == crate::security_patterns::AuthorizationHelperBehavior::Boolean
                && !boolean_authorization_failure_branch_exits(&source_lines, fact.start_line)
            {
                continue;
            }
            let route_id = format!("route:{}:{route}", fact.file_path);
            let arguments = call_arguments(line, &fact.name);
            let subject_var = arguments.first().cloned();
            let resource_var = arguments.get(1).and_then(|argument| {
                (!is_quoted_literal(argument)).then(|| argument.trim().to_string())
            });
            let roles = if helper.kind == crate::security_patterns::AuthorizationHelperKind::Role {
                arguments
                    .iter()
                    .skip(1)
                    .filter_map(|argument| unquoted_literal(argument))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let permissions =
                if helper.kind == crate::security_patterns::AuthorizationHelperKind::Policy {
                    arguments
                        .iter()
                        .skip(1)
                        .filter_map(|argument| unquoted_literal(argument))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
            security_facts.push(Fact {
                kind: FactKind::AuthorizationGuardCalled,
                file_path: fact.file_path.clone(),
                name: fact.name.clone(),
                value: Some(
                    json!({
                        "guard_id": helper.guard_id,
                        "route_id": route_id,
                        "guard_kind": helper.kind.as_str(),
                        "behavior": helper.behavior.as_str(),
                        "subject_var": subject_var,
                        "resource_var": resource_var,
                        "roles": roles,
                        "permissions": permissions,
                        "dominates_sinks": true,
                    })
                    .to_string(),
                ),
                imported_name: Some(helper.symbol.clone()),
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
    }
    security_facts.extend(request_input_read_facts(
        &normalized_file_path,
        &facts,
        &source_lines,
    ));
    security_facts.extend(session_read_facts(
        &normalized_file_path,
        &facts,
        &source_lines,
    ));
    let facts_with_security = facts
        .iter()
        .cloned()
        .chain(security_facts.iter().cloned())
        .collect::<Vec<_>>();
    security_facts.extend(tenant_source_facts(
        &normalized_file_path,
        &facts_with_security,
        &source_lines,
        phase4_policy,
    ));
    security_facts.extend(tenant_guard_facts(
        &normalized_file_path,
        &facts_with_security,
        &source_lines,
        phase4_policy,
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

fn call_arguments(line: &str, call_name: &str) -> Vec<String> {
    let marker = format!("{call_name}(");
    let Some(after_marker) = line.split(&marker).nth(1) else {
        return Vec::new();
    };
    let Some(arguments) = after_marker.split_once(')').map(|(arguments, _)| arguments) else {
        return Vec::new();
    };
    arguments
        .split(',')
        .map(str::trim)
        .filter(|argument| !argument.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_quoted_literal(argument: &str) -> bool {
    let trimmed = argument.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
}

fn unquoted_literal(argument: &str) -> Option<String> {
    let trimmed = argument.trim();
    if !(trimmed.starts_with('"') || trimmed.starts_with('\'')) {
        return None;
    }
    let quote = trimmed.chars().next()?;
    let value = trimmed.trim_matches(quote);
    (!value.is_empty()).then(|| value.to_string())
}

fn boolean_authorization_failure_branch_exits(lines: &[&str], line_number: usize) -> bool {
    if line_number == 0 {
        return false;
    }
    let branch_lines = lines
        .iter()
        .skip(line_number.saturating_sub(1))
        .take(6)
        .copied()
        .collect::<Vec<_>>();
    let branch_text = branch_lines.join("\n");
    branch_text.contains("if")
        && branch_text.contains('!')
        && (branch_text.contains("return ") || branch_text.contains("throw "))
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
        } else if line.contains("cookies().get(") || line.contains("request.cookies.get(") {
            if let Some(variable) = assigned_variable(line) {
                request_facts.push(request_input_fact(
                    file_path,
                    line_number,
                    route_id,
                    "cookies",
                    variable,
                    quoted_argument(line, "cookies().get(")
                        .or_else(|| quoted_argument(line, "request.cookies.get(")),
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

fn session_read_facts(file_path: &str, facts: &[Fact], lines: &[&str]) -> Vec<Fact> {
    let mut session_facts = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let Some(variable) = assigned_variable(line) else {
            continue;
        };
        let source = if line.contains("request.headers.get(") {
            Some("headers")
        } else if line.contains("await request.json()")
            || line.contains("await request.formData()")
            || line.contains("await request.text()")
        {
            Some("body")
        } else if line.contains("cookies().get(") || line.contains("request.cookies.get(") {
            Some("cookies")
        } else {
            None
        };
        let Some(source) = source else {
            continue;
        };
        if !is_session_like_variable(&variable) {
            continue;
        }
        let route = route_for_line(facts, line_number).unwrap_or("unknown");
        session_facts.push(Fact {
            kind: FactKind::SessionRead,
            file_path: file_path.to_string(),
            name: variable.clone(),
            value: Some(
                json!({
                    "route_id": format!("route:{file_path}:{route}"),
                    "source": source,
                    "trust": "untrusted",
                    "variable": variable,
                })
                .to_string(),
            ),
            imported_name: None,
            start_line: line_number,
            end_line: line_number,
        });
    }
    session_facts
}

fn tenant_source_facts(
    file_path: &str,
    facts: &[Fact],
    lines: &[&str],
    phase4_policy: &Phase4SecurityPolicy,
) -> Vec<Fact> {
    let trusted_session_variables = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::SessionRead)
        .filter_map(|fact| {
            let value = serde_json::from_str::<serde_json::Value>(fact.value.as_deref()?).ok()?;
            (value.get("source")?.as_str()? == "auth_result")
                .then(|| value.get("variable")?.as_str().map(str::to_string))
                .flatten()
        })
        .collect::<Vec<_>>();
    let body_variables = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::RequestInputRead)
        .filter_map(|fact| {
            let value = serde_json::from_str::<serde_json::Value>(fact.value.as_deref()?).ok()?;
            (value.get("source")?.as_str()? == "body")
                .then(|| value.get("variable")?.as_str().map(str::to_string))
                .flatten()
        })
        .collect::<Vec<_>>();
    let mut tenant_facts = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let route = route_for_line(facts, line_number).unwrap_or("unknown");
        let route_id = format!("route:{file_path}:{route}");
        if let Some(variable) = assigned_variable(line) {
            for key in &phase4_policy.tenant_keys {
                if phase4_policy
                    .tenant_sources
                    .iter()
                    .any(|source| source == "session")
                    && trusted_session_variables.iter().any(|session_var| {
                        line.contains(&format!("{session_var}.user.{key}"))
                            || line.contains(&format!("{session_var}.{key}"))
                    })
                {
                    let session_variable = trusted_session_variables
                        .iter()
                        .find(|session_var| {
                            line.contains(&format!("{}.user.{key}", session_var))
                                || line.contains(&format!("{}.{key}", session_var))
                        })
                        .cloned();
                    tenant_facts.push(tenant_source_fact(
                        file_path,
                        line_number,
                        route_id.clone(),
                        &variable,
                        TenantSourceFactMetadata {
                            source: "session",
                            tenant_key: key,
                            trusted: true,
                            session_variable,
                        },
                    ));
                } else if phase4_policy
                    .tenant_sources
                    .iter()
                    .any(|source| source == "path_param" || source == "params")
                    && (line.contains(&format!("params.{key}"))
                        || line.contains(&format!("context.params.{key}")))
                {
                    tenant_facts.push(tenant_source_fact(
                        file_path,
                        line_number,
                        route_id.clone(),
                        &variable,
                        TenantSourceFactMetadata {
                            source: "path_param",
                            tenant_key: key,
                            trusted: false,
                            session_variable: None,
                        },
                    ));
                } else if phase4_policy
                    .tenant_sources
                    .iter()
                    .any(|source| source == "query" || source == "search_params")
                    && line.contains("searchParams.get(")
                    && quoted_argument(line, "searchParams.get(").as_deref() == Some(key.as_str())
                {
                    tenant_facts.push(tenant_source_fact(
                        file_path,
                        line_number,
                        route_id.clone(),
                        &variable,
                        TenantSourceFactMetadata {
                            source: "query",
                            tenant_key: key,
                            trusted: false,
                            session_variable: None,
                        },
                    ));
                } else if phase4_policy
                    .tenant_sources
                    .iter()
                    .any(|source| source == "body")
                    && body_variables
                        .iter()
                        .any(|body_var| line.contains(&format!("{body_var}.{key}")))
                {
                    tenant_facts.push(tenant_source_fact(
                        file_path,
                        line_number,
                        route_id.clone(),
                        &variable,
                        TenantSourceFactMetadata {
                            source: "body",
                            tenant_key: key,
                            trusted: false,
                            session_variable: None,
                        },
                    ));
                }
            }
        }
        if line.contains("} = params") {
            for (key, variable) in destructured_aliases(line) {
                if phase4_policy.tenant_keys.contains(&key)
                    && phase4_policy
                        .tenant_sources
                        .iter()
                        .any(|source| source == "path_param" || source == "params")
                {
                    tenant_facts.push(tenant_source_fact(
                        file_path,
                        line_number,
                        route_id.clone(),
                        &variable,
                        TenantSourceFactMetadata {
                            source: "path_param",
                            tenant_key: &key,
                            trusted: false,
                            session_variable: None,
                        },
                    ));
                }
            }
        }
    }
    tenant_facts
}

fn tenant_guard_facts(
    file_path: &str,
    facts: &[Fact],
    lines: &[&str],
    phase4_policy: &Phase4SecurityPolicy,
) -> Vec<Fact> {
    let mut guard_facts = Vec::new();
    for operation in facts
        .iter()
        .filter(|fact| fact.kind == FactKind::DataOperationDetected)
    {
        let route = route_for_line(facts, operation.start_line).unwrap_or("unknown");
        let route_id = format!("route:{file_path}:{route}");
        let operation_text = lines
            .iter()
            .skip(operation.start_line.saturating_sub(1))
            .take(
                operation
                    .end_line
                    .saturating_sub(operation.start_line)
                    .saturating_add(1),
            )
            .copied()
            .collect::<Vec<_>>()
            .join("\n");
        let operation_name = operation
            .value
            .as_deref()
            .map(|receiver| format!("{receiver}.{}", operation.name))
            .unwrap_or_else(|| operation.name.clone());
        for key in &phase4_policy.tenant_keys {
            if operation_text.contains("where:")
                && operation_text.contains(&format!("{key}:"))
                && (operation_text.contains(&format!(".user.{key}"))
                    || operation_text.contains(&format!(".{key}")))
            {
                guard_facts.push(tenant_guard_fact(
                    file_path,
                    operation.start_line,
                    route_id.clone(),
                    &operation_name,
                    "equality",
                    key,
                    None,
                ));
            }
        }
    }
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let route = route_for_line(facts, line_number).unwrap_or("unknown");
        let route_id = format!("route:{file_path}:{route}");
        for helper in &phase4_policy.tenant_helpers {
            if line.contains(&format!("{}(", helper.symbol))
                && helper.import_source.as_deref().is_none_or(|expected| {
                    facts.iter().any(|fact| {
                        fact.kind == FactKind::ImportUsed
                            && fact.name == helper.symbol
                            && fact.imported_name.as_deref() == Some(helper.symbol.as_str())
                            && fact.value.as_deref() == Some(expected)
                    })
                })
            {
                guard_facts.push(tenant_guard_fact(
                    file_path,
                    line_number,
                    route_id.clone(),
                    &helper.symbol,
                    "scoped_helper",
                    &helper.tenant_key,
                    Some(helper.symbol.clone()),
                ));
            }
        }
    }
    guard_facts
}

fn tenant_guard_fact(
    file_path: &str,
    line_number: usize,
    route_id: String,
    name: &str,
    predicate_kind: &str,
    tenant_key: &str,
    helper_symbol: Option<String>,
) -> Fact {
    Fact {
        kind: FactKind::TenantGuardCalled,
        file_path: file_path.to_string(),
        name: name.to_string(),
        value: Some(
            json!({
                "route_id": route_id,
                "predicate_kind": predicate_kind,
                "tenant_key": tenant_key,
                "data_operation": if predicate_kind == "equality" { Some(name) } else { None },
                "helper_symbol": helper_symbol,
            })
            .to_string(),
        ),
        imported_name: helper_symbol,
        start_line: line_number,
        end_line: line_number,
    }
}

fn tenant_source_fact(
    file_path: &str,
    line_number: usize,
    route_id: String,
    variable: &str,
    metadata: TenantSourceFactMetadata<'_>,
) -> Fact {
    Fact {
        kind: FactKind::TenantSource,
        file_path: file_path.to_string(),
        name: variable.to_string(),
        value: Some(
            json!({
                "route_id": route_id,
                "source": metadata.source,
                "variable": variable,
                "tenant_key": metadata.tenant_key,
                "trusted": metadata.trusted,
                "session_variable": metadata.session_variable,
            })
            .to_string(),
        ),
        imported_name: None,
        start_line: line_number,
        end_line: line_number,
    }
}

struct TenantSourceFactMetadata<'a> {
    source: &'a str,
    tenant_key: &'a str,
    trusted: bool,
    session_variable: Option<String>,
}

fn is_session_like_variable(variable: &str) -> bool {
    let lower = variable.to_ascii_lowercase();
    lower.contains("session") || lower.contains("user") || lower.contains("token")
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

fn destructured_aliases(line: &str) -> Vec<(String, String)> {
    let Some(start) = line.find('{') else {
        return Vec::new();
    };
    let Some(end) = line[start + 1..].find('}') else {
        return Vec::new();
    };
    line[start + 1..start + 1 + end]
        .split(',')
        .filter_map(|part| {
            let mut pieces = part.split(':');
            let key = pieces.next()?.trim().trim_start_matches("...").trim();
            let variable = pieces.next().map(str::trim).unwrap_or(key);
            (key.chars().all(is_identifier_char) && variable.chars().all(is_identifier_char))
                .then(|| (key.to_string(), variable.to_string()))
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
