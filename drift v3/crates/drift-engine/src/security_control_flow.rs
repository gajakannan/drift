use crate::{Fact, FactKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DominatedSink {
    pub sink_id: String,
    pub sink_kind: String,
    pub edge_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedMiddleware {
    pub middleware_id: String,
    pub matcher_fact_id: String,
    pub protects_route_edge_id: String,
    pub protection_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareMismatch {
    pub middleware_id: Option<String>,
    pub reason: String,
    pub parser_gap_id: Option<String>,
}

pub fn guard_dominates_straight_line_sinks(facts: &[Fact]) -> Vec<DominatedSink> {
    let Some(first_guard_line) = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::AuthGuardCalled)
        .map(|fact| fact.start_line)
        .min()
    else {
        return Vec::new();
    };

    protected_sinks(facts)
        .into_iter()
        .filter(|sink| first_guard_line < sink.start_line)
        .map(|sink| DominatedSink {
            sink_id: sink_id(sink),
            sink_kind: sink_kind(sink).to_string(),
            edge_id: format!("edge:auth-dominates:{}:{}", sink.file_path, sink.start_line),
        })
        .collect()
}

pub fn undominated_straight_line_reasons(facts: &[Fact]) -> Vec<String> {
    let first_guard_line = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::AuthGuardCalled)
        .map(|fact| fact.start_line)
        .min();

    protected_sinks(facts)
        .into_iter()
        .filter_map(|sink| match first_guard_line {
            Some(line) if line > sink.start_line => Some("guard_after_sink".to_string()),
            Some(_) => None,
            None => Some("no_guard_call".to_string()),
        })
        .collect()
}

pub fn branch_bypass_reasons(source: &str, facts: &[Fact]) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("if") || !line.contains('{') {
            continue;
        }
        let if_line = index + 1;
        let Some(else_line) = lines
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, candidate)| candidate.contains("else") && candidate.contains('{'))
            .map(|(else_index, _)| else_index + 1)
        else {
            continue;
        };
        let else_end = closing_block_line(&lines, else_line).unwrap_or(else_line);
        let then = if_line + 1..else_line;
        let alternate = else_line + 1..else_end;
        let then_has_guard = has_fact_in_range(facts, FactKind::AuthGuardCalled, then.clone());
        let then_has_sink = has_sink_in_range(facts, then);
        let else_has_guard = has_fact_in_range(facts, FactKind::AuthGuardCalled, alternate.clone());
        let else_has_sink = has_sink_in_range(facts, alternate);

        if (then_has_guard && else_has_sink && !else_has_guard)
            || (else_has_guard && then_has_sink && !then_has_guard)
        {
            return vec!["guard_only_in_one_branch".to_string()];
        }
    }
    Vec::new()
}

pub fn conditional_guard_without_else_reasons(source: &str, facts: &[Fact]) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("if") || !line.contains('{') {
            continue;
        }
        let if_line = index + 1;
        let Some(block_end) = closing_block_line(&lines, if_line) else {
            continue;
        };
        let has_else = lines
            .iter()
            .skip(block_end)
            .take_while(|candidate| {
                candidate.trim().is_empty() || candidate.trim_start().starts_with('}')
            })
            .any(|candidate| candidate.contains("else"))
            || lines
                .get(block_end.saturating_sub(1))
                .is_some_and(|candidate| candidate.contains("else"));
        if has_else {
            continue;
        }
        let guarded_range = if_line + 1..block_end;
        let guard_inside_if = has_fact_in_range(facts, FactKind::AuthGuardCalled, guarded_range);
        let sink_after_if = protected_sinks(facts)
            .iter()
            .any(|fact| fact.start_line > block_end);
        if guard_inside_if && sink_after_if {
            return vec!["guard_only_in_one_branch".to_string()];
        }
    }
    Vec::new()
}

pub fn callback_boundary_reasons(source: &str, facts: &[Fact]) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let guard_in_callback = facts
        .iter()
        .filter(|fact| fact.kind == FactKind::AuthGuardCalled)
        .any(|fact| line_is_inside_callback(&lines, fact.start_line));

    if guard_in_callback {
        vec!["callback_boundary".to_string()]
    } else {
        Vec::new()
    }
}

pub fn unsupported_dynamic_control_flow(source: &str) -> bool {
    source.contains("guards[")
        || source.contains("await guard(")
        || source.contains("computed_handler")
}

pub fn protected_sinks(facts: &[Fact]) -> Vec<&Fact> {
    facts
        .iter()
        .filter(|fact| {
            matches!(
                fact.kind,
                FactKind::DataOperationDetected | FactKind::RouteReturnsResponse
            )
        })
        .collect()
}

pub fn static_middleware_coverage(
    middleware_facts: &[Fact],
    route_file_path: &str,
    route_method: &str,
) -> (Vec<MatchedMiddleware>, Vec<MiddlewareMismatch>) {
    let Some(route_path) = route_path_from_file(route_file_path) else {
        return (
            Vec::new(),
            vec![MiddlewareMismatch {
                middleware_id: None,
                reason: "unknown_framework".to_string(),
                parser_gap_id: None,
            }],
        );
    };
    let middleware_id = middleware_facts
        .iter()
        .find(|fact| fact.kind == FactKind::MiddlewareDeclared)
        .and_then(metadata_middleware_id);
    let protection_kind = middleware_facts
        .iter()
        .find(|fact| fact.kind == FactKind::MiddlewareDeclared)
        .and_then(metadata_protection_kind)
        .unwrap_or_else(|| "unknown".to_string());

    let mut matched = Vec::new();
    let mut mismatches = Vec::new();
    for matcher in middleware_facts
        .iter()
        .filter(|fact| fact.kind == FactKind::MiddlewareMatcherDeclared)
    {
        let metadata = matcher
            .value
            .as_deref()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
        let pattern = metadata
            .as_ref()
            .and_then(|value| {
                value
                    .get("path_pattern")
                    .and_then(|pattern| pattern.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| matcher.name.clone());
        let excluded = metadata
            .as_ref()
            .and_then(|value| value.get("matcher_kind"))
            .and_then(|kind| kind.as_str())
            == Some("excluded_path");
        if excluded && static_matcher_covers_path(&pattern, &route_path) {
            return (
                Vec::new(),
                vec![MiddlewareMismatch {
                    middleware_id: middleware_id.clone(),
                    reason: "path_not_matched".to_string(),
                    parser_gap_id: None,
                }],
            );
        }
        if static_matcher_covers_path(&pattern, &route_path)
            && static_matcher_covers_method(&pattern, route_method)
        {
            let middleware_id = middleware_id
                .clone()
                .unwrap_or_else(|| format!("middleware:{}", matcher.file_path));
            matched.push(MatchedMiddleware {
                matcher_fact_id: fact_id(matcher),
                protects_route_edge_id: format!(
                    "edge:middleware-protects:{}:{}",
                    middleware_id, route_file_path
                ),
                middleware_id,
                protection_kind: protection_kind.clone(),
            });
        } else if !static_matcher_covers_path(&pattern, &route_path) {
            mismatches.push(MiddlewareMismatch {
                middleware_id: middleware_id.clone(),
                reason: "path_not_matched".to_string(),
                parser_gap_id: None,
            });
        } else {
            mismatches.push(MiddlewareMismatch {
                middleware_id: middleware_id.clone(),
                reason: "method_not_matched".to_string(),
                parser_gap_id: None,
            });
        }
    }
    (matched, mismatches)
}

fn metadata_middleware_id(fact: &Fact) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(fact.value.as_deref()?).ok()?;
    value
        .get("middleware_id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn metadata_protection_kind(fact: &Fact) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(fact.value.as_deref()?).ok()?;
    value
        .get("protection_kind")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn route_path_from_file(file_path: &str) -> Option<String> {
    if let Some(rest) = file_path
        .strip_prefix("app/")
        .and_then(|path| path.strip_suffix("/route.ts"))
    {
        return Some(format!("/{}", rest.trim_end_matches('/')));
    }
    if let Some(rest) = file_path
        .strip_prefix("pages")
        .and_then(|path| path.strip_suffix(".ts"))
    {
        return Some(rest.to_string());
    }
    None
}

fn static_matcher_covers_path(pattern: &str, route_path: &str) -> bool {
    let pattern = pattern
        .trim()
        .rsplit_once('#')
        .map(|(path, _)| path)
        .unwrap_or_else(|| pattern.trim());
    if pattern == route_path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/:path*") {
        return route_path == prefix || route_path.starts_with(&format!("{prefix}/"));
    }
    if let Some(prefix) = pattern.strip_suffix("(.*)") {
        return route_path == prefix || route_path.starts_with(prefix);
    }
    false
}

fn static_matcher_covers_method(pattern: &str, route_method: &str) -> bool {
    if let Some((_, method)) = pattern.trim().rsplit_once('#') {
        method.eq_ignore_ascii_case(route_method)
    } else {
        true
    }
}

fn fact_id(fact: &Fact) -> String {
    format!(
        "fact:{}:{}:{}",
        fact.file_path, fact.kind as u8, fact.start_line
    )
}

fn sink_id(fact: &Fact) -> String {
    format!("sink:{}:{}:{}", fact.file_path, fact.start_line, fact.name)
}

fn sink_kind(fact: &Fact) -> &'static str {
    match fact.kind {
        FactKind::DataOperationDetected => "data_operation",
        FactKind::RouteReturnsResponse => "response",
        _ => "unknown",
    }
}

fn closing_block_line(lines: &[&str], start_line: usize) -> Option<usize> {
    let mut depth = 1_i32;
    for (index, line) in lines.iter().enumerate().skip(start_line) {
        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if depth == 0 {
            return Some(index + 1);
        }
    }
    None
}

fn has_fact_in_range(facts: &[Fact], kind: FactKind, range: std::ops::Range<usize>) -> bool {
    facts
        .iter()
        .any(|fact| fact.kind == kind && range.contains(&fact.start_line))
}

fn has_sink_in_range(facts: &[Fact], range: std::ops::Range<usize>) -> bool {
    protected_sinks(facts)
        .iter()
        .any(|fact| range.contains(&fact.start_line))
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
