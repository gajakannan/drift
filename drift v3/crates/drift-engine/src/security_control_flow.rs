use crate::{Fact, FactKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DominatedSink {
    pub sink_id: String,
    pub sink_kind: String,
    pub edge_id: String,
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
