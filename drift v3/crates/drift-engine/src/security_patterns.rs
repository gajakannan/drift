use crate::{Fact, FactKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAuthHelper {
    pub guard_id: String,
    pub symbol: String,
    pub behavior: AuthGuardBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthGuardBehavior {
    Throws,
    ReturnsUser,
    ReturnsSession,
    Boolean,
    Unknown,
}

impl AuthGuardBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthGuardBehavior::Throws => "throws",
            AuthGuardBehavior::ReturnsUser => "returns_user",
            AuthGuardBehavior::ReturnsSession => "returns_session",
            AuthGuardBehavior::Boolean => "boolean",
            AuthGuardBehavior::Unknown => "unknown",
        }
    }
}

pub fn accepted_auth_helper_for_call<'a>(
    call: &Fact,
    facts: &[Fact],
    accepted_auth_helpers: &'a [AcceptedAuthHelper],
) -> Option<&'a AcceptedAuthHelper> {
    accepted_auth_helpers.iter().find(|helper| {
        facts.iter().any(|fact| {
            fact.kind == FactKind::ImportUsed
                && fact.name == call.name
                && fact.imported_name.as_deref() == Some(helper.symbol.as_str())
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticMiddlewareMatcher {
    pub path_pattern: String,
    pub excluded: bool,
    pub start_line: usize,
    pub end_line: usize,
}

pub fn static_middleware_matchers(source: &str) -> Vec<StaticMiddlewareMatcher> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut matchers = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("matcher") {
            continue;
        }
        let start_line = index + 1;
        let mut matcher_text = line.to_string();
        if line.contains('[') && !line.contains(']') {
            for next in lines.iter().skip(index + 1) {
                matcher_text.push('\n');
                matcher_text.push_str(next);
                if next.contains(']') {
                    break;
                }
            }
        }
        for value in quoted_values(&matcher_text) {
            if value.starts_with('/') || value.starts_with("!/") {
                matchers.push(StaticMiddlewareMatcher {
                    excluded: value.starts_with("!/"),
                    path_pattern: value.trim_start_matches('!').to_string(),
                    start_line,
                    end_line: start_line,
                });
            }
        }
    }
    matchers
}

pub fn dynamic_middleware_matcher_line(source: &str) -> Option<usize> {
    source.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim();
        if trimmed.starts_with("matcher:")
            && !trimmed.contains('"')
            && !trimmed.contains('\'')
            && !trimmed.contains('[')
        {
            Some(index + 1)
        } else {
            None
        }
    })
}

fn quoted_values(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = value.char_indices().peekable();
    while let Some((_, current)) = chars.next() {
        if current != '"' && current != '\'' {
            continue;
        }
        let quote = current;
        let mut quoted = String::new();
        for (_, next) in chars.by_ref() {
            if next == quote {
                break;
            }
            quoted.push(next);
        }
        if !quoted.is_empty() {
            values.push(quoted);
        }
    }
    values
}
