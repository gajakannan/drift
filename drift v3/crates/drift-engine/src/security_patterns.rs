use crate::{Fact, FactKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAuthHelper {
    pub guard_id: String,
    pub symbol: String,
    pub behavior: AuthGuardBehavior,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Phase4SecurityPolicy {
    pub accepted_auth_helpers: Vec<AcceptedAuthHelper>,
    pub auth_helper_imports: Vec<AcceptedHelperImport>,
    pub authorization_helpers: Vec<AcceptedAuthorizationHelper>,
    pub tenant_helpers: Vec<AcceptedTenantHelper>,
    pub tenant_keys: Vec<String>,
    pub tenant_sources: Vec<String>,
    pub data_operations: Vec<String>,
}

impl Phase4SecurityPolicy {
    pub fn from_auth_helpers(accepted_auth_helpers: &[AcceptedAuthHelper]) -> Self {
        Self {
            accepted_auth_helpers: accepted_auth_helpers.to_vec(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedHelperImport {
    pub symbol: String,
    pub import_source: Option<String>,
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

pub fn accepted_phase4_auth_helper_for_call<'a>(
    call: &Fact,
    facts: &[Fact],
    policy: &'a Phase4SecurityPolicy,
) -> Option<&'a AcceptedAuthHelper> {
    policy.accepted_auth_helpers.iter().find(|helper| {
        facts.iter().any(|fact| {
            fact.kind == FactKind::ImportUsed
                && fact.name == call.name
                && fact.imported_name.as_deref() == Some(helper.symbol.as_str())
                && helper_import_matches(
                    fact,
                    policy
                        .auth_helper_imports
                        .iter()
                        .find(|contract| contract.symbol == helper.symbol)
                        .and_then(|contract| contract.import_source.as_deref()),
                )
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRequestValidator {
    pub validator_id: String,
    pub symbol: String,
    pub kind: RequestValidatorKind,
    pub behavior: RequestValidatorBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestValidatorKind {
    Schema,
    Helper,
}

impl RequestValidatorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestValidatorKind::Schema => "schema",
            RequestValidatorKind::Helper => "helper",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestValidatorBehavior {
    Throws,
    ReturnsParsed,
    Boolean,
    Unknown,
}

impl RequestValidatorBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            RequestValidatorBehavior::Throws => "throws",
            RequestValidatorBehavior::ReturnsParsed => "returns_parsed",
            RequestValidatorBehavior::Boolean => "boolean",
            RequestValidatorBehavior::Unknown => "unknown",
        }
    }
}

pub fn accepted_request_validator_for_call<'a>(
    call: &Fact,
    facts: &[Fact],
    accepted_validators: &'a [AcceptedRequestValidator],
) -> Option<&'a AcceptedRequestValidator> {
    accepted_validators
        .iter()
        .find(|validator| match validator.kind {
            RequestValidatorKind::Helper => {
                call.value.is_none()
                    && (call.name == validator.symbol
                        || imported_symbol_matches(facts, &call.name, &validator.symbol))
            }
            RequestValidatorKind::Schema => {
                matches!(call.name.as_str(), "parse" | "safeParse")
                    && call.value.as_deref().is_some_and(|receiver| {
                        schema_receiver_matches(facts, receiver, &validator.symbol)
                    })
            }
        })
}

fn imported_symbol_matches(facts: &[Fact], local_name: &str, accepted_symbol: &str) -> bool {
    facts.iter().any(|fact| {
        fact.kind == FactKind::ImportUsed
            && fact.name == local_name
            && fact.imported_name.as_deref() == Some(accepted_symbol)
    })
}

fn imported_symbol_matches_with_source(
    facts: &[Fact],
    local_name: &str,
    accepted_symbol: &str,
    import_source: Option<&str>,
) -> bool {
    facts.iter().any(|fact| {
        fact.kind == FactKind::ImportUsed
            && fact.name == local_name
            && fact.imported_name.as_deref() == Some(accepted_symbol)
            && helper_import_matches(fact, import_source)
    })
}

fn helper_import_matches(fact: &Fact, import_source: Option<&str>) -> bool {
    import_source.is_none_or(|expected| fact.value.as_deref() == Some(expected))
}

fn receiver_root(receiver: &str) -> &str {
    receiver.split('.').next().unwrap_or(receiver)
}

fn schema_receiver_matches(facts: &[Fact], receiver: &str, accepted_symbol: &str) -> bool {
    if receiver_root(receiver) == accepted_symbol
        || imported_symbol_matches(facts, receiver_root(receiver), accepted_symbol)
    {
        return true;
    }
    let mut parts = receiver.split('.');
    let Some(namespace) = parts.next() else {
        return false;
    };
    let Some(symbol) = parts.next() else {
        return false;
    };
    symbol == accepted_symbol
        && parts.next().is_none()
        && facts.iter().any(|fact| {
            fact.kind == FactKind::ImportUsed
                && fact.name == namespace
                && fact.imported_name.as_deref() == Some("*")
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedTenantHelper {
    pub helper_id: String,
    pub symbol: String,
    pub import_source: Option<String>,
    pub tenant_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAuthorizationHelper {
    pub guard_id: String,
    pub symbol: String,
    pub import_source: Option<String>,
    pub kind: AuthorizationHelperKind,
    pub behavior: AuthorizationHelperBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationHelperKind {
    Role,
    Policy,
}

impl AuthorizationHelperKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthorizationHelperKind::Role => "role",
            AuthorizationHelperKind::Policy => "policy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationHelperBehavior {
    Throws,
    Boolean,
}

impl AuthorizationHelperBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthorizationHelperBehavior::Throws => "throws",
            AuthorizationHelperBehavior::Boolean => "boolean",
        }
    }
}

pub fn accepted_authorization_helper_for_call<'a>(
    call: &Fact,
    facts: &[Fact],
    accepted_helpers: &'a [AcceptedAuthorizationHelper],
) -> Option<&'a AcceptedAuthorizationHelper> {
    accepted_helpers.iter().find(|helper| {
        if helper.import_source.is_some() {
            return imported_symbol_matches_with_source(
                facts,
                &call.name,
                &helper.symbol,
                helper.import_source.as_deref(),
            );
        }
        call.name == helper.symbol || imported_symbol_matches(facts, &call.name, &helper.symbol)
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
