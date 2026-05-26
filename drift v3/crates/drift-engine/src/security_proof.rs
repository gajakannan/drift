use crate::{
    AcceptedAuthHelper, Fact, FactExtractError, extract_security_facts, extract_typescript_facts,
    security_control_flow::{
        DominatedSink, MatchedMiddleware, MiddlewareMismatch, branch_bypass_reasons,
        callback_boundary_reasons, conditional_guard_without_else_reasons,
        guard_dominates_straight_line_sinks, protected_sinks, static_middleware_coverage,
        undominated_straight_line_reasons, unsupported_dynamic_control_flow,
    },
    security_patterns::dynamic_middleware_matcher_line,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityBoundaryProof {
    pub auth: AuthBoundaryProof,
    pub middleware: MiddlewareBoundaryProof,
    pub parser_gaps: Vec<SecurityParserGap>,
    pub result: SecurityProofResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSecurityBoundaryProof {
    pub route_id: String,
    pub file_path: String,
    pub handler_symbol: String,
    pub auth: AuthBoundaryProof,
    pub trusted_guard_calls: Vec<TrustedGuardCallProof>,
    pub undominated_sinks: Vec<UndominatedSinkProof>,
    pub parser_gaps: Vec<SecurityParserGap>,
    pub missing_proof_codes: Vec<String>,
    pub result: SecurityProofResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedGuardCallProof {
    pub fact_id: String,
    pub guard_id: String,
    pub symbol: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndominatedSinkProof {
    pub sink_id: String,
    pub sink_kind: String,
    pub reason: String,
    pub fact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBoundaryProof {
    pub required: bool,
    pub proven: bool,
    pub dominated_sinks: Vec<DominatedSink>,
    pub undominated_sinks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareBoundaryProof {
    pub required: bool,
    pub proven: bool,
    pub matched_middleware: Vec<MatchedMiddleware>,
    pub mismatches: Vec<MiddlewareMismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityProofResult {
    pub proof_status: SecurityProofStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityParserGap {
    pub parser_gap_id: String,
    pub code: String,
    pub file_path: String,
    pub reason: String,
    pub blocks_enforcement: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProofStatus {
    Proven,
    MissingProof,
    ParserGap,
}

pub fn build_auth_boundary_proof(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_auth_helpers: &[AcceptedAuthHelper],
) -> Result<SecurityBoundaryProof, FactExtractError> {
    let base_facts = extract_typescript_facts(&file_path, source)?;
    let security_facts = extract_security_facts(file_path, source, accepted_auth_helpers)?;
    let mut facts: Vec<Fact> = base_facts.into_iter().chain(security_facts).collect();
    facts.sort_by_key(|fact| fact.start_line);

    let dominated_sinks = guard_dominates_straight_line_sinks(&facts);
    let mut undominated_sinks = undominated_straight_line_reasons(&facts);
    undominated_sinks.extend(branch_bypass_reasons(source, &facts));
    undominated_sinks.extend(callback_boundary_reasons(source, &facts));
    let dynamic_control_flow = unsupported_dynamic_control_flow(source);
    if dynamic_control_flow {
        undominated_sinks.push("unsupported_dynamic_control_flow".to_string());
    }
    let parser_gaps = if dynamic_control_flow {
        vec![SecurityParserGap {
            parser_gap_id: format!(
                "parser_gap:{}:unsupported_dynamic_control_flow",
                facts
                    .first()
                    .map(|fact| fact.file_path.as_str())
                    .unwrap_or("unknown")
            ),
            code: "unsupported_dynamic_control_flow".to_string(),
            file_path: facts
                .first()
                .map(|fact| fact.file_path.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            reason: "Unsupported dynamic control flow prevents auth dominance proof".to_string(),
            blocks_enforcement: true,
        }]
    } else {
        Vec::new()
    };
    let sink_count = protected_sinks(&facts).len();
    let proven =
        sink_count > 0 && dominated_sinks.len() == sink_count && undominated_sinks.is_empty();

    Ok(SecurityBoundaryProof {
        auth: AuthBoundaryProof {
            required: true,
            proven,
            dominated_sinks,
            undominated_sinks,
        },
        middleware: MiddlewareBoundaryProof {
            required: false,
            proven: false,
            matched_middleware: Vec::new(),
            mismatches: Vec::new(),
        },
        parser_gaps,
        result: SecurityProofResult {
            proof_status: if dynamic_control_flow {
                SecurityProofStatus::ParserGap
            } else if proven {
                SecurityProofStatus::Proven
            } else {
                SecurityProofStatus::MissingProof
            },
        },
    })
}

pub fn build_auth_boundary_proofs_for_file(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_auth_helpers: &[AcceptedAuthHelper],
) -> Result<Vec<RouteSecurityBoundaryProof>, FactExtractError> {
    let file_path_string = file_path.as_ref().to_string_lossy().replace('\\', "/");
    let base_facts = extract_typescript_facts(&file_path, source)?;
    let security_facts = extract_security_facts(file_path, source, accepted_auth_helpers)?;
    let mut facts: Vec<Fact> = base_facts.into_iter().chain(security_facts).collect();
    facts.sort_by_key(|fact| fact.start_line);

    let routes = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::RouteDeclared)
        .cloned()
        .collect::<Vec<_>>();
    let mut proofs = Vec::new();
    for route in routes {
        let route_facts = facts
            .iter()
            .filter(|fact| route.start_line <= fact.start_line && fact.end_line <= route.end_line)
            .cloned()
            .collect::<Vec<_>>();
        let route_id = format!("route:{}:{}", file_path_string, route.name);
        proofs.push(build_route_auth_boundary_proof(
            route_id,
            file_path_string.clone(),
            route.name,
            source,
            &route_facts,
        ));
    }
    Ok(proofs)
}

fn build_route_auth_boundary_proof(
    route_id: String,
    file_path: String,
    handler_symbol: String,
    route_source: &str,
    facts: &[Fact],
) -> RouteSecurityBoundaryProof {
    let sinks = protected_sinks(facts);
    let first_guard_line = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::AuthGuardCalled)
        .map(|fact| fact.start_line)
        .min();
    let trusted_guard_calls = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::AuthGuardCalled)
        .map(|fact| TrustedGuardCallProof {
            fact_id: fact_id(fact),
            guard_id: guard_id(fact),
            symbol: fact
                .imported_name
                .clone()
                .unwrap_or_else(|| fact.name.clone()),
            start_line: fact.start_line,
            end_line: fact.end_line,
        })
        .collect::<Vec<_>>();
    let callback_reasons = callback_boundary_reasons(route_source, facts);
    let branch_reasons = branch_bypass_reasons(route_source, facts);
    let conditional_reasons = conditional_guard_without_else_reasons(route_source, facts);
    let dynamic_control_flow = unsupported_dynamic_control_flow(route_source);
    let path_sensitive_reasons = callback_reasons
        .iter()
        .chain(branch_reasons.iter())
        .chain(conditional_reasons.iter())
        .cloned()
        .collect::<Vec<_>>();

    let mut dominated_sinks = Vec::new();
    let mut undominated_sinks = Vec::new();
    let mut undominated_sink_proofs = Vec::new();
    for sink in sinks {
        let sink_id = sink_id(sink);
        let sink_kind = sink_kind(sink).to_string();
        let fact_ids = vec![fact_id(sink)];
        if dynamic_control_flow {
            undominated_sinks.push("unsupported_dynamic_control_flow".to_string());
            undominated_sink_proofs.push(UndominatedSinkProof {
                sink_id,
                sink_kind,
                reason: "unsupported_dynamic_control_flow".to_string(),
                fact_ids,
            });
        } else if let Some(reason) = path_sensitive_reasons.first() {
            undominated_sinks.push(reason.clone());
            undominated_sink_proofs.push(UndominatedSinkProof {
                sink_id,
                sink_kind,
                reason: reason.clone(),
                fact_ids,
            });
        } else if first_guard_line.is_some_and(|line| line < sink.start_line) {
            dominated_sinks.push(DominatedSink {
                sink_id,
                sink_kind,
                edge_id: format!("edge:auth-dominates:{}:{}", sink.file_path, sink.start_line),
            });
        } else if first_guard_line.is_some_and(|line| line > sink.start_line) {
            undominated_sinks.push("guard_after_sink".to_string());
            undominated_sink_proofs.push(UndominatedSinkProof {
                sink_id,
                sink_kind,
                reason: "guard_after_sink".to_string(),
                fact_ids,
            });
        } else {
            undominated_sinks.push("no_guard_call".to_string());
            undominated_sink_proofs.push(UndominatedSinkProof {
                sink_id,
                sink_kind,
                reason: "no_guard_call".to_string(),
                fact_ids,
            });
        }
    }
    undominated_sinks.sort();
    undominated_sinks.dedup();
    undominated_sink_proofs
        .sort_by(|left, right| (&left.reason, &left.sink_id).cmp(&(&right.reason, &right.sink_id)));
    undominated_sink_proofs
        .dedup_by(|left, right| left.reason == right.reason && left.sink_id == right.sink_id);

    let parser_gaps = if dynamic_control_flow {
        vec![SecurityParserGap {
            parser_gap_id: format!("{route_id}:parser_gap:unsupported_dynamic_control_flow"),
            code: "unsupported_dynamic_control_flow".to_string(),
            file_path: file_path.clone(),
            reason: "Unsupported dynamic control flow prevents auth dominance proof".to_string(),
            blocks_enforcement: true,
        }]
    } else {
        Vec::new()
    };
    let sink_count = protected_sinks(facts).len();
    let proven =
        sink_count > 0 && dominated_sinks.len() == sink_count && undominated_sinks.is_empty();
    let missing_proof_codes = if proven {
        Vec::new()
    } else if dynamic_control_flow {
        vec!["unsupported_dynamic_control_flow".to_string()]
    } else {
        undominated_sinks
            .iter()
            .map(|reason| missing_proof_code(reason).to_string())
            .collect()
    };

    RouteSecurityBoundaryProof {
        route_id,
        file_path,
        handler_symbol,
        auth: AuthBoundaryProof {
            required: true,
            proven,
            dominated_sinks,
            undominated_sinks,
        },
        trusted_guard_calls,
        undominated_sinks: undominated_sink_proofs,
        parser_gaps,
        missing_proof_codes,
        result: SecurityProofResult {
            proof_status: if dynamic_control_flow {
                SecurityProofStatus::ParserGap
            } else if proven {
                SecurityProofStatus::Proven
            } else {
                SecurityProofStatus::MissingProof
            },
        },
    }
}

fn missing_proof_code(reason: &str) -> &'static str {
    match reason {
        "no_guard_call" => "missing_auth_guard",
        "unsupported_dynamic_control_flow" => "unsupported_dynamic_control_flow",
        _ => "auth_guard_not_dominating_sink",
    }
}

fn fact_id(fact: &Fact) -> String {
    format!(
        "fact:{}:{}:{}",
        fact.file_path, fact.kind as u8, fact.start_line
    )
}

fn guard_id(fact: &Fact) -> String {
    fact.value
        .as_ref()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .and_then(|value| {
            value
                .get("guard_id")
                .and_then(|guard| guard.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            format!(
                "auth:{}",
                fact.imported_name.as_deref().unwrap_or(&fact.name)
            )
        })
}

fn sink_id(fact: &Fact) -> String {
    format!("sink:{}:{}:{}", fact.file_path, fact.start_line, fact.name)
}

fn sink_kind(fact: &Fact) -> &'static str {
    match fact.kind {
        crate::FactKind::DataOperationDetected => "data_operation",
        crate::FactKind::RouteReturnsResponse => "response",
        _ => "unknown",
    }
}

pub fn build_middleware_coverage_proof(
    middleware_file_path: impl AsRef<std::path::Path>,
    middleware_source: &str,
    route_file_path: impl AsRef<std::path::Path>,
    route_source: &str,
    accepted_auth_helpers: &[AcceptedAuthHelper],
) -> Result<SecurityBoundaryProof, FactExtractError> {
    let middleware_file_path_string = middleware_file_path
        .as_ref()
        .to_string_lossy()
        .replace('\\', "/");
    let middleware_facts = extract_security_facts(
        &middleware_file_path,
        middleware_source,
        accepted_auth_helpers,
    )?;
    let route_facts = extract_typescript_facts(&route_file_path, route_source)?;
    let route_file_path = route_file_path
        .as_ref()
        .to_string_lossy()
        .replace('\\', "/");
    let route_method = route_facts
        .iter()
        .find(|fact| fact.kind == crate::FactKind::RouteDeclared)
        .map(|fact| fact.name.as_str())
        .unwrap_or("GET");
    let (matched_middleware, mismatches) =
        static_middleware_coverage(&middleware_facts, &route_file_path, route_method);
    let dynamic_matcher_line = dynamic_middleware_matcher_line(middleware_source);
    let parser_gaps = dynamic_matcher_line
        .map(|line| {
            vec![SecurityParserGap {
                parser_gap_id: format!(
                    "parser_gap:{}:{}:unsupported_dynamic_middleware_matcher",
                    middleware_file_path_string, line
                ),
                code: "unsupported_dynamic_middleware_matcher".to_string(),
                file_path: middleware_file_path_string.clone(),
                reason: "Dynamic middleware matcher prevents deterministic route coverage proof"
                    .to_string(),
                blocks_enforcement: true,
            }]
        })
        .unwrap_or_default();
    let proven = parser_gaps.is_empty()
        && !matched_middleware.is_empty()
        && matched_middleware
            .iter()
            .any(|middleware| middleware.protection_kind == "auth");

    Ok(SecurityBoundaryProof {
        auth: AuthBoundaryProof {
            required: false,
            proven: false,
            dominated_sinks: Vec::new(),
            undominated_sinks: Vec::new(),
        },
        middleware: MiddlewareBoundaryProof {
            required: true,
            proven,
            matched_middleware,
            mismatches,
        },
        parser_gaps,
        result: SecurityProofResult {
            proof_status: if dynamic_matcher_line.is_some() {
                SecurityProofStatus::ParserGap
            } else if proven {
                SecurityProofStatus::Proven
            } else {
                SecurityProofStatus::MissingProof
            },
        },
    })
}
