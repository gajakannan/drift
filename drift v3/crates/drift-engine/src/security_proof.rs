use crate::{
    AcceptedAuthHelper, AcceptedPhase5Contract, AcceptedRequestValidator, Fact, FactExtractError,
    extract_security_facts, extract_security_facts_with_phase5,
    extract_security_facts_with_validation, extract_typescript_facts,
    security_control_flow::{
        DominatedSink, MatchedMiddleware, MiddlewareMismatch, branch_bypass_reasons,
        callback_boundary_reasons, conditional_guard_without_else_reasons,
        guard_dominates_straight_line_sinks, indirect_secret_flow_parser_gaps, protected_sinks,
        static_middleware_coverage, undominated_straight_line_reasons,
        unsupported_dynamic_control_flow,
    },
    security_patterns::dynamic_middleware_matcher_line,
};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityBoundaryProof {
    pub auth: AuthBoundaryProof,
    pub middleware: MiddlewareBoundaryProof,
    pub request_validation: RequestValidationProof,
    pub response_shape: ResponseShapeProof,
    pub secret_exposure: SecretExposureProof,
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
pub struct RequestValidationProof {
    pub required: bool,
    pub proven: bool,
    pub input_reads: Vec<RequestInputReadProof>,
    pub validations: Vec<RequestValidationCallProof>,
    pub validated_uses: Vec<RequestValidatedUseProof>,
    pub unvalidated_uses: Vec<RequestUnvalidatedUseProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestInputReadProof {
    pub fact_id: String,
    pub source: String,
    pub variable: String,
    pub key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestValidationCallProof {
    pub fact_id: String,
    pub validator_symbol: String,
    pub schema_symbol: Option<String>,
    pub input_var: Option<String>,
    pub result_var: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestValidatedUseProof {
    pub fact_id: String,
    pub source_input_var: String,
    pub validated_var: String,
    pub sink_fact_id: String,
    pub sink_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestUnvalidatedUseProof {
    pub input_fact_id: String,
    pub sink_fact_id: String,
    pub sink_kind: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseShapeProof {
    pub required: bool,
    pub proven: bool,
    pub sensitive_leaks: Vec<ResponseSensitiveLeakProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSensitiveLeakProof {
    pub field_fact_id: String,
    pub field_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretExposureProof {
    pub required: bool,
    pub proven: bool,
    pub exposed_secrets: Vec<ExposedSecretProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedSecretProof {
    pub secret_fact_id: String,
    pub secret_class: String,
    pub sink_kind: String,
    pub sink_line: usize,
    pub reason: String,
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
        request_validation: RequestValidationProof::not_required(),
        response_shape: ResponseShapeProof::not_required(),
        secret_exposure: SecretExposureProof::not_required(),
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
        request_validation: RequestValidationProof::not_required(),
        response_shape: ResponseShapeProof::not_required(),
        secret_exposure: SecretExposureProof::not_required(),
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

pub fn build_request_validation_proof(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_validators: &[AcceptedRequestValidator],
) -> Result<SecurityBoundaryProof, FactExtractError> {
    build_request_validation_proof_with_scope(
        file_path,
        source,
        accepted_validators,
        &RequestValidationProofScope::default(),
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestValidationProofScope {
    pub input_sources: Vec<String>,
    pub sink_kinds: Vec<String>,
}

pub fn build_request_validation_proof_with_scope(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_validators: &[AcceptedRequestValidator],
    scope: &RequestValidationProofScope,
) -> Result<SecurityBoundaryProof, FactExtractError> {
    let base_facts = extract_typescript_facts(&file_path, source)?;
    let security_facts =
        extract_security_facts_with_validation(file_path, source, &[], accepted_validators)?;
    let mut facts: Vec<Fact> = base_facts.into_iter().chain(security_facts).collect();
    facts.sort_by_key(|fact| fact.start_line);
    let lines = source.lines().collect::<Vec<_>>();

    let input_reads = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::RequestInputRead)
        .filter_map(request_input_read_proof)
        .filter(|input| {
            scope.input_sources.is_empty() || scope.input_sources.contains(&input.source)
        })
        .collect::<Vec<_>>();
    let input_variables = input_reads
        .iter()
        .map(|input| input.variable.clone())
        .collect::<Vec<_>>();
    let validations = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::RequestValidationCalled)
        .filter_map(request_validation_call_proof)
        .collect::<Vec<_>>();
    let validated_uses = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::ValidatedInputUsed)
        .filter_map(request_validated_use_proof)
        .filter(|validated| {
            (scope.sink_kinds.is_empty() || scope.sink_kinds.contains(&validated.sink_kind))
                && input_variables.contains(&validated.source_input_var)
        })
        .collect::<Vec<_>>();
    let parser_gaps = request_input_parser_gaps(&file_path_string(&facts), &lines, &input_reads);
    if input_reads.is_empty() {
        return Ok(SecurityBoundaryProof {
            auth: AuthBoundaryProof {
                required: false,
                proven: false,
                dominated_sinks: Vec::new(),
                undominated_sinks: Vec::new(),
            },
            middleware: MiddlewareBoundaryProof {
                required: false,
                proven: false,
                matched_middleware: Vec::new(),
                mismatches: Vec::new(),
            },
            request_validation: RequestValidationProof::not_required(),
            response_shape: ResponseShapeProof::not_required(),
            secret_exposure: SecretExposureProof::not_required(),
            parser_gaps,
            result: SecurityProofResult {
                proof_status: SecurityProofStatus::Proven,
            },
        });
    }
    let unvalidated_uses = request_unvalidated_uses(
        &facts,
        &lines,
        &input_reads,
        &validations,
        &validated_uses,
        &scope.sink_kinds,
    );
    let proven = parser_gaps.is_empty()
        && !input_reads.is_empty()
        && !validated_uses.is_empty()
        && unvalidated_uses.is_empty();
    let proof_status = if !parser_gaps.is_empty() {
        SecurityProofStatus::ParserGap
    } else if proven {
        SecurityProofStatus::Proven
    } else {
        SecurityProofStatus::MissingProof
    };

    Ok(SecurityBoundaryProof {
        auth: AuthBoundaryProof {
            required: false,
            proven: false,
            dominated_sinks: Vec::new(),
            undominated_sinks: Vec::new(),
        },
        middleware: MiddlewareBoundaryProof {
            required: false,
            proven: false,
            matched_middleware: Vec::new(),
            mismatches: Vec::new(),
        },
        request_validation: RequestValidationProof {
            required: true,
            proven,
            input_reads,
            validations,
            validated_uses,
            unvalidated_uses,
        },
        response_shape: ResponseShapeProof::not_required(),
        secret_exposure: SecretExposureProof::not_required(),
        parser_gaps,
        result: SecurityProofResult { proof_status },
    })
}

pub fn build_response_shape_proof(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_phase5: &AcceptedPhase5Contract,
) -> Result<SecurityBoundaryProof, FactExtractError> {
    let base_facts = extract_typescript_facts(&file_path, source)?;
    let security_facts =
        extract_security_facts_with_phase5(&file_path, source, &[], &[], Some(accepted_phase5))?;
    let mut facts: Vec<Fact> = base_facts.into_iter().chain(security_facts).collect();
    facts.sort_by_key(|fact| fact.start_line);

    let sensitive_fields = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::SensitiveFieldDeclared)
        .filter_map(sensitive_field_declared_value)
        .filter(|field| field.source != "candidate")
        .collect::<Vec<_>>();
    let serializers = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::SerializerCalled)
        .filter_map(serializer_called_value)
        .collect::<Vec<_>>();
    let file_path_string = file_path.as_ref().to_string_lossy().replace('\\', "/");
    let parser_gaps = response_shape_parser_gaps(&file_path_string, source);
    let mut leaks = Vec::new();
    for response_field in facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::ResponseEmitsField)
        .filter_map(response_emits_field_value)
    {
        if !sensitive_fields
            .iter()
            .any(|field| field.field_path == response_field.field_path)
        {
            continue;
        }
        if serializers
            .iter()
            .any(|serializer| serializer_proves_response_field(serializer, &response_field))
        {
            continue;
        }
        leaks.push(ResponseSensitiveLeakProof {
            field_fact_id: response_field.fact_id,
            field_path: response_field.field_path,
            reason: "sensitive_field_without_serializer".to_string(),
        });
    }
    let proven = leaks.is_empty() && parser_gaps.is_empty();
    let proof_status = if !parser_gaps.is_empty() {
        SecurityProofStatus::ParserGap
    } else if proven {
        SecurityProofStatus::Proven
    } else {
        SecurityProofStatus::MissingProof
    };

    Ok(SecurityBoundaryProof {
        auth: AuthBoundaryProof {
            required: false,
            proven: false,
            dominated_sinks: Vec::new(),
            undominated_sinks: Vec::new(),
        },
        middleware: MiddlewareBoundaryProof {
            required: false,
            proven: false,
            matched_middleware: Vec::new(),
            mismatches: Vec::new(),
        },
        request_validation: RequestValidationProof::not_required(),
        response_shape: ResponseShapeProof {
            required: true,
            proven,
            sensitive_leaks: leaks,
        },
        secret_exposure: SecretExposureProof::not_required(),
        parser_gaps,
        result: SecurityProofResult { proof_status },
    })
}

pub fn build_secret_exposure_proof(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    accepted_phase5: &AcceptedPhase5Contract,
) -> Result<SecurityBoundaryProof, FactExtractError> {
    let base_facts = extract_typescript_facts(&file_path, source)?;
    let security_facts =
        extract_security_facts_with_phase5(&file_path, source, &[], &[], Some(accepted_phase5))?;
    let mut facts: Vec<Fact> = base_facts.into_iter().chain(security_facts).collect();
    facts.sort_by_key(|fact| fact.start_line);

    let secret_reads = facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::SecretRead)
        .filter_map(|fact| secret_read_value(fact, source))
        .collect::<Vec<_>>();
    let secret_vars = secret_reads
        .iter()
        .filter_map(|secret| secret.variable.clone())
        .collect::<Vec<_>>();
    let direct_exposures = secret_sink_exposures(source, &secret_reads, &accepted_phase5.log_sinks);
    let exposed_secrets = direct_exposures
        .into_iter()
        .map(|exposure| ExposedSecretProof {
            secret_fact_id: exposure.secret_fact_id,
            secret_class: exposure.secret_class,
            sink_kind: exposure.sink_kind,
            sink_line: exposure.sink_line,
            reason: "secret_reaches_sink".to_string(),
        })
        .collect::<Vec<_>>();
    let file_path_string = file_path.as_ref().to_string_lossy().replace('\\', "/");
    let parser_gaps =
        indirect_secret_flow_parser_gaps(source, &secret_vars, &accepted_phase5.log_sinks)
            .into_iter()
            .map(|gap| SecurityParserGap {
                parser_gap_id: format!(
                    "parser_gap:{}:{}:{}",
                    file_path_string, gap.source_line, gap.code
                ),
                code: gap.code,
                file_path: file_path_string.clone(),
                reason: "Indirect helper secret flow prevents deterministic secret exposure proof"
                    .to_string(),
                blocks_enforcement: true,
            })
            .collect::<Vec<_>>();
    let proven = exposed_secrets.is_empty() && parser_gaps.is_empty();
    let proof_status = if !parser_gaps.is_empty() {
        SecurityProofStatus::ParserGap
    } else if proven {
        SecurityProofStatus::Proven
    } else {
        SecurityProofStatus::MissingProof
    };

    Ok(SecurityBoundaryProof {
        auth: AuthBoundaryProof {
            required: false,
            proven: false,
            dominated_sinks: Vec::new(),
            undominated_sinks: Vec::new(),
        },
        middleware: MiddlewareBoundaryProof {
            required: false,
            proven: false,
            matched_middleware: Vec::new(),
            mismatches: Vec::new(),
        },
        request_validation: RequestValidationProof::not_required(),
        response_shape: ResponseShapeProof::not_required(),
        secret_exposure: SecretExposureProof {
            required: true,
            proven,
            exposed_secrets,
        },
        parser_gaps,
        result: SecurityProofResult { proof_status },
    })
}

struct SensitiveFieldValue {
    field_path: String,
    source: String,
}

struct ResponseFieldValue {
    fact_id: String,
    route_id: String,
    field_path: String,
    source_var: Option<String>,
    source_expr: Option<String>,
}

struct SerializerValue {
    route_id: String,
    output_var: Option<String>,
    filtered_fields: Vec<String>,
}

struct SecretReadValue {
    fact_id: String,
    line: usize,
    variable: Option<String>,
    secret_class: String,
}

struct SecretExposureCandidate {
    secret_fact_id: String,
    secret_class: String,
    sink_kind: String,
    sink_line: usize,
}

fn sensitive_field_declared_value(fact: &Fact) -> Option<SensitiveFieldValue> {
    let value: Value = serde_json::from_str(fact.value.as_deref()?).ok()?;
    Some(SensitiveFieldValue {
        field_path: value.get("field_path")?.as_str()?.to_string(),
        source: value.get("source")?.as_str()?.to_string(),
    })
}

fn response_emits_field_value(fact: &Fact) -> Option<ResponseFieldValue> {
    let value: Value = serde_json::from_str(fact.value.as_deref()?).ok()?;
    Some(ResponseFieldValue {
        fact_id: format!("fact:{}:{}", fact.file_path, fact.start_line),
        route_id: value.get("route_id")?.as_str()?.to_string(),
        field_path: value.get("field_path")?.as_str()?.to_string(),
        source_var: value
            .get("source_var")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source_expr: value
            .get("source_expr")
            .and_then(Value::as_str)
            .map(ToString::to_string),
    })
}

fn serializer_called_value(fact: &Fact) -> Option<SerializerValue> {
    let value: Value = serde_json::from_str(fact.value.as_deref()?).ok()?;
    Some(SerializerValue {
        route_id: value.get("route_id")?.as_str()?.to_string(),
        output_var: value
            .get("output_var")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        filtered_fields: value
            .get("filtered_fields")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect(),
    })
}

fn serializer_proves_response_field(
    serializer: &SerializerValue,
    response_field: &ResponseFieldValue,
) -> bool {
    if serializer.route_id != response_field.route_id
        || !serializer
            .filtered_fields
            .contains(&response_field.field_path)
    {
        return false;
    }
    let Some(output_var) = serializer.output_var.as_deref() else {
        return false;
    };
    response_field.source_var.as_deref() == Some(output_var)
        || response_field
            .source_expr
            .as_deref()
            .is_some_and(|expr| expr == output_var || expr.starts_with(&format!("{output_var}.")))
}

fn secret_read_value(fact: &Fact, source: &str) -> Option<SecretReadValue> {
    let value: Value = serde_json::from_str(fact.value.as_deref()?).ok()?;
    let line = source.lines().nth(fact.start_line.saturating_sub(1));
    Some(SecretReadValue {
        fact_id: format!("fact:{}:{}", fact.file_path, fact.start_line),
        line: fact.start_line,
        variable: line.and_then(assigned_variable),
        secret_class: value.get("secret_class")?.as_str()?.to_string(),
    })
}

fn response_shape_parser_gaps(file_path: &str, source: &str) -> Vec<SecurityParserGap> {
    let lines = source.lines().collect::<Vec<_>>();
    let spread_variables = response_spread_variables(&lines);
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            (line.contains("Response.json(")
                || line.contains("NextResponse.json(")
                || line.contains(".json("))
                && (line.contains("...")
                    || spread_variables
                        .iter()
                        .any(|variable| line_uses_identifier(line, variable)))
        })
        .map(|(index, _)| SecurityParserGap {
            parser_gap_id: format!(
                "parser_gap:{}:{}:unsupported_destructuring_or_spread",
                file_path,
                index + 1
            ),
            code: "unsupported_destructuring_or_spread".to_string(),
            file_path: file_path.to_string(),
            reason: "Dynamic response spread prevents deterministic response-shape proof"
                .to_string(),
            blocks_enforcement: true,
        })
        .collect()
}

fn response_spread_variables(lines: &[&str]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| line.contains("..."))
        .filter_map(|line| assigned_variable(line))
        .collect()
}

fn secret_sink_exposures(
    source: &str,
    secret_reads: &[SecretReadValue],
    log_sinks: &[String],
) -> Vec<SecretExposureCandidate> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut tainted = secret_reads
        .iter()
        .filter_map(|secret| {
            secret.variable.as_ref().map(|variable| {
                (
                    variable.clone(),
                    secret.fact_id.clone(),
                    secret.secret_class.clone(),
                )
            })
        })
        .collect::<Vec<_>>();

    let mut changed = true;
    while changed {
        changed = false;
        for line in &lines {
            let Some(assigned) = assigned_variable(line) else {
                continue;
            };
            if tainted.iter().any(|(variable, _, _)| variable == &assigned) {
                continue;
            }
            if let Some((_, fact_id, secret_class)) = tainted
                .iter()
                .find(|(variable, _, _)| line_uses_identifier(line, variable))
            {
                tainted.push((assigned, fact_id.clone(), secret_class.clone()));
                changed = true;
            }
        }
    }

    let mut exposures = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let sink_kind = if is_response_sink_line(line) {
            Some("response")
        } else if log_sinks.iter().any(|sink| line.contains(sink)) {
            Some("log")
        } else {
            None
        };
        let Some(sink_kind) = sink_kind else {
            continue;
        };
        if let Some(secret) = secret_reads
            .iter()
            .find(|secret| secret.line == line_number)
        {
            exposures.push(SecretExposureCandidate {
                secret_fact_id: secret.fact_id.clone(),
                secret_class: secret.secret_class.clone(),
                sink_kind: sink_kind.to_string(),
                sink_line: line_number,
            });
        }
        for (variable, fact_id, secret_class) in &tainted {
            if line_uses_identifier(line, variable) {
                exposures.push(SecretExposureCandidate {
                    secret_fact_id: fact_id.clone(),
                    secret_class: secret_class.clone(),
                    sink_kind: sink_kind.to_string(),
                    sink_line: line_number,
                });
            }
        }
    }
    exposures.sort_by(|left, right| {
        (
            left.secret_fact_id.as_str(),
            left.sink_kind.as_str(),
            left.sink_line,
        )
            .cmp(&(
                right.secret_fact_id.as_str(),
                right.sink_kind.as_str(),
                right.sink_line,
            ))
    });
    exposures.dedup_by(|left, right| {
        left.secret_fact_id == right.secret_fact_id
            && left.sink_kind == right.sink_kind
            && left.sink_line == right.sink_line
    });
    exposures
}

fn is_response_sink_line(line: &str) -> bool {
    line.contains("Response.json(")
        || line.contains("NextResponse.json(")
        || line.contains(".json(")
}

fn file_path_string(facts: &[Fact]) -> String {
    facts
        .first()
        .map(|fact| fact.file_path.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

fn request_input_parser_gaps(
    file_path: &str,
    lines: &[&str],
    input_reads: &[RequestInputReadProof],
) -> Vec<SecurityParserGap> {
    let mut gaps = Vec::new();
    for input in input_reads {
        for (index, line) in lines.iter().enumerate() {
            let spread_marker = format!("...{}", input.variable);
            if line.contains(&spread_marker) {
                gaps.push(SecurityParserGap {
                    parser_gap_id: format!(
                        "parser_gap:{}:{}:unsupported_request_input_spread",
                        file_path,
                        index + 1
                    ),
                    code: "unsupported_request_input_spread".to_string(),
                    file_path: file_path.to_string(),
                    reason:
                        "Object spread from request input prevents deterministic validation proof"
                            .to_string(),
                    blocks_enforcement: true,
                });
            }
            let destructure_marker = format!("}} = {}", input.variable);
            if line.contains('{') && line.contains(&destructure_marker) {
                gaps.push(SecurityParserGap {
                    parser_gap_id: format!(
                        "parser_gap:{}:{}:unsupported_request_input_destructure",
                        file_path,
                        index + 1
                    ),
                    code: "unsupported_request_input_destructure".to_string(),
                    file_path: file_path.to_string(),
                    reason:
                        "Destructuring from request input prevents deterministic validation proof"
                            .to_string(),
                    blocks_enforcement: true,
                });
            }
        }
    }
    gaps
}

impl RequestValidationProof {
    fn not_required() -> Self {
        Self {
            required: false,
            proven: false,
            input_reads: Vec::new(),
            validations: Vec::new(),
            validated_uses: Vec::new(),
            unvalidated_uses: Vec::new(),
        }
    }
}

impl ResponseShapeProof {
    fn not_required() -> Self {
        Self {
            required: false,
            proven: false,
            sensitive_leaks: Vec::new(),
        }
    }
}

impl SecretExposureProof {
    fn not_required() -> Self {
        Self {
            required: false,
            proven: false,
            exposed_secrets: Vec::new(),
        }
    }
}

fn request_unvalidated_uses(
    facts: &[Fact],
    lines: &[&str],
    input_reads: &[RequestInputReadProof],
    validations: &[RequestValidationCallProof],
    validated_uses: &[RequestValidatedUseProof],
    allowed_sink_kinds: &[String],
) -> Vec<RequestUnvalidatedUseProof> {
    let mut uses = Vec::new();
    for input in input_reads {
        uses.extend(unknown_validator_uses(
            facts,
            lines,
            input,
            allowed_sink_kinds,
        ));
        for sink in protected_sinks(facts) {
            if !allowed_sink_kinds.is_empty()
                && !allowed_sink_kinds
                    .iter()
                    .any(|kind| kind == sink_kind(sink))
            {
                continue;
            }
            if sink.start_line <= input_line_from_fact_id(&input.fact_id) {
                continue;
            }
            let sink_text = source_text_for_sink(lines, sink);
            let sink_fact_id = sink_id(sink);
            let validated = validated_uses.iter().any(|validated| {
                validated.source_input_var == input.variable
                    && validated.sink_fact_id == sink_fact_id
            });
            let raw_input_validated = validated_uses.iter().any(|validated| {
                validated.source_input_var == input.variable
                    && validated.validated_var == input.variable
                    && validated.sink_fact_id == sink_fact_id
            });
            if validation_result_used_without_validated_use(
                validations,
                &input.variable,
                &sink_text,
                validated,
            ) {
                uses.push(RequestUnvalidatedUseProof {
                    input_fact_id: input.fact_id.clone(),
                    sink_fact_id,
                    sink_kind: sink_kind(sink).to_string(),
                    reason: "validation_result_not_used".to_string(),
                });
                continue;
            }
            if !line_uses_identifier(&sink_text, &input.variable) {
                continue;
            }
            if !raw_input_validated {
                uses.push(RequestUnvalidatedUseProof {
                    input_fact_id: input.fact_id.clone(),
                    sink_fact_id,
                    sink_kind: sink_kind(sink).to_string(),
                    reason: "request_input_not_validated".to_string(),
                });
            }
        }
    }
    uses
}

fn validation_result_used_without_validated_use(
    validations: &[RequestValidationCallProof],
    input_var: &str,
    sink_text: &str,
    validated: bool,
) -> bool {
    !validated
        && validations.iter().any(|validation| {
            validation.input_var.as_deref() == Some(input_var)
                && validation
                    .result_var
                    .as_deref()
                    .is_some_and(|result_var| line_uses_identifier(sink_text, result_var))
        })
}

fn unknown_validator_uses(
    facts: &[Fact],
    lines: &[&str],
    input: &RequestInputReadProof,
    allowed_sink_kinds: &[String],
) -> Vec<RequestUnvalidatedUseProof> {
    let input_line = input_line_from_fact_id(&input.fact_id);
    let mut uses = Vec::new();
    for call in facts
        .iter()
        .filter(|fact| fact.kind == crate::FactKind::SymbolCalled)
        .filter(|fact| fact.start_line > input_line)
        .filter(|fact| {
            fact.name.starts_with("validate")
                || fact
                    .value
                    .as_deref()
                    .is_some_and(|receiver| receiver.ends_with("Schema"))
        })
    {
        if facts.iter().any(|fact| {
            fact.kind == crate::FactKind::RequestValidationCalled
                && fact.start_line == call.start_line
                && fact.name == call.name
        }) {
            continue;
        }
        let Some(call_line) = lines.get(call.start_line.saturating_sub(1)) else {
            continue;
        };
        if !line_uses_identifier(call_line, &input.variable) {
            continue;
        }
        let Some(result_var) = assigned_variable(call_line) else {
            continue;
        };
        for sink in protected_sinks(facts)
            .into_iter()
            .filter(|sink| sink.start_line > call.start_line)
            .filter(|sink| {
                allowed_sink_kinds.is_empty()
                    || allowed_sink_kinds
                        .iter()
                        .any(|kind| kind == sink_kind(sink))
            })
        {
            let sink_text = source_text_for_sink(lines, sink);
            if line_uses_identifier(&sink_text, &result_var) {
                uses.push(RequestUnvalidatedUseProof {
                    input_fact_id: input.fact_id.clone(),
                    sink_fact_id: sink_id(sink),
                    sink_kind: sink_kind(sink).to_string(),
                    reason: "unknown_validator".to_string(),
                });
            }
        }
    }
    uses
}

fn source_text_for_sink(lines: &[&str], sink: &Fact) -> String {
    let start_line = sink.start_line;
    let end_line = if sink.kind == crate::FactKind::RouteReturnsResponse {
        sink.start_line
    } else {
        sink.end_line
    };
    if start_line == 0 {
        return String::new();
    }
    lines
        .iter()
        .skip(start_line.saturating_sub(1))
        .take(end_line.saturating_sub(start_line).saturating_add(1))
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
}

fn assigned_variable(line: &str) -> Option<String> {
    let before_equals = line.split_once('=')?.0.trim();
    let variable = before_equals
        .strip_prefix("const ")
        .or_else(|| before_equals.strip_prefix("let "))
        .or_else(|| before_equals.strip_prefix("var "))
        .unwrap_or(before_equals)
        .trim();
    (!variable.is_empty()
        && variable.chars().all(|character| {
            character == '_' || character == '$' || character.is_ascii_alphanumeric()
        }))
    .then(|| variable.to_string())
}

fn request_input_read_proof(fact: &Fact) -> Option<RequestInputReadProof> {
    let value = serde_json::from_str::<serde_json::Value>(fact.value.as_deref()?).ok()?;
    Some(RequestInputReadProof {
        fact_id: fact_id(fact),
        source: value.get("source")?.as_str()?.to_string(),
        variable: value.get("variable")?.as_str()?.to_string(),
        key: value
            .get("key")
            .and_then(|key| key.as_str())
            .map(str::to_string),
    })
}

fn request_validation_call_proof(fact: &Fact) -> Option<RequestValidationCallProof> {
    let value = serde_json::from_str::<serde_json::Value>(fact.value.as_deref()?).ok()?;
    Some(RequestValidationCallProof {
        fact_id: fact_id(fact),
        validator_symbol: value.get("validator_symbol")?.as_str()?.to_string(),
        schema_symbol: value
            .get("schema_symbol")
            .and_then(|symbol| symbol.as_str())
            .map(str::to_string),
        input_var: value
            .get("input_var")
            .and_then(|symbol| symbol.as_str())
            .map(str::to_string),
        result_var: value
            .get("result_var")
            .and_then(|symbol| symbol.as_str())
            .map(str::to_string),
    })
}

fn request_validated_use_proof(fact: &Fact) -> Option<RequestValidatedUseProof> {
    let value = serde_json::from_str::<serde_json::Value>(fact.value.as_deref()?).ok()?;
    Some(RequestValidatedUseProof {
        fact_id: fact_id(fact),
        source_input_var: value.get("source_input_var")?.as_str()?.to_string(),
        validated_var: value.get("validated_var")?.as_str()?.to_string(),
        sink_fact_id: value.get("sink_fact_id")?.as_str()?.to_string(),
        sink_kind: value.get("sink_kind")?.as_str()?.to_string(),
    })
}

fn input_line_from_fact_id(fact_id: &str) -> usize {
    fact_id
        .rsplit(':')
        .next()
        .and_then(|line| line.parse::<usize>().ok())
        .unwrap_or(0)
}

fn line_uses_identifier(line: &str, identifier: &str) -> bool {
    line.split(|character: char| {
        character != '_' && character != '$' && !character.is_ascii_alphanumeric()
    })
    .any(|token| token == identifier)
}
