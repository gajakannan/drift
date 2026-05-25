use crate::{
    AcceptedAuthHelper, Fact, FactExtractError, extract_security_facts, extract_typescript_facts,
    security_control_flow::{
        DominatedSink, branch_bypass_reasons, callback_boundary_reasons,
        guard_dominates_straight_line_sinks, protected_sinks, undominated_straight_line_reasons,
        unsupported_dynamic_control_flow,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityBoundaryProof {
    pub auth: AuthBoundaryProof,
    pub parser_gaps: Vec<SecurityParserGap>,
    pub result: SecurityProofResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBoundaryProof {
    pub required: bool,
    pub proven: bool,
    pub dominated_sinks: Vec<DominatedSink>,
    pub undominated_sinks: Vec<String>,
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
