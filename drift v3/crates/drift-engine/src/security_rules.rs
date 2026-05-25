use crate::{AcceptedAuthHelper, FactExtractError, SecurityProofStatus, build_auth_boundary_proof};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuthContract {
    pub contract_id: String,
    pub enforcement_mode: SecurityEnforcementMode,
    pub accepted_auth_helpers: Vec<AcceptedAuthHelper>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEnforcementMode {
    Off,
    Brief,
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFindingResult {
    Brief,
    Warn,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    pub contract_id: String,
    pub title: String,
    pub expected_layer: String,
    pub actual_layer: String,
    pub enforcement_result: SecurityFindingResult,
    pub drift_category: String,
    pub confidence_label: String,
}

pub fn evaluate_api_route_requires_auth_helper(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    contract: &SecurityAuthContract,
) -> Result<Vec<SecurityFinding>, FactExtractError> {
    if contract.enforcement_mode == SecurityEnforcementMode::Off
        || contract.accepted_auth_helpers.is_empty()
    {
        return Ok(Vec::new());
    }

    let proof = build_auth_boundary_proof(file_path, source, &contract.accepted_auth_helpers)?;
    if proof.result.proof_status == SecurityProofStatus::Proven {
        return Ok(Vec::new());
    }

    Ok(vec![SecurityFinding {
        contract_id: contract.contract_id.clone(),
        title: "API route missing required auth proof".to_string(),
        expected_layer: "auth_guard".to_string(),
        actual_layer: proof
            .auth
            .undominated_sinks
            .first()
            .cloned()
            .unwrap_or_else(|| "missing_auth_guard".to_string()),
        enforcement_result: match contract.enforcement_mode {
            SecurityEnforcementMode::Brief => SecurityFindingResult::Brief,
            SecurityEnforcementMode::Warn => SecurityFindingResult::Warn,
            SecurityEnforcementMode::Block => SecurityFindingResult::Block,
            SecurityEnforcementMode::Off => return Ok(Vec::new()),
        },
        drift_category: "missing_proof".to_string(),
        confidence_label: "certain".to_string(),
    }])
}
