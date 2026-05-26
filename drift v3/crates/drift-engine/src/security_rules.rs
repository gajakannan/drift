use crate::{
    AcceptedAuthHelper, FactExtractError, SecurityProofStatus, build_auth_boundary_proof,
    build_middleware_coverage_proof,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuthContract {
    pub contract_id: String,
    pub enforcement_mode: SecurityEnforcementMode,
    pub accepted_auth_helpers: Vec<AcceptedAuthHelper>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityMiddlewareContract {
    pub contract_id: String,
    pub capability: SecurityContractCapability,
    pub enforcement_mode: SecurityEnforcementMode,
    pub route_paths: Vec<String>,
    pub methods: Vec<String>,
    pub accepted_auth_helpers: Vec<AcceptedAuthHelper>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityContractCapability {
    BriefingOnly,
    HeuristicCheck,
    DeterministicCheck,
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
        actual_layer: normalize_auth_actual_layer(
            &proof
                .auth
                .undominated_sinks
                .first()
                .cloned()
                .unwrap_or_else(|| "missing_auth_guard".to_string()),
        ),
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

pub fn evaluate_api_route_requires_auth_helper_with_middleware(
    route_file_path: impl AsRef<std::path::Path>,
    route_source: &str,
    middleware_file_path: impl AsRef<std::path::Path>,
    middleware_source: &str,
    contract: &SecurityAuthContract,
) -> Result<Vec<SecurityFinding>, FactExtractError> {
    if contract.enforcement_mode == SecurityEnforcementMode::Off
        || contract.accepted_auth_helpers.is_empty()
    {
        return Ok(Vec::new());
    }
    let middleware_proof = build_middleware_coverage_proof(
        middleware_file_path,
        middleware_source,
        route_file_path.as_ref(),
        route_source,
        &contract.accepted_auth_helpers,
    )?;
    if middleware_proof.result.proof_status == SecurityProofStatus::Proven
        && middleware_proof.middleware.proven
    {
        return Ok(Vec::new());
    }
    evaluate_api_route_requires_auth_helper(route_file_path, route_source, contract)
}

fn normalize_auth_actual_layer(reason: &str) -> String {
    if reason == "no_guard_call" {
        "missing_auth_guard".to_string()
    } else {
        reason.to_string()
    }
}

pub fn evaluate_middleware_must_cover_routes(
    middleware_file_path: impl AsRef<std::path::Path>,
    middleware_source: &str,
    route_file_path: impl AsRef<std::path::Path>,
    route_source: &str,
    contract: &SecurityMiddlewareContract,
) -> Result<Vec<SecurityFinding>, FactExtractError> {
    if contract.enforcement_mode == SecurityEnforcementMode::Off
        || contract.capability != SecurityContractCapability::DeterministicCheck
        || contract.accepted_auth_helpers.is_empty()
    {
        return Ok(Vec::new());
    }
    let route_file_path_string = route_file_path
        .as_ref()
        .to_string_lossy()
        .replace('\\', "/");
    if !contract.route_paths.is_empty()
        && route_path_from_file(&route_file_path_string)
            .is_none_or(|route_path| !contract.route_paths.contains(&route_path))
    {
        return Ok(Vec::new());
    }

    let proof = build_middleware_coverage_proof(
        middleware_file_path,
        middleware_source,
        route_file_path,
        route_source,
        &contract.accepted_auth_helpers,
    )?;
    if proof.result.proof_status == SecurityProofStatus::Proven {
        return Ok(Vec::new());
    }

    Ok(vec![SecurityFinding {
        contract_id: contract.contract_id.clone(),
        title: "Middleware does not cover required route".to_string(),
        expected_layer: "middleware_coverage".to_string(),
        actual_layer: proof
            .middleware
            .mismatches
            .first()
            .map(|mismatch| mismatch.reason.clone())
            .unwrap_or_else(|| "middleware_not_covering_route".to_string()),
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
