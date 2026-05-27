use crate::{
    AcceptedAuthHelper, AcceptedAuthorizationHelper, AcceptedRequestValidator,
    AcceptedTenantHelper, AuthorizationHelperBehavior, AuthorizationHelperKind, FactExtractError,
    Phase4SecurityPolicy, RequestValidationProofScope, SecurityProofStatus,
    build_auth_boundary_proof, build_middleware_coverage_proof,
    build_phase4_security_proof_with_policy, build_request_validation_proof_with_scope,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRequestValidationContract {
    pub contract_id: String,
    pub capability: SecurityContractCapability,
    pub enforcement_mode: SecurityEnforcementMode,
    pub methods: Vec<String>,
    pub input_sources: Vec<String>,
    pub sinks: Vec<String>,
    pub accepted_validators: Vec<AcceptedRequestValidator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityTenantScopeContract {
    pub contract_id: String,
    pub capability: SecurityContractCapability,
    pub enforcement_mode: SecurityEnforcementMode,
    pub accepted_auth_helpers: Vec<AcceptedAuthHelper>,
    pub tenant_helpers: Vec<String>,
    pub tenant_keys: Vec<String>,
    pub tenant_sources: Vec<String>,
    pub data_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAuthorizationContract {
    pub contract_id: String,
    pub capability: SecurityContractCapability,
    pub enforcement_mode: SecurityEnforcementMode,
    pub accepted_auth_helpers: Vec<AcceptedAuthHelper>,
    pub authorization_helpers: Vec<String>,
    pub data_operations: Vec<String>,
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

pub fn evaluate_api_route_requires_request_validation(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    contract: &SecurityRequestValidationContract,
) -> Result<Vec<SecurityFinding>, FactExtractError> {
    if contract.enforcement_mode == SecurityEnforcementMode::Off
        || contract.capability != SecurityContractCapability::DeterministicCheck
        || contract.accepted_validators.is_empty()
    {
        return Ok(Vec::new());
    }
    if !contract.methods.is_empty() {
        let route_method = first_route_method(source);
        if route_method
            .is_none_or(|method| !contract.methods.iter().any(|allowed| allowed == &method))
        {
            return Ok(Vec::new());
        }
    }

    let proof = build_request_validation_proof_with_scope(
        file_path,
        source,
        &contract.accepted_validators,
        &RequestValidationProofScope {
            input_sources: contract.input_sources.clone(),
            sink_kinds: contract.sinks.clone(),
        },
    )?;
    if proof.result.proof_status == SecurityProofStatus::Proven {
        return Ok(Vec::new());
    }

    Ok(vec![SecurityFinding {
        contract_id: contract.contract_id.clone(),
        title: "API route uses unvalidated request input".to_string(),
        expected_layer: "request_validation".to_string(),
        actual_layer: proof
            .request_validation
            .unvalidated_uses
            .first()
            .map(|use_proof| use_proof.reason.clone())
            .unwrap_or_else(|| "request_input_not_validated".to_string()),
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

pub fn evaluate_api_route_requires_tenant_scope(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    contract: &SecurityTenantScopeContract,
) -> Result<Vec<SecurityFinding>, FactExtractError> {
    if contract.enforcement_mode == SecurityEnforcementMode::Off
        || contract.capability != SecurityContractCapability::DeterministicCheck
    {
        return Ok(Vec::new());
    }

    let proof = build_phase4_security_proof_with_policy(
        file_path,
        source,
        &tenant_phase4_policy(contract),
    )?;
    if !proof.tenant.required || proof.tenant.proven {
        return Ok(Vec::new());
    }

    Ok(vec![SecurityFinding {
        contract_id: contract.contract_id.clone(),
        title: "API route missing required tenant scope proof".to_string(),
        expected_layer: "tenant_scope".to_string(),
        actual_layer: proof
            .tenant
            .missing
            .first()
            .map(|missing| missing.reason.clone())
            .unwrap_or_else(|| "tenant_predicate_missing".to_string()),
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

pub fn evaluate_api_route_requires_authorization(
    file_path: impl AsRef<std::path::Path>,
    source: &str,
    contract: &SecurityAuthorizationContract,
) -> Result<Vec<SecurityFinding>, FactExtractError> {
    if contract.enforcement_mode == SecurityEnforcementMode::Off
        || contract.capability != SecurityContractCapability::DeterministicCheck
    {
        return Ok(Vec::new());
    }

    let proof = build_phase4_security_proof_with_policy(
        file_path,
        source,
        &authorization_phase4_policy(contract),
    )?;
    if !proof.authorization.required || proof.authorization.proven {
        return Ok(Vec::new());
    }

    Ok(vec![SecurityFinding {
        contract_id: contract.contract_id.clone(),
        title: "API route missing required authorization proof".to_string(),
        expected_layer: "authorization".to_string(),
        actual_layer: proof
            .authorization
            .missing
            .first()
            .map(|missing| missing.reason.clone())
            .unwrap_or_else(|| "authorization_guard_missing".to_string()),
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

fn tenant_phase4_policy(contract: &SecurityTenantScopeContract) -> Phase4SecurityPolicy {
    Phase4SecurityPolicy {
        accepted_auth_helpers: contract.accepted_auth_helpers.clone(),
        tenant_helpers: contract
            .tenant_helpers
            .iter()
            .map(|symbol| AcceptedTenantHelper {
                helper_id: format!("tenant:{symbol}"),
                symbol: symbol.clone(),
                import_source: None,
                tenant_key: contract
                    .tenant_keys
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "tenantId".to_string()),
            })
            .collect(),
        tenant_keys: contract.tenant_keys.clone(),
        tenant_sources: contract.tenant_sources.clone(),
        data_operations: contract.data_operations.clone(),
        ..Phase4SecurityPolicy::default()
    }
}

fn authorization_phase4_policy(contract: &SecurityAuthorizationContract) -> Phase4SecurityPolicy {
    Phase4SecurityPolicy {
        accepted_auth_helpers: contract.accepted_auth_helpers.clone(),
        authorization_helpers: contract
            .authorization_helpers
            .iter()
            .map(|symbol| AcceptedAuthorizationHelper {
                guard_id: format!("authorization:{symbol}"),
                symbol: symbol.clone(),
                import_source: None,
                kind: if symbol.to_ascii_lowercase().contains("role") {
                    AuthorizationHelperKind::Role
                } else {
                    AuthorizationHelperKind::Policy
                },
                behavior: if symbol.to_ascii_lowercase().starts_with("can") {
                    AuthorizationHelperBehavior::Boolean
                } else {
                    AuthorizationHelperBehavior::Throws
                },
            })
            .collect(),
        tenant_keys: Vec::new(),
        data_operations: contract.data_operations.clone(),
        ..Phase4SecurityPolicy::default()
    }
}

fn first_route_method(source: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let trimmed = line.trim_start();
        let rest = trimmed.strip_prefix("export async function ")?;
        let method = rest.split('(').next()?.trim();
        if method.is_empty() {
            None
        } else {
            Some(method.to_uppercase())
        }
    })
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
