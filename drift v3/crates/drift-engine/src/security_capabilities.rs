#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityCapabilityStatus {
    Complete,
    Partial,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityScanCapability {
    pub name: String,
    pub capability: String,
    pub status: SecurityCapabilityStatus,
    pub can_block: bool,
    pub block_requires_accepted_convention: bool,
}

pub fn security_capabilities() -> Vec<SecurityScanCapability> {
    vec![
        SecurityScanCapability {
            name: "security_facts".to_string(),
            capability: "deterministic_check".to_string(),
            status: SecurityCapabilityStatus::Partial,
            can_block: false,
            block_requires_accepted_convention: true,
        },
        SecurityScanCapability {
            name: "auth_boundary_facts".to_string(),
            capability: "deterministic_check".to_string(),
            status: SecurityCapabilityStatus::Partial,
            can_block: true,
            block_requires_accepted_convention: true,
        },
        SecurityScanCapability {
            name: "control_flow_guard_dominance".to_string(),
            capability: "deterministic_check".to_string(),
            status: SecurityCapabilityStatus::Partial,
            can_block: true,
            block_requires_accepted_convention: true,
        },
    ]
}
