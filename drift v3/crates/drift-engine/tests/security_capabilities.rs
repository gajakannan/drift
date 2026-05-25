use drift_engine::{SecurityCapabilityStatus, security_capabilities};

#[test]
fn reports_phase_one_security_capabilities() {
    let capabilities = security_capabilities();
    let names: Vec<&str> = capabilities
        .iter()
        .map(|capability| capability.name.as_str())
        .collect();

    assert!(
        names.contains(&"security_facts"),
        "missing security_facts: {capabilities:#?}"
    );
    assert!(
        names.contains(&"auth_boundary_facts"),
        "missing auth_boundary_facts: {capabilities:#?}"
    );
    assert!(
        names.contains(&"control_flow_guard_dominance"),
        "missing control_flow_guard_dominance: {capabilities:#?}"
    );
    assert!(
        capabilities
            .iter()
            .all(|capability| capability.block_requires_accepted_convention),
        "security capabilities must require accepted conventions: {capabilities:#?}"
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.status == SecurityCapabilityStatus::Partial),
        "Phase 1 guard dominance should report partial, not overclaim complete: {capabilities:#?}"
    );
}
