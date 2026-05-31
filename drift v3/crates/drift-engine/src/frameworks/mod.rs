use crate::protocol::{
    EngineFact, EngineFrameworkAdapter, EngineFrameworkCapability, EngineFrameworkParserGap,
    EngineNormalizedEntrypoint, ScannedFile,
};

const NEXT_ADAPTER_ID: &str = "framework_adapter_next_v1";

#[derive(Debug, Clone)]
pub struct EndpointShape {
    pub pattern: String,
    pub framework_role: &'static str,
    pub framework: &'static str,
    pub adapter_id: &'static str,
    pub dynamic_params: Vec<String>,
}

#[derive(Debug, Default)]
pub struct FrameworkScanData {
    pub adapters: Vec<EngineFrameworkAdapter>,
    pub entrypoints: Vec<EngineNormalizedEntrypoint>,
    pub parser_gaps: Vec<EngineFrameworkParserGap>,
    pub capabilities: Vec<EngineFrameworkCapability>,
}

pub fn collect_framework_scan_data(
    repo_id: &str,
    scan_id: &str,
    scanned: &[(ScannedFile, Vec<EngineFact>)],
) -> FrameworkScanData {
    let mut data = FrameworkScanData::default();
    let mut next_seen = false;

    for (_file, facts) in scanned {
        for fact in facts.iter().filter(|fact| fact.kind == "route_declared") {
            let Some(endpoint) = endpoint_shape(&fact.file_path, &fact.name) else {
                continue;
            };
            if endpoint.adapter_id == NEXT_ADAPTER_ID {
                next_seen = true;
            }
            data.entrypoints.push(EngineNormalizedEntrypoint {
                schema_version: "engine.normalized_entrypoint.v1",
                entrypoint_id: format!(
                    "entrypoint:{}:{}:{}",
                    endpoint.framework, fact.file_path, fact.name
                ),
                repo_id: repo_id.to_string(),
                scan_id: scan_id.to_string(),
                adapter_id: endpoint.adapter_id.to_string(),
                framework: endpoint.framework.to_string(),
                kind: "api_route".to_string(),
                file_path: fact.file_path.clone(),
                exported_symbol: None,
                handler_symbol: fact.value.clone().or_else(|| Some(fact.name.clone())),
                route_pattern: Some(endpoint.pattern),
                method: Some(fact.name.clone()),
                route_group: None,
                package_name: None,
                subdirectory_role: None,
                middleware_refs: Vec::new(),
                request_source_refs: Vec::new(),
                response_sink_refs: Vec::new(),
                data_operation_refs: Vec::new(),
                confidence_label: "high".to_string(),
                evidence_refs: vec![format!(
                    "fact:{}:route_declared:{}:{}-{}",
                    fact.file_path, fact.name, fact.start_line, fact.end_line
                )],
                parser_gap_ids: Vec::new(),
            });
        }
    }

    if next_seen {
        data.adapters.push(next_adapter());
        data.capabilities
            .push(next_capability("entrypoint_discovery", "complete", true));
        data.capabilities.push(next_capability(
            "route_pattern_resolution",
            "complete",
            true,
        ));
        data.capabilities
            .push(next_capability("method_resolution", "complete", true));
    }

    data
}

pub fn endpoint_shape(file_path: &str, method: &str) -> Option<EndpointShape> {
    let normalized = file_path.replace('\\', "/");
    if is_next_app_route_path(&normalized) {
        let route_path = strip_before_segment(&normalized, "app/api/")?
            .strip_suffix("/route.ts")
            .or_else(|| strip_before_segment(&normalized, "app/api/")?.strip_suffix("/route.tsx"))
            .or_else(|| strip_before_segment(&normalized, "app/api/")?.strip_suffix("/route.js"))
            .or_else(|| {
                strip_before_segment(&normalized, "app/api/")?.strip_suffix("/route.jsx")
            })?;
        let (pattern, dynamic_params) = route_pattern_from_segments(route_path);
        return Some(EndpointShape {
            pattern,
            framework_role: "next_app_route",
            framework: "next_app",
            adapter_id: NEXT_ADAPTER_ID,
            dynamic_params,
        });
    }
    if let Some(route_path) = strip_pages_api_route(&normalized) {
        let (pattern, dynamic_params) = route_pattern_from_segments(route_path);
        return Some(EndpointShape {
            pattern,
            framework_role: "next_pages_api",
            framework: "next_pages",
            adapter_id: NEXT_ADAPTER_ID,
            dynamic_params,
        });
    }
    if method.is_empty() {
        return None;
    }
    None
}

fn next_adapter() -> EngineFrameworkAdapter {
    EngineFrameworkAdapter {
        schema_version: "engine.framework.adapter.v1",
        adapter_id: NEXT_ADAPTER_ID.to_string(),
        framework: "next_app".to_string(),
        adapter_version: drift_engine::DRIFT_ENGINE_VERSION.to_string(),
        package_names: vec!["next".to_string()],
        entrypoint_kinds: vec!["api_route".to_string()],
        supported_patterns: vec![
            "app/api/**/route.{ts,tsx,js,jsx}".to_string(),
            "pages/api/**/*.{ts,tsx,js,jsx}".to_string(),
        ],
        unsupported_patterns: Vec::new(),
    }
}

fn next_capability(
    capability: &'static str,
    status: &'static str,
    can_block: bool,
) -> EngineFrameworkCapability {
    EngineFrameworkCapability {
        schema_version: "engine.framework.capability.v1",
        adapter_id: NEXT_ADAPTER_ID.to_string(),
        framework: "next_app".to_string(),
        capability: capability.to_string(),
        status: status.to_string(),
        can_block,
        block_requires_accepted_convention: true,
        parser_gap_ids: Vec::new(),
        missing_proof_ids: Vec::new(),
    }
}

fn is_next_app_route_path(file_path: &str) -> bool {
    file_path.ends_with("/route.ts")
        || file_path.ends_with("/route.tsx")
        || file_path.ends_with("/route.js")
        || file_path.ends_with("/route.jsx")
}

fn strip_before_segment<'a>(file_path: &'a str, segment: &str) -> Option<&'a str> {
    let index = file_path.find(segment)?;
    Some(&file_path[index + "app/".len()..])
}

fn strip_pages_api_route(file_path: &str) -> Option<&str> {
    let index = file_path.find("pages/api/")?;
    let route = &file_path[index + "pages/".len()..];
    route
        .strip_suffix(".ts")
        .or_else(|| route.strip_suffix(".tsx"))
        .or_else(|| route.strip_suffix(".js"))
        .or_else(|| route.strip_suffix(".jsx"))
}

fn route_pattern_from_segments(route_path: &str) -> (String, Vec<String>) {
    let mut dynamic_params = Vec::new();
    let segments = route_path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if let Some(param) = segment
                .strip_prefix("[[...")
                .and_then(|value| value.strip_suffix("]]"))
            {
                dynamic_params.push(param.to_string());
                format!(":{param}*")
            } else if let Some(param) = segment
                .strip_prefix("[...")
                .and_then(|value| value.strip_suffix(']'))
            {
                dynamic_params.push(param.to_string());
                format!(":{param}*")
            } else if let Some(param) = segment
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
            {
                dynamic_params.push(param.to_string());
                format!(":{param}")
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>();
    (format!("/{}", segments.join("/")), dynamic_params)
}
