use serde_json::{Map, Value};

/// Detection result from polling endpoint.
#[derive(Clone, Debug, Default)]
pub struct DetectionResult {
    pub finished: bool,
    pub tests: Map<String, Value>,
    pub raw_json: Value,
    pub exit_ip: String,
    /// Total bandwidth used (bytes sent + received).
    pub bandwidth_bytes: u64,
}

/// Parse polling response JSON.
pub fn parse_result(
    data: &[u8],
) -> Result<DetectionResult, Box<dyn std::error::Error + Send + Sync>> {
    let raw: Value = serde_json::from_slice(data)?;
    let mut result = DetectionResult {
        raw_json: raw.clone(),
        ..Default::default()
    };

    if let Value::Object(mut map) = raw {
        if let Some(Value::Bool(finished)) = map.remove("finished") {
            result.finished = finished;
        }
        result.tests = map;
    }

    Ok(result)
}
