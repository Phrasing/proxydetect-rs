use regex::Regex;
use std::sync::LazyLock;

static UUID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"uuid:"([a-f0-9]{16})""#).unwrap());
static RIP_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"rip:"([^"]+)""#).unwrap());

/// Server config extracted from pd-lib.js.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub uuid: String,
    pub rip: String, // Remote/exit IP as seen by detection server
}

/// Parse UUID and exit IP from pd-lib.js response body.
pub fn parse_config(
    script_body: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let uuid = UUID_REGEX
        .captures(script_body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or("failed to extract UUID from pd-lib.js")?;

    let rip = RIP_REGEX
        .captures(script_body)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or("failed to extract exit IP from pd-lib.js")?;

    Ok(ServerConfig { uuid, rip })
}
