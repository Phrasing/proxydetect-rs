use crate::browser::{ipapi_headers, Preset};
use serde_json::Value;
use std::time::Duration;
use wreq_util::tower::delay::JitterDelayLayer;

#[derive(Clone, Debug, Default)]
pub struct IpInfo {
    pub ip: String,
    pub is_proxy: bool,
    pub is_vpn: bool,
    pub is_datacenter: bool,
    pub is_tor: bool,
    pub is_abuser: bool,
    pub abuser_score: f64,
    pub abuser_label: String,
    pub company: String,
    pub company_type: String,
    pub asn_org: String,
    pub country: String,
    pub city: String,
}

/// Fetch IP intelligence through the current proxy path.
pub async fn lookup(
    proxy_url: Option<&str>,
    preset: &Preset,
) -> Result<IpInfo, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = wreq::Client::builder()
        .emulation(preset.emulation)
        .layer(JitterDelayLayer::new(Duration::from_millis(120), 0.4));

    if let Some(proxy) = proxy_url {
        builder = builder.proxy(wreq::Proxy::all(proxy)?);
    }

    let client = builder.build()?;
    let headers = ipapi_headers(preset);

    let resp = client
        .get("https://api.ipapi.is/")
        .headers(headers)
        .send()
        .await?;
    let status = resp.status();

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("ipapi request failed (status {}): {}", status, body).into());
    }

    let body = resp.text().await?;
    let json: Value = serde_json::from_str(&body)?;
    Ok(parse_response(&json))
}

fn parse_response(json: &Value) -> IpInfo {
    let abuser_score_raw = get_string(json, &["company", "abuser_score"]);
    let (abuser_score, abuser_label) = parse_abuser_score(&abuser_score_raw);

    IpInfo {
        ip: get_string(json, &["ip"]),
        is_proxy: get_bool(json, &["is_proxy"]),
        is_vpn: get_bool(json, &["is_vpn"]),
        is_datacenter: get_bool(json, &["is_datacenter"]),
        is_tor: get_bool(json, &["is_tor"]),
        is_abuser: get_bool(json, &["is_abuser"]),
        abuser_score,
        abuser_label,
        company: get_string(json, &["company", "name"]),
        company_type: get_string(json, &["company", "type"]),
        asn_org: get_string(json, &["asn", "org"]),
        country: get_string(json, &["location", "country"]),
        city: get_string(json, &["location", "city"]),
    }
}

fn parse_abuser_score(input: &str) -> (f64, String) {
    let mut score_part = input.trim();
    let mut label = String::new();

    if let Some(open) = score_part.find('(') {
        if let Some(close) = score_part.rfind(')') {
            if close > open {
                label = score_part[open + 1..close].trim().to_string();
                score_part = score_part[..open].trim();
            }
        }
    }

    let score = score_part.parse::<f64>().unwrap_or(0.0);
    (score, label)
}

fn get_bool(json: &Value, path: &[&str]) -> bool {
    get_value(json, path)
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

fn get_string(json: &Value, path: &[&str]) -> String {
    get_value(json, path)
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string()
}

fn get_value<'a>(json: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = json;

    for segment in path {
        current = current.get(*segment)?;
    }

    Some(current)
}
