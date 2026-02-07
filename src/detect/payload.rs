use super::ServerConfig;
use crate::browser::{compute_fingerprint, Preset};
use crate::timezone::Info as TzInfo;
use serde::Serialize;

/// Client telemetry payload for POST /s.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClientPayload {
    pub uuid: String,
    pub idx: i32,
    pub loaded: f64,
    pub elapsed: f64,
    pub location: String,
    pub user_agent: String,
    pub time: TimeData,
    pub net: NetData,
    pub timezone_details: TZDetails,
    pub webrtc: WebRTCData,
    pub machine: MachineData,
    pub image_latencies: Vec<f64>,
    pub ws_latencies: Vec<f64>,
    pub fp: u32,
}

#[derive(Serialize, Clone, Debug)]
pub struct TimeData {
    pub timestamp: i64,
    pub time_str: String,
    pub time_zone: String,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct NetData {
    pub dns_resolving: NetTestResult,
    #[serde(rename = "canLoadScriptFromUncommonPort")]
    pub uncommon_port: NetTestResult,
}

#[derive(Serialize, Clone, Debug)]
pub struct NetTestResult {
    pub res: i32,
    pub perf: f64,
}

#[derive(Serialize, Clone, Debug)]
pub struct TZDetails {
    pub valid: TZValid,
    pub date: String,
    pub time: String,
    pub zone: String,
    pub reported_offset: i32,
    pub computed_offset: i32,
    pub reported_location: String,
    #[serde(rename = "resolvedOptionsEpoch")]
    pub resolved_epoch: i64,
    #[serde(rename = "systemEpoch")]
    pub system_epoch: i64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TZValid {
    pub time: bool,
    pub clock: bool,
    pub date: bool,
    pub invalid_date: bool,
    pub offset: bool,
    pub matching_offset: bool,
    pub now_time: bool,
    pub utc_time: bool,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WebRTCData {
    pub ips: Vec<String>,
    pub finish_event: String,
    pub elapsed: f64,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct MachineData {
    pub ua_identifiers: bool,
    pub core: bool,
    pub system: bool,
    pub device: bool,
    pub platform: bool,
    pub speech_synthesis: bool,
    pub device_memory: bool,
    pub hardware_concurrency: bool,
    pub gpu: bool,
}

/// Build the client telemetry payload for POST /s.
pub fn build_payload(
    cfg: &ServerConfig,
    preset: &Preset,
    tz_info: &TzInfo,
    image_latencies: &[f64],
    ws_latencies: &[f64],
    loaded_ms: f64,
    elapsed_ms: f64,
) -> ClientPayload {
    ClientPayload {
        uuid: cfg.uuid.clone(),
        idx: 1,
        loaded: loaded_ms,
        elapsed: elapsed_ms,
        location: "https://proxydetect.live/".to_string(),
        user_agent: preset.user_agent.to_string(),
        time: TimeData {
            timestamp: tz_info.timestamp_millis,
            time_str: tz_info.date_string.clone(),
            time_zone: tz_info.iana_name.clone(),
        },
        net: NetData {
            dns_resolving: NetTestResult {
                res: 0,
                perf: 215.0,
            },
            uncommon_port: NetTestResult {
                res: 1,
                perf: 622.0,
            },
        },
        timezone_details: TZDetails {
            valid: TZValid {
                time: true,
                clock: true,
                date: true,
                invalid_date: true,
                offset: true,
                matching_offset: true,
                now_time: true,
                utc_time: true,
            },
            date: tz_info.date_string.clone(),
            time: tz_info.time_string.clone(),
            zone: tz_info.windows_zone.clone(),
            reported_offset: tz_info.offset_minutes,
            computed_offset: tz_info.offset_minutes,
            reported_location: tz_info.iana_name.clone(),
            resolved_epoch: tz_info.resolved_epoch,
            system_epoch: tz_info.system_epoch,
        },
        webrtc: WebRTCData {
            ips: vec![],
            finish_event: "notSupported".to_string(),
            elapsed: 0.0,
        },
        machine: MachineData::default(),
        image_latencies: image_latencies.to_vec(),
        ws_latencies: ws_latencies.to_vec(),
        fp: compute_fingerprint(preset.name),
    }
}
