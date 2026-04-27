use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanRecord {
    pub scan_id: String,
    pub observed_at: String,
    pub platform: String,
    pub adapter_id: String,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub band: Option<String>,
    pub channel: Option<u16>,
    pub frequency_mhz: Option<u32>,
    pub width_mhz: Option<u16>,
    pub rssi_dbm: Option<i32>,
    pub signal_percent: Option<u8>,
    pub noise_dbm: Option<i32>,
    pub snr_db: Option<i32>,
    pub security: Option<String>,
    pub phy: Option<String>,
    #[serde(default)]
    pub hidden: bool,
    pub country: Option<String>,
    #[serde(default)]
    pub raw: Value,
}

impl ScanRecord {
    pub fn new(scan_id: String, observed_at: String, platform: String, adapter_id: String) -> Self {
        Self {
            scan_id,
            observed_at,
            platform,
            adapter_id,
            ssid: None,
            bssid: None,
            band: None,
            channel: None,
            frequency_mhz: None,
            width_mhz: None,
            rssi_dbm: None,
            signal_percent: None,
            noise_dbm: None,
            snr_db: None,
            security: None,
            phy: None,
            hidden: false,
            country: None,
            raw: Value::Null,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChannelRecommendation {
    pub band: String,
    pub channel: u16,
    pub frequency_mhz: u32,
    pub score: f64,
    pub interference: f64,
    pub visible_aps: usize,
    pub strong_aps: usize,
    pub reason: String,
}
