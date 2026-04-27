use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use wifi_core::{normalize_records, ScanRecord};

use crate::WifiScanner;

#[derive(Debug, Default)]
pub struct MockScanner;

impl WifiScanner for MockScanner {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn scan(&self) -> Result<Vec<ScanRecord>> {
        let scan_id = Uuid::new_v4().to_string();
        let observed_at = Utc::now().to_rfc3339();
        let mut records = vec![
            sample(
                &scan_id,
                &observed_at,
                "Cafe-Lab",
                "aa:bb:cc:00:00:01",
                "2.4",
                1,
                -48,
                "WPA2",
            ),
            sample(
                &scan_id,
                &observed_at,
                "Office",
                "aa:bb:cc:00:00:02",
                "2.4",
                6,
                -61,
                "WPA2/WPA3",
            ),
            sample(
                &scan_id,
                &observed_at,
                "Printer",
                "aa:bb:cc:00:00:03",
                "2.4",
                6,
                -77,
                "WPA2",
            ),
            sample(
                &scan_id,
                &observed_at,
                "Mesh-5G",
                "aa:bb:cc:00:00:04",
                "5",
                36,
                -55,
                "WPA3",
            ),
            sample(
                &scan_id,
                &observed_at,
                "Mesh-5G",
                "aa:bb:cc:00:00:05",
                "5",
                149,
                -70,
                "WPA3",
            ),
        ];
        normalize_records(&mut records);
        Ok(records)
    }
}

fn sample(
    scan_id: &str,
    observed_at: &str,
    ssid: &str,
    bssid: &str,
    band: &str,
    channel: u16,
    rssi: i32,
    security: &str,
) -> ScanRecord {
    let mut record = ScanRecord::new(
        scan_id.to_owned(),
        observed_at.to_owned(),
        "mock".to_owned(),
        "mock0".to_owned(),
    );
    record.ssid = Some(ssid.to_owned());
    record.bssid = Some(bssid.to_owned());
    record.band = Some(band.to_owned());
    record.channel = Some(channel);
    record.width_mhz = Some(20);
    record.rssi_dbm = Some(rssi);
    record.security = Some(security.to_owned());
    record.raw = json!({ "source": "mock" });
    record
}
