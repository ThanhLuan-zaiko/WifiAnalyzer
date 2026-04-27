use std::process::Command;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use wifi_core::{normalize_records, ScanRecord};

use crate::WifiScanner;

#[derive(Debug, Default)]
pub struct MacosAirportScanner;

impl WifiScanner for MacosAirportScanner {
    fn name(&self) -> &'static str {
        "macos-airport"
    }

    fn scan(&self) -> Result<Vec<ScanRecord>> {
        let output = Command::new(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        )
        .arg("-s")
        .output()
        .context("failed to execute airport scan command")?;

        if !output.status.success() {
            bail!(
                "airport scan failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("deprecated") || stdout.contains("removed") {
            bail!("airport scan is unavailable on this macOS version; replace adapter with CoreWLAN bridge");
        }

        let scan_id = Uuid::new_v4().to_string();
        let observed_at = Utc::now().to_rfc3339();
        let mut records = stdout
            .lines()
            .skip(1)
            .filter_map(|line| parse_airport_line(line, &scan_id, &observed_at))
            .collect::<Vec<_>>();

        normalize_records(&mut records);
        Ok(records)
    }
}

fn parse_airport_line(line: &str, scan_id: &str, observed_at: &str) -> Option<ScanRecord> {
    let columns = line.split_whitespace().collect::<Vec<_>>();
    if columns.len() < 6 {
        return None;
    }

    let bssid_index = columns
        .iter()
        .position(|part| part.matches(':').count() == 5)?;
    let ssid = columns[..bssid_index].join(" ");
    let bssid = columns[bssid_index];
    let rssi = columns.get(bssid_index + 1)?.parse().ok();
    let channel = columns
        .get(bssid_index + 2)
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.parse().ok());
    let security = columns.last().map(|value| (*value).to_owned());

    let mut record = ScanRecord::new(
        scan_id.to_owned(),
        observed_at.to_owned(),
        "macos".to_owned(),
        "airport".to_owned(),
    );
    record.ssid = if ssid.is_empty() { None } else { Some(ssid) };
    record.bssid = Some(bssid.to_owned());
    record.channel = channel;
    record.rssi_dbm = rssi;
    record.security = security;
    record.hidden = record.ssid.is_none();
    record.raw = json!({ "source": "airport", "line": line });
    Some(record)
}
