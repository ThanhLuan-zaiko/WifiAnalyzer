use std::process::Command;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use wifi_core::{normalize_records, ScanRecord};

use crate::WifiScanner;

#[derive(Debug, Default)]
pub struct LinuxNmcliScanner;

impl WifiScanner for LinuxNmcliScanner {
    fn name(&self) -> &'static str {
        "linux-nmcli"
    }

    fn scan(&self) -> Result<Vec<ScanRecord>> {
        let output = Command::new("nmcli")
            .args([
                "-t",
                "-f",
                "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                "dev",
                "wifi",
                "list",
                "--rescan",
                "yes",
            ])
            .output()
            .context("failed to execute nmcli")?;

        if !output.status.success() {
            bail!(
                "nmcli scan failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let scan_id = Uuid::new_v4().to_string();
        let observed_at = Utc::now().to_rfc3339();
        let mut records = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| parse_nmcli_line(line, &scan_id, &observed_at))
            .collect::<Vec<_>>();

        normalize_records(&mut records);
        Ok(records)
    }
}

fn parse_nmcli_line(line: &str, scan_id: &str, observed_at: &str) -> Option<ScanRecord> {
    let parts = split_nmcli(line);
    if parts.len() < 6 {
        return None;
    }

    let mut record = ScanRecord::new(
        scan_id.to_owned(),
        observed_at.to_owned(),
        "linux".to_owned(),
        "nmcli".to_owned(),
    );
    record.ssid = if parts[0].is_empty() {
        None
    } else {
        Some(parts[0].clone())
    };
    record.bssid = if parts[1].is_empty() {
        None
    } else {
        Some(parts[1].clone())
    };
    record.channel = parts[2].parse().ok();
    record.frequency_mhz = parts[3].parse().ok();
    record.signal_percent = parts[4].parse().ok();
    record.security = if parts[5].is_empty() {
        None
    } else {
        Some(parts[5].clone())
    };
    record.hidden = record.ssid.is_none();
    record.raw = json!({ "source": "nmcli", "line": line });
    Some(record)
}

fn split_nmcli(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ':' {
            parts.push(current);
            current = String::new();
        } else {
            current.push(ch);
        }
    }

    parts.push(current);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_escaped_bssid() {
        let record = parse_nmcli_line(
            "Cafe:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:2437:76:WPA2",
            "s1",
            "now",
        )
        .unwrap();
        assert_eq!(record.bssid.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(record.channel, Some(6));
    }
}
