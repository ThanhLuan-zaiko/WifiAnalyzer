use std::ptr::{null, null_mut};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use wifi_core::{channel::frequency_to_channel, normalize_records, ScanRecord};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WiFi::{
    dot11_BSS_type_any, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanGetNetworkBssList,
    WlanOpenHandle, WlanScan, WLAN_BSS_ENTRY,
};

use crate::WifiScanner;

#[derive(Debug, Default)]
pub struct WindowsWlanScanner;

impl WifiScanner for WindowsWlanScanner {
    fn name(&self) -> &'static str {
        "windows-wlan-api"
    }

    fn scan(&self) -> Result<Vec<ScanRecord>> {
        let mut records = scan_with_wlan_api().context("Windows WLAN API scan failed")?;
        normalize_records(&mut records);
        Ok(records)
    }
}

struct WlanClient {
    handle: HANDLE,
}

impl WlanClient {
    fn open() -> Result<Self> {
        let mut negotiated_version = 0;
        let mut handle = null_mut();
        let status = unsafe { WlanOpenHandle(2, null(), &mut negotiated_version, &mut handle) };
        if status != ERROR_SUCCESS {
            bail!("WlanOpenHandle failed with code {status}");
        }
        Ok(Self { handle })
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        unsafe {
            WlanCloseHandle(self.handle, null());
        }
    }
}

fn scan_with_wlan_api() -> Result<Vec<ScanRecord>> {
    let client = WlanClient::open()?;
    let mut interface_list_ptr = null_mut();
    let status = unsafe { WlanEnumInterfaces(client.handle, null(), &mut interface_list_ptr) };
    if status != ERROR_SUCCESS {
        bail!("WlanEnumInterfaces failed with code {status}");
    }
    if interface_list_ptr.is_null() {
        bail!("WlanEnumInterfaces returned no interface list");
    }

    let scan_id = Uuid::new_v4().to_string();
    let observed_at = Utc::now().to_rfc3339();
    let mut records = Vec::new();

    unsafe {
        let interface_list = &*interface_list_ptr;
        let interfaces = std::slice::from_raw_parts(
            interface_list.InterfaceInfo.as_ptr(),
            interface_list.dwNumberOfItems as usize,
        );

        for interface in interfaces {
            let _ = WlanScan(
                client.handle,
                &interface.InterfaceGuid,
                null(),
                null(),
                null(),
            );
            thread::sleep(Duration::from_millis(750));

            let mut bss_list_ptr = null_mut();
            let status = WlanGetNetworkBssList(
                client.handle,
                &interface.InterfaceGuid,
                null(),
                dot11_BSS_type_any,
                0,
                null(),
                &mut bss_list_ptr,
            );
            if status != ERROR_SUCCESS {
                continue;
            }
            if bss_list_ptr.is_null() {
                continue;
            }

            let bss_list = &*bss_list_ptr;
            let entries = std::slice::from_raw_parts(
                bss_list.wlanBssEntries.as_ptr(),
                bss_list.dwNumberOfItems as usize,
            );
            let adapter_id = utf16_nul_to_string(&interface.strInterfaceDescription)
                .unwrap_or_else(|| "wlan0".to_owned());

            for entry in entries {
                records.push(record_from_bss_entry(
                    &scan_id,
                    &observed_at,
                    &adapter_id,
                    entry,
                ));
            }

            WlanFreeMemory(bss_list_ptr.cast());
        }

        WlanFreeMemory(interface_list_ptr.cast());
    }

    if records.is_empty() {
        return Err(anyhow!(
            "no WiFi BSS records found; check WLAN AutoConfig, radio state, and Windows location permission"
        ));
    }

    Ok(records)
}

fn record_from_bss_entry(
    scan_id: &str,
    observed_at: &str,
    adapter_id: &str,
    entry: &WLAN_BSS_ENTRY,
) -> ScanRecord {
    let ssid_len = entry.dot11Ssid.uSSIDLength.min(32) as usize;
    let ssid = String::from_utf8_lossy(&entry.dot11Ssid.ucSSID[..ssid_len]).to_string();
    let frequency_mhz = Some(entry.ulChCenterFrequency / 1000);
    let channel = frequency_mhz.and_then(frequency_to_channel);
    let bssid = entry
        .dot11Bssid
        .iter()
        .map(|part| format!("{part:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    let mut record = ScanRecord::new(
        scan_id.to_owned(),
        observed_at.to_owned(),
        "windows".to_owned(),
        adapter_id.to_owned(),
    );
    record.ssid = if ssid.is_empty() { None } else { Some(ssid) };
    record.bssid = Some(bssid);
    record.channel = channel;
    record.frequency_mhz = frequency_mhz;
    record.width_mhz = Some(20);
    record.rssi_dbm = Some(entry.lRssi);
    record.signal_percent = Some(entry.uLinkQuality.min(100) as u8);
    record.security = Some(if entry.usCapabilityInformation & 0x0010 != 0 {
        "secured".to_owned()
    } else {
        "open".to_owned()
    });
    record.phy = Some(entry.dot11BssPhyType.to_string());
    record.hidden = record.ssid.is_none();
    record.raw = json!({
        "source": "wlanapi",
        "phy_id": entry.uPhyId,
        "beacon_period": entry.usBeaconPeriod,
        "capability": entry.usCapabilityInformation,
    });
    record
}

fn utf16_nul_to_string(input: &[u16]) -> Option<String> {
    let end = input
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(input.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&input[..end]))
}
