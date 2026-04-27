use uuid::Uuid;

use crate::channel::{
    channel_to_frequency, frequency_to_band, frequency_to_channel, infer_band_from_channel,
};
use crate::model::ScanRecord;

pub fn normalize_records(records: &mut [ScanRecord]) {
    for record in records {
        normalize_record(record);
    }
}

pub fn normalize_record(record: &mut ScanRecord) {
    if record.scan_id.trim().is_empty() {
        record.scan_id = Uuid::new_v4().to_string();
    }

    if record.band.is_none() {
        record.band = record
            .frequency_mhz
            .and_then(frequency_to_band)
            .or_else(|| record.channel.and_then(infer_band_from_channel))
            .map(ToOwned::to_owned);
    }

    if record.channel.is_none() {
        record.channel = record.frequency_mhz.and_then(frequency_to_channel);
    }

    if record.frequency_mhz.is_none() {
        if let (Some(channel), Some(band)) = (record.channel, record.band.as_deref()) {
            record.frequency_mhz = channel_to_frequency(channel, band);
        }
    }

    if record.width_mhz.is_none() {
        record.width_mhz = Some(20);
    }

    if record.signal_percent.is_none() {
        record.signal_percent = record.rssi_dbm.map(rssi_to_percent);
    }

    if record.snr_db.is_none() {
        if let (Some(rssi), Some(noise)) = (record.rssi_dbm, record.noise_dbm) {
            record.snr_db = Some(rssi - noise);
        }
    }

    if record.hidden {
        return;
    }

    record.hidden = record.ssid.as_deref().is_none_or(str::is_empty);
}

fn rssi_to_percent(rssi: i32) -> u8 {
    if rssi <= -100 {
        0
    } else if rssi >= -50 {
        100
    } else {
        ((rssi + 100) * 2) as u8
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn fills_derived_fields() {
        let mut record = ScanRecord {
            scan_id: String::new(),
            observed_at: "2026-04-27T00:00:00Z".to_owned(),
            platform: "test".to_owned(),
            adapter_id: "mock0".to_owned(),
            ssid: Some("lab".to_owned()),
            bssid: None,
            band: None,
            channel: None,
            frequency_mhz: Some(2412),
            width_mhz: None,
            rssi_dbm: Some(-62),
            signal_percent: None,
            noise_dbm: Some(-92),
            snr_db: None,
            security: None,
            phy: None,
            hidden: false,
            country: None,
            raw: Value::Null,
        };

        normalize_record(&mut record);

        assert_eq!(record.band.as_deref(), Some("2.4"));
        assert_eq!(record.channel, Some(1));
        assert_eq!(record.signal_percent, Some(76));
        assert_eq!(record.snr_db, Some(30));
        assert!(!record.scan_id.is_empty());
    }
}
