use crate::channel::{candidate_channels, channel_to_frequency, frequency_to_channel};
use crate::model::{ChannelRecommendation, ScanRecord};

pub fn recommend_channels(
    records: &[ScanRecord],
    band: &str,
    top_n: usize,
) -> Vec<ChannelRecommendation> {
    let candidates = candidate_channels(band);
    let mut recommendations: Vec<_> = candidates
        .into_iter()
        .filter_map(|channel| score_candidate(records, band, channel))
        .collect();

    recommendations.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.channel.cmp(&right.channel))
    });
    recommendations.truncate(top_n);
    recommendations
}

fn score_candidate(
    records: &[ScanRecord],
    band: &str,
    channel: u16,
) -> Option<ChannelRecommendation> {
    let frequency_mhz = channel_to_frequency(channel, band)?;
    let same_band: Vec<&ScanRecord> = records
        .iter()
        .filter(|record| record.band.as_deref() == Some(band))
        .collect();

    let mut interference = 0.0;
    let mut strong_aps = 0;
    let mut overlapping_aps = 0;

    for record in &same_band {
        let overlap = overlap_factor(record, band, channel, frequency_mhz);
        if overlap <= 0.0 {
            continue;
        }

        overlapping_aps += 1;
        if record.rssi_dbm.is_some_and(|rssi| rssi >= -67) {
            strong_aps += 1;
        }

        interference += overlap * signal_weight(record) * width_weight(record);
    }

    let score = (100.0 - interference * 18.0).clamp(0.0, 100.0);
    let reason = if overlapping_aps == 0 {
        "no visible overlapping APs"
    } else if strong_aps == 0 {
        "overlap exists but signals are weak"
    } else {
        "strong overlapping APs present"
    }
    .to_owned();

    Some(ChannelRecommendation {
        band: band.to_owned(),
        channel,
        frequency_mhz,
        score: round2(score),
        interference: round2(interference),
        visible_aps: overlapping_aps,
        strong_aps,
        reason,
    })
}

fn overlap_factor(
    record: &ScanRecord,
    band: &str,
    candidate_channel: u16,
    candidate_frequency: u32,
) -> f64 {
    let ap_channel = record
        .channel
        .or_else(|| record.frequency_mhz.and_then(frequency_to_channel));

    if band == "2.4" {
        let Some(ap_channel) = ap_channel else {
            return 0.0;
        };
        let gap = (i32::from(ap_channel) - i32::from(candidate_channel)).abs() as f64;
        return if gap >= 5.0 { 0.0 } else { 1.0 - gap / 5.0 };
    }

    let Some(ap_frequency) = record.frequency_mhz else {
        return 0.0;
    };
    let ap_width = f64::from(record.width_mhz.unwrap_or(20).max(20));
    let candidate_width = 20.0;
    let half_span = (ap_width + candidate_width) / 2.0;
    let distance = (i64::from(ap_frequency) - i64::from(candidate_frequency)).abs() as f64;

    if distance >= half_span {
        0.0
    } else {
        1.0 - distance / half_span
    }
}

fn signal_weight(record: &ScanRecord) -> f64 {
    if let Some(rssi) = record.rssi_dbm {
        return ((f64::from(rssi) + 95.0) / 60.0).clamp(0.05, 1.0);
    }

    record
        .signal_percent
        .map(|signal| (f64::from(signal) / 100.0).clamp(0.05, 1.0))
        .unwrap_or(0.25)
}

fn width_weight(record: &ScanRecord) -> f64 {
    (f64::from(record.width_mhz.unwrap_or(20).max(20)) / 20.0).clamp(1.0, 8.0)
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn record(channel: u16, rssi: i32) -> ScanRecord {
        ScanRecord {
            scan_id: "s1".to_owned(),
            observed_at: "2026-04-27T00:00:00Z".to_owned(),
            platform: "test".to_owned(),
            adapter_id: "mock0".to_owned(),
            ssid: Some(format!("ap-{channel}")),
            bssid: None,
            band: Some("2.4".to_owned()),
            channel: Some(channel),
            frequency_mhz: None,
            width_mhz: Some(20),
            rssi_dbm: Some(rssi),
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

    #[test]
    fn ranks_less_congested_channel_higher() {
        let records = vec![record(1, -45), record(6, -58)];
        let recommendations = recommend_channels(&records, "2.4", 3);
        assert_eq!(recommendations[0].channel, 11);
        assert!(recommendations[0].score > recommendations[2].score);
    }
}
