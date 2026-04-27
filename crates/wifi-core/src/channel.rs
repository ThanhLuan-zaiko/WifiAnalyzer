pub fn frequency_to_band(frequency_mhz: u32) -> Option<&'static str> {
    match frequency_mhz {
        2400..=2500 => Some("2.4"),
        4900..=5900 => Some("5"),
        5925..=7125 => Some("6"),
        _ => None,
    }
}

pub fn infer_band_from_channel(channel: u16) -> Option<&'static str> {
    match channel {
        1..=14 => Some("2.4"),
        15..=196 => Some("5"),
        197..=233 => Some("6"),
        _ => None,
    }
}

pub fn channel_to_frequency(channel: u16, band: &str) -> Option<u32> {
    match band {
        "2.4" if channel == 14 => Some(2484),
        "2.4" if (1..=13).contains(&channel) => Some(2407 + u32::from(channel) * 5),
        "5" if (1..=196).contains(&channel) => Some(5000 + u32::from(channel) * 5),
        "6" if (1..=233).contains(&channel) => Some(5950 + u32::from(channel) * 5),
        _ => None,
    }
}

pub fn frequency_to_channel(frequency_mhz: u32) -> Option<u16> {
    match frequency_mhz {
        2484 => Some(14),
        2412..=2472 if (frequency_mhz - 2407) % 5 == 0 => Some(((frequency_mhz - 2407) / 5) as u16),
        5005..=5980 if (frequency_mhz - 5000) % 5 == 0 => Some(((frequency_mhz - 5000) / 5) as u16),
        5955..=7115 if (frequency_mhz - 5950) % 5 == 0 => Some(((frequency_mhz - 5950) / 5) as u16),
        _ => None,
    }
}

pub fn candidate_channels(band: &str) -> Vec<u16> {
    match band {
        "2.4" => vec![1, 6, 11],
        "5" => vec![36, 40, 44, 48, 149, 153, 157, 161],
        "6" => vec![
            5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229,
        ],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_common_channels() {
        assert_eq!(channel_to_frequency(1, "2.4"), Some(2412));
        assert_eq!(frequency_to_channel(2412), Some(1));
        assert_eq!(channel_to_frequency(36, "5"), Some(5180));
        assert_eq!(frequency_to_channel(5180), Some(36));
        assert_eq!(channel_to_frequency(5, "6"), Some(5975));
        assert_eq!(frequency_to_band(5975), Some("6"));
    }
}
