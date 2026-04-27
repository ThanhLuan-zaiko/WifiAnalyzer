from __future__ import annotations

from wifianalyzer import backend


def test_normalize_records_fills_channel_and_band() -> None:
    records = [
        {
            "scan_id": "s1",
            "observed_at": "2026-04-27T00:00:00Z",
            "platform": "test",
            "adapter_id": "mock0",
            "ssid": "Lab",
            "frequency_mhz": 2412,
            "rssi_dbm": -60,
        }
    ]

    normalized = backend.normalize_records(records)

    assert normalized[0]["band"] == "2.4"
    assert normalized[0]["channel"] == 1
    assert normalized[0]["signal_percent"] == 80


def test_recommend_channels_prefers_less_congested_channel() -> None:
    records = [
        {
            "scan_id": "s1",
            "observed_at": "2026-04-27T00:00:00Z",
            "platform": "test",
            "adapter_id": "mock0",
            "ssid": "A",
            "band": "2.4",
            "channel": 1,
            "rssi_dbm": -45,
        },
        {
            "scan_id": "s1",
            "observed_at": "2026-04-27T00:00:00Z",
            "platform": "test",
            "adapter_id": "mock0",
            "ssid": "B",
            "band": "2.4",
            "channel": 6,
            "rssi_dbm": -58,
        },
    ]

    recommendations = backend.recommend_channels(records, "2.4", 3)

    assert recommendations[0]["channel"] == 11
