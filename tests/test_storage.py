from __future__ import annotations

from pathlib import Path

from wifianalyzer import storage


def test_ingest_and_summary_roundtrip(tmp_path: Path) -> None:
    records = [
        {
            "scan_id": "s1",
            "observed_at": "2026-04-27T00:00:00Z",
            "platform": "test",
            "adapter_id": "mock0",
            "ssid": "Lab",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "band": "2.4",
            "channel": 1,
            "rssi_dbm": -60,
        }
    ]

    result = storage.ingest_records(records, tmp_path)
    summary = storage.history_summary(tmp_path)

    assert result["records"] == 1
    assert summary["scan_sessions"] == 1
    assert summary["bands"]["2.4"] == 1
