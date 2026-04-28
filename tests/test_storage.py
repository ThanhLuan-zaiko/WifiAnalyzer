from __future__ import annotations

import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path

import polars as pl
from wifianalyzer import storage


def test_ingest_and_summary_roundtrip() -> None:
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

    with _workspace_temp_dir() as data_dir:
        result = storage.ingest_records(records, data_dir)
        summary = storage.history_summary(data_dir)

    assert result["records"] == 1
    assert summary["scan_sessions"] == 1
    assert summary["bands"]["2.4"] == 1


def test_load_records_handles_mixed_raw_structs() -> None:
    with _workspace_temp_dir() as data_dir:
        _write_parquet(
            data_dir,
            "s1",
            {
                "scan_id": "s1",
                "observed_at": "2026-04-27T00:00:00Z",
                "platform": "test",
                "adapter_id": "mock0",
                "ssid": "Old",
                "bssid": "aa:bb:cc:dd:ee:01",
                "band": "2.4",
                "channel": 1,
                "rssi_dbm": -60,
                "raw": {"source": "wlanapi"},
            },
        )
        _write_parquet(
            data_dir,
            "s2",
            {
                "scan_id": "s2",
                "observed_at": "2026-04-27T00:00:00Z",
                "platform": "test",
                "adapter_id": "mock0",
                "ssid": "New",
                "bssid": "aa:bb:cc:dd:ee:02",
                "band": "2.4",
                "channel": 6,
                "rssi_dbm": -50,
                "raw": {
                    "beacon_period": 100,
                    "capability": 5169,
                    "phy_id": 0,
                    "source": "wlanapi",
                },
            },
        )

        records = storage.load_records(data_dir)

    assert {row["ssid"] for row in records} == {"Old", "New"}
    assert records[0]["raw"] is not None


@contextmanager
def _workspace_temp_dir() -> Path:
    path = Path("target") / "test-tmp" / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _write_parquet(data_dir: Path, scan_id: str, record: dict[str, object]) -> None:
    raw_dir = data_dir / "raw" / "date=2026-04-27"
    raw_dir.mkdir(parents=True, exist_ok=True)
    pl.DataFrame([record]).write_parquet(raw_dir / f"{scan_id}.parquet")
