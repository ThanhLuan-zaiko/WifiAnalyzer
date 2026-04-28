from __future__ import annotations

import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path

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


@contextmanager
def _workspace_temp_dir() -> Path:
    path = Path("target") / "test-tmp" / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
