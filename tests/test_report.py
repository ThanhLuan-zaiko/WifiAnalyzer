from __future__ import annotations

import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path

from wifianalyzer import report, storage


def test_report_json_includes_security_audit() -> None:
    with _workspace_temp_dir() as data_dir:
        storage.ingest_records(
            [
                _record("Guest", "open"),
                _record("Modern", "WPA3"),
            ],
            data_dir,
        )

        result = report.build_report("json", data_dir)

    assert result["summary"]["records"] == 2
    assert result["security_audit"]["records"] == 2
    assert result["security_audit"]["severity_counts"]["critical"] == 1
    assert result["security_audit"]["top_networks"][0]["location"] == "link-layer encryption"


def test_report_markdown_includes_security_section() -> None:
    with _workspace_temp_dir() as data_dir:
        storage.ingest_records([_record("Guest", "open")], data_dir)

        result = report.build_report("md", data_dir)

    assert "## Security Audit" in result["content"]
    assert "Guest" in result["content"]
    assert "Location" in result["content"]


@contextmanager
def _workspace_temp_dir() -> Path:
    path = Path("target") / "test-tmp" / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _record(ssid: str, security_name: str) -> dict[str, object]:
    return {
        "scan_id": "s1",
        "observed_at": "2026-04-27T00:00:00Z",
        "platform": "test",
        "adapter_id": "mock0",
        "ssid": ssid,
        "bssid": f"aa:bb:cc:dd:ee:{len(ssid):02x}",
        "band": "2.4",
        "channel": 1,
        "rssi_dbm": -55,
        "security": security_name,
    }
