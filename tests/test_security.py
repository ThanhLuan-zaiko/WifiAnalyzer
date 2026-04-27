from __future__ import annotations

import io
import json
import sys
from typing import Any

from wifianalyzer import security, worker


def test_security_audit_flags_open_legacy_and_default_like_networks() -> None:
    rows = security.audit_records(
        [
            _record("Guest", "open"),
            _record("Printer", "WEP"),
            _record("TP-Link_1234", "WPA2"),
            _record("Modern", "WPA3"),
        ]
    )

    by_ssid = {row["ssid"]: row for row in rows}

    assert by_ssid["Guest"]["severity"] == "critical"
    assert by_ssid["Guest"]["password_risk"]["level"] == "not_applicable"
    assert _finding_ids(by_ssid["Guest"]) == {"open_network"}

    assert by_ssid["Printer"]["severity"] == "high"
    assert "wep" in _finding_ids(by_ssid["Printer"])

    assert by_ssid["TP-Link_1234"]["severity"] == "medium"
    assert "default_like_ssid" in _finding_ids(by_ssid["TP-Link_1234"])
    assert by_ssid["TP-Link_1234"]["password_risk"]["level"] == "possible_default_or_weak"

    assert by_ssid["Modern"]["severity"] == "info"
    assert _finding_ids(by_ssid["Modern"]) == {"wpa3"}


def test_security_audit_filters_by_minimum_severity() -> None:
    rows = security.audit_records(
        [
            _record("Guest", "open"),
            _record("Office", "WPA2"),
            _record("Modern", "WPA3"),
        ],
        min_severity="high",
    )

    assert [row["ssid"] for row in rows] == ["Guest"]


def test_worker_security_audit_reads_stdin(monkeypatch: Any, capsys: Any) -> None:
    payload = json.dumps([_record("Guest", "open"), _record("Office", "WPA2")])
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))

    exit_code = worker.main(["security-audit", "--stdin", "--min-severity", "high"])

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert exit_code == 0
    assert [row["ssid"] for row in rows] == ["Guest"]


def _record(ssid: str, security_name: str) -> dict[str, Any]:
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


def _finding_ids(row: dict[str, Any]) -> set[str]:
    return {finding["id"] for finding in row["findings"]}
