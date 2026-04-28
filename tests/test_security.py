from __future__ import annotations

import io
import json
import shutil
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
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


def test_security_audit_uses_wordlist_as_passive_risk_markers() -> None:
    rows = security.audit_records(
        [_record("Internal-Router-Default", "WPA2")],
        wordlist_terms=["router default", "x"],
    )

    row = rows[0]
    assert "wordlist_ssid_marker" in _finding_ids(row)
    assert row["password_risk"]["level"] == "possible_default_or_weak"


def test_security_audit_flags_wps_and_pmf_metadata() -> None:
    record = _record("Office", "WPA2")
    record["raw"] = {"wps": {"enabled": True}, "pmf": "optional"}

    rows = security.audit_records([record])

    assert _finding_ids(rows[0]) >= {"wps_advertised", "pmf_optional"}
    assert rows[0]["severity"] == "high"
    assert rows[0]["location"] in {
        "security mode",
        "router management metadata",
    }
    assert rows[0]["evidence"]


def test_security_summary_counts_risk_levels_and_recommendations() -> None:
    summary = security.summarize_audit(
        [
            _record("Guest", "open"),
            _record("Modern", "WPA3"),
        ]
    )

    assert summary["records"] == 2
    assert summary["audited_records"] == 2
    assert summary["severity_counts"]["critical"] == 1
    assert summary["severity_counts"]["info"] == 1
    assert summary["elevated_records"] == 1
    assert summary["top_networks"][0]["ssid"] == "Guest"
    assert "Enable WPA3-Personal or WPA2-AES with a unique passphrase." in summary[
        "recommendations"
    ]


def test_worker_security_audit_reads_stdin(monkeypatch: Any, capsys: Any) -> None:
    payload = json.dumps([_record("Guest", "open"), _record("Office", "WPA2")])
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))

    exit_code = worker.main(["security-audit", "--stdin", "--min-severity", "high"])

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert exit_code == 0
    assert [row["ssid"] for row in rows] == ["Guest"]


def test_worker_security_audit_loads_wordlist(monkeypatch: Any, capsys: Any) -> None:
    with _workspace_temp_dir() as temp_dir:
        wordlist = temp_dir / "security_markers.txt"
        wordlist.write_text("# markers\nrouter default\ntplink\n", encoding="utf-8")
        payload = json.dumps([_record("Corp-Router-Default", "WPA2")])
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))

        exit_code = worker.main(
            ["security-audit", "--stdin", "--wordlist", str(wordlist), "--min-severity", "medium"]
        )

        captured = capsys.readouterr()

    rows = json.loads(captured.out)
    assert exit_code == 0
    assert [row["ssid"] for row in rows] == ["Corp-Router-Default"]
    assert "wordlist_ssid_marker" in _finding_ids(rows[0])
    wordlist_finding = next(
        finding for finding in rows[0]["findings"] if finding["id"] == "wordlist_ssid_marker"
    )
    assert wordlist_finding["location"] == "SSID naming"


@contextmanager
def _workspace_temp_dir() -> Any:
    path = Path("target") / "test-tmp" / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


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
