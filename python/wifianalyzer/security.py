from __future__ import annotations

from typing import Any

from . import backend

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_SSID_MARKERS = (
    "asus",
    "belkin",
    "d-link",
    "dlink",
    "fpt",
    "linksys",
    "netgear",
    "tplink",
    "tp-link",
    "tenda",
    "viettel",
    "vnpt",
    "xiaomi",
)


def audit_records(
    records: list[dict[str, Any]],
    min_severity: str = "info",
) -> list[dict[str, Any]]:
    """Audit passive WiFi metadata without passwords, handshakes, or active probing."""
    _validate_severity(min_severity)
    normalized = backend.normalize_records(records)
    rows = [_audit_record(record) for record in normalized]
    minimum = SEVERITY_RANK[min_severity]
    return [
        row
        for row in sorted(rows, key=lambda item: (-int(item["risk_score"]), _ssid_key(item)))
        if SEVERITY_RANK[row["severity"]] >= minimum
    ]


def _audit_record(record: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    security = str(record.get("security") or "").strip()
    ssid = str(record.get("ssid") or "") if record.get("ssid") else None

    findings.extend(_security_findings(security))
    findings.extend(_configuration_findings(record, ssid))

    if not findings:
        findings.append(
            _finding(
                "no_high_risk_metadata",
                "info",
                5,
                "No high-risk metadata observed",
                "Scan metadata does not show open, legacy, or clearly weak security.",
                "Confirm router settings still use a unique WPA2/WPA3 passphrase.",
            )
        )

    risk_score = min(100, sum(int(item["score"]) for item in findings))
    severity = _severity_from_findings(findings)

    return {
        "ssid": ssid,
        "bssid": record.get("bssid"),
        "band": record.get("band"),
        "channel": record.get("channel"),
        "rssi_dbm": record.get("rssi_dbm"),
        "security": security or None,
        "severity": severity,
        "risk_score": risk_score,
        "findings": findings,
        "recommendations": _recommendations(findings),
        "password_risk": _password_risk(security, findings),
    }


def _security_findings(security: str) -> list[dict[str, Any]]:
    if not security:
        return [
            _finding(
                "security_unknown",
                "medium",
                45,
                "Security mode unavailable",
                "The scan did not expose encryption details for this access point.",
                "Inspect the router or client connection details and prefer WPA3 or WPA2-AES.",
            )
        ]

    normalized = _normalize_security(security)
    findings: list[dict[str, Any]] = []

    if _is_open_security(normalized):
        findings.append(
            _finding(
                "open_network",
                "critical",
                95,
                "Open network",
                "The access point advertises no link-layer encryption.",
                "Enable WPA3-Personal or WPA2-AES with a unique passphrase.",
            )
        )
        return findings

    if "wep" in normalized:
        findings.append(
            _finding(
                "wep",
                "high",
                85,
                "Legacy WEP security",
                "WEP is cryptographically broken and should not be used.",
                "Replace WEP with WPA3-Personal or WPA2-AES.",
            )
        )

    if _has_wpa1(normalized):
        findings.append(
            _finding(
                "wpa1",
                "high",
                75,
                "Legacy WPA security",
                "WPA/TKIP-era security is obsolete compared with WPA2-AES or WPA3.",
                "Disable WPA/WPA1 compatibility and use WPA3 or WPA2-AES.",
            )
        )

    if "tkip" in normalized:
        findings.append(
            _finding(
                "tkip",
                "high",
                70,
                "TKIP cipher advertised",
                "TKIP is a legacy cipher and weakens the network configuration.",
                "Use AES/CCMP only.",
            )
        )

    if normalized in {"secured", "secure"}:
        findings.append(
            _finding(
                "encryption_details_unavailable",
                "medium",
                40,
                "Encryption details unavailable",
                "The platform only reported that the network is secured, "
                "not the WPA mode or cipher.",
                "Verify the router is configured for WPA3 or WPA2-AES.",
            )
        )
    elif "wpa2" in normalized and "wpa3" not in normalized:
        findings.append(
            _finding(
                "wpa2",
                "low",
                15,
                "WPA2 network",
                "WPA2 is acceptable when paired with AES and a unique passphrase.",
                "Prefer WPA3 where available and disable TKIP.",
            )
        )
    elif "wpa2" in normalized and "wpa3" in normalized:
        findings.append(
            _finding(
                "transition_mode",
                "low",
                20,
                "WPA2/WPA3 transition mode",
                "Transition mode improves compatibility but can be weaker than WPA3-only.",
                "Use WPA3-only where all clients support it.",
            )
        )
    elif "wpa3" in normalized:
        findings.append(
            _finding(
                "wpa3",
                "info",
                5,
                "WPA3 network",
                "The access point advertises modern WPA3 security.",
                "Keep firmware updated and use a unique passphrase.",
            )
        )

    return findings


def _configuration_findings(record: dict[str, Any], ssid: str | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if bool(record.get("hidden")):
        findings.append(
            _finding(
                "hidden_ssid",
                "info",
                5,
                "Hidden SSID",
                "Hidden SSIDs are not a meaningful security control.",
                "Rely on WPA2/WPA3 security instead of SSID hiding.",
            )
        )

    if ssid and _looks_default_ssid(ssid):
        findings.append(
            _finding(
                "default_like_ssid",
                "medium",
                35,
                "Default-like SSID",
                "The SSID resembles a vendor or ISP default naming pattern.",
                "Use a custom SSID and verify the WiFi passphrase is unique.",
            )
        )

    return findings


def _finding(
    finding_id: str,
    severity: str,
    score: int,
    title: str,
    detail: str,
    recommendation: str,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "score": score,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    }


def _recommendations(findings: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    recommendations: list[str] = []
    for finding in findings:
        recommendation = str(finding["recommendation"])
        if recommendation not in seen:
            seen.add(recommendation)
            recommendations.append(recommendation)
    return recommendations


def _password_risk(security: str, findings: list[dict[str, Any]]) -> dict[str, str]:
    finding_ids = {str(finding["id"]) for finding in findings}
    if "open_network" in finding_ids:
        return {
            "level": "not_applicable",
            "reason": "The network is open; no WiFi password strength can be inferred.",
        }
    if "default_like_ssid" in finding_ids:
        return {
            "level": "possible_default_or_weak",
            "reason": "Default-like SSIDs can indicate unchanged router defaults, "
            "but Nzig did not observe a password.",
        }
    if security:
        return {
            "level": "unknown",
            "reason": "Passive scan metadata cannot prove whether the WiFi password "
            "is strong or weak.",
        }
    return {
        "level": "unknown",
        "reason": "Security metadata is unavailable, so password strength cannot be inferred.",
    }


def _severity_from_findings(findings: list[dict[str, Any]]) -> str:
    return max(
        (str(finding["severity"]) for finding in findings),
        key=lambda item: SEVERITY_RANK[item],
    )


def _looks_default_ssid(ssid: str) -> bool:
    normalized = _normalize_security(ssid)
    return any(marker in normalized for marker in DEFAULT_SSID_MARKERS)


def _normalize_security(value: str) -> str:
    return (
        value.strip()
        .casefold()
        .replace("_", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("/", "")
    )


def _is_open_security(normalized: str) -> bool:
    return normalized in {"open", "none", "unencrypted", "unsecured", "opn", "--"}


def _has_wpa1(normalized: str) -> bool:
    return "wpa" in normalized and "wpa2" not in normalized and "wpa3" not in normalized


def _ssid_key(row: dict[str, Any]) -> str:
    return str(row.get("ssid") or row.get("bssid") or "")


def _validate_severity(severity: str) -> None:
    if severity not in SEVERITY_RANK:
        choices = ", ".join(SEVERITY_RANK)
        raise ValueError(f"unknown severity {severity!r}; expected one of: {choices}")
