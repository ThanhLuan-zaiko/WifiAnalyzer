from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
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
    wordlist_terms: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Audit passive WiFi metadata without passwords, handshakes, or active probing."""
    _validate_severity(min_severity)
    normalized_terms = _normalize_wordlist_terms(wordlist_terms or [])
    normalized = backend.normalize_records(records)
    rows = [_audit_record(record, normalized_terms) for record in normalized]
    minimum = SEVERITY_RANK[min_severity]
    return [
        row
        for row in sorted(rows, key=lambda item: (-int(item["risk_score"]), _ssid_key(item)))
        if SEVERITY_RANK[row["severity"]] >= minimum
    ]


def summarize_audit(
    records: list[dict[str, Any]],
    wordlist_terms: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Summarize passive security posture from scan metadata."""
    normalized_terms = _normalize_wordlist_terms(wordlist_terms or [])
    normalized = backend.normalize_records(records)
    rows = [_audit_record(record, normalized_terms) for record in normalized]

    severity_counts = {severity: 0 for severity in SEVERITY_RANK}
    finding_counts: dict[str, int] = {}
    elevated_rows: list[dict[str, Any]] = []

    for row in rows:
        severity_counts[row["severity"]] += 1
        if SEVERITY_RANK[row["severity"]] > SEVERITY_RANK["info"]:
            elevated_rows.append(row)
        for finding in row["findings"]:
            finding_id = str(finding["id"])
            finding_counts[finding_id] = finding_counts.get(finding_id, 0) + 1

    top_rows = sorted(rows, key=lambda item: (-int(item["risk_score"]), _ssid_key(item)))[:5]
    highest_severity = (
        max((row["severity"] for row in rows), key=lambda item: SEVERITY_RANK[item])
        if rows
        else "info"
    )

    return {
        "records": len(normalized),
        "audited_records": len(rows),
        "highest_severity": highest_severity,
        "severity_counts": severity_counts,
        "elevated_records": len(elevated_rows),
        "finding_counts": dict(
            sorted(finding_counts.items(), key=lambda item: (-item[1], item[0]))
        ),
        "top_networks": [
            {
                "ssid": row.get("ssid"),
                "bssid": row.get("bssid"),
                "severity": row["severity"],
                "risk_score": row["risk_score"],
                "location": _primary_location(row["findings"]),
                "source": _primary_source(row["findings"]),
                "evidence": _primary_evidence(row["findings"]),
                "findings": [finding["title"] for finding in row["findings"]],
                "recommendations": row["recommendations"],
            }
            for row in top_rows
            if SEVERITY_RANK[row["severity"]] > SEVERITY_RANK["info"]
        ],
        "recommendations": _unique_recommendations(
            row["recommendations"] for row in elevated_rows or rows
        ),
    }


def load_wordlist_terms(paths: Iterable[str | Path]) -> list[str]:
    """Load passive risk markers from UTF-8 wordlist files.

    The terms are only used for SSID/vendor/default-pattern matching. They are
    not treated as candidate WiFi passwords and are never attempted against a
    network.
    """
    terms: list[str] = []
    seen: set[str] = set()
    for path_value in paths:
        path = Path(path_value)
        if not path.is_file():
            raise ValueError(f"wordlist path is not a file: {path}")
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            term = line.strip()
            if not term or term.startswith("#"):
                continue
            normalized = _normalize_security(term)
            if len(normalized) < 3:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            terms.append(term)
    return terms


def _audit_record(record: dict[str, Any], wordlist_terms: set[str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    security = str(record.get("security") or "").strip()
    ssid = str(record.get("ssid") or "") if record.get("ssid") else None

    findings.extend(_security_findings(security))
    findings.extend(_configuration_findings(record, ssid, wordlist_terms))
    findings.extend(_metadata_findings(record, security))
    findings = [_enrich_finding(finding, record, security, ssid) for finding in findings]

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
        "location": _primary_location(findings),
        "source": _primary_source(findings),
        "evidence": _primary_evidence(findings),
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


def _configuration_findings(
    record: dict[str, Any],
    ssid: str | None,
    wordlist_terms: set[str],
) -> list[dict[str, Any]]:
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

    if ssid and _matches_wordlist_marker(ssid, wordlist_terms):
        findings.append(
            _finding(
                "wordlist_ssid_marker",
                "medium",
                35,
                "SSID matched supplied risk marker",
                "The SSID matched a marker from a supplied wordlist. "
                "Nzig did not observe or test the WiFi password.",
                "Verify the SSID and WiFi passphrase are custom, unique, "
                "and not based on vendor defaults.",
            )
        )

    return findings


def _metadata_findings(record: dict[str, Any], security: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if _has_wps_metadata(record, security):
        findings.append(
            _finding(
                "wps_advertised",
                "high",
                65,
                "WPS advertised",
                "Passive metadata indicates WPS may be enabled. "
                "WPS PIN mode can weaken an otherwise strong WPA2/WPA3 setup.",
                "Disable WPS, especially WPS PIN, and keep router firmware updated.",
            )
        )

    pmf_state = _pmf_state(record, security)
    if pmf_state == "disabled":
        findings.append(
            _finding(
                "pmf_disabled",
                "medium",
                35,
                "Protected management frames disabled",
                "Passive metadata indicates PMF/802.11w is disabled.",
                "Enable PMF where client compatibility allows it.",
            )
        )
    elif pmf_state == "optional":
        findings.append(
            _finding(
                "pmf_optional",
                "low",
                20,
                "Protected management frames optional",
                "Passive metadata indicates PMF/802.11w is optional rather than required.",
                "Require PMF on WPA3-capable networks where all clients support it.",
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


def _enrich_finding(
    finding: dict[str, Any],
    record: dict[str, Any],
    security: str,
    ssid: str | None,
) -> dict[str, Any]:
    enriched = dict(finding)
    finding_id = str(enriched["id"])
    enriched["source"] = _finding_source(finding_id)
    enriched["location"] = _finding_location(finding_id)
    enriched["evidence"] = _finding_evidence(finding_id, record, security, ssid)
    return enriched


def _finding_source(finding_id: str) -> str:
    if finding_id in {
        "open_network",
        "wep",
        "wpa1",
        "tkip",
        "wpa2",
        "transition_mode",
        "wpa3",
        "security_unknown",
        "encryption_details_unavailable",
    }:
        return "security-advertisement"
    if finding_id in {"hidden_ssid", "default_like_ssid", "wordlist_ssid_marker"}:
        return "ssid"
    if finding_id in {"wps_advertised", "pmf_disabled", "pmf_optional"}:
        return "management-metadata"
    return "scan-metadata"


def _finding_location(finding_id: str) -> str:
    locations = {
        "open_network": "link-layer encryption",
        "wep": "link-layer encryption",
        "wpa1": "link-layer encryption",
        "tkip": "cipher suite",
        "wpa2": "security mode",
        "transition_mode": "security mode",
        "wpa3": "security mode",
        "security_unknown": "security field",
        "encryption_details_unavailable": "security field",
        "hidden_ssid": "SSID broadcast behavior",
        "default_like_ssid": "SSID naming",
        "wordlist_ssid_marker": "SSID naming",
        "wps_advertised": "router management metadata",
        "pmf_disabled": "protected management frames metadata",
        "pmf_optional": "protected management frames metadata",
    }
    return locations.get(finding_id, "scan metadata")


def _finding_evidence(
    finding_id: str,
    record: dict[str, Any],
    security: str,
    ssid: str | None,
) -> str:
    if finding_id == "open_network":
        return f"security={security!r}"
    if finding_id in {
        "wep",
        "wpa1",
        "tkip",
        "wpa2",
        "transition_mode",
        "wpa3",
        "security_unknown",
        "encryption_details_unavailable",
    }:
        return f"security={security!r}"
    if finding_id == "hidden_ssid":
        return "ssid missing or hidden"
    if finding_id in {"default_like_ssid", "wordlist_ssid_marker"}:
        return f"ssid={ssid!r}"
    if finding_id == "wps_advertised":
        return f"raw={record.get('raw')!r}"
    if finding_id in {"pmf_disabled", "pmf_optional"}:
        return f"raw={record.get('raw')!r}"
    return f"record keys={sorted(record)}"


def _recommendations(findings: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    recommendations: list[str] = []
    for finding in findings:
        recommendation = str(finding["recommendation"])
        if recommendation not in seen:
            seen.add(recommendation)
            recommendations.append(recommendation)
    return recommendations


def _unique_recommendations(groups: Iterable[Iterable[str]]) -> list[str]:
    seen: set[str] = set()
    recommendations: list[str] = []
    for group in groups:
        for recommendation in group:
            if recommendation in seen:
                continue
            seen.add(recommendation)
            recommendations.append(recommendation)
    return recommendations


def _primary_location(findings: list[dict[str, Any]]) -> str:
    for finding in findings:
        location = str(finding.get("location") or "").strip()
        if location:
            return location
    return "scan metadata"


def _primary_source(findings: list[dict[str, Any]]) -> str:
    for finding in findings:
        source = str(finding.get("source") or "").strip()
        if source:
            return source
    return "scan-metadata"


def _primary_evidence(findings: list[dict[str, Any]]) -> str:
    for finding in findings:
        evidence = str(finding.get("evidence") or "").strip()
        if evidence:
            return evidence
    return "scan metadata"


def _password_risk(security: str, findings: list[dict[str, Any]]) -> dict[str, str]:
    finding_ids = {str(finding["id"]) for finding in findings}
    if "open_network" in finding_ids:
        return {
            "level": "not_applicable",
            "reason": "The network is open; no WiFi password strength can be inferred.",
        }
    if "default_like_ssid" in finding_ids or "wordlist_ssid_marker" in finding_ids:
        return {
            "level": "possible_default_or_weak",
            "reason": "Default-like SSIDs or supplied risk markers can indicate unchanged "
            "router defaults, but Nzig did not observe or test a password.",
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


def _matches_wordlist_marker(ssid: str, wordlist_terms: set[str]) -> bool:
    if not wordlist_terms:
        return False
    normalized_ssid = _normalize_security(ssid)
    return any(term in normalized_ssid for term in wordlist_terms)


def _normalize_wordlist_terms(terms: Iterable[str]) -> set[str]:
    normalized_terms: set[str] = set()
    for term in terms:
        normalized = _normalize_security(str(term))
        if len(normalized) >= 3:
            normalized_terms.add(normalized)
    return normalized_terms


def _has_wps_metadata(record: dict[str, Any], security: str) -> bool:
    if "wps" in _normalize_security(security):
        return True

    for key, value in _metadata_pairs(record.get("raw")):
        normalized_key = _normalize_security(key)
        normalized_value = _normalize_security(str(value))
        if "wps" in normalized_key and _is_enabled_value(value):
            return True
        if normalized_key in {"security", "capabilities", "informationelements", "flags", "line"}:
            if "wps" in normalized_value:
                return True
    return False


def _pmf_state(record: dict[str, Any], security: str) -> str | None:
    for text in (security,):
        state = _pmf_state_from_text(text)
        if state:
            return state

    for key, value in _metadata_pairs(record.get("raw")):
        normalized_key = _normalize_security(key)
        if any(marker in normalized_key for marker in ("pmf", "mfp", "80211w", "ieee80211w")):
            state = _pmf_state_from_value(value)
            if state:
                return state
        if normalized_key in {"security", "capabilities", "informationelements", "flags", "line"}:
            state = _pmf_state_from_text(str(value))
            if state:
                return state
    return None


def _pmf_state_from_value(value: Any) -> str | None:
    if value is True:
        return None
    if value is False or value is None:
        return "disabled"
    normalized = _normalize_security(str(value))
    if normalized in {"0", "false", "no", "off", "disabled", "disable", "none"}:
        return "disabled"
    if normalized in {"optional", "capable", "supported", "allowed"}:
        return "optional"
    return _pmf_state_from_text(str(value))


def _pmf_state_from_text(value: str) -> str | None:
    normalized = _normalize_security(value)
    if not any(marker in normalized for marker in ("pmf", "mfp", "80211w", "ieee80211w")):
        return None
    if any(
        marker in normalized
        for marker in ("disabled", "disable", "off", "false", "none", "no")
    ):
        return "disabled"
    if any(marker in normalized for marker in ("optional", "capable", "supported", "allowed")):
        return "optional"
    return None


def _is_enabled_value(value: Any) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, dict):
        return any(_is_enabled_value(child) for child in value.values())
    if isinstance(value, list):
        return any(_is_enabled_value(child) for child in value)
    normalized = _normalize_security(str(value))
    return normalized not in {"", "0", "false", "no", "off", "disabled", "none"}


def _metadata_pairs(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_prefix = f"{prefix}.{key_text}" if prefix else key_text
            yield child_prefix, child
            yield from _metadata_pairs(child, child_prefix)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_prefix = f"{prefix}.{index}" if prefix else str(index)
            yield child_prefix, child
            yield from _metadata_pairs(child, child_prefix)


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
