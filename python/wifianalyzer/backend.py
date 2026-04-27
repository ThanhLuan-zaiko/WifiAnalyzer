from __future__ import annotations

import json
from typing import Any

try:
    from . import wifi_backend as native
except ImportError:  # pragma: no cover - exercised when maturin develop has not run.
    native = None


def native_available() -> bool:
    return native is not None


def normalize_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if native is not None:
        return json.loads(native.normalize_records_json(json.dumps(records)))
    return [_normalize_record(record) for record in records]


def recommend_channels(records: list[dict[str, Any]], band: str, top: int) -> list[dict[str, Any]]:
    if native is not None:
        return json.loads(native.recommend_channels_json(json.dumps(records), band, top))
    return _fallback_recommend(records, band, top)


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(record)
    frequency = normalized.get("frequency_mhz")
    channel = normalized.get("channel")
    band = normalized.get("band")

    if band is None and frequency is not None:
        normalized["band"] = _band_from_frequency(int(frequency))
        band = normalized["band"]
    if channel is None and frequency is not None:
        normalized["channel"] = _channel_from_frequency(int(frequency))
        channel = normalized["channel"]
    if frequency is None and channel is not None and band is not None:
        normalized["frequency_mhz"] = _frequency_from_channel(int(channel), str(band))

    normalized.setdefault("width_mhz", 20)
    if normalized.get("signal_percent") is None and normalized.get("rssi_dbm") is not None:
        rssi = int(normalized["rssi_dbm"])
        normalized["signal_percent"] = max(0, min(100, (rssi + 100) * 2))
    if normalized.get("snr_db") is None:
        rssi = normalized.get("rssi_dbm")
        noise = normalized.get("noise_dbm")
        if rssi is not None and noise is not None:
            normalized["snr_db"] = int(rssi) - int(noise)
    normalized["hidden"] = bool(normalized.get("hidden") or not normalized.get("ssid"))
    return normalized


def _fallback_recommend(records: list[dict[str, Any]], band: str, top: int) -> list[dict[str, Any]]:
    records = normalize_records(records)
    candidates = {
        "2.4": [1, 6, 11],
        "5": [36, 40, 44, 48, 149, 153, 157, 161],
        "6": [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229],
    }.get(band, [])
    rows = []
    for candidate in candidates:
        interference = 0.0
        visible = 0
        strong = 0
        for record in records:
            if record.get("band") != band:
                continue
            overlap = _overlap(record, band, candidate)
            if overlap <= 0:
                continue
            visible += 1
            if record.get("rssi_dbm") is not None and int(record["rssi_dbm"]) >= -67:
                strong += 1
            width_weight = max(1.0, float(record.get("width_mhz") or 20) / 20)
            interference += overlap * _signal_weight(record) * width_weight
        score = round(max(0.0, min(100.0, 100.0 - interference * 18.0)), 2)
        rows.append(
            {
                "band": band,
                "channel": candidate,
                "frequency_mhz": _frequency_from_channel(candidate, band),
                "score": score,
                "interference": round(interference, 2),
                "visible_aps": visible,
                "strong_aps": strong,
                "reason": "native backend unavailable; Python fallback used",
            }
        )
    return sorted(rows, key=lambda row: (-row["score"], row["channel"]))[:top]


def _overlap(record: dict[str, Any], band: str, candidate: int) -> float:
    channel = record.get("channel")
    if channel is None:
        return 0.0
    if band == "2.4":
        gap = abs(int(channel) - candidate)
        return 0.0 if gap >= 5 else 1.0 - gap / 5.0

    frequency = record.get("frequency_mhz")
    candidate_frequency = _frequency_from_channel(candidate, band)
    if frequency is None or candidate_frequency is None:
        return 0.0
    width = max(20.0, float(record.get("width_mhz") or 20))
    half_span = (20.0 + width) / 2.0
    distance = abs(float(frequency) - float(candidate_frequency))
    return 0.0 if distance >= half_span else 1.0 - distance / half_span


def _signal_weight(record: dict[str, Any]) -> float:
    if record.get("rssi_dbm") is not None:
        return max(0.05, min(1.0, (float(record["rssi_dbm"]) + 95.0) / 60.0))
    if record.get("signal_percent") is not None:
        return max(0.05, min(1.0, float(record["signal_percent"]) / 100.0))
    return 0.25


def _band_from_frequency(frequency: int) -> str | None:
    if 2400 <= frequency <= 2500:
        return "2.4"
    if 4900 <= frequency <= 5900:
        return "5"
    if 5925 <= frequency <= 7125:
        return "6"
    return None


def _channel_from_frequency(frequency: int) -> int | None:
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
        return (frequency - 2407) // 5
    if 5005 <= frequency <= 5980 and (frequency - 5000) % 5 == 0:
        return (frequency - 5000) // 5
    if 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
        return (frequency - 5950) // 5
    return None


def _frequency_from_channel(channel: int, band: str) -> int | None:
    if band == "2.4" and channel == 14:
        return 2484
    if band == "2.4" and 1 <= channel <= 13:
        return 2407 + channel * 5
    if band == "5" and 1 <= channel <= 196:
        return 5000 + channel * 5
    if band == "6" and 1 <= channel <= 233:
        return 5950 + channel * 5
    return None
