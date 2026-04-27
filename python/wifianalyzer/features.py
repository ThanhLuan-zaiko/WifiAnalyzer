from __future__ import annotations

from typing import Any

import polars as pl

from . import backend

BAND_CODE = {"2.4": 24, "5": 50, "6": 60}


def candidate_features(
    records: list[dict[str, Any]],
    band: str,
) -> tuple[pl.DataFrame, list[dict[str, Any]]]:
    recommendations = backend.recommend_channels(records, band, 999)
    rows = [
        {
            "band_code": BAND_CODE.get(row["band"], 0),
            "channel": row["channel"],
            "frequency_mhz": row["frequency_mhz"],
            "interference": row["interference"],
            "visible_aps": row["visible_aps"],
            "strong_aps": row["strong_aps"],
            "score": row["score"],
        }
        for row in recommendations
    ]
    return pl.DataFrame(rows), recommendations
