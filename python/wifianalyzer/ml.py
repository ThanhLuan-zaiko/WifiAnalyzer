from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import polars as pl
from sklearn.ensemble import RandomForestRegressor

from . import backend, features, storage

MODEL_NAME = "channel_recommender.joblib"
FEATURE_COLUMNS = [
    "band_code",
    "channel",
    "frequency_mhz",
    "interference",
    "visible_aps",
    "strong_aps",
]


def train_channel_model(data_dir: Path | None = None) -> dict[str, Any]:
    data_dir = data_dir or storage.default_data_dir()
    records = storage.load_records(data_dir)
    if not records:
        raise ValueError("no scan history available; run `wifi-analyzer scan --save` first")

    frames = []
    for band in ("2.4", "5", "6"):
        band_records = [record for record in records if record.get("band") == band]
        if not band_records:
            continue
        frame, _ = features.candidate_features(band_records, band)
        if frame.height:
            frames.append(frame)

    if not frames:
        raise ValueError("scan history has no usable band/channel records")

    training = pl.concat(frames, how="diagonal").drop_nulls(FEATURE_COLUMNS + ["score"])
    if training.height < 3:
        raise ValueError("not enough channel candidates to train model")

    x = training.select(FEATURE_COLUMNS).to_numpy()
    y = training.select("score").to_numpy().ravel()
    model = RandomForestRegressor(n_estimators=128, random_state=42, min_samples_leaf=1)
    model.fit(x, y)

    model_dir = data_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / MODEL_NAME
    joblib.dump(model, model_path)

    return {
        "model_path": str(model_path),
        "training_rows": training.height,
        "features": FEATURE_COLUMNS,
    }


def predict_channels(
    records: list[dict[str, Any]],
    band: str,
    top: int,
    data_dir: Path | None = None,
) -> list[dict[str, Any]]:
    data_dir = data_dir or storage.default_data_dir()
    model_path = data_dir / "models" / MODEL_NAME
    if not model_path.exists():
        return backend.recommend_channels(records, band, top)

    frame, recommendations = features.candidate_features(records, band)
    if frame.is_empty():
        return []

    model = joblib.load(model_path)
    predictions = model.predict(frame.select(FEATURE_COLUMNS).to_numpy())
    ranked = []
    for row, predicted_score in zip(recommendations, predictions, strict=True):
        updated = dict(row)
        updated["score"] = round(float(predicted_score), 2)
        updated["reason"] = f"ML model score; baseline: {row['reason']}"
        ranked.append(updated)
    return sorted(ranked, key=lambda row: (-row["score"], row["channel"]))[:top]
