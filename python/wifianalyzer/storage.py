from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb
import polars as pl

from . import backend


def default_data_dir() -> Path:
    return Path(os.environ.get("NZIG_DATA_DIR") or os.environ.get("WIFI_ANALYZER_DATA_DIR", "data"))


def ingest_records(records: list[dict[str, Any]], data_dir: Path | None = None) -> dict[str, Any]:
    data_dir = data_dir or default_data_dir()
    records = backend.normalize_records(records)
    if not records:
        raise ValueError("no records to ingest")

    scan_id = records[0]["scan_id"]
    observed_at = records[0].get("observed_at") or datetime.now(UTC).isoformat()
    date_key = observed_at[:10]
    raw_dir = data_dir / "raw" / f"date={date_key}"
    raw_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = raw_dir / f"{scan_id}.parquet"

    frame = pl.DataFrame(records)
    frame.write_parquet(parquet_path)

    _register_session(data_dir, scan_id, observed_at, parquet_path, len(records))
    return {
        "scan_id": scan_id,
        "records": len(records),
        "parquet_path": str(parquet_path),
        "duckdb_path": str(_duckdb_path(data_dir)),
    }


def load_records(data_dir: Path | None = None) -> list[dict[str, Any]]:
    data_dir = data_dir or default_data_dir()
    files = sorted((data_dir / "raw").rglob("*.parquet"))
    if not files:
        return []

    raw_glob = (data_dir / "raw" / "**" / "*.parquet").as_posix()
    connection = duckdb.connect()
    try:
        cursor = connection.execute(
            f"""
            SELECT * EXCLUDE (date)
            FROM read_parquet('{raw_glob}', union_by_name = true)
            """
        )
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row, strict=False)) for row in cursor.fetchall()]
    finally:
        connection.close()


def history_summary(data_dir: Path | None = None) -> dict[str, Any]:
    records = load_records(data_dir)
    if not records:
        return {"scan_sessions": 0, "records": 0, "bands": {}, "latest_observed_at": None}

    frame = pl.DataFrame(records)
    bands = (
        frame.group_by("band")
        .len()
        .sort("band")
        .rename({"len": "records"})
        .to_dicts()
    )
    return {
        "scan_sessions": frame.select(pl.col("scan_id").n_unique()).item(),
        "records": frame.height,
        "bands": {row["band"] or "unknown": row["records"] for row in bands},
        "latest_observed_at": frame.select(pl.col("observed_at").max()).item(),
    }


def _register_session(
    data_dir: Path,
    scan_id: str,
    observed_at: str,
    parquet_path: Path,
    record_count: int,
) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(str(_duckdb_path(data_dir)))
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                scan_id VARCHAR PRIMARY KEY,
                observed_at VARCHAR,
                parquet_path VARCHAR,
                record_count INTEGER,
                ingested_at TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            INSERT OR REPLACE INTO scan_sessions
            VALUES (?, ?, ?, ?, current_timestamp)
            """,
            [scan_id, observed_at, str(parquet_path), record_count],
        )
        raw_glob = (data_dir / "raw" / "**" / "*.parquet").as_posix()
        connection.execute(
            f"""
            CREATE OR REPLACE VIEW scan_records AS
            SELECT * FROM read_parquet('{raw_glob}', union_by_name = true)
            """
        )
    finally:
        connection.close()


def _duckdb_path(data_dir: Path) -> Path:
    return data_dir / "wifi.duckdb"
