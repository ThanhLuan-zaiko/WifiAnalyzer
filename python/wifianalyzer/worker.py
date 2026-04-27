from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import duckdb
import polars as pl
import sklearn

from . import backend, ml, report, security, storage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="wifianalyzer.worker")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor")
    subparsers.add_parser("ingest")

    recommend = subparsers.add_parser("recommend")
    recommend.add_argument("--stdin", action="store_true")
    recommend.add_argument("--band", default="2.4")
    recommend.add_argument("--top", type=int, default=5)

    security_audit = subparsers.add_parser("security-audit")
    security_audit.add_argument("--stdin", action="store_true")
    security_audit.add_argument(
        "--min-severity",
        choices=["info", "low", "medium", "high", "critical"],
        default="info",
    )

    subparsers.add_parser("history-summary")
    subparsers.add_parser("model-train")

    predict = subparsers.add_parser("model-predict")
    predict.add_argument("--stdin", action="store_true")
    predict.add_argument("--band", default="2.4")
    predict.add_argument("--top", type=int, default=5)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--format", choices=["md", "json"], default="md")

    args = parser.parse_args(argv)

    try:
        result = dispatch(args)
    except Exception as error:  # noqa: BLE001 - CLI worker should return compact JSON errors.
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1

    if isinstance(result, str):
        print(result)
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def dispatch(args: argparse.Namespace) -> Any:
    if args.command == "doctor":
        return {
            "duckdb": duckdb.__version__,
            "polars": pl.__version__,
            "sklearn": sklearn.__version__,
            "native_backend": backend.native_available(),
        }

    if args.command == "ingest":
        return storage.ingest_records(_read_records_from_stdin())

    if args.command == "recommend":
        records = _read_records_from_stdin() if args.stdin else storage.load_records()
        return backend.recommend_channels(records, args.band, args.top)

    if args.command == "security-audit":
        records = _read_records_from_stdin() if args.stdin else storage.load_records()
        return security.audit_records(records, args.min_severity)

    if args.command == "history-summary":
        return storage.history_summary()

    if args.command == "model-train":
        return ml.train_channel_model()

    if args.command == "model-predict":
        records = _read_records_from_stdin() if args.stdin else storage.load_records()
        return ml.predict_channels(records, args.band, args.top)

    if args.command == "report":
        return report.build_report(args.format)

    raise ValueError(f"unknown command: {args.command}")


def _read_records_from_stdin() -> list[dict[str, Any]]:
    payload = sys.stdin.read()
    if not payload.strip():
        raise ValueError("expected scan records JSON on stdin")
    records = json.loads(payload)
    if not isinstance(records, list):
        raise ValueError("expected a JSON array of scan records")
    return records


if __name__ == "__main__":
    raise SystemExit(main())
