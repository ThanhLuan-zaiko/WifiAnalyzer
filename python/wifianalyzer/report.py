from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import backend, storage


def build_report(format_name: str, data_dir: Path | None = None) -> dict[str, Any]:
    data_dir = data_dir or storage.default_data_dir()
    records = storage.load_records(data_dir)
    summary = storage.history_summary(data_dir)
    recommendations = {
        band: backend.recommend_channels([r for r in records if r.get("band") == band], band, 3)
        for band in ("2.4", "5", "6")
    }

    if format_name == "json":
        return {"summary": summary, "recommendations": recommendations}

    content = _markdown(summary, recommendations)
    report_dir = data_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"wifi-report-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(content, encoding="utf-8")
    return {"path": str(path), "content": content}


def _markdown(summary: dict[str, Any], recommendations: dict[str, list[dict[str, Any]]]) -> str:
    lines = [
        "# WifiAnalyzer Report",
        "",
        f"- Scan sessions: {summary['scan_sessions']}",
        f"- Records: {summary['records']}",
        f"- Latest observed at: {summary['latest_observed_at']}",
        "",
    ]
    for band, rows in recommendations.items():
        lines.append(f"## Band {band} GHz")
        if not rows:
            lines.append("")
            lines.append("No data.")
            lines.append("")
            continue
        lines.append("")
        lines.append("| Channel | Score | Interference | Reason |")
        lines.append("| --- | ---: | ---: | --- |")
        for row in rows:
            lines.append(
                f"| {row['channel']} | {row['score']} | {row['interference']} | {row['reason']} |"
            )
        lines.append("")
    return "\n".join(lines)
