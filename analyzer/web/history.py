"""Local report history shared by the dashboard and existing CLI results."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PureWindowsPath
from tempfile import NamedTemporaryFile
from uuid import uuid4

from analyzer.record import SessionRecord


def _directory() -> Path:
    return Path(os.environ.get("IPSEC_ANALYZER_REPORT_DIR") or Path.home() / ".ipsec-analyzer" / "reports")


def save(capture: dict, records: list[dict], *, example: bool, seconds: float) -> dict:
    entry = {
        "id": uuid4().hex,
        "saved_at": datetime.now(UTC).isoformat(),
        "source": "example" if example else "capture",
        "processing_seconds": seconds,
        "capture": capture,
        "records": records,
    }
    directory = _directory()
    directory.mkdir(parents=True, exist_ok=True)
    # Publish the complete run at once, including when several requests finish together.
    temporary = None
    try:
        with NamedTemporaryFile(
            dir=directory, prefix=".assessment-", encoding="utf-8", mode="w", delete=False,
        ) as output:
            temporary = Path(output.name)
            json.dump(entry, output, ensure_ascii=False, separators=(",", ":"))
        temporary.replace(directory / f"{entry['id']}.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return entry


def _read_entry(path: Path) -> dict:
    entry = json.loads(path.read_text(encoding="utf-8"))
    if entry["id"] != path.stem or not entry["records"]:
        raise ValueError("Invalid saved assessment")
    return entry


def _cli_id(path: Path) -> str:
    return "cli-" + sha256(path.name.encode()).hexdigest()[:32]


def _cli_entry(path: Path) -> dict:
    record = SessionRecord.load(path)
    if record.score is None:
        raise ValueError("The CLI record has no assessment")
    return {
        "id": _cli_id(path),
        "saved_at": record.generated_at or datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat(),
        "source": "cli",
        "processing_seconds": None,
        "capture": {
            "name": PureWindowsPath(record.source.path or "").name or path.name,
            "summary": f"{record.source.packet_count:,} packets in this session",
            "warnings": record.warnings,
        },
        "records": [record.to_json()],
    }


def list_entries() -> tuple[list[dict], int]:
    entries = []
    unreadable = 0
    sources = [(_directory().glob("*.json"), _read_entry), (Path("results").glob("*.json"), _cli_entry)]
    for paths, read in sources:
        for path in paths:
            try:
                entry = read(path)
                records = entry["records"]
                risks = ("low", "medium", "high", "critical")
                entries.append({
                    "id": entry["id"],
                    "name": entry["capture"]["name"],
                    "source": entry["source"],
                    "saved_at": entry["saved_at"],
                    "processing_seconds": entry["processing_seconds"],
                    "session_count": len(records),
                    "worst_risk": max((row["score"]["risk_level"] for row in records), key=risks.index),
                    "partial": any(row["source"].get("truncated", False) for row in records),
                })
            except (OSError, ValueError, KeyError, TypeError):
                unreadable += 1
    return sorted(entries, key=lambda row: row["saved_at"], reverse=True), unreadable


def load(entry_id: str) -> dict:
    if entry_id.startswith("cli-"):
        for path in Path("results").glob("*.json"):
            if _cli_id(path) == entry_id:
                return _cli_entry(path)
        raise FileNotFoundError(entry_id)
    return _read_entry(_directory() / f"{entry_id}.json")
