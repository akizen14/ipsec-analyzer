"""Local report history shared by the dashboard and existing CLI results."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PureWindowsPath
from tempfile import NamedTemporaryFile
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken

from analyzer.record import SessionRecord

MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_ENCRYPTED_BYTES = 12 * 1024 * 1024


def directory() -> Path:
    return Path(os.environ.get("IPSEC_ANALYZER_REPORT_DIR") or Path.home() / ".ipsec-analyzer" / "reports")


def report_cipher() -> Fernet | None:
    key_path = os.environ.get("IPSEC_ANALYZER_REPORT_KEY_FILE")
    if key_path is None:
        return None
    try:
        with Path(key_path).open("rb") as key_file:
            key = key_file.read(128).strip()
        return Fernet(key)
    except (OSError, ValueError) as error:
        raise ValueError("IPSEC_ANALYZER_REPORT_KEY_FILE must point to a readable Fernet key.") from error


def save(capture: dict, records: list[dict], *, example: bool, seconds: float) -> dict:
    entry = {
        "id": uuid4().hex,
        "saved_at": datetime.now(UTC).isoformat(),
        "source": "example" if example else "capture",
        "processing_seconds": seconds,
        "capture": capture,
        "records": records,
    }
    archive = directory()
    archive.mkdir(mode=0o700, parents=True, exist_ok=True)
    contents = json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode()
    if len(contents) > MAX_RECORD_BYTES:
        raise OSError("Assessment exceeds the archive size limit")
    cipher = report_cipher()
    if cipher is not None:
        contents = cipher.encrypt(contents)
    extension = ".enc" if cipher is not None else ".json"
    # Publish the complete run at once, including when several requests finish together.
    temporary = None
    try:
        with NamedTemporaryFile(
            dir=archive, prefix=".assessment-", mode="wb", delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(contents)
        temporary.replace(archive / f"{entry['id']}{extension}")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return entry


def _read_data(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(path)
    with path.open("rb") as source:
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Saved record exceeds the size limit")
    return data


def _read_entry(path: Path) -> dict:
    if path.suffix == ".enc":
        raw = _read_data(path, MAX_ENCRYPTED_BYTES)
        cipher = report_cipher()
        if cipher is None:
            raise ValueError("An archive key is required")
        try:
            data = cipher.decrypt(raw)
        except InvalidToken as error:
            raise ValueError("This archived report could not be decrypted") from error
    else:
        data = _read_data(path, MAX_RECORD_BYTES)
    entry = json.loads(data)
    if entry["id"] != path.stem or not isinstance(entry["records"], list) or not entry["records"]:
        raise ValueError("Invalid saved assessment")
    return entry


def _cli_id(path: Path) -> str:
    return "cli-" + sha256(path.name.encode()).hexdigest()[:32]


def _cli_entry(path: Path) -> dict:
    record = SessionRecord.from_json(json.loads(_read_data(path, MAX_RECORD_BYTES)))
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
    archive = directory()
    sources = [
        (archive.glob("*.json"), _read_entry),
        (archive.glob("*.enc"), _read_entry),
        (Path("results").glob("*.json"), _cli_entry),
    ]
    for paths, read in sources:
        for path in paths:
            try:
                entry = read(path)
                records = entry["records"]
                risks = ("low", "medium", "high", "critical")
                saved_at = entry["saved_at"]
                if not isinstance(saved_at, str):
                    raise ValueError("Invalid assessment timestamp")
                entries.append({
                    "id": entry["id"],
                    "name": entry["capture"]["name"],
                    "source": entry["source"],
                    "saved_at": saved_at,
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
    archive = directory()
    try:
        return _read_entry(archive / f"{entry_id}.enc")
    except FileNotFoundError:
        return _read_entry(archive / f"{entry_id}.json")
