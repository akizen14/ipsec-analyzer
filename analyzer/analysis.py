"""Shared entry point for passive capture analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from analyzer.ingest.pcap import read_capture
from analyzer.record import SessionRecord
from analyzer.record.validate import validate
from analyzer.scoring.score import assess
from analyzer.sessions.builder import build_sessions


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    capture_summary: str
    warnings: tuple[str, ...]
    records: tuple[SessionRecord, ...]
    packet_count: int


def analyse_capture(path: str | Path, *, max_packets: int | None = None) -> AnalysisResult:
    """Read a capture and return assessed, schema-validated session records."""
    capture = read_capture(path, max_packets=max_packets)
    records = build_sessions(capture)
    for record in records:
        assess(record)
        validate(record)
    return AnalysisResult(
        capture.summary(), tuple(capture.warnings), tuple(records), capture.packet_count
    )
