"""Shared fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).parent / "golden"


@pytest.fixture(scope="session")
def golden_dir() -> Path:
    return GOLDEN_DIR


@pytest.fixture(scope="session")
def expected() -> dict:
    return json.loads((GOLDEN_DIR / "expected.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def analysed() -> dict:
    """Every golden capture, analysed once and shared across tests.

    Analysing is the slow part, so it happens once per session. The records are
    read-only in the tests that use them.
    """
    from analyzer.ingest.pcap import read_capture
    from analyzer.scoring.score import assess
    from analyzer.sessions.builder import build_sessions

    out = {}
    for pcap in sorted(GOLDEN_DIR.glob("*.pcapng")):
        records = build_sessions(read_capture(pcap))
        for record in records:
            assess(record)
        out[pcap.stem] = records
    return out
