"""Turn the analyzer's session record into a normalised prediction (PLAN.md E3).

One call per capture. Unknown is a valid prediction and is kept as None with
its evidence level, never dropped.
"""

from __future__ import annotations

from pathlib import Path

from analyzer.ingest.pcap import read_capture
from analyzer.scoring.score import assess
from analyzer.sessions.builder import build_sessions


def _v(attr):
    return None if attr is None or attr.evidence == "unknown" else attr.value


def _ev(attr):
    return "unknown" if attr is None else attr.evidence


def predict(capture: Path) -> dict:
    """IKE fields, score and per-SA ESP predictions for the capture's one session."""
    records = build_sessions(read_capture(capture))
    if len(records) != 1:
        raise ValueError(f"{capture}: expected one session, found {len(records)}")
    record = assess(records[0])
    ike = record.ike
    pfs = record.child_sas[0].pfs_on_rekey if record.child_sas else None
    return {
        "ike": {"encr": _v(ike.encr), "encr_key_bits": _v(ike.encr_key_bits),
                "integ": _v(ike.integ), "prf": _v(ike.prf), "dh_group": _v(ike.dh_group)},
        "pfs": _v(pfs), "pfs_evidence": _ev(pfs),
        "pfs_groups": ((pfs.features or {}).get("key_exchange_groups_fitting", "")
                       if pfs is not None and pfs.evidence == "inferred" else ""),
        "score": record.score.value,
        "risk": record.score.risk_level,
        "sas": [
            {"sa_spi": sa.spi,
             "cipher_family": _v(sa.cipher_family), "cipher_family_evidence": _ev(sa.cipher_family),
             "icv_bytes": _v(sa.icv_bytes), "icv_evidence": _ev(sa.icv_bytes),
             "mode": _v(sa.mode), "mode_evidence": _ev(sa.mode),
             "confidence": sa.mode.confidence if sa.mode else 0.0,
             "packets": sa.packet_count}
            for sa in record.child_sas if sa.protocol.value == "ESP"
        ],
    }
