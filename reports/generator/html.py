"""Render a session record as HTML.

Two reports, from one record and one template set:

* **technical** - every attribute with its evidence level, every finding with its
  standard reference, the threat matrix, and an appendix of what could not be
  determined and why.
* **executive** - one to two pages: posture in a sentence, the score, the top
  three risks in plain language, and what to do about them.

Everything is inlined and nothing is fetched at view time, so a report opens on
an air-gapped machine (VISION.md principle 6).

The templates read the record and nothing else. No finding, number or verdict is
computed here, so a report cannot disagree with the record it came from.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from analyzer.record import SessionRecord

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"

#: How each evidence level is presented. The wording is deliberately plain: a
#: reader who has not read VISION.md still needs to know how far to trust a row.
EVIDENCE_LABELS: dict[str, tuple[str, str]] = {
    "observed": ("Observed", "Read directly from a cleartext protocol field"),
    "inferred": ("Inferred", "Derived from traffic metadata, with a confidence"),
    "assisted": ("Assisted", "Read from material supplied by the operator"),
    "unknown": ("Unknown", "Not determinable from the available evidence"),
}

#: Attribute order for the configuration table, so two reports of different
#: deployments can be read side by side.
IKE_FIELD_ORDER: tuple[tuple[str, str], ...] = (
    ("version", "IKE version"),
    ("exchange_mode", "Exchange mode"),
    ("encr", "IKE encryption"),
    ("encr_key_bits", "IKE key length"),
    ("prf", "IKE PRF"),
    ("integ", "IKE integrity"),
    ("dh_group", "Key exchange group"),
    ("auth_method", "Authentication method"),
    ("peer_identity", "Peer identity"),
    ("sa_lifetime_s", "IKE SA lifetime"),
    ("fragmentation_used", "IKE fragmentation"),
)

CHILD_FIELD_ORDER: tuple[tuple[str, str], ...] = (
    ("protocol", "Protocol"),
    ("cipher_family", "Cipher family"),
    ("block_size_bytes", "Block size"),
    ("key_length", "Key length"),
    ("integ", "Integrity"),
    ("icv_bytes", "ICV length"),
    ("mode", "Operating mode"),
    ("pfs_on_rekey", "PFS on rekey"),
    ("rekey_interval_s", "Observed rekey interval"),
    ("traffic_type", "Encapsulated traffic type"),
    ("udp_encapsulated", "UDP encapsulation"),
)


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["evidence_label"] = lambda level: EVIDENCE_LABELS.get(level, (level, ""))[0]
    env.filters["evidence_help"] = lambda level: EVIDENCE_LABELS.get(level, ("", ""))[1]
    env.filters["pct"] = lambda v: f"{v:.0%}" if isinstance(v, (int, float)) else ""
    return env


def _rows(obj: Any, order: tuple[tuple[str, str], ...]) -> list[dict[str, Any]]:
    """Flatten an object attributes into display rows, in a fixed order.

    An attribute that was never set is skipped; one that is Unknown is kept,
    because "we looked and could not tell" is information and an empty row is not.
    """
    rows = []
    for field, label in order:
        attr = getattr(obj, field, None)
        if attr is None:
            continue
        rows.append(
            {
                "label": label,
                "field": field,
                "value": attr.value,
                "evidence": attr.evidence,
                "confidence": attr.confidence,
                "packets": list(attr.packets),
                "reason": attr.reason,
                "note": attr.note,
                "method": attr.method,
                "source": attr.source,
                "features": attr.features,
                "resolvable_by": attr.resolvable_by,
            }
        )
    return rows


def _context(record: SessionRecord) -> dict[str, Any]:
    """Everything the templates need, computed once."""
    from analyzer.rules.engine import load_catalogue, unimplemented_rules

    coverage = record.coverage()
    findings = record.findings_sorted()
    actionable = [f for f in findings if f.severity != "informational"]

    by_level: dict[str, int] = {}
    for attr in record.all_attributes().values():
        by_level[attr.evidence] = by_level.get(attr.evidence, 0) + 1

    return {
        "record": record,
        "score": record.score,
        "coverage": coverage,
        "findings": findings,
        "actionable": actionable,
        "top_risks": actionable[:3],
        "ike_rows": _rows(record.ike, IKE_FIELD_ORDER),
        "child_tables": [
            {"sa": sa, "rows": _rows(sa, CHILD_FIELD_ORDER)} for sa in record.child_sas
        ],
        "evidence_counts": by_level,
        "evidence_labels": EVIDENCE_LABELS,
        "baseline": load_catalogue()["baseline"],
        "unimplemented": unimplemented_rules(),
        "severity_counts": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("critical", "high", "medium", "low", "informational")
        },
    }


def render(record: SessionRecord, *, kind: str = "technical") -> str:
    """Render a report to an HTML string."""
    if kind not in ("technical", "executive"):
        raise ValueError(f"unknown report kind {kind!r}")
    template = _environment().get_template(f"{kind}.html.j2")
    return template.render(**_context(record))


def write(record: SessionRecord, path: str | Path, *, kind: str = "technical") -> Path:
    """Render a report and write it to disk."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(record, kind=kind), encoding="utf-8")
    return out
