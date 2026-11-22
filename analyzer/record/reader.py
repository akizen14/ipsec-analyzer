"""Hydrate validated session JSON into the same model used for fresh analysis."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from analyzer import SCHEMA_VERSION
from analyzer.record.attribute import Attribute, EvidenceError
from analyzer.record.model import (
    ChildSa,
    Deduction,
    Endpoints,
    Finding,
    IkeSa,
    Proposal,
    RekeyEvent,
    ReplayEvidence,
    Score,
    SessionRecord,
    Source,
    ThreatRow,
)
from analyzer.record.validate import RecordInvalid, validate


def _attributes(data: dict[str, Any], *names: str) -> dict[str, Any]:
    for name in names:
        if name in data:
            data[name] = Attribute.from_json(data[name])
    return data


def _rekeys(data: dict[str, Any]) -> list[RekeyEvent]:
    return [
        RekeyEvent(**_attributes(event, "key_exchange_present"))
        for event in data.pop("rekeys", [])
    ]


def _ike(data: dict[str, Any]) -> IkeSa:
    offered = [Proposal(**proposal) for proposal in data.pop("offered_proposals", [])]
    selected = data.pop("selected_proposal", None)
    rekeys = _rekeys(data)
    return IkeSa(
        **_attributes(
            data, "version", "exchange_mode", "encr", "encr_key_bits", "prf", "integ",
            "dh_group", "auth_method", "peer_identity", "sa_lifetime_s", "fragmentation_used",
        ),
        offered_proposals=offered,
        selected_proposal=Proposal(**selected) if selected is not None else None,
        rekeys=rekeys,
    )


def _child(data: dict[str, Any]) -> ChildSa:
    replay = data.pop("replay_evidence", None)
    rekeys = _rekeys(data)
    return ChildSa(
        **_attributes(
            data, "protocol", "cipher_family", "icv_bytes", "block_size_bytes", "key_length",
            "integ", "mode", "pfs_on_rekey", "rekey_interval_s", "traffic_type", "udp_encapsulated",
        ),
        replay_evidence=ReplayEvidence(**replay) if replay is not None else None,
        rekeys=rekeys,
    )


def _score(data: dict[str, Any] | None) -> Score | None:
    if data is None:
        return None
    deductions = [Deduction(**entry) for entry in data.pop("deductions", [])]
    return Score(**data, deductions=deductions)


def hydrate(data: dict[str, Any], record_type: type[SessionRecord]) -> SessionRecord:
    """Validate JSON before constructing typed evidence, sessions, and findings."""
    if isinstance(data, dict) and "schema_version" in data and data["schema_version"] != SCHEMA_VERSION:
        raise RecordInvalid(
            f"Unsupported session schema version {data['schema_version']!r}. "
            f"This analyzer reads version {SCHEMA_VERSION}."
        )
    validate(data)
    fields = deepcopy(data)
    coverage = fields.pop("coverage")
    del fields["schema_version"]
    fields.setdefault("generated_at", "")

    try:
        fields["source"] = Source(**fields["source"])
        fields["endpoints"] = Endpoints(**_attributes(fields["endpoints"], "nat_t"))
        fields["ike"] = _ike(fields["ike"])
        fields["child_sas"] = [_child(child) for child in fields["child_sas"]]
        fields["findings"] = [Finding(**({"standard": ""} | item)) for item in fields["findings"]]
        fields["threat_matrix"] = [ThreatRow(**item) for item in fields.get("threat_matrix", [])]
        fields["score"] = _score(fields.get("score"))
        record = record_type(**fields)
    except (EvidenceError, KeyError, TypeError) as error:
        raise RecordInvalid(f"Session record cannot be loaded: {error}") from error

    computed = record.coverage().to_json()
    if any(coverage[key] != computed[key] for key in ("determinable", "total", "fraction")):
        raise RecordInvalid("Session record coverage does not match its evidence.")
    return record
