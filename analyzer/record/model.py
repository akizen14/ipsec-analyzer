"""The session record container.

One record per analysed VPN session. PLAN.md section 3 calls this the contract
between the analysis half and the product half, so the dataclasses here mirror
``dataset/schemas/session_record.schema.json`` field for field. Changing one
without the other breaks the contract, and ``tests/test_session_record.py``
fails when they drift.

Two rules are enforced in code rather than left to discipline:

* :meth:`SessionRecord.coverage` is computed from the attributes themselves, so
  an Unknown always lowers coverage and never costs score points.
* :meth:`Finding.from_rule` sets confidence to the lowest among the attributes
  the finding rests on, so a conclusion is never surer than its weakest input.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from analyzer.record.attribute import Attribute, Resolution

Severity = Literal["informational", "low", "medium", "high", "critical"]

RiskLevel = Literal["low", "medium", "high", "critical"]

#: Worst-last, so ``max`` picks the most severe and sorting agrees with how an
#: analyst reads a report.
SEVERITY_ORDER: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _attrs(obj: Any) -> dict[str, Attribute]:
    """Every Attribute held directly by a dataclass instance, keyed by field name."""
    return {
        name: getattr(obj, name)
        for name in obj.__slots__
        if isinstance(getattr(obj, name, None), Attribute)
    }


# --------------------------------------------------------------------- pieces


@dataclass(slots=True)
class Source:
    """Where the evidence came from, and what limits it carries."""

    kind: Literal["pcap", "live", "probe"]
    path: str | None = None
    sha256: str | None = None
    capture_start: str | None = None
    capture_duration_s: float | None = None
    packet_count: int = 0
    truncated: bool = False
    keys_supplied: bool = False
    testbed_run_id: str | None = None

    @classmethod
    def from_pcap(cls, path: str | Path, **kwargs: Any) -> Source:
        """Build a Source for a capture file, hashing it for reproducibility.

        The digest is what ties an evaluation result to the exact bytes it came
        from, which PLAN.md section 9 needs since captures stay out of git.
        """
        p = Path(path)
        digest = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return cls(kind="pcap", path=str(p), sha256=digest.hexdigest(), **kwargs)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "packet_count": self.packet_count}
        for key in ("path", "sha256", "capture_start", "capture_duration_s", "testbed_run_id"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        out["truncated"] = self.truncated
        out["keys_supplied"] = self.keys_supplied
        return out


@dataclass(slots=True)
class Endpoints:
    initiator: str
    responder: str
    ip_version: Literal[4, 6]
    nat_t: Attribute | None = None
    initiator_port: int | None = None
    responder_port: int | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "initiator": self.initiator,
            "responder": self.responder,
            "ip_version": self.ip_version,
        }
        if self.nat_t is not None:
            out["nat_t"] = self.nat_t.to_json()
        if self.initiator_port is not None:
            out["initiator_port"] = self.initiator_port
        if self.responder_port is not None:
            out["responder_port"] = self.responder_port
        return out


@dataclass(slots=True)
class Proposal:
    """One IKE or child SA proposal, with the raw IANA numbers kept alongside.

    Canonical names come from ``analyzer.ike.transforms``. The raw transforms are
    retained so an unrecognised algorithm still appears in the report instead of
    vanishing, which matters when assessing equipment the parser has not met.
    """

    number: int | None = None
    protocol: Literal["IKE", "ESP", "AH"] | None = None
    spi: str | None = None
    encr: str | None = None
    encr_key_bits: int | None = None
    prf: str | None = None
    integ: str | None = None
    dh_group: int | None = None
    esn: str | None = None
    raw_transforms: list[dict[str, Any]] = field(default_factory=list)
    packet: int | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            key: getattr(self, key)
            for key in (
                "number",
                "protocol",
                "spi",
                "encr",
                "encr_key_bits",
                "prf",
                "integ",
                "dh_group",
                "esn",
                "packet",
            )
            if getattr(self, key) is not None
        }
        if self.raw_transforms:
            out["raw_transforms"] = self.raw_transforms
        return out

    def label(self) -> str:
        """A short human-readable form, for report tables and log lines."""
        head = f"{self.encr}-{self.encr_key_bits}" if self.encr_key_bits else (self.encr or "?")
        bits = [head]
        if self.integ:
            bits.append(self.integ)
        if self.prf:
            bits.append(self.prf)
        if self.dh_group is not None:
            bits.append(f"DH{self.dh_group}")
        return "/".join(bits)


@dataclass(slots=True)
class RekeyEvent:
    at: float | None = None
    packet: int | None = None
    old_spi: str | None = None
    new_spi: str | None = None
    interval_s: float | None = None
    key_exchange_present: Attribute | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            key: getattr(self, key)
            for key in ("at", "packet", "old_spi", "new_spi", "interval_s")
            if getattr(self, key) is not None
        }
        if self.key_exchange_present is not None:
            out["key_exchange_present"] = self.key_exchange_present.to_json()
        return out


@dataclass(slots=True)
class IkeSa:
    """The IKE security association. Mostly cleartext, so mostly Observed."""

    version: Attribute | None = None
    exchange_mode: Attribute | None = None
    initiator_spi: str | None = None
    responder_spi: str | None = None
    encr: Attribute | None = None
    encr_key_bits: Attribute | None = None
    prf: Attribute | None = None
    integ: Attribute | None = None
    dh_group: Attribute | None = None
    auth_method: Attribute | None = None
    peer_identity: Attribute | None = None
    sa_lifetime_s: Attribute | None = None
    offered_proposals: list[Proposal] = field(default_factory=list)
    selected_proposal: Proposal | None = None
    vendor_ids: list[dict[str, Any]] = field(default_factory=list)
    notifications: list[dict[str, Any]] = field(default_factory=list)
    fragmentation_used: Attribute | None = None
    rekeys: list[RekeyEvent] = field(default_factory=list)

    def attributes(self) -> dict[str, Attribute]:
        return _attrs(self)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {name: attr.to_json() for name, attr in _attrs(self).items()}
        for name in ("initiator_spi", "responder_spi"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        if self.offered_proposals:
            out["offered_proposals"] = [p.to_json() for p in self.offered_proposals]
        if self.selected_proposal is not None:
            out["selected_proposal"] = self.selected_proposal.to_json()
        if self.vendor_ids:
            out["vendor_ids"] = self.vendor_ids
        if self.notifications:
            out["notifications"] = self.notifications
        if self.rekeys:
            out["rekeys"] = [r.to_json() for r in self.rekeys]
        return out


@dataclass(slots=True)
class ReplayEvidence:
    """What the sequence numbers show.

    Anti-replay enforcement happens at the receiver and is not visible on the
    wire, so this is reported as evidence rather than as a configured setting
    (VISION.md section 12 row 6).
    """

    monotonic: bool = True
    duplicate_seqs: int = 0
    reordered_seqs: int = 0
    gaps: int = 0
    highest_seq: int = 0
    esn_suspected: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "monotonic": self.monotonic,
            "duplicate_seqs": self.duplicate_seqs,
            "reordered_seqs": self.reordered_seqs,
            "gaps": self.gaps,
            "highest_seq": self.highest_seq,
            "esn_suspected": self.esn_suspected,
        }


@dataclass(slots=True)
class ChildSa:
    """An ESP or AH child SA. Mostly encrypted, so mostly Inferred or Unknown."""

    spi: str
    protocol: Attribute
    direction_pair_spi: str | None = None
    src: str | None = None
    dst: str | None = None
    cipher_family: Attribute | None = None
    icv_bytes: Attribute | None = None
    block_size_bytes: Attribute | None = None
    key_length: Attribute | None = None
    integ: Attribute | None = None
    mode: Attribute | None = None
    pfs_on_rekey: Attribute | None = None
    rekey_interval_s: Attribute | None = None
    traffic_type: Attribute | None = None
    udp_encapsulated: Attribute | None = None
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float | None = None
    last_seen: float | None = None
    replay_evidence: ReplayEvidence | None = None
    length_histogram: dict[str, int] = field(default_factory=dict)
    rekeys: list[RekeyEvent] = field(default_factory=list)

    def attributes(self) -> dict[str, Attribute]:
        return _attrs(self)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"spi": self.spi}
        for name, attr in _attrs(self).items():
            out[name] = attr.to_json()
        for name in ("direction_pair_spi", "src", "dst", "first_seen", "last_seen"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        out["packet_count"] = self.packet_count
        out["byte_count"] = self.byte_count
        if self.replay_evidence is not None:
            out["replay_evidence"] = self.replay_evidence.to_json()
        if self.length_histogram:
            out["length_histogram"] = self.length_histogram
        if self.rekeys:
            out["rekeys"] = [r.to_json() for r in self.rekeys]
        return out


@dataclass(slots=True)
class Finding:
    """One rule that fired.

    No finding without a rule ID, no rule without a reference (PLAN.md section 9),
    so ``rule_id`` and ``standard`` are both required at construction.
    """

    rule_id: str
    title: str
    severity: Severity
    confidence: float
    standard: str
    remediation: str = ""
    threat: str | None = None
    evidence: list[str] = field(default_factory=list)
    detail: str = ""

    @classmethod
    def from_rule(
        cls,
        rule_id: str,
        title: str,
        severity: Severity,
        standard: str,
        *,
        depends_on: list[Attribute] | None = None,
        remediation: str = "",
        threat: str | None = None,
        evidence: list[str] | None = None,
        detail: str = "",
    ) -> Finding:
        """Build a finding whose confidence is inherited from its inputs.

        A finding is only as sure as the least sure attribute it rests on, so a
        conclusion drawn from a 0.7-confidence inference is reported at 0.7 and
        not at 1.0 (PLAN.md phase 5).
        """
        inputs = depends_on or []
        confidence = min((a.confidence for a in inputs), default=1.0)
        return cls(
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence=confidence,
            standard=standard,
            remediation=remediation,
            threat=threat,
            evidence=evidence or [],
            detail=detail,
        )

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "standard": self.standard,
        }
        if self.remediation:
            out["remediation"] = self.remediation
        if self.threat is not None:
            out["threat"] = self.threat
        if self.evidence:
            out["evidence"] = self.evidence
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass(slots=True)
class ThreatRow:
    threat: str
    likelihood: Literal["low", "medium", "high"]
    impact: Literal["low", "medium", "high"]
    rating: Severity
    enabled_by: list[str] = field(default_factory=list)
    mitigation: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "threat": self.threat,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "rating": self.rating,
        }
        if self.enabled_by:
            out["enabled_by"] = self.enabled_by
        if self.mitigation:
            out["mitigation"] = self.mitigation
        return out


@dataclass(slots=True)
class Deduction:
    rule_id: str
    points: float
    category: str = ""
    capped: bool = False

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"rule_id": self.rule_id, "points": self.points}
        if self.category:
            out["category"] = self.category
        out["capped"] = self.capped
        return out


@dataclass(slots=True)
class Score:
    value: int
    risk_level: RiskLevel
    deductions: list[Deduction] = field(default_factory=list)
    overall_confidence: float | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"value": self.value, "risk_level": self.risk_level}
        if self.deductions:
            out["deductions"] = [d.to_json() for d in self.deductions]
        if self.overall_confidence is not None:
            out["overall_confidence"] = round(self.overall_confidence, 4)
        return out


@dataclass(slots=True)
class UnknownGap:
    pointer: str
    reason: str
    resolvable_by: Resolution | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"pointer": self.pointer, "reason": self.reason}
        if self.resolvable_by:
            out["resolvable_by"] = self.resolvable_by
        return out


@dataclass(slots=True)
class Coverage:
    """How much of the configuration the evidence actually reached.

    Shown next to the score, never folded into it, so a capture that reveals
    little is visibly incomplete rather than quietly clean.
    """

    determinable: int
    total: int
    unknowns: list[UnknownGap] = field(default_factory=list)

    @property
    def fraction(self) -> float:
        return (self.determinable / self.total) if self.total else 0.0

    def to_json(self) -> dict[str, Any]:
        return {
            "determinable": self.determinable,
            "total": self.total,
            "fraction": round(self.fraction, 4),
            "unknowns": [u.to_json() for u in self.unknowns],
        }


# ---------------------------------------------------------------- the record


@dataclass(slots=True)
class SessionRecord:
    """Everything known about one analysed VPN session."""

    session_id: str
    source: Source
    endpoints: Endpoints
    ike: IkeSa = field(default_factory=IkeSa)
    child_sas: list[ChildSa] = field(default_factory=list)
    probe: dict[str, Any] | None = None
    findings: list[Finding] = field(default_factory=list)
    threat_matrix: list[ThreatRow] = field(default_factory=list)
    score: Score | None = None
    warnings: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=_utc_now)
    analyzer_version: str | None = None

    # ------------------------------------------------------------- inspection

    def all_attributes(self) -> dict[str, Attribute]:
        """Every attribute in the record, keyed by JSON pointer.

        Pointers are what findings cite as evidence, so a report can link a
        conclusion back to the exact field that produced it.
        """
        out: dict[str, Attribute] = {}
        if self.endpoints.nat_t is not None:
            out["/endpoints/nat_t"] = self.endpoints.nat_t
        for name, attr in self.ike.attributes().items():
            out[f"/ike/{name}"] = attr
        for i, sa in enumerate(self.child_sas):
            for name, attr in sa.attributes().items():
                out[f"/child_sas/{i}/{name}"] = attr
        return out

    def coverage(self) -> Coverage:
        """Compute coverage from the attributes present.

        Derived rather than stored, so it cannot drift out of step with the
        attributes it describes.
        """
        attrs = self.all_attributes()
        gaps = [
            UnknownGap(pointer=ptr, reason=a.reason or "", resolvable_by=a.resolvable_by)
            for ptr, a in sorted(attrs.items())
            if not a.is_known
        ]
        determinable = sum(1 for a in attrs.values() if a.is_known)
        return Coverage(determinable=determinable, total=len(attrs), unknowns=gaps)

    @property
    def worst_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.severity_rank).severity

    def findings_sorted(self) -> list[Finding]:
        """Worst first, then by rule ID so the order is stable across runs.

        Stability matters because PLAN.md section 7 requires identical output when
        the same capture is analysed twice.
        """
        return sorted(self.findings, key=lambda f: (-f.severity_rank, f.rule_id))

    # ---------------------------------------------------------- serialisation

    def to_json(self) -> dict[str, Any]:
        from analyzer import SCHEMA_VERSION

        out: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "session_id": self.session_id,
            "generated_at": self.generated_at,
            "source": self.source.to_json(),
            "endpoints": self.endpoints.to_json(),
            "ike": self.ike.to_json(),
            "child_sas": [sa.to_json() for sa in self.child_sas],
            "findings": [f.to_json() for f in self.findings_sorted()],
            "coverage": self.coverage().to_json(),
        }
        if self.analyzer_version:
            out["analyzer_version"] = self.analyzer_version
        if self.probe is not None:
            out["probe"] = self.probe
        if self.threat_matrix:
            out["threat_matrix"] = [t.to_json() for t in self.threat_matrix]
        if self.score is not None:
            out["score"] = self.score.to_json()
        if self.warnings:
            out["warnings"] = self.warnings
        return out

    def dump(self, path: str | Path, *, indent: int = 2) -> Path:
        """Write the record to disk with sorted keys.

        Deterministic bytes mean two analyses of the same capture produce
        identical files, which is how the repeatability test in PLAN.md section 7
        is checked.
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self.to_json(), indent=indent, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return p
