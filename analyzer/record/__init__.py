"""The session record: one JSON document per analysed VPN session.

Importing from this package gives the two things most code needs: the
``Attribute`` type that carries evidence levels, and the ``SessionRecord``
container that holds them.
"""

from analyzer.record.attribute import (
    Attribute,
    AssistedSource,
    EvidenceError,
    EvidenceLevel,
    Resolution,
    encrypted_unknown,
)
from analyzer.record.model import (
    ChildSa,
    Coverage,
    Deduction,
    Endpoints,
    Finding,
    IkeSa,
    Proposal,
    RekeyEvent,
    ReplayEvidence,
    Score,
    SessionRecord,
    Severity,
    Source,
    ThreatRow,
    UnknownGap,
)

__all__ = [
    "UnknownGap",
    "ReplayEvidence",
    "Deduction",
    "AssistedSource",
    "Attribute",
    "ChildSa",
    "Coverage",
    "Endpoints",
    "EvidenceError",
    "EvidenceLevel",
    "Finding",
    "IkeSa",
    "Proposal",
    "RekeyEvent",
    "Resolution",
    "Score",
    "SessionRecord",
    "Severity",
    "Source",
    "ThreatRow",
    "encrypted_unknown",
]
