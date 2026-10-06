"""The session record: one JSON document per analysed VPN session.

Importing from this package gives the two things most code needs: the
``Attribute`` type that carries evidence levels, and the ``SessionRecord``
container that holds them.
"""

from analyzer.record.attribute import (
    AssistedSource,
    Attribute,
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
    "AssistedSource",
    "Attribute",
    "ChildSa",
    "Coverage",
    "Deduction",
    "Endpoints",
    "EvidenceError",
    "EvidenceLevel",
    "Finding",
    "IkeSa",
    "Proposal",
    "RekeyEvent",
    "ReplayEvidence",
    "Resolution",
    "Score",
    "SessionRecord",
    "Severity",
    "Source",
    "ThreatRow",
    "UnknownGap",
    "encrypted_unknown",
]
