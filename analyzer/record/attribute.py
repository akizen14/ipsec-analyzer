"""The Attribute type: a reported value that carries its own evidence.

VISION.md section 5 sets one rule for the whole project:

    Parse what the protocol shows in cleartext. Infer what it hides.
    Say "unknown" when neither is possible. Never present an inference
    as an observation.

That rule only holds if it is hard to break by accident, so there is no public
constructor here. An Attribute is built through one of four classmethods, one per
evidence level, and each demands the proof that its level requires:

    observed  -> the packet numbers that show the field
    assisted  -> the name of the material the user supplied
    inferred  -> a probability and the name of the method that produced it
    unknown   -> a reason, and a null value

``to_json`` then emits only the keys that the matching branch of
``dataset/schemas/session_record.schema.json`` allows, so a record that
round-trips through this class cannot mislabel its own evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

EvidenceLevel = Literal["observed", "inferred", "assisted", "unknown"]

AssistedSource = Literal["session_keys", "device_config", "operator_input"]

#: What an operator could do to turn an Unknown into a known value. Reported so a
#: coverage gap comes with an action rather than just a blank.
Resolution = Literal[
    "supply_keys",
    "supply_config",
    "active_probe",
    "longer_capture",
    "not_resolvable",
]


class EvidenceError(ValueError):
    """Raised when an Attribute is built without the proof its level requires."""


@dataclass(frozen=True, slots=True)
class Attribute:
    """One reported value plus the evidence behind it.

    Construct through :meth:`observed`, :meth:`assisted`, :meth:`inferred` or
    :meth:`unknown`. Instances are frozen, so the evidence behind an attribute
    cannot be edited after the fact, only replaced by a new attribute.
    """

    value: Any
    evidence: EvidenceLevel
    confidence: float
    packets: tuple[int, ...] = ()
    method: str | None = None
    features: dict[str, Any] = field(default_factory=dict)
    alternatives: tuple[tuple[Any, float], ...] = ()
    calibrated: bool = False
    source: AssistedSource | None = None
    source_detail: str | None = None
    reason: str | None = None
    resolvable_by: Resolution | None = None
    raw: str | int | None = None
    note: str | None = None

    # ---------------------------------------------------------------- builders

    @classmethod
    def observed(
        cls,
        value: Any,
        packets: list[int] | tuple[int, ...],
        *,
        raw: str | int | None = None,
        note: str | None = None,
    ) -> Attribute:
        """A value read straight from a cleartext protocol field.

        ``packets`` is mandatory and must be non-empty. An observation whose
        source packets cannot be named is not an observation, and the point of
        requiring them is that a reader can open the capture and check.
        """
        if value is None:
            raise EvidenceError(
                "observed attribute cannot have a null value; use Attribute.unknown"
            )
        packets = tuple(packets)
        if not packets:
            raise EvidenceError(f"observed value {value!r} needs at least one source packet number")
        return cls(
            value=value,
            evidence="observed",
            confidence=1.0,
            packets=packets,
            raw=raw,
            note=note,
        )

    @classmethod
    def assisted(
        cls,
        value: Any,
        source: AssistedSource,
        *,
        source_detail: str | None = None,
        note: str | None = None,
    ) -> Attribute:
        """A value read from material the user supplied, so certain but not on the wire.

        This is how an Unknown gets closed: exported session keys, or a device
        configuration. The source is named in the report so a reader knows the
        fact did not come from the capture alone.
        """
        if value is None:
            raise EvidenceError(
                "assisted attribute cannot have a null value; use Attribute.unknown"
            )
        return cls(
            value=value,
            evidence="assisted",
            confidence=1.0,
            source=source,
            source_detail=source_detail,
            note=note,
        )

    @classmethod
    def inferred(
        cls,
        value: Any,
        confidence: float,
        method: str,
        *,
        features: dict[str, Any] | None = None,
        alternatives: list[tuple[Any, float]] | None = None,
        calibrated: bool = False,
        note: str | None = None,
    ) -> Attribute:
        """A value derived from the metadata of encrypted traffic.

        ``method`` is mandatory so that every number in a report traces back to
        the code that produced it. ``features`` records what drove the call, which
        is what makes an inference arguable rather than magic.
        """
        if value is None:
            raise EvidenceError(
                "inferred attribute cannot have a null value; use Attribute.unknown"
            )
        if not 0.0 <= confidence <= 1.0:
            raise EvidenceError(f"confidence {confidence!r} is outside [0, 1]")
        if not method:
            raise EvidenceError(f"inferred value {value!r} must name the method that produced it")
        return cls(
            value=value,
            evidence="inferred",
            confidence=float(confidence),
            method=method,
            features=dict(features or {}),
            alternatives=tuple(alternatives or ()),
            calibrated=calibrated,
            note=note,
        )

    @classmethod
    def unknown(
        cls,
        reason: str,
        *,
        resolvable_by: Resolution | None = None,
        note: str | None = None,
    ) -> Attribute:
        """Not determinable from the evidence available.

        Unknown is an answer, not a failure (VISION.md principle 3). It carries
        confidence 0.0 and is excluded from the score, lowering coverage instead,
        so a gap is never quietly scored as safe.
        """
        if not reason:
            raise EvidenceError("unknown attribute must state why the value is not determinable")
        return cls(
            value=None,
            evidence="unknown",
            confidence=0.0,
            reason=reason,
            resolvable_by=resolvable_by,
            note=note,
        )

    # --------------------------------------------------------------- behaviour

    @property
    def is_known(self) -> bool:
        """True when there is a value to report at all."""
        return self.evidence != "unknown"

    @property
    def is_certain(self) -> bool:
        """True for Observed and Assisted, the two levels that are not probabilistic."""
        return self.evidence in ("observed", "assisted")

    @property
    def scoreable(self) -> bool:
        """Whether the rule engine may act on this attribute.

        Unknowns are not scored. They reduce coverage instead, so the score never
        rewards an endpoint for hiding something.
        """
        return self.is_known

    def at_least(self, threshold: float) -> bool:
        """Whether this attribute is confident enough to act on.

        Used by the abstain logic: an inference below the threshold is reported as
        Unknown rather than as a weak claim.
        """
        return self.is_known and self.confidence >= threshold

    def abstain_below(self, threshold: float, reason: str | None = None) -> Attribute:
        """Return this attribute, or an Unknown if its confidence is too low.

        The abstain threshold from PLAN.md phase 4 lives here so every inference
        path gets the same treatment.
        """
        if self.evidence != "inferred" or self.confidence >= threshold:
            return self
        return Attribute.unknown(
            reason
            or (
                f"{self.method} returned {self.value!r} at confidence "
                f"{self.confidence:.2f}, below the {threshold:.2f} abstain threshold"
            ),
            resolvable_by="longer_capture",
        )

    # ------------------------------------------------------------ serialisation

    def to_json(self) -> dict[str, Any]:
        """Emit only the keys the matching schema branch permits."""
        out: dict[str, Any] = {"value": self.value, "evidence": self.evidence}

        if self.evidence == "observed":
            out["confidence"] = 1.0
            out["packets"] = list(self.packets)
            if self.raw is not None:
                out["raw"] = self.raw
        elif self.evidence == "assisted":
            out["confidence"] = 1.0
            out["source"] = self.source
            if self.source_detail:
                out["source_detail"] = self.source_detail
        elif self.evidence == "inferred":
            out["confidence"] = round(self.confidence, 4)
            out["method"] = self.method
            if self.features:
                out["features"] = self.features
            if self.alternatives:
                out["alternatives"] = [
                    {"value": v, "confidence": round(c, 4)} for v, c in self.alternatives
                ]
            out["calibrated"] = self.calibrated
        else:  # unknown
            out["confidence"] = 0.0
            out["reason"] = self.reason
            if self.resolvable_by:
                out["resolvable_by"] = self.resolvable_by

        if self.note:
            out["note"] = self.note
        return out

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Attribute:
        """Rebuild an Attribute from a serialised record.

        Routes through the same four builders as fresh construction, so a record
        loaded from disk meets the same invariants that created it.
        """
        level = data.get("evidence")
        if level == "observed":
            return cls.observed(
                data["value"], data["packets"], raw=data.get("raw"), note=data.get("note")
            )
        if level == "assisted":
            return cls.assisted(
                data["value"],
                data["source"],
                source_detail=data.get("source_detail"),
                note=data.get("note"),
            )
        if level == "inferred":
            return cls.inferred(
                data["value"],
                data["confidence"],
                data["method"],
                features=data.get("features"),
                alternatives=[(a["value"], a["confidence"]) for a in data.get("alternatives", [])],
                calibrated=data.get("calibrated", False),
                note=data.get("note"),
            )
        if level == "unknown":
            return cls.unknown(
                data["reason"], resolvable_by=data.get("resolvable_by"), note=data.get("note")
            )
        raise EvidenceError(f"unrecognised evidence level {level!r}")

    def __str__(self) -> str:
        if self.evidence == "unknown":
            return f"unknown ({self.reason})"
        if self.is_certain:
            return f"{self.value} [{self.evidence}]"
        return f"{self.value} [{self.evidence} {self.confidence:.0%}]"


def encrypted_unknown(what: str, *, resolvable_by: Resolution = "supply_keys") -> Attribute:
    """An Unknown whose reason is that the field sits inside an encrypted payload.

    Shorthand for most of the Unknown rows in the VISION.md section 5.1
    visibility table.
    """
    return Attribute.unknown(f"{what} is inside an encrypted payload", resolvable_by=resolvable_by)
