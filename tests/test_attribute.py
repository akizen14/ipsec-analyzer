"""The evidence discipline has to be hard to break by accident.

These are the project load-bearing invariants: if an inference can be
serialised as an observation, every claim the tool makes becomes suspect.
"""

from __future__ import annotations

import dataclasses

import pytest

from analyzer.record import Attribute, EvidenceError
from analyzer.record.attribute import encrypted_unknown


class TestConstructionGuards:
    def test_observed_requires_packets(self):
        with pytest.raises(EvidenceError, match="source packet"):
            Attribute.observed("IKEv2", [])

    def test_observed_rejects_null_value(self):
        with pytest.raises(EvidenceError, match="null value"):
            Attribute.observed(None, [1])

    def test_inferred_requires_a_method(self):
        with pytest.raises(EvidenceError, match="name the method"):
            Attribute.inferred("tunnel", 0.9, "")

    @pytest.mark.parametrize("bad", [-0.1, 1.1, 42.0])
    def test_inferred_confidence_must_be_a_probability(self, bad):
        with pytest.raises(EvidenceError, match="outside"):
            Attribute.inferred("tunnel", bad, "m")

    def test_unknown_requires_a_reason(self):
        with pytest.raises(EvidenceError, match="why"):
            Attribute.unknown("")

    def test_assisted_requires_a_source(self):
        # source is positional and mandatory, so omitting it is a TypeError
        with pytest.raises(TypeError):
            Attribute.assisted(256)


class TestSerialisation:
    def test_observed_never_serialises_a_method(self):
        out = Attribute.observed(14, [2]).to_json()
        assert out["evidence"] == "observed"
        assert out["confidence"] == 1.0
        assert out["packets"] == [2]
        assert "method" not in out
        assert "reason" not in out

    def test_inferred_carries_method_and_confidence(self):
        out = Attribute.inferred(8, 0.6, "residue", features={"n": 3}).to_json()
        assert out["evidence"] == "inferred"
        assert out["method"] == "residue"
        assert out["confidence"] == 0.6
        assert out["features"] == {"n": 3}
        assert "packets" not in out

    def test_unknown_is_null_with_a_reason(self):
        out = Attribute.unknown("encrypted", resolvable_by="supply_keys").to_json()
        assert out["value"] is None
        assert out["confidence"] == 0.0
        assert out["reason"] == "encrypted"
        assert out["resolvable_by"] == "supply_keys"

    @pytest.mark.parametrize(
        "attr",
        [
            Attribute.observed("IKEv2", [1], raw="0x20"),
            Attribute.inferred("tunnel", 0.8, "m", alternatives=[("transport", 0.2)]),
            Attribute.assisted(256, "session_keys", source_detail="save-keys"),
            Attribute.unknown("no evidence", resolvable_by="longer_capture"),
        ],
    )
    def test_round_trip_preserves_evidence(self, attr):
        back = Attribute.from_json(attr.to_json())
        assert back.evidence == attr.evidence
        assert back.value == attr.value
        assert back.confidence == pytest.approx(attr.confidence)


class TestBehaviour:
    def test_unknown_is_not_scoreable(self):
        assert not Attribute.unknown("x").scoreable
        assert Attribute.observed(1, [1]).scoreable
        assert Attribute.inferred(1, 0.5, "m").scoreable

    def test_only_observed_and_assisted_are_certain(self):
        assert Attribute.observed(1, [1]).is_certain
        assert Attribute.assisted(1, "device_config").is_certain
        assert not Attribute.inferred(1, 0.99, "m").is_certain
        assert not Attribute.unknown("x").is_certain

    def test_abstain_turns_a_weak_inference_into_unknown(self):
        weak = Attribute.inferred("tunnel", 0.4, "mode_model")
        assert weak.abstain_below(0.7).evidence == "unknown"
        assert "below the 0.70 abstain threshold" in weak.abstain_below(0.7).reason

    def test_abstain_keeps_a_strong_inference(self):
        strong = Attribute.inferred("tunnel", 0.95, "mode_model")
        assert strong.abstain_below(0.7) is strong

    def test_abstain_never_downgrades_an_observation(self):
        # An Observed value is certain; a threshold must not touch it.
        observed = Attribute.observed("tunnel", [7])
        assert observed.abstain_below(0.99) is observed

    def test_attributes_are_immutable(self):
        """Frozen, so evidence cannot be edited after the fact."""
        attr = Attribute.observed(14, [2])
        with pytest.raises(dataclasses.FrozenInstanceError):
            attr.value = 2

    def test_encrypted_unknown_helper(self):
        attr = encrypted_unknown("the authentication method")
        assert attr.evidence == "unknown"
        assert "encrypted payload" in attr.reason
