"""Rule predicates and the scoring path.

The invariant that matters most here: a rule must never fire on an Unknown
attribute. An Unknown is not evidence of weakness any more than it is evidence
of strength, and scoring it either way would be dishonest.
"""

from __future__ import annotations

import pytest

from analyzer.record import (
    Attribute,
    ChildSa,
    Endpoints,
    IkeSa,
    Proposal,
    ReplayEvidence,
    SessionRecord,
    Source,
)
from analyzer.rules.engine import PREDICATES, evaluate, load_catalogue, proposal_strength
from analyzer.scoring.score import assess

STRONG = Proposal(
    number=1, encr="ENCR_AES_CBC", encr_key_bits=256,
    integ="AUTH_HMAC_SHA2_256_128", prf="PRF_HMAC_SHA2_256", dh_group=14,
)
WEAK = Proposal(
    number=2, encr="ENCR_3DES", integ="AUTH_HMAC_SHA1_96",
    prf="PRF_HMAC_SHA1", dh_group=2,
)


def record(ike: IkeSa | None = None, child_sas=None, **source_kw) -> SessionRecord:
    return SessionRecord(
        session_id="t",
        source=Source(kind="pcap", packet_count=10, **source_kw),
        endpoints=Endpoints(initiator="10.0.0.1", responder="10.0.0.2", ip_version=4),
        ike=ike or IkeSa(),
        child_sas=child_sas or [],
    )


def ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


class TestCatalogueIntegrity:
    def test_every_predicate_has_a_catalogue_entry(self):
        catalogue_ids = {r["id"] for r in load_catalogue()["rules"]}
        assert set(PREDICATES) <= catalogue_ids

    def test_every_rule_cites_a_standard(self):
        for entry in load_catalogue()["rules"]:
            assert entry["standard"].strip(), f"{entry['id']} has no standard reference"
            assert entry["remediation"].strip(), f"{entry['id']} has no remediation"

    def test_every_rule_category_exists(self):
        catalogue = load_catalogue()
        for entry in catalogue["rules"]:
            assert entry["category"] in catalogue["categories"]


class TestNoRuleFiresOnUnknown:
    """The central invariant. An all-Unknown record must produce no findings
    about the algorithms, because nothing about them was established."""

    def test_all_unknown_ike_yields_no_crypto_findings(self):
        unknown = Attribute.unknown("encrypted")
        ike = IkeSa(
            version=unknown, encr=unknown, integ=unknown, prf=unknown,
            dh_group=unknown, auth_method=unknown, exchange_mode=unknown,
        )
        found = ids(evaluate(record(ike)))
        for rule_id in ("IKE-001", "IKE-010", "IKE-011", "IKE-020", "IKE-021",
                        "IKE-030", "IKE-031", "IKE-002"):
            assert rule_id not in found, f"{rule_id} fired on Unknown evidence"

    def test_unknown_block_size_does_not_trigger_esp_010(self):
        sa = ChildSa(
            spi="aaaa", protocol=Attribute.observed("ESP", [1]),
            block_size_bytes=Attribute.unknown("not enough distinct lengths"),
        )
        assert "ESP-010" not in ids(evaluate(record(child_sas=[sa])))

    def test_unknown_integ_does_not_trigger_esp_001(self):
        sa = ChildSa(
            spi="aaaa", protocol=Attribute.observed("ESP", [1]),
            integ=Attribute.unknown("negotiated inside the encrypted exchange"),
        )
        assert "ESP-001" not in ids(evaluate(record(child_sas=[sa])))


class TestAlgorithmRules:
    @pytest.mark.parametrize(
        "encr,expected",
        [("ENCR_DES", "IKE-010"), ("ENCR_3DES", "IKE-011")],
    )
    def test_weak_ciphers(self, encr, expected):
        ike = IkeSa(encr=Attribute.observed(encr, [2]))
        assert expected in ids(evaluate(record(ike)))

    def test_des_rule_does_not_also_fire_on_3des(self):
        ike = IkeSa(encr=Attribute.observed("ENCR_3DES", [2]))
        found = ids(evaluate(record(ike)))
        assert "IKE-011" in found and "IKE-010" not in found

    def test_aes_is_clean(self):
        ike = IkeSa(
            encr=Attribute.observed("ENCR_AES_CBC", [2]),
            encr_key_bits=Attribute.observed(256, [2]),
            integ=Attribute.observed("AUTH_HMAC_SHA2_256_128", [2]),
            dh_group=Attribute.observed(19, [2]),
        )
        found = ids(evaluate(record(ike)))
        assert not ({"IKE-010", "IKE-011", "IKE-020", "IKE-021", "IKE-030", "IKE-031"} & found)

    @pytest.mark.parametrize("group,expected", [(1, "IKE-030"), (22, "IKE-030"),
                                                (2, "IKE-031"), (5, "IKE-031"),
                                                (24, "IKE-031")])
    def test_weak_dh_groups(self, group, expected):
        ike = IkeSa(dh_group=Attribute.observed(group, [2]))
        assert expected in ids(evaluate(record(ike)))

    @pytest.mark.parametrize("group", [14, 19, 20, 21, 31, 32])
    def test_acceptable_dh_groups_are_clean(self, group):
        ike = IkeSa(dh_group=Attribute.observed(group, [2]))
        assert not ({"IKE-030", "IKE-031"} & ids(evaluate(record(ike))))

    def test_md5_fires_for_both_integ_and_prf(self):
        ike = IkeSa(
            integ=Attribute.observed("AUTH_HMAC_MD5_96", [2]),
            prf=Attribute.observed("PRF_HMAC_MD5", [2]),
        )
        hits = [f for f in evaluate(record(ike)) if f.rule_id == "IKE-020"]
        assert len(hits) == 2

    def test_ikev1_detected(self):
        ike = IkeSa(version=Attribute.observed("IKEv1", [1]))
        assert "IKE-001" in ids(evaluate(record(ike)))

    def test_aggressive_mode_needs_all_three_observations(self):
        # version and mode known, auth Unknown -> must stay silent
        ike = IkeSa(
            version=Attribute.observed("IKEv1", [1]),
            exchange_mode=Attribute.observed("AGGRESSIVE", [1]),
            auth_method=Attribute.unknown("not captured"),
        )
        assert "IKE-002" not in ids(evaluate(record(ike)))

        ike.auth_method = Attribute.observed("PRE_SHARED_KEY", [1])
        assert "IKE-002" in ids(evaluate(record(ike)))


class TestDowngradeRules:
    def test_downgrade_detected_when_responder_picks_weaker(self):
        ike = IkeSa(
            offered_proposals=[STRONG, WEAK],
            selected_proposal=WEAK,
            encr=Attribute.observed("ENCR_3DES", [4]),
            dh_group=Attribute.observed(2, [4]),
        )
        found = ids(evaluate(record(ike)))
        assert "IKE-040" in found
        assert "IKE-041" in found

    def test_no_downgrade_when_the_best_was_selected(self):
        ike = IkeSa(
            offered_proposals=[STRONG, WEAK],
            selected_proposal=STRONG,
            encr=Attribute.observed("ENCR_AES_CBC", [4]),
        )
        assert "IKE-040" not in ids(evaluate(record(ike)))

    def test_single_offer_cannot_be_a_downgrade(self):
        ike = IkeSa(offered_proposals=[STRONG], selected_proposal=STRONG)
        found = ids(evaluate(record(ike)))
        assert "IKE-040" not in found and "IKE-041" not in found

    def test_all_weak_offers_are_not_reported_as_downgrade_surface(self):
        """Every offer being weak is a different problem, already covered by the
        algorithm rules. Reporting it here too would double-count."""
        ike = IkeSa(offered_proposals=[WEAK, WEAK], selected_proposal=WEAK)
        assert "IKE-041" not in ids(evaluate(record(ike)))

    def test_unscoreable_proposal_is_left_out_rather_than_assumed(self):
        """AES with no key length attribute cannot be scored, so it must not be
        treated as either strong or weak."""
        vague = Proposal(number=1, encr="ENCR_AES_CBC", dh_group=14)
        assert proposal_strength(vague) is None
        ike = IkeSa(offered_proposals=[vague, WEAK], selected_proposal=WEAK)
        assert "IKE-040" not in ids(evaluate(record(ike)))


class TestStrengthOrdering:
    def test_weakest_link_decides(self):
        # AES-256 held back by DH group 14 at about 112 bits
        assert proposal_strength(STRONG) == 112
        assert proposal_strength(WEAK) == 80

    def test_aead_needs_no_separate_integrity(self):
        gcm = Proposal(encr="ENCR_AES_GCM_16", encr_key_bits=256, dh_group=31)
        assert proposal_strength(gcm) == 128

    def test_stronger_group_raises_the_floor(self):
        better = Proposal(
            encr="ENCR_AES_CBC", encr_key_bits=256,
            integ="AUTH_HMAC_SHA2_256_128", dh_group=21,
        )
        assert proposal_strength(better) > proposal_strength(STRONG)


class TestScoring:
    def test_clean_record_scores_full_marks(self):
        rec = assess(record(IkeSa(
            version=Attribute.observed("IKEv2", [1]),
            encr=Attribute.observed("ENCR_AES_GCM_16", [2]),
            encr_key_bits=Attribute.observed(256, [2]),
            dh_group=Attribute.observed(31, [2]),
            notifications=[{"type": 16435, "name": "USE_PPK", "packet": 1}],
        )))
        assert rec.score.value == 100
        assert rec.score.risk_level == "low"
        assert rec.findings == []

    def test_unknowns_cost_no_points_but_lower_coverage(self):
        unknown = Attribute.unknown("encrypted")
        rec = assess(record(IkeSa(
            version=Attribute.observed("IKEv2", [1]),
            encr=unknown, integ=unknown, dh_group=unknown,
            notifications=[{"type": 16435, "name": "USE_PPK", "packet": 1}],
        )))
        assert rec.score.value == 100, "an Unknown must never cost score points"
        coverage = rec.coverage()
        assert coverage.fraction < 1.0, "an Unknown must lower coverage"
        assert len(coverage.unknowns) == 3

    def test_critical_finding_caps_the_score(self):
        rec = assess(record(IkeSa(
            encr=Attribute.observed("ENCR_DES", [2]),
            dh_group=Attribute.observed(1, [2]),
        )))
        assert rec.score.risk_level == "critical"
        assert rec.score.value <= 20

    def test_risk_follows_the_worst_finding_not_the_score(self):
        """Many lesser findings drive the score down but must not invent a
        Critical risk level that no finding supports."""
        rec = assess(record(IkeSa(
            encr=Attribute.observed("ENCR_3DES", [2]),
            integ=Attribute.observed("AUTH_HMAC_SHA1_96", [2]),
            prf=Attribute.observed("PRF_HMAC_SHA1", [2]),
            dh_group=Attribute.observed(2, [2]),
            offered_proposals=[STRONG, WEAK],
            selected_proposal=WEAK,
        )))
        assert rec.worst_severity == "high"
        assert rec.score.risk_level == "high"
        assert rec.score.value < 50

    def test_category_cap_limits_one_area(self):
        rec = assess(record(IkeSa(
            encr=Attribute.observed("ENCR_3DES", [2]),
            integ=Attribute.observed("AUTH_HMAC_SHA1_96", [2]),
            prf=Attribute.observed("PRF_HMAC_SHA1", [2]),
            offered_proposals=[STRONG, WEAK],
            selected_proposal=WEAK,
        )))
        cap = load_catalogue()["categories"]["ike_crypto"]["cap"]
        spent = sum(d.points for d in rec.score.deductions if d.category == "ike_crypto")
        assert spent <= cap
        assert any(d.capped for d in rec.score.deductions)

    def test_finding_confidence_is_inherited_from_inferred_evidence(self):
        sa = ChildSa(
            spi="bbbb", protocol=Attribute.observed("ESP", [1]),
            block_size_bytes=Attribute.inferred(8, 0.6, "residue"),
        )
        rec = assess(record(child_sas=[sa]))
        esp = next(f for f in rec.findings if f.rule_id == "ESP-010")
        assert esp.confidence == pytest.approx(0.6)

    def test_scoring_is_deterministic(self):
        def build():
            return assess(record(IkeSa(
                encr=Attribute.observed("ENCR_3DES", [2]),
                dh_group=Attribute.observed(2, [2]),
                integ=Attribute.observed("AUTH_HMAC_SHA1_96", [2]),
            )))

        first, second = build(), build()
        assert first.score.value == second.score.value
        assert first.score.risk_level == second.score.risk_level
        assert [f.rule_id for f in first.findings_sorted()] == [
            f.rule_id for f in second.findings_sorted()
        ]
        assert first.to_json()["findings"] == second.to_json()["findings"]

    def test_replay_evidence_fires_only_on_duplicates(self):
        clean = ChildSa(spi="c1", protocol=Attribute.observed("ESP", [1]),
                        replay_evidence=ReplayEvidence(duplicate_seqs=0))
        assert "SA-003" not in ids(evaluate(record(child_sas=[clean])))

        dupes = ChildSa(spi="c2", protocol=Attribute.observed("ESP", [1]),
                        replay_evidence=ReplayEvidence(duplicate_seqs=3, monotonic=False))
        assert "SA-003" in ids(evaluate(record(child_sas=[dupes])))


class TestThreatMatrix:
    def test_only_enabled_threats_appear(self):
        rec = assess(record(IkeSa(dh_group=Attribute.observed(2, [2]))))
        assert rec.threat_matrix
        for row in rec.threat_matrix:
            assert row.enabled_by, "a threat row must name the findings that enable it"
            assert set(row.enabled_by) <= {f.rule_id for f in rec.findings}

    def test_clean_record_has_a_near_empty_matrix(self):
        rec = assess(record(IkeSa(
            version=Attribute.observed("IKEv2", [1]),
            encr=Attribute.observed("ENCR_AES_GCM_16", [2]),
            encr_key_bits=Attribute.observed(256, [2]),
            dh_group=Attribute.observed(31, [2]),
            notifications=[{"type": 16441, "name": "ADDITIONAL_KEY_EXCHANGE", "packet": 1}],
        )))
        assert rec.threat_matrix == []
