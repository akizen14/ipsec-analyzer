"""End-to-end tests against captures with known configurations.

The expected values in ``golden/expected.json`` were taken from what strongSwan
reported when each tunnel came up, not from analyzer output. So these tests
check the analyzer against reality. A failure here means either the capture was
regenerated or the analyzer regressed, and those are worth telling apart before
anyone edits the expectations.

This is the check behind the VISION.md section 9 target that IKE parsing match
ground truth on every cleartext field, where a miss is a bug rather than a
tuning problem.
"""

from __future__ import annotations

import json

import pytest

from analyzer.record.validate import validate

CAPTURES = ["ikev2-aes256-sha256-dh14", "ikev2-3des-sha1-dh2-downgrade"]


@pytest.fixture(params=CAPTURES)
def case(request, analysed, expected):
    name = request.param
    records = analysed[name]
    assert len(records) == expected[name]["sessions"], (
        f"{name}: expected {expected[name]['sessions']} session(s), got {len(records)}"
    )
    return name, records[0], expected[name]


class TestIkeParsingMatchesGroundTruth:
    """Every cleartext IKE field must match exactly. No tolerance here."""

    def test_observed_fields_match_what_strongswan_reported(self, case):
        name, record, want = case
        for field, value in want["ike"].items():
            attr = getattr(record.ike, field)
            assert attr is not None, f"{name}: {field} was not populated at all"
            assert attr.evidence == "observed", (
                f"{name}: {field} is {attr.evidence}, but it is a cleartext field "
                "and must be Observed"
            )
            assert attr.value == value, (
                f"{name}: {field} parsed as {attr.value!r}, strongSwan said {value!r}"
            )

    def test_observed_attributes_cite_their_packets(self, case):
        name, record, _want = case
        for pointer, attr in record.all_attributes().items():
            if attr.evidence == "observed":
                assert attr.packets, f"{name}: {pointer} is Observed but cites no packet"

    def test_encrypted_fields_are_unknown_not_guessed(self, case):
        """IKEv2 keeps these inside IKE_AUTH. Reporting a value would be a
        fabrication, so they must come back Unknown with a reason."""
        name, record, _want = case
        for field in ("auth_method", "peer_identity", "sa_lifetime_s"):
            attr = getattr(record.ike, field)
            assert attr is not None and attr.evidence == "unknown", (
                f"{name}: {field} should be Unknown for IKEv2, got {attr}"
            )
            assert attr.reason, f"{name}: {field} is Unknown with no reason given"

    def test_the_capture_parses_without_defects(self, case):
        name, record, _want = case
        parse_warnings = [w for w in record.warnings if "parse defect" in w]
        assert not parse_warnings, f"{name}: {parse_warnings}"

    def test_child_sa_count(self, case):
        name, record, want = case
        assert len(record.child_sas) == want["child_sa_count"], (
            f"{name}: expected {want['child_sa_count']} child SA(s), "
            f"got {len(record.child_sas)}"
        )


class TestFindings:
    def test_expected_rules_fire(self, case):
        name, record, want = case
        fired = {f.rule_id for f in record.findings}
        missing = sorted(set(want["expect_rules"]) - fired)
        assert not missing, f"{name}: these rules should have fired but did not: {missing}"

    def test_rules_that_should_stay_silent_do(self, case):
        name, record, want = case
        fired = {f.rule_id for f in record.findings}
        spurious = sorted(set(want["expect_no_rules"]) & fired)
        assert not spurious, f"{name}: these rules fired but should not have: {spurious}"

    def test_every_finding_cites_a_standard(self, case):
        name, record, _want = case
        for finding in record.findings:
            assert finding.standard.strip(), f"{name}: {finding.rule_id} cites no standard"


class TestScoreAndRisk:
    def test_risk_level(self, case):
        name, record, want = case
        assert record.score.risk_level == want["risk_level"], (
            f"{name}: risk {record.score.risk_level}, expected {want['risk_level']}"
        )

    def test_score_in_the_expected_range(self, case):
        name, record, want = case
        if "score_at_least" in want:
            assert record.score.value >= want["score_at_least"], f"{name} scored too low"
        if "score_at_most" in want:
            assert record.score.value <= want["score_at_most"], f"{name} scored too high"

    def test_risk_level_is_supported_by_a_finding(self, case):
        """A risk band with no finding behind it cannot be explained to a reader."""
        name, record, _want = case
        if record.score.risk_level == "low":
            return
        severities = {f.severity for f in record.findings}
        assert record.score.risk_level in severities, (
            f"{name}: risk {record.score.risk_level} but no finding of that severity"
        )

    def test_every_deduction_names_a_rule_that_fired(self, case):
        name, record, _want = case
        fired = {f.rule_id for f in record.findings}
        for deduction in record.score.deductions:
            assert deduction.rule_id in fired, (
                f"{name}: deduction for {deduction.rule_id} with no matching finding"
            )

    def test_score_arithmetic_adds_up(self, case):
        name, record, _want = case
        spent = sum(d.points for d in record.score.deductions)
        if record.worst_severity == "critical":
            assert record.score.value <= 20
        else:
            assert record.score.value == max(0, min(100, round(100 - spent))), (
                f"{name}: score {record.score.value} does not match 100 - {spent}"
            )


class TestSchemaAndDeterminism:
    def test_record_validates_against_the_schema(self, case):
        _name, record, _want = case
        validate(record)

    def test_reanalysis_is_byte_identical(self, case, golden_dir):
        """PLAN.md section 7: the same capture analysed twice gives the same score
        and findings. Compared on the serialised bytes, so field ordering counts."""
        from analyzer.ingest.pcap import read_capture
        from analyzer.scoring.score import assess
        from analyzer.sessions.builder import build_sessions

        name, first, _want = case
        again = build_sessions(read_capture(golden_dir / f"{name}.pcapng"))[0]
        assess(again)

        a, b = first.to_json(), again.to_json()
        for volatile in ("generated_at",):
            a.pop(volatile, None)
            b.pop(volatile, None)
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


class TestEspInference:
    def test_cipher_family_evidence_level(self, case):
        """One capture has uniform packet sizes and must abstain; the other has
        varied sizes and must reach a conclusion. Both behaviours are required:
        abstaining always would be useless, concluding always would be wrong."""
        name, record, want = case
        esp = [sa for sa in record.child_sas if sa.protocol.value == "ESP"]
        assert esp, f"{name}: no ESP child SA found"
        families = {sa.cipher_family.evidence for sa in esp if sa.cipher_family}
        assert want["esp_cipher_family_evidence"] in families, (
            f"{name}: expected cipher_family evidence "
            f"{want['esp_cipher_family_evidence']}, saw {families}"
        )

    def test_abstention_explains_itself(self, case):
        name, record, want = case
        if want["esp_cipher_family_evidence"] != "unknown":
            return
        reasons = [
            sa.cipher_family.reason
            for sa in record.child_sas
            if sa.cipher_family and sa.cipher_family.evidence == "unknown"
        ]
        needle = want["esp_cipher_family_reason_contains"]
        assert any(needle in (r or "") for r in reasons), (
            f"{name}: abstention reason should mention {needle!r}, got {reasons}"
        )

    def test_inferred_block_size_matches_the_real_cipher(self, case):
        name, record, want = case
        if "esp_block_size_bytes" not in want:
            return
        sizes = {
            sa.block_size_bytes.value
            for sa in record.child_sas
            if sa.block_size_bytes and sa.block_size_bytes.is_known
        }
        assert want["esp_block_size_bytes"] in sizes, (
            f"{name}: expected block size {want['esp_block_size_bytes']}, got {sizes}"
        )

    def test_esp_key_length_is_always_unknown(self, case):
        """The project load-bearing negative result: AES-128 and AES-256 are
        indistinguishable in ciphertext, so this must never report a value."""
        name, record, _want = case
        for sa in record.child_sas:
            if sa.key_length is None:
                continue
            assert sa.key_length.evidence == "unknown", (
                f"{name}: ESP key length claims {sa.key_length.value!r}, but it is "
                "not recoverable from ciphertext"
            )


class TestRekeyObservation:
    def test_measured_rekey_intervals_match_the_configured_lifetime(self, case):
        name, record, want = case
        if "child_sa_rekey_intervals_s" not in want:
            return
        measured = sorted(
            sa.rekey_interval_s.value
            for sa in record.child_sas
            if sa.rekey_interval_s and sa.rekey_interval_s.is_known
        )
        wanted = sorted(want["child_sa_rekey_intervals_s"])
        assert len(measured) == len(wanted), (
            f"{name}: expected {len(wanted)} measured interval(s), got {measured}"
        )
        for got, expect in zip(measured, wanted):
            assert got == pytest.approx(expect, abs=1.0), (
                f"{name}: interval {got}s differs from the configured {expect}s"
            )

    def test_last_sa_has_no_measurable_lifetime(self, case):
        """The final SA in a capture has no successor, so its lifetime was never
        shown. Reporting one would be inventing it."""
        name, record, want = case
        if want.get("child_sa_count", 0) < 2:
            return
        unknowns = [
            sa for sa in record.child_sas
            if sa.rekey_interval_s and not sa.rekey_interval_s.is_known
        ]
        assert unknowns, f"{name}: every SA claims a lifetime, including the last"

    def test_ike_rekeys_are_inferred_never_observed(self, case):
        """An IKE SA rekey happens inside the encrypted exchange, so the link
        between old and new SA cannot be Observed."""
        name, record, want = case
        if "ike_rekeys_inferred" not in want:
            return
        assert len(record.ike.rekeys) == want["ike_rekeys_inferred"], (
            f"{name}: expected {want['ike_rekeys_inferred']} inferred IKE rekey(s), "
            f"got {len(record.ike.rekeys)}"
        )
        for rekey in record.ike.rekeys:
            assert rekey.key_exchange_present.evidence == "inferred"
            assert rekey.key_exchange_present.confidence < 1.0
