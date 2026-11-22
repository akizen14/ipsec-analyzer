"""Separate fresh negotiations between the same endpoints."""

from dataclasses import replace
from pathlib import Path

import pytest

from analyzer.ingest.pcap import read_capture
from analyzer.record.validate import validate
from analyzer.scoring.score import assess
from analyzer.sessions.builder import build_sessions


@pytest.fixture
def reconnect_capture(golden_dir):
    first = read_capture(golden_dir / "ikev2-aes256-sha256-dh14.pcapng")
    second = read_capture(golden_dir / "ikev2-3des-sha1-dh2-downgrade.pcapng")
    shift = first.last_timestamp + 5 - second.first_timestamp

    def move(packet):
        return replace(
            packet,
            timestamp=packet.timestamp + shift,
            packet_number=packet.packet_number + first.packet_count,
        )

    # The checked-in endpoint pairs match and the two testbed runs have
    # different initiator SPIs. Place them in consecutive capture windows.
    return replace(
        first,
        path=Path("reconnect.pcapng"),
        ike=[*first.ike, *(move(packet) for packet in second.ike)],
        esp=[*first.esp, *(move(packet) for packet in second.esp)],
        packet_count=first.packet_count + second.packet_count,
        last_timestamp=second.last_timestamp + shift,
    ), second.esp[0].spi


def test_reconnect_keeps_both_negotiations_and_their_evidence(reconnect_capture):
    capture, second_spi = reconnect_capture
    records = build_sessions(capture)
    assert [record.ike.encr.value for record in records] == ["ENCR_AES_CBC", "ENCR_3DES"]
    first, second = records
    assert len(first.ike.rekeys) == 1
    assert second.ike.rekeys == []
    assert [len(record.child_sas) for record in records] == [3, 1]
    assert second_spi in {second.child_sas[0].spi, second.child_sas[0].direction_pair_spi}
    assert any("timing" in warning for warning in second.warnings)

    for record in records:
        assess(record)
        validate(record)
    assert [record.score.risk_level for record in records] == ["low", "high"]
    assert "IKE-011" not in {finding.rule_id for finding in first.findings}
    assert "IKE-011" in {finding.rule_id for finding in second.findings}


def test_overlapping_traffic_is_kept_without_a_guessed_ike_parent(reconnect_capture):
    capture, second_spi = reconnect_capture
    last_packet = replace(
        capture.esp[0],
        timestamp=capture.last_timestamp + 1,
        packet_number=capture.packet_count + 1,
    )
    capture.esp.append(last_packet)
    capture.last_timestamp = last_packet.timestamp
    capture.packet_count += 1

    first, second, unmatched = build_sessions(capture)
    assert first.ike.encr.value == "ENCR_AES_CBC"
    assert second.ike.encr.value == "ENCR_3DES"
    assert second.child_sas == []
    assert unmatched.ike.encr is None
    assert second_spi in {
        spi for sa in unmatched.child_sas for spi in (sa.spi, sa.direction_pair_spi)
    }
    assert all(sa.direction_pair_spi is None for sa in unmatched.child_sas)
    assert all(not sa.rekey_interval_s.is_known for sa in unmatched.child_sas)
    assert any("could not be associated" in warning for warning in unmatched.warnings)
    for record in (first, second, unmatched):
        assess(record)
        validate(record)
