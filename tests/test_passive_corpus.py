"""Offline regression cases derived from the committed strongSwan captures."""

from scapy.layers.inet import IP
from scapy.utils import PcapReader, PcapWriter

from analyzer.analysis import analyse_capture


def test_classic_pcap_keeps_two_endpoint_pairs_separate(golden_dir, tmp_path):
    fixture = golden_dir / "ikev2-aes256-sha256-dh14.pcapng"
    with PcapReader(str(fixture)) as reader:
        packets = list(reader)

    # Preserve the known healthy session. Copy unidirectional ESP to
    # documentation-only addresses to simulate a second tunnel
    # captured mid-session. Reusing the SPI is deliberate.
    alternate = {"10.80.0.2": "192.0.2.10", "10.80.0.3": "192.0.2.20"}
    esp = [
        packet
        for packet in packets
        if IP in packet and packet[IP].proto == 50 and packet[IP].src == "10.80.0.2"
    ]
    merged = tmp_path / "two-sessions.pcap"
    with PcapWriter(str(merged)) as writer:
        writer.write(packets)
        for index, packet in enumerate(esp[:24], start=1):
            duplicate = packet.copy()
            ip = duplicate[IP]
            ip.src, ip.dst = alternate[ip.src], alternate[ip.dst]
            del ip.chksum
            duplicate.time = packets[-1].time + index
            writer.write(duplicate)

    original, esp_only = analyse_capture(merged).records
    assert (original.endpoints.initiator, original.endpoints.responder) == ("10.80.0.2", "10.80.0.3")
    assert original.ike.encr.value == "ENCR_AES_CBC"
    assert "PQ-001" in {finding.rule_id for finding in original.findings}
    assert original.score.risk_level == "low"

    assert (esp_only.endpoints.initiator, esp_only.endpoints.responder) == (
        "192.0.2.10", "192.0.2.20",
    )
    assert esp_only.ike.encr is None
    assert esp_only.endpoints.nat_t.evidence == "unknown"
    assert {child.protocol.value for child in esp_only.child_sas} == {"ESP"}
    assert {child.spi for child in esp_only.child_sas} <= {
        child.spi for child in original.child_sas
    }
    assert sum(child.packet_count for child in esp_only.child_sas) == 24
    assert any("no IKE handshake" in warning for warning in esp_only.warnings)
    assert not any(finding.rule_id.startswith(("IKE-", "PQ-")) for finding in esp_only.findings)
