"""Wire-format parsing, including the cases real captures actually contain."""

from __future__ import annotations

import struct

import pytest

from analyzer.ike.messages import (
    IKE_HEADER_LEN,
    PAYLOAD_SK,
    MalformedMessage,
    looks_like_ike,
    parse_attributes,
    parse_header,
    parse_message,
)

ISPI = bytes.fromhex("1122334455667788")
ZERO = b"\x00" * 8


def ike_packet(payloads: list[tuple[int, bytes]], *, first: int, exchange: int = 34,
               flags: int = 0x08, rspi: bytes = ZERO) -> bytes:
    """Build an IKE message from (payload_type, body) pairs."""
    chain = b""
    for index, (_ptype, body) in enumerate(payloads):
        nxt = payloads[index + 1][0] if index + 1 < len(payloads) else 0
        chain += struct.pack("!BBH", nxt, 0, 4 + len(body)) + body
    total = IKE_HEADER_LEN + len(chain)
    header = (
        ISPI + rspi + struct.pack("!BBBB", first, 0x20, exchange, flags)
        + struct.pack("!II", 0, total)
    )
    return header + chain


class TestHeader:
    def test_reads_the_fixed_fields(self):
        h = parse_header(ike_packet([(33, b"\x00" * 4)], first=33))
        assert h.version == "IKEv2"
        assert h.exchange_type == 34
        assert h.is_initiator and h.is_request
        assert h.is_first_request
        assert h.initiator_spi_hex == "1122334455667788"

    def test_too_short_is_malformed(self):
        with pytest.raises(MalformedMessage, match="28 bytes"):
            parse_header(b"\x00" * 12)

    def test_impossible_declared_length_is_malformed(self):
        bad = ISPI + ZERO + struct.pack("!BBBB", 33, 0x20, 34, 0x08) + struct.pack("!II", 0, 4)
        with pytest.raises(MalformedMessage, match="below the header"):
            parse_header(bad)

    def test_response_flag(self):
        h = parse_header(ike_packet([(33, b"")], first=33, flags=0x20))
        assert h.is_response and not h.is_request


class TestPayloadChain:
    def test_walks_several_payloads(self):
        pkt = ike_packet([(33, b"\xaa" * 8), (34, b"\xbb" * 4), (40, b"\xcc" * 4)], first=33)
        m = parse_message(pkt, packet_number=1, timestamp=0.0, src="a", dst="b",
                          sport=500, dport=500)
        assert m.payload_types == [33, 34, 40]
        assert m.payloads[0].body == b"\xaa" * 8
        assert not m.defects

    def test_stops_at_the_encrypted_payload(self):
        """The SK Next Payload names what is inside it, not a sibling.

        Walking past it lands at the end of the message and invents a truncation.
        This was a real bug: every SK-bearing message in a live capture reported
        a defect that was not there.
        """
        pkt = ike_packet([(PAYLOAD_SK, b"\xee" * 32)], first=PAYLOAD_SK)
        # make the SK payload claim an inner next-payload, as a real one does
        patched = bytearray(pkt)
        patched[IKE_HEADER_LEN] = 35  # IDi, which lives inside the ciphertext
        m = parse_message(bytes(patched), packet_number=3, timestamp=0.0, src="a",
                          dst="b", sport=4500, dport=4500)
        assert m.payload_types == [PAYLOAD_SK]
        assert not m.defects, f"unexpected defects: {m.defects}"

    def test_truncated_payload_is_kept_and_flagged(self):
        pkt = ike_packet([(33, b"\xaa" * 40)], first=33)
        m = parse_message(pkt[:-20], packet_number=4, timestamp=0.0, src="a", dst="b",
                          sport=500, dport=500)
        assert m.truncated
        assert m.payload_types == [33]
        # the partial body survives, because it is often still readable
        assert len(m.payloads[0].body) > 0

    def test_zero_length_payload_does_not_loop(self):
        bad = (
            ISPI + ZERO + struct.pack("!BBBB", 33, 0x20, 34, 0x08)
            + struct.pack("!II", 0, IKE_HEADER_LEN + 4)
            + struct.pack("!BBH", 33, 0, 0)
        )
        m = parse_message(bad, packet_number=5, timestamp=0.0, src="a", dst="b",
                          sport=500, dport=500)
        assert any("below the" in d for d in m.defects)


class TestLooksLikeIke:
    def test_accepts_a_real_header(self):
        assert looks_like_ike(ike_packet([(33, b"")], first=33))

    @pytest.mark.parametrize(
        "data",
        [b"", b"\x00" * 10, b"\x00" * 40, b"\xff" * 40],
        ids=["empty", "short", "all-zero", "all-ones"],
    )
    def test_rejects_non_ike(self, data):
        assert not looks_like_ike(data)


class TestAttributes:
    def test_tv_form(self):
        assert parse_attributes(struct.pack("!HH", 0x800E, 256)) == {14: 256}

    def test_tlv_form(self):
        assert parse_attributes(struct.pack("!HHI", 12, 4, 3600)) == {12: 3600}

    def test_overlong_declaration_is_flagged_not_truncated(self):
        defects: list[str] = []
        assert parse_attributes(struct.pack("!HH", 12, 99), defects) == {}
        assert defects and "99 bytes" in defects[0]

    def test_wide_value_is_skipped_rather_than_truncated(self):
        """A 16-byte attribute value is not silently cut to an integer."""
        defects: list[str] = []
        data = struct.pack("!HH", 6, 16) + b"\xab" * 16
        assert parse_attributes(data, defects) == {}
        assert any("not read as an integer" in d for d in defects)
