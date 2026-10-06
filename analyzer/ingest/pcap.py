"""Read a capture file and sort its packets into IKE, ESP and AH.

This is stage 1 of the pipeline. It does no interpretation beyond deciding what
each packet is, but two of those decisions are easy to get wrong and worth
spelling out:

**Telling IKE from ESP on UDP 4500.** Once peers decide NAT is in the way they
move both IKE and ESP onto UDP 4500 (RFC 3948). The two are told apart by the
non-ESP marker: an IKE message is prefixed with four zero bytes, while an
ESP-in-UDP packet starts straight in on its SPI. An SPI of zero is not legal, so
the test is unambiguous. Getting this backwards silently drops half a capture.

**Measuring the ESP payload.** The length-residue analysis in phase 4 depends on
measuring the right bytes: everything after the 8-byte SPI and sequence number,
which is IV plus ciphertext plus padding plus the ICV. It is recorded here once,
at read time, so every later stage measures the same thing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

#: UDP ports that carry IKE.
PORT_IKE = 500
PORT_IKE_NATT = 4500

#: IP protocol numbers for the IPsec protocols themselves.
PROTO_ESP = 50
PROTO_AH = 51

#: Four zero bytes prefixed to an IKE message sent over UDP 4500, to distinguish
#: it from ESP (RFC 3948 section 2.2).
NON_ESP_MARKER = b"\x00\x00\x00\x00"

#: ESP header is SPI plus sequence number.
ESP_HEADER_LEN = 8


@dataclass(slots=True)
class IkePacket:
    """A UDP payload that looks like an IKE message."""

    data: bytes
    packet_number: int
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    ip_version: int
    udp_encapsulated: bool = False


@dataclass(slots=True)
class EspPacket:
    """One ESP packet, reduced to the fields visible without decryption."""

    spi: str
    seq: int
    payload_len: int
    packet_number: int
    timestamp: float
    src: str
    dst: str
    ip_version: int
    #: Length of the whole ESP datagram including the 8-byte header.
    esp_len: int
    udp_encapsulated: bool = False


@dataclass(slots=True)
class AhPacket:
    """One AH packet.

    AH does not encrypt, so the next-header field is readable and tells Tunnel
    from Transport mode outright. That is the one place IPsec mode is Observed
    rather than Inferred (VISION.md section 5.1).
    """

    spi: str
    seq: int
    next_header: int
    icv_len: int
    packet_number: int
    timestamp: float
    src: str
    dst: str
    ip_version: int
    payload_len: int


@dataclass(slots=True)
class Capture:
    """Everything stage 1 recovered from one capture file."""

    path: Path
    ike: list[IkePacket] = field(default_factory=list)
    esp: list[EspPacket] = field(default_factory=list)
    ah: list[AhPacket] = field(default_factory=list)
    packet_count: int = 0
    #: Packets that were none of IKE, ESP or AH. Counted, not kept: a VPN capture
    #: usually contains plenty of unrelated traffic and the count is enough to
    #: tell an analyst the filter was wider than the analysis.
    other_count: int = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def duration_s(self) -> float:
        if self.first_timestamp is None or self.last_timestamp is None:
            return 0.0
        return self.last_timestamp - self.first_timestamp

    @property
    def is_empty(self) -> bool:
        return not (self.ike or self.esp or self.ah)

    def summary(self) -> str:
        return (
            f"{self.packet_count} packets over {self.duration_s:.1f}s: "
            f"{len(self.ike)} IKE, {len(self.esp)} ESP, {len(self.ah)} AH, "
            f"{self.other_count} other"
        )


def _classify_udp(
    payload: bytes,
    *,
    sport: int,
    dport: int,
) -> str | None:
    """Decide whether a UDP payload is IKE, ESP-in-UDP, or neither.

    Returns "ike", "esp", or None.
    """
    if sport not in (PORT_IKE, PORT_IKE_NATT) and dport not in (PORT_IKE, PORT_IKE_NATT):
        return None

    on_natt_port = PORT_IKE_NATT in (sport, dport)

    if on_natt_port:
        # The non-ESP marker says IKE. Anything else on 4500 is ESP, because an
        # all-zero SPI is not valid, so there is no ambiguity to resolve.
        if payload.startswith(NON_ESP_MARKER):
            return "ike"
        if len(payload) >= ESP_HEADER_LEN:
            return "esp"
        return None

    # Port 500 carries IKE only, with no marker.
    return "ike" if len(payload) >= 28 else None


def _parse_esp(payload: bytes) -> tuple[str, int, int] | None:
    """Pull the SPI, sequence number and payload length out of an ESP packet."""
    if len(payload) < ESP_HEADER_LEN:
        return None
    spi, seq = struct.unpack("!II", payload[:ESP_HEADER_LEN])
    return f"{spi:08x}", seq, len(payload) - ESP_HEADER_LEN


def _parse_ah(payload: bytes) -> tuple[str, int, int, int, int] | None:
    """Pull the readable fields out of an AH packet (RFC 4302 section 2).

    Returns SPI, sequence, next header, ICV length and the length of what AH is
    protecting. The ICV length is derived from the payload-length field, which
    counts 32-bit words of the whole header minus two.
    """
    if len(payload) < 12:
        return None
    next_header, payload_len_words = struct.unpack("!BB", payload[:2])
    spi, seq = struct.unpack("!II", payload[4:12])
    total_header = (payload_len_words + 2) * 4
    icv_len = max(0, total_header - 12)
    return f"{spi:08x}", seq, next_header, icv_len, max(0, len(payload) - total_header)


def read_capture(path: str | Path, *, max_packets: int | None = None) -> Capture:
    """Read a pcap or pcapng file and sort out the IPsec traffic.

    Streams the file rather than loading it, so a capture far larger than memory
    is fine, which the 100 MB speed target in VISION.md section 9 requires.

    Packet numbers are 1-based to match what Wireshark shows, because an Observed
    attribute citing "packet 2" has to mean the same packet to the analyst who
    opens the capture to check it.
    """
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    p = Path(path)
    capture = Capture(path=p)

    with PcapReader(str(p)) as reader:
        for index, packet in enumerate(reader, start=1):
            if max_packets is not None and index > max_packets:
                capture.warnings.append(
                    f"stopped after {max_packets} packets at the caller request"
                )
                break

            capture.packet_count = index
            timestamp = float(packet.time)
            if capture.first_timestamp is None:
                capture.first_timestamp = timestamp
            capture.last_timestamp = timestamp

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                ip_version = 4
                proto = ip_layer.proto
            elif packet.haslayer(IPv6):
                ip_layer = packet[IPv6]
                ip_version = 6
                proto = ip_layer.nh
            else:
                capture.other_count += 1
                continue

            src, dst = str(ip_layer.src), str(ip_layer.dst)

            if proto == PROTO_ESP:
                parsed = _parse_esp(bytes(ip_layer.payload))
                if parsed is None:
                    capture.warnings.append(f"packet {index}: ESP header too short to read")
                    capture.other_count += 1
                    continue
                spi, seq, payload_len = parsed
                capture.esp.append(
                    EspPacket(
                        spi=spi,
                        seq=seq,
                        payload_len=payload_len,
                        packet_number=index,
                        timestamp=timestamp,
                        src=src,
                        dst=dst,
                        ip_version=ip_version,
                        esp_len=payload_len + ESP_HEADER_LEN,
                    )
                )
                continue

            if proto == PROTO_AH:
                parsed_ah = _parse_ah(bytes(ip_layer.payload))
                if parsed_ah is None:
                    capture.warnings.append(f"packet {index}: AH header too short to read")
                    capture.other_count += 1
                    continue
                spi, seq, next_header, icv_len, protected_len = parsed_ah
                capture.ah.append(
                    AhPacket(
                        spi=spi,
                        seq=seq,
                        next_header=next_header,
                        icv_len=icv_len,
                        packet_number=index,
                        timestamp=timestamp,
                        src=src,
                        dst=dst,
                        ip_version=ip_version,
                        payload_len=protected_len,
                    )
                )
                continue

            if not packet.haslayer(UDP):
                capture.other_count += 1
                continue

            udp = packet[UDP]
            payload = bytes(udp.payload)
            kind = _classify_udp(payload, sport=int(udp.sport), dport=int(udp.dport))

            if kind == "ike":
                on_natt = PORT_IKE_NATT in (int(udp.sport), int(udp.dport))
                data = payload[len(NON_ESP_MARKER) :] if on_natt else payload
                capture.ike.append(
                    IkePacket(
                        data=data,
                        packet_number=index,
                        timestamp=timestamp,
                        src=src,
                        dst=dst,
                        sport=int(udp.sport),
                        dport=int(udp.dport),
                        ip_version=ip_version,
                        udp_encapsulated=on_natt,
                    )
                )
            elif kind == "esp":
                parsed = _parse_esp(payload)
                if parsed is None:
                    capture.other_count += 1
                    continue
                spi, seq, payload_len = parsed
                capture.esp.append(
                    EspPacket(
                        spi=spi,
                        seq=seq,
                        payload_len=payload_len,
                        packet_number=index,
                        timestamp=timestamp,
                        src=src,
                        dst=dst,
                        ip_version=ip_version,
                        esp_len=payload_len + ESP_HEADER_LEN,
                        udp_encapsulated=True,
                    )
                )
            else:
                capture.other_count += 1

    if capture.is_empty:
        capture.warnings.append(
            "No IKE, ESP or AH traffic found. Check that the capture covers the "
            "link between the peers and was not filtered to exclude IPsec."
        )

    return capture
