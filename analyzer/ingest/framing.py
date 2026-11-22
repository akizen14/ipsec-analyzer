"""Check capture framing before Scapy can mistake a short read for EOF."""

from __future__ import annotations

import struct
from itertools import islice
from typing import BinaryIO

PCAP_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xa1\xb2\x3c\x4d": ">",
}
SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
BYTE_ORDER = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}
PACKET_BLOCKS = {2, 3, 6}


def _pcap_packets(source: BinaryIO, end: int, endian: str):
    if end < 24:
        raise EOFError("Truncated PCAP file header.")
    source.seek(24)
    while source.tell() < end:
        header = source.read(16)
        if len(header) != 16:
            raise EOFError("Truncated PCAP packet header.")
        captured_size = struct.unpack_from(f"{endian}I", header, 8)[0]
        if source.tell() + captured_size > end:
            raise EOFError("Truncated PCAP packet data.")
        source.seek(captured_size, 1)
        yield


def _pcapng_packets(source: BinaryIO, end: int):
    endian = "<"
    while (start := source.tell()) < end:
        header = source.read(8)
        if len(header) != 8:
            raise EOFError("Truncated PCAPNG block header.")
        section = header[:4] == SECTION_HEADER
        if section:
            byte_order = BYTE_ORDER.get(source.read(4))
            if byte_order is None:
                raise EOFError("Invalid PCAPNG section byte order.")
            endian = byte_order

        block_type, size = struct.unpack(f"{endian}II", header)
        if size < (28 if section else 12) or size % 4 or start + size > end:
            raise EOFError("Invalid or truncated PCAPNG block length.")
        source.seek(start + size - 4)
        if source.read(4) != header[4:]:
            raise EOFError("PCAPNG block length does not match its trailer.")
        if block_type in PACKET_BLOCKS:
            yield


def check_framing(source: BinaryIO, max_packets: int | None) -> None:
    """Check frame boundaries without reading packet bodies or passing the limit."""
    magic = source.read(4)
    if magic == SECTION_HEADER or magic in PCAP_ENDIAN:
        size = source.seek(0, 2)
        source.seek(0)
        packets = (
            _pcapng_packets(source, size)
            if magic == SECTION_HEADER
            else _pcap_packets(source, size, PCAP_ENDIAN[magic])
        )
        stop = max_packets + 1 if max_packets is not None else None
        for _ in islice(packets, stop):
            pass
    source.seek(0)
