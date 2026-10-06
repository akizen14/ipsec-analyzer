"""Structural parsing of IKE messages, version agnostic.

This module walks bytes and nothing more. It knows the shapes in RFC 7296
section 3 and RFC 2408 section 3, so it can split a UDP payload into a header
and a list of payloads, but it attaches no meaning to what it finds. Meaning is
added in ``parser_v2.py`` (and later ``parser_v1.py``), which is what keeps the
wire format and the security interpretation separable and separately testable.

Two decisions worth knowing about:

* **Nothing raises on malformed input.** A capture of real traffic contains
  truncated packets, retransmissions and the occasional thing no RFC describes.
  A parse problem is recorded on the message as a defect and the walk stops
  cleanly, because a tool that crashes on packet 4000 of 4001 is useless.
* **Offsets are kept.** Every payload remembers where in the packet it came
  from, so an Observed attribute can cite a byte range and not just a packet
  number.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator

#: Length of the fixed IKE header, identical in IKEv1 and IKEv2.
IKE_HEADER_LEN = 28

#: Length of the generic payload header that precedes every payload body.
PAYLOAD_HEADER_LEN = 4

#: IKEv2 header flags (RFC 7296 section 3.1).
FLAG_INITIATOR = 0x08
FLAG_VERSION = 0x10
FLAG_RESPONSE = 0x20

#: An all-zero responder SPI marks the very first message of an exchange.
ZERO_SPI = b"\x00" * 8

#: IKEv2 payload types whose Next Payload field describes their own encrypted
#: contents rather than a sibling payload, so the outer chain ends at them.
#: SK is the Encrypted payload and SKF the Encrypted Fragment (RFC 7383).
PAYLOAD_SK = 46
PAYLOAD_SKF = 53
PAYLOAD_TERMINATORS_V2 = frozenset({PAYLOAD_SK, PAYLOAD_SKF})


class MalformedMessage(ValueError):
    """Raised by the strict parse helpers when bytes cannot be a valid IKE message."""


@dataclass(frozen=True, slots=True)
class IkeHeader:
    """The fixed 28-byte IKE header."""

    initiator_spi: bytes
    responder_spi: bytes
    next_payload: int
    major_version: int
    minor_version: int
    exchange_type: int
    flags: int
    message_id: int
    length: int

    @property
    def is_initiator(self) -> bool:
        """Whether this message came from the original initiator of the IKE SA."""
        return bool(self.flags & FLAG_INITIATOR)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def is_request(self) -> bool:
        return not self.is_response

    @property
    def version(self) -> str:
        return f"IKEv{self.major_version}"

    @property
    def spi_pair(self) -> tuple[bytes, bytes]:
        """Identifies the IKE SA this message belongs to.

        The session builder groups messages by this pair. Note that the responder
        SPI is zero in the first request, so the builder has to match on the
        initiator SPI alone until the responder has answered.
        """
        return (self.initiator_spi, self.responder_spi)

    @property
    def initiator_spi_hex(self) -> str:
        return self.initiator_spi.hex()

    @property
    def responder_spi_hex(self) -> str:
        return self.responder_spi.hex()

    @property
    def is_first_request(self) -> bool:
        return self.responder_spi == ZERO_SPI and self.is_request


@dataclass(frozen=True, slots=True)
class RawPayload:
    """One payload, split out but not interpreted.

    ``body`` excludes the 4-byte generic header, since every payload-specific
    parser wants to start at its own first field.
    """

    payload_type: int
    critical: bool
    body: bytes
    offset: int

    def __len__(self) -> int:
        return len(self.body)


@dataclass(slots=True)
class IkeMessage:
    """One IKE message, located in its capture.

    ``defects`` is the honest record of anything that did not parse. It travels
    with the message so the session record can carry a warning instead of the
    analysis quietly reporting less than it should.
    """

    header: IkeHeader
    payloads: list[RawPayload]
    packet_number: int
    timestamp: float
    src: str
    dst: str
    sport: int
    dport: int
    udp_encapsulated: bool = False
    defects: list[str] = field(default_factory=list)

    def of_type(self, payload_type: int) -> Iterator[RawPayload]:
        """Every payload of a given type, in wire order."""
        for p in self.payloads:
            if p.payload_type == payload_type:
                yield p

    def first_of_type(self, payload_type: int) -> RawPayload | None:
        return next(self.of_type(payload_type), None)

    def has_type(self, payload_type: int) -> bool:
        return any(p.payload_type == payload_type for p in self.payloads)

    @property
    def payload_types(self) -> list[int]:
        return [p.payload_type for p in self.payloads]

    @property
    def truncated(self) -> bool:
        """Whether the declared header length exceeds what was actually captured."""
        return any(d.startswith("truncated") for d in self.defects)


def parse_header(data: bytes) -> IkeHeader:
    """Parse the fixed IKE header.

    Raises :class:`MalformedMessage` when the buffer is too short or the declared
    length is impossible, which is the signal to the caller that these bytes were
    probably never an IKE message in the first place.
    """
    if len(data) < IKE_HEADER_LEN:
        raise MalformedMessage(
            f"need {IKE_HEADER_LEN} bytes for an IKE header, got {len(data)}"
        )

    ispi = data[0:8]
    rspi = data[8:16]
    next_payload, version, exchange_type, flags = struct.unpack("!BBBB", data[16:20])
    message_id, length = struct.unpack("!II", data[20:28])

    if length < IKE_HEADER_LEN:
        raise MalformedMessage(f"declared IKE length {length} is below the header size")

    return IkeHeader(
        initiator_spi=ispi,
        responder_spi=rspi,
        next_payload=next_payload,
        major_version=(version >> 4) & 0x0F,
        minor_version=version & 0x0F,
        exchange_type=exchange_type,
        flags=flags,
        message_id=message_id,
        length=length,
    )


def walk_payloads(
    data: bytes,
    first_payload_type: int,
    *,
    start: int = IKE_HEADER_LEN,
    defects: list[str] | None = None,
    terminators: frozenset[int] = frozenset(),
) -> list[RawPayload]:
    """Walk the payload chain, stopping cleanly at the first thing that does not fit.

    The chain is singly linked: each payload header names the type of the next
    one, and a type of 0 ends it. That makes the walk vulnerable to a single bad
    length field, so every step is bounds-checked and any problem is appended to
    ``defects`` rather than raised. Whatever parsed before the problem is still
    returned and still usable.

    ``terminators`` names payload types after which the walk must stop even
    though their Next Payload field is non-zero. The IKEv2 Encrypted payload is
    why this exists: its Next Payload names the first payload *inside* the
    ciphertext, not a sibling that follows it. Walking past it lands at the end
    of the message and reports a truncation that is not real.
    """
    log = defects if defects is not None else []
    payloads: list[RawPayload] = []
    offset = start
    next_type = first_payload_type
    seen = 0

    while next_type != 0:
        seen += 1
        if seen > 64:
            log.append(f"payload chain exceeded 64 payloads at offset {offset}, stopping")
            break
        if offset + PAYLOAD_HEADER_LEN > len(data):
            log.append(
                f"truncated at offset {offset}: payload header needs "
                f"{PAYLOAD_HEADER_LEN} bytes, {len(data) - offset} remain"
            )
            break

        nxt, critical_byte, payload_length = struct.unpack(
            "!BBH", data[offset : offset + PAYLOAD_HEADER_LEN]
        )

        if payload_length < PAYLOAD_HEADER_LEN:
            log.append(
                f"payload type {next_type} at offset {offset} declares length "
                f"{payload_length}, below the {PAYLOAD_HEADER_LEN}-byte header"
            )
            break

        end = offset + payload_length
        if end > len(data):
            # Keep what was captured. A capture cut mid-payload is common and the
            # partial body is often still enough to read the fields that matter.
            log.append(
                f"truncated payload type {next_type} at offset {offset}: declares "
                f"{payload_length} bytes, {len(data) - offset} remain"
            )
            payloads.append(
                RawPayload(
                    payload_type=next_type,
                    critical=bool(critical_byte & 0x80),
                    body=data[offset + PAYLOAD_HEADER_LEN :],
                    offset=offset,
                )
            )
            break

        payloads.append(
            RawPayload(
                payload_type=next_type,
                critical=bool(critical_byte & 0x80),
                body=data[offset + PAYLOAD_HEADER_LEN : end],
                offset=offset,
            )
        )

        if next_type in terminators:
            # Its Next Payload describes what is inside it, not what follows.
            break

        offset = end
        next_type = nxt

    return payloads


def parse_message(
    data: bytes,
    *,
    packet_number: int,
    timestamp: float,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    udp_encapsulated: bool = False,
    terminators: frozenset[int] = PAYLOAD_TERMINATORS_V2,
) -> IkeMessage:
    """Parse one UDP payload into an :class:`IkeMessage`.

    Raises :class:`MalformedMessage` only when the header itself is unusable.
    Problems past the header become defects on the returned message, so a
    partially readable handshake still yields what it can.

    ``terminators`` defaults to the IKEv2 encrypted payload types. Pass an empty
    set when parsing IKEv1, where payload type 46 has no such meaning.
    """
    header = parse_header(data)
    defects: list[str] = []

    if header.major_version not in (1, 2):
        defects.append(f"unexpected IKE major version {header.major_version}")

    # Trust the capture over the header when they disagree: a short snaplen or a
    # cut capture is far likelier than a gateway lying about its own length.
    if header.length > len(data):
        defects.append(
            f"truncated message: header declares {header.length} bytes, {len(data)} captured"
        )
        body = data
    else:
        body = data[: header.length]

    payloads = walk_payloads(
        body, header.next_payload, defects=defects, terminators=terminators
    )

    return IkeMessage(
        header=header,
        payloads=payloads,
        packet_number=packet_number,
        timestamp=timestamp,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        udp_encapsulated=udp_encapsulated,
        defects=defects,
    )


def looks_like_ike(data: bytes) -> bool:
    """Cheap plausibility check before committing to a full parse.

    Used by the ingest stage to tell IKE apart from other traffic on the same
    ports. Deliberately permissive: it screens out obvious non-IKE rather than
    trying to validate.
    """
    if len(data) < IKE_HEADER_LEN:
        return False
    major = (data[17] >> 4) & 0x0F
    if major not in (1, 2):
        return False
    declared = struct.unpack("!I", data[24:28])[0]
    if declared < IKE_HEADER_LEN or declared > 65535:
        return False
    # The initiator SPI is random and never all zeroes in practice.
    return data[0:8] != ZERO_SPI


def parse_attributes(data: bytes, defects: list[str] | None = None) -> dict[int, int]:
    """Parse the TV and TLV attribute encoding shared by IKEv1 and IKEv2.

    Each attribute begins with two bytes whose top bit is the format flag: set
    means the following two bytes are the value itself (TV), clear means they are
    a length followed by that many bytes (TLV). Returns a mapping of attribute
    type to integer value.

    Values wider than 8 bytes are recorded as a defect rather than truncated. The
    only attributes this project reads are small (key length, lifetime), and a
    silently truncated big integer would be worse than a missing one.
    """
    log = defects if defects is not None else []
    out: dict[int, int] = {}
    offset = 0

    while offset + 2 <= len(data):
        raw_type = struct.unpack("!H", data[offset : offset + 2])[0]
        is_tv = bool(raw_type & 0x8000)
        attr_type = raw_type & 0x7FFF
        offset += 2

        if is_tv:
            if offset + 2 > len(data):
                log.append(f"attribute {attr_type} claims a 2-byte value past the end")
                break
            out[attr_type] = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            continue

        if offset + 2 > len(data):
            log.append(f"attribute {attr_type} claims a length field past the end")
            break
        attr_len = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2
        if offset + attr_len > len(data):
            log.append(
                f"attribute {attr_type} declares {attr_len} bytes, {len(data) - offset} remain"
            )
            break
        if 0 < attr_len <= 8:
            out[attr_type] = int.from_bytes(data[offset : offset + attr_len], "big")
        elif attr_len > 8:
            log.append(f"attribute {attr_type} value is {attr_len} bytes, not read as an integer")
        offset += attr_len

    return out
