"""Deterministic IKEv2 parser.

This is the Observed half of the project. Everything it reports comes from a
cleartext field and cites the packet it was read from, so there is no model and
no probability anywhere in this file. VISION.md section 12 row 1 settles the
disagreement between the source documents in favour of exactly this: the IKE
parameters are parsed, not predicted.

What it reaches, and what it deliberately does not:

* ``IKE_SA_INIT`` is cleartext, so the IKE SA cipher, PRF, integrity algorithm,
  key exchange group, notifications and vendor IDs are all Observed.
* The proposals the initiator **offered** come from the request, and the single
  proposal the responder **selected** comes from the response. Keeping both is
  what makes the downgrade rules IKE-040 and IKE-041 possible.
* ``IKE_AUTH`` is encrypted, so the authentication method and the peer
  identities are Unknown for IKEv2. They are reported as such with a reason,
  never guessed. This is the row that the deck got wrong and VISION.md
  section 5.1 corrects.
* IKEv2 does not negotiate an IKE SA lifetime at all, so that is Unknown here
  and is inferred from observed rekey timing elsewhere.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from analyzer.ike import transforms as tf
from analyzer.ike.messages import IkeMessage, RawPayload, parse_attributes
from analyzer.record import Attribute, IkeSa, Proposal

#: IKEv2 payload type numbers this parser acts on.
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_NONCE = 40
PAYLOAD_NOTIFY = 41
PAYLOAD_VENDOR_ID = 43
PAYLOAD_SK = 46
PAYLOAD_SKF = 53

EXCHANGE_IKE_SA_INIT = 34
EXCHANGE_IKE_AUTH = 35
EXCHANGE_CREATE_CHILD_SA = 36
EXCHANGE_INFORMATIONAL = 37

#: Last Substruc values. 2 means another proposal follows, 3 another transform.
MORE_PROPOSALS = 2
MORE_TRANSFORMS = 3


@dataclass(slots=True)
class Notification:
    """One cleartext notify payload."""

    notify_type: int
    name: str
    protocol_id: int
    spi: bytes
    data: bytes
    packet: int

    def to_json(self) -> dict[str, object]:
        return {"type": self.notify_type, "name": self.name, "packet": self.packet}


@dataclass(slots=True)
class VendorId:
    raw: bytes
    packet: int

    def interpret(self) -> str | None:
        """Best-effort identification of the sender.

        Deliberately conservative. A vendor ID is attacker-controllable and
        several implementations send a hash, so this only names what it is sure
        of and returns None otherwise. Learned fingerprinting is a later phase
        and belongs in ``analyzer/probe``, not here.
        """
        text = self.raw.decode("ascii", errors="ignore")
        printable = "".join(c for c in text if c.isprintable())
        if len(printable) >= 6 and printable.strip():
            return printable.strip()
        return None

    def to_json(self) -> dict[str, object]:
        return {"raw": self.raw.hex(), "interpreted": self.interpret(), "packet": self.packet}


def parse_transform(data: bytes, offset: int, defects: list[str]) -> tuple[dict, int] | None:
    """Parse one transform substructure (RFC 7296 section 3.3.2).

    Returns the transform and the offset of the next one, or None when the bytes
    will not support a transform, which ends the enclosing loop.
    """
    if offset + 8 > len(data):
        defects.append(f"transform at offset {offset} is cut short")
        return None

    last, _reserved, length = struct.unpack("!BBH", data[offset : offset + 4])
    ttype, _res2, tid = struct.unpack("!BBH", data[offset + 4 : offset + 8])

    if length < 8:
        defects.append(f"transform at offset {offset} declares length {length}, minimum is 8")
        return None
    end = min(offset + length, len(data))
    if offset + length > len(data):
        defects.append(
            f"transform at offset {offset} declares {length} bytes, "
            f"{len(data) - offset} remain"
        )

    attrs = parse_attributes(data[offset + 8 : end], defects)

    return (
        {
            "type": ttype,
            "id": tid,
            "name": tf.transform_name(ttype, tid),
            "attributes": attrs,
            "last": last != MORE_TRANSFORMS,
        },
        end,
    )


def parse_proposal(data: bytes, offset: int, defects: list[str]) -> tuple[Proposal, int, bool] | None:
    """Parse one proposal substructure (RFC 7296 section 3.3.1).

    Returns the proposal, the offset of the next one, and whether this was the
    last. Transforms are collapsed onto the Proposal fields by type, while the
    raw list is kept so an algorithm the registries do not know still reaches
    the report.
    """
    if offset + 8 > len(data):
        defects.append(f"proposal at offset {offset} is cut short")
        return None

    last, _reserved, prop_length = struct.unpack("!BBH", data[offset : offset + 4])
    prop_num, protocol_id, spi_size, num_transforms = struct.unpack(
        "!BBBB", data[offset + 4 : offset + 8]
    )

    if prop_length < 8:
        defects.append(f"proposal at offset {offset} declares length {prop_length}, minimum is 8")
        return None

    prop_end = min(offset + prop_length, len(data))
    if offset + prop_length > len(data):
        defects.append(
            f"proposal {prop_num} declares {prop_length} bytes, {len(data) - offset} remain"
        )

    cursor = offset + 8
    spi = b""
    if spi_size:
        if cursor + spi_size > len(data):
            defects.append(f"proposal {prop_num} SPI of {spi_size} bytes runs past the payload")
            return None
        spi = data[cursor : cursor + spi_size]
        cursor += spi_size

    proposal = Proposal(
        number=prop_num,
        protocol=tf.PROTOCOL_IDS.get(protocol_id, f"PROTO_{protocol_id}"),
        spi=spi.hex() or None,
    )

    seen = 0
    while cursor < prop_end and seen < num_transforms + 4:
        parsed = parse_transform(data, cursor, defects)
        if parsed is None:
            break
        transform, cursor = parsed
        seen += 1
        _apply_transform(proposal, transform)
        proposal.raw_transforms.append(
            {"type": transform["type"], "id": transform["id"], "attributes": transform["attributes"]}
        )
        if transform["last"]:
            break

    if seen != num_transforms:
        defects.append(
            f"proposal {prop_num} declares {num_transforms} transforms, parsed {seen}"
        )

    return proposal, prop_end, last != MORE_PROPOSALS


def _apply_transform(proposal: Proposal, transform: dict) -> None:
    """Fold one transform onto the matching Proposal field.

    Key length arrives as transform attribute 14 on the encryption transform
    rather than as part of the transform ID, which is why AES-128 and AES-256
    share the ID 12 and are told apart only by this attribute.
    """
    ttype = transform["type"]
    tid = transform["id"]
    attrs = transform["attributes"]

    if ttype == tf.TRANSFORM_ENCR:
        proposal.encr = tf.encr_name(tid)
        key_bits = attrs.get(tf.TRANSFORM_ATTR_KEY_LENGTH)
        if key_bits:
            proposal.encr_key_bits = key_bits
    elif ttype == tf.TRANSFORM_PRF:
        proposal.prf = tf.prf_name(tid)
    elif ttype == tf.TRANSFORM_INTEG:
        proposal.integ = tf.integ_name(tid)
    elif ttype == tf.TRANSFORM_DH:
        proposal.dh_group = tid
    elif ttype == tf.TRANSFORM_ESN:
        proposal.esn = tf.esn_name(tid)


def parse_sa_payload(payload: RawPayload, packet: int, defects: list[str]) -> list[Proposal]:
    """Parse an SA payload into its list of proposals."""
    proposals: list[Proposal] = []
    offset = 0
    guard = 0

    while offset < len(payload.body) and guard < 32:
        guard += 1
        parsed = parse_proposal(payload.body, offset, defects)
        if parsed is None:
            break
        proposal, offset, is_last = parsed
        proposal.packet = packet
        proposals.append(proposal)
        if is_last:
            break

    return proposals


def parse_ke_payload(payload: RawPayload, defects: list[str]) -> int | None:
    """Read the key exchange group from a KE payload (RFC 7296 section 3.4).

    Worth reading separately from the SA proposal because the KE payload records
    the group actually used for this exchange, whereas the proposal records what
    was on offer. A mismatch means the responder sent INVALID_KE_PAYLOAD and the
    exchange restarted, which is a real condition seen in captures.
    """
    if len(payload.body) < 4:
        defects.append("KE payload shorter than its 4-byte header")
        return None
    group, _reserved = struct.unpack("!HH", payload.body[:4])
    return group


def parse_notify_payload(payload: RawPayload, packet: int, defects: list[str]) -> Notification | None:
    """Parse a notify payload (RFC 7296 section 3.10)."""
    if len(payload.body) < 4:
        defects.append("notify payload shorter than its 4-byte header")
        return None
    protocol_id, spi_size, notify_type = struct.unpack("!BBH", payload.body[:4])
    cursor = 4
    spi = b""
    if spi_size:
        if cursor + spi_size > len(payload.body):
            defects.append(f"notify {notify_type} SPI runs past the payload")
            return None
        spi = payload.body[cursor : cursor + spi_size]
        cursor += spi_size
    return Notification(
        notify_type=notify_type,
        name=tf.notify_name(notify_type),
        protocol_id=protocol_id,
        spi=spi,
        data=payload.body[cursor:],
        packet=packet,
    )


@dataclass(slots=True)
class IkeV2Result:
    """What the IKEv2 parser recovered from one IKE SA."""

    ike: IkeSa
    notifications: list[Notification] = field(default_factory=list)
    vendor_ids: list[VendorId] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Child SA SPIs seen in cleartext notify payloads (REKEY_SA carries one).
    rekey_spis: list[str] = field(default_factory=list)


def parse_ikev2(messages: list[IkeMessage]) -> IkeV2Result:
    """Build an :class:`IkeSa` from the IKEv2 messages of one SA.

    ``messages`` must already be grouped by SPI pair and ordered by time; that
    grouping is the session builder job, not this one.

    The selected proposal is taken from the ``IKE_SA_INIT`` response, because
    that is the one actually in force. The offered list comes from the request.
    When no response was captured, every negotiated field becomes Unknown rather
    than falling back to the first offer, since what the initiator wanted is not
    evidence of what was agreed.
    """
    ike = IkeSa()
    result = IkeV2Result(ike=ike)
    defects = result.defects

    for message in messages:
        defects.extend(f"packet {message.packet_number}: {d}" for d in message.defects)

    init_requests = [
        m for m in messages if m.header.exchange_type == EXCHANGE_IKE_SA_INIT and m.header.is_request
    ]
    init_responses = [
        m
        for m in messages
        if m.header.exchange_type == EXCHANGE_IKE_SA_INIT and m.header.is_response
    ]

    if not messages:
        return result

    first = messages[0]
    ike.initiator_spi = first.header.initiator_spi_hex
    ike.version = Attribute.observed(
        "IKEv2", [first.packet_number], raw=f"major={first.header.major_version}"
    )

    # Collect notify and vendor ID payloads across every cleartext message.
    for message in messages:
        for payload in message.of_type(PAYLOAD_NOTIFY):
            notification = parse_notify_payload(payload, message.packet_number, defects)
            if notification is not None:
                result.notifications.append(notification)
                if notification.name == "REKEY_SA" and notification.spi:
                    result.rekey_spis.append(notification.spi.hex())
        for payload in message.of_type(PAYLOAD_VENDOR_ID):
            result.vendor_ids.append(VendorId(raw=payload.body, packet=message.packet_number))

    ike.notifications = [n.to_json() for n in result.notifications]
    ike.vendor_ids = [v.to_json() for v in result.vendor_ids]

    # --- offered proposals, from the first request
    if init_requests:
        request = init_requests[0]
        sa_payload = request.first_of_type(PAYLOAD_SA)
        if sa_payload is not None:
            ike.offered_proposals = parse_sa_payload(sa_payload, request.packet_number, defects)
        else:
            defects.append(f"packet {request.packet_number}: IKE_SA_INIT request has no SA payload")
    else:
        result.warnings.append(
            "No IKE_SA_INIT request in the capture, so the proposals the initiator "
            "offered are unknown. The downgrade rules cannot be evaluated."
        )

    # --- selected proposal, from the response that concluded the negotiation.
    #
    # There can be more than one IKE_SA_INIT response. When the initiator offers
    # a key exchange group the responder will not take, the responder answers
    # with a bare INVALID_KE_PAYLOAD notify naming the group it wants, and the
    # initiator starts again. Only the final response carries an SA payload, so
    # taking the first would read the rejection and conclude nothing was agreed.
    selected: Proposal | None = None
    answered = [m for m in init_responses if m.has_type(PAYLOAD_SA)]
    rejections = [m for m in init_responses if not m.has_type(PAYLOAD_SA)]

    if rejections:
        rejected_packets = {m.packet_number for m in rejections}
        reasons = sorted(
            {n.name for n in result.notifications if n.packet in rejected_packets}
        )
        result.warnings.append(
            f"The responder rejected {len(rejections)} initial IKE_SA_INIT attempt(s) "
            f"({', '.join(reasons) or 'no notify parsed'}) before agreeing. A rejected "
            "key exchange group means the group finally used was the responder choice "
            "rather than the initiator preference, which is worth checking against policy."
        )

    if answered:
        response = answered[-1]
        ike.responder_spi = response.header.responder_spi_hex
        sa_payload = response.first_of_type(PAYLOAD_SA)
        if sa_payload is not None:
            chosen = parse_sa_payload(sa_payload, response.packet_number, defects)
            if len(chosen) > 1:
                defects.append(
                    f"packet {response.packet_number}: responder returned {len(chosen)} "
                    "proposals, RFC 7296 allows exactly one"
                )
            selected = chosen[0] if chosen else None
        ke_payload = response.first_of_type(PAYLOAD_KE)
        if ke_payload is not None and selected is not None:
            group = parse_ke_payload(ke_payload, defects)
            if group is not None and selected.dh_group is not None and group != selected.dh_group:
                defects.append(
                    f"packet {response.packet_number}: KE payload group {group} does not "
                    f"match the selected proposal group {selected.dh_group}"
                )
    elif rejections:
        result.warnings.append(
            "Every captured IKE_SA_INIT response was a rejection, so no cipher suite "
            "was ever agreed. Either the peers failed to negotiate, or the capture "
            "ended before they succeeded."
        )
    else:
        result.warnings.append(
            "No IKE_SA_INIT response in the capture, so the agreed cipher suite is unknown. "
            "Only what the initiator offered can be reported."
        )

    _record_selected(ike, selected, answered)
    _record_encrypted_unknowns(ike)
    _record_fragmentation(ike, messages, result)

    return result


def _record_selected(ike: IkeSa, selected: Proposal | None, responses: list[IkeMessage]) -> None:
    """Turn the selected proposal into Observed attributes on the IKE SA.

    Each field cites the packet the responder sent, because that is where the
    agreement is visible. Without a response, every field is Unknown with a
    reason naming what a longer capture would fix.
    """
    if selected is None:
        reason = "no IKE_SA_INIT response was captured, so the agreed suite is not visible"
        for name in ("encr", "prf", "integ", "dh_group"):
            setattr(ike, name, Attribute.unknown(reason, resolvable_by="longer_capture"))
        return

    ike.selected_proposal = selected
    packet = selected.packet or (responses[0].packet_number if responses else 0)
    cite = [packet] if packet else [0]

    if selected.encr:
        ike.encr = Attribute.observed(selected.encr, cite, raw=selected.encr)
    if selected.encr_key_bits:
        ike.encr_key_bits = Attribute.observed(selected.encr_key_bits, cite)
    elif selected.encr and not tf.is_aead(selected.encr):
        # Key length is an optional attribute. Its absence means the default for
        # that transform, which the RFC does not state for AES, so this is a real
        # Unknown rather than a safe assumption of 128.
        ike.encr_key_bits = Attribute.unknown(
            f"{selected.encr} carried no key length attribute, so the negotiated "
            "key size follows local policy and is not on the wire",
            resolvable_by="supply_config",
        )
    if selected.prf:
        ike.prf = Attribute.observed(selected.prf, cite)
    if selected.integ:
        ike.integ = Attribute.observed(selected.integ, cite)
    elif selected.encr and tf.is_aead(selected.encr):
        ike.integ = Attribute.observed(
            "AEAD_INTEGRAL",
            cite,
            note=f"{selected.encr} is AEAD, so integrity is built into the cipher",
        )
    if selected.dh_group is not None:
        ike.dh_group = Attribute.observed(
            selected.dh_group, cite, raw=tf.dh_group_name(selected.dh_group)
        )


def _record_encrypted_unknowns(ike: IkeSa) -> None:
    """Record the fields IKEv2 keeps out of sight.

    These are the honest Unknowns of VISION.md section 5.1. Writing them down
    explicitly, rather than omitting them, is what makes the coverage figure
    meaningful: the report shows what it could not see and why.
    """
    ike.auth_method = Attribute.unknown(
        "the authentication method is inside the encrypted IKE_AUTH exchange, "
        "which IKEv2 protects by design",
        resolvable_by="supply_keys",
    )
    ike.peer_identity = Attribute.unknown(
        "peer identities are inside the encrypted IKE_AUTH exchange",
        resolvable_by="supply_keys",
    )
    ike.sa_lifetime_s = Attribute.unknown(
        "IKEv2 does not negotiate an IKE SA lifetime; each peer applies its own "
        "local policy, so the value is inferred from observed rekey timing instead",
        resolvable_by="longer_capture",
    )


def _record_fragmentation(ike: IkeSa, messages: list[IkeMessage], result: IkeV2Result) -> None:
    """Record whether IKEv2 fragmentation was negotiated and used.

    Both matter. Support being signalled is a capability; a fragment payload
    actually appearing tells the analyst why a later payload may be unreadable,
    which is better than the parser silently reporting less.
    """
    supporters = {
        n.packet for n in result.notifications if n.notify_type == tf.NOTIFY_FRAGMENTATION_SUPPORTED
    }
    fragments_seen = [m.packet_number for m in messages if m.has_type(PAYLOAD_SKF)]

    if fragments_seen:
        ike.fragmentation_used = Attribute.observed(
            True, sorted(fragments_seen), note="encrypted fragment payloads present"
        )
        result.warnings.append(
            "This exchange used IKEv2 fragmentation (RFC 7383). Fragmented payloads "
            "are encrypted, so nothing beyond IKE_SA_INIT can be read from them."
        )
    elif supporters:
        ike.fragmentation_used = Attribute.observed(
            False,
            sorted(supporters),
            note="fragmentation was offered but no fragment payloads were sent",
        )


def nat_traversal_attribute(result: IkeV2Result, *, udp_encapsulated: bool = False) -> Attribute:
    """Whether NAT sits between the peers.

    A good example of why the evidence levels exist. The NAT detection payloads
    carry hashes of the address and port as each peer sees them, and both peers
    send them whenever they support the feature, so their presence proves support
    and not NAT. Deciding NAT from them means recomputing the hash over the IP
    header and comparing, which this parser does not do yet.

    What is solid evidence is traffic on UDP 4500 with the non-ESP marker, since
    peers use that only after concluding NAT is present (RFC 3948). So port 4500
    gives an Observed true, detection payloads alone give an Unknown that names
    what would settle it, and nothing at all gives an Unknown.
    """
    detections = sorted(
        {n.packet for n in result.notifications if n.notify_type in tf.NAT_DETECTION_NOTIFIES}
    )

    if udp_encapsulated:
        return Attribute.observed(
            True,
            detections or [0],
            note="IKE and ESP were encapsulated in UDP 4500, which peers use only "
            "after deciding NAT is present (RFC 3948)",
        )

    if detections:
        return Attribute.unknown(
            "both peers exchanged NAT detection payloads, which proves they support "
            "NAT traversal but not that NAT is present; deciding that needs the "
            "payload hashes recomputed over the IP header, which is not implemented",
            resolvable_by="not_resolvable",
        )

    return Attribute.unknown(
        "neither peer sent a NAT detection payload, so NAT presence cannot be judged",
        resolvable_by="not_resolvable",
    )
