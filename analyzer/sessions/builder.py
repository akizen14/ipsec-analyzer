"""Assemble a session record from a capture.

Stage 2 of the pipeline. It owns the grouping decisions, which are where most of
the judgement in the passive path lives:

**One record per endpoint pair, not per IKE SA.** An operator thinks of one VPN
between two gateways. A capture long enough to contain an IKE SA rekey holds two
or more IKE SAs for that one VPN, with unrelated SPIs. Emitting a record each
would report the same deployment several times, most of them nearly empty.

**A rekeyed IKE SA cannot be linked to its parent from the wire.** The rekey is
negotiated inside an encrypted CREATE_CHILD_SA exchange, so the new SPI pair
never appears in cleartext beside the old one. The link is therefore Inferred
from timing and endpoints, and it is recorded as such rather than asserted. The
SA that carries a readable IKE_SA_INIT is the one whose configuration is
reported; the others contribute their child SAs and a noted rekey.

**ESP SPIs are keyed with their addresses.** An SPI is chosen by the receiver
and only has to be unique to that receiver, so the address pair goes in the key.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from analyzer import __version__
from analyzer.esp_ah.stats import (
    FlowStats,
    ah_flows,
    detect_rekeys,
    esp_flows,
    observed_rekey_interval,
    pair_flows,
)
from analyzer.ike.messages import IkeMessage, MalformedMessage, parse_message
from analyzer.ike.parser_v2 import IkeV2Result, nat_traversal_attribute, parse_ikev2
from analyzer.inference.esp_structure import infer_block_size, key_length_attribute
from analyzer.ingest.pcap import Capture
from analyzer.record import (
    Attribute,
    ChildSa,
    Endpoints,
    IkeSa,
    RekeyEvent,
    SessionRecord,
    Source,
)

#: IKEv2 exchange type for a rekey or new child SA.
EXCHANGE_CREATE_CHILD_SA = 36


@dataclass(slots=True)
class IkeSaGroup:
    """All cleartext messages belonging to one IKE SA, by initiator SPI."""

    initiator_spi: bytes
    messages: list[IkeMessage]

    @property
    def first_seen(self) -> float:
        return min(m.timestamp for m in self.messages)

    @property
    def has_sa_init(self) -> bool:
        """Whether an IKE_SA_INIT was captured, so the suite is readable."""
        return any(m.header.exchange_type == 34 for m in self.messages)


def _endpoint_key(a: str, b: str) -> tuple[str, str]:
    """A direction-independent key for a host pair."""
    return (a, b) if a <= b else (b, a)


def parse_ike_messages(capture: Capture) -> tuple[list[IkeMessage], list[str]]:
    """Parse every IKE packet, collecting rather than raising on bad ones."""
    messages: list[IkeMessage] = []
    warnings: list[str] = []

    for pkt in capture.ike:
        try:
            messages.append(
                parse_message(
                    pkt.data,
                    packet_number=pkt.packet_number,
                    timestamp=pkt.timestamp,
                    src=pkt.src,
                    dst=pkt.dst,
                    sport=pkt.sport,
                    dport=pkt.dport,
                    udp_encapsulated=pkt.udp_encapsulated,
                )
            )
        except MalformedMessage as exc:
            warnings.append(
                f"packet {pkt.packet_number} reached the IKE parser but is not a "
                f"readable IKE message: {exc}"
            )

    return messages, warnings


def group_ike_sas(messages: list[IkeMessage]) -> dict[tuple[str, str], list[IkeSaGroup]]:
    """Group IKE messages by endpoint pair, then by IKE SA within each pair."""
    by_endpoint: dict[tuple[str, str], dict[bytes, list[IkeMessage]]] = defaultdict(
        lambda: defaultdict(list)
    )

    for message in messages:
        key = _endpoint_key(message.src, message.dst)
        by_endpoint[key][message.header.initiator_spi].append(message)

    out: dict[tuple[str, str], list[IkeSaGroup]] = {}
    for endpoint_key, spi_map in by_endpoint.items():
        groups = [
            IkeSaGroup(initiator_spi=spi, messages=sorted(msgs, key=lambda m: m.timestamp))
            for spi, msgs in spi_map.items()
        ]
        out[endpoint_key] = sorted(groups, key=lambda g: g.first_seen)

    return out


def _ike_rekey_events(groups: list[IkeSaGroup], primary: IkeSaGroup) -> list[RekeyEvent]:
    """Record the IKE SAs that are most likely rekeys of the primary one.

    Inferred, not Observed. What is on the wire is a second IKE SA between the
    same two addresses with no IKE_SA_INIT of its own, starting after a
    CREATE_CHILD_SA exchange in the first. That pattern is what an IKE SA rekey
    looks like from outside the encryption, but a fresh SA set up by a peer that
    simply never retransmitted its IKE_SA_INIT where the capture could see it
    would look identical. Hence a confidence below 1 and a stated reason.
    """
    events: list[RekeyEvent] = []

    for group in groups:
        if group is primary:
            continue

        create_child_before = [
            m
            for m in primary.messages
            if m.header.exchange_type == EXCHANGE_CREATE_CHILD_SA
            and m.timestamp <= group.first_seen
        ]
        # A rekey of the IKE SA is itself carried in a CREATE_CHILD_SA, so seeing
        # one in the old SA just before the new SA appears is the corroboration.
        confidence = 0.85 if create_child_before else 0.5
        note = (
            "a CREATE_CHILD_SA exchange in the previous IKE SA precedes this one"
            if create_child_before
            else "no CREATE_CHILD_SA was seen beforehand, so this may be an "
            "unrelated new IKE SA rather than a rekey"
        )

        events.append(
            RekeyEvent(
                at=round(group.first_seen - primary.first_seen, 3),
                packet=min(m.packet_number for m in group.messages),
                old_spi=primary.initiator_spi.hex(),
                new_spi=group.initiator_spi.hex(),
                interval_s=round(group.first_seen - primary.first_seen, 1),
                key_exchange_present=Attribute.inferred(
                    True,
                    confidence,
                    "ike_sa_rekey_from_spi_change",
                    features={
                        "create_child_sa_before": len(create_child_before),
                        "seconds_after_primary": round(group.first_seen - primary.first_seen, 1),
                    },
                    note=(
                        "an IKE SA rekey always carries a key exchange, so PFS applies; "
                        f"the rekey itself is encrypted, so this is inferred. {note}"
                    ),
                ),
            )
        )

    return events


def _build_child_sa(
    flow: FlowStats,
    reverse: FlowStats | None,
    protocol: str,
    rekey_intervals: dict[str, float],
) -> ChildSa:
    """Turn one ESP or AH flow pair into a child SA entry."""
    packets = [flow.packet_count, reverse.packet_count if reverse else 0]

    sa = ChildSa(
        spi=flow.spi,
        protocol=Attribute.observed(
            protocol,
            [1],
            note=f"read from the IP protocol number on {sum(packets)} packets",
        ),
        direction_pair_spi=reverse.spi if reverse else None,
        src=flow.src,
        dst=flow.dst,
        packet_count=flow.packet_count,
        byte_count=flow.byte_count,
        first_seen=round(flow.first_seen, 3),
        last_seen=round(flow.last_seen, 3),
        replay_evidence=flow.replay_evidence(),
        length_histogram=flow.histogram_json(),
        udp_encapsulated=Attribute.observed(
            flow.udp_encapsulated,
            [1],
            note="UDP 4500 encapsulation, so the peers decided NAT was present"
            if flow.udp_encapsulated
            else "ESP carried directly over IP, so no NAT traversal was needed",
        ),
    )

    if protocol == "ESP":
        block, family, _ev = infer_block_size(flow)
        sa.block_size_bytes = block
        sa.cipher_family = family
        sa.key_length = key_length_attribute()
        # Tunnel against Transport mode needs the packet-overhead comparison that
        # PLAN.md phase 4 builds. Claiming it from this capture alone would be a
        # guess, so it is left honestly open.
        sa.mode = Attribute.unknown(
            "distinguishing Tunnel from Transport mode needs the inner-header "
            "overhead model from phase 4, which is not implemented yet; the ESP "
            "child SA negotiation that would state it outright is encrypted",
            resolvable_by="supply_keys",
        )
        sa.integ = Attribute.unknown(
            "the ESP integrity algorithm is negotiated inside the encrypted child "
            "SA exchange; the ICV length narrows the candidates but does not pick one",
            resolvable_by="supply_keys",
        )

    interval = rekey_intervals.get(flow.spi)
    sa.rekey_interval_s = observed_rekey_interval([interval] if interval else [])

    sa.traffic_type = Attribute.unknown(
        "traffic-type classification is the phase 4 model and is not trained yet",
        resolvable_by="not_resolvable",
    )
    sa.pfs_on_rekey = Attribute.unknown(
        "PFS on the child SA rekey is judged from the size of the encrypted rekey "
        "exchange, which the phase 4 inference adds",
        resolvable_by="longer_capture",
    )

    return sa


def build_sessions(capture: Capture, *, session_prefix: str = "") -> list[SessionRecord]:
    """Build one session record per endpoint pair found in the capture.

    Returns records with findings and score still unset: the rule engine and the
    scoring stage fill those in. Ordering is by first activity so repeated runs
    over the same capture emit records in the same order, which the
    repeatability requirement in PLAN.md section 7 needs.
    """
    messages, warnings = parse_ike_messages(capture)
    ike_by_endpoint = group_ike_sas(messages)

    esp_by_endpoint: dict[tuple[str, str], dict] = defaultdict(dict)
    for key, flow in esp_flows(capture.esp).items():
        esp_by_endpoint[_endpoint_key(flow.src, flow.dst)][key] = flow

    ah_by_endpoint: dict[tuple[str, str], dict] = defaultdict(dict)
    for key, flow in ah_flows(capture.ah).items():
        ah_by_endpoint[_endpoint_key(flow.src, flow.dst)][key] = flow

    all_endpoints = set(ike_by_endpoint) | set(esp_by_endpoint) | set(ah_by_endpoint)
    records: list[SessionRecord] = []

    for index, endpoint_key in enumerate(sorted(all_endpoints), start=1):
        groups = ike_by_endpoint.get(endpoint_key, [])
        record = _build_one(
            endpoint_key=endpoint_key,
            groups=groups,
            esp=esp_by_endpoint.get(endpoint_key, {}),
            ah=ah_by_endpoint.get(endpoint_key, {}),
            capture=capture,
            session_id=f"{session_prefix or capture.path.stem}-{index:02d}",
        )
        record.warnings.extend(warnings)
        records.append(record)

    return sorted(records, key=lambda r: r.session_id)


def _build_one(
    *,
    endpoint_key: tuple[str, str],
    groups: list[IkeSaGroup],
    esp: dict,
    ah: dict,
    capture: Capture,
    session_id: str,
) -> SessionRecord:
    """Build the record for a single endpoint pair."""
    # Prefer the IKE SA whose IKE_SA_INIT was captured, since it is the only one
    # whose negotiated suite is readable. Fall back to the earliest.
    readable = [g for g in groups if g.has_sa_init]
    primary = readable[0] if readable else (groups[0] if groups else None)

    parsed: IkeV2Result | None = parse_ikev2(primary.messages) if primary else None
    ike: IkeSa = parsed.ike if parsed else IkeSa()

    initiator, responder, ip_version, udp_encap = _endpoints_from(primary, esp, ah, endpoint_key)

    endpoints = Endpoints(
        initiator=initiator,
        responder=responder,
        ip_version=ip_version,
        nat_t=(
            nat_traversal_attribute(parsed, udp_encapsulated=udp_encap)
            if parsed
            else Attribute.unknown(
                "no cleartext IKE was captured, so NAT traversal cannot be judged",
                resolvable_by="not_resolvable",
            )
        ),
    )

    record = SessionRecord(
        session_id=session_id,
        source=Source(
            kind="pcap",
            path=str(capture.path),
            packet_count=capture.packet_count,
            capture_duration_s=round(capture.duration_s, 3),
            truncated=any(m.truncated for g in groups for m in g.messages),
        ),
        endpoints=endpoints,
        ike=ike,
        analyzer_version=__version__,
    )

    if primary and len(groups) > 1:
        ike.rekeys = _ike_rekey_events(groups, primary)
        record.warnings.append(
            f"{len(groups)} IKE SAs seen between these endpoints. The first with a "
            "readable IKE_SA_INIT is reported; the others are inferred to be rekeys "
            "and contribute their child SAs only, because an IKE SA rekey is "
            "negotiated inside the encrypted exchange."
        )

    if parsed:
        record.warnings.extend(parsed.warnings)
        if parsed.defects:
            record.warnings.append(
                f"{len(parsed.defects)} IKE parse defect(s); the first is: {parsed.defects[0]}"
            )

    _attach_child_sas(record, esp, ah)

    if not groups and (esp or ah):
        record.warnings.append(
            "ESP or AH traffic was captured with no IKE handshake, so the capture "
            "probably started after the tunnel was already up. The cipher suite "
            "cannot be read; only the child SA behaviour can be assessed."
        )

    record.warnings.extend(capture.warnings)
    return record


def _endpoints_from(
    primary: IkeSaGroup | None,
    esp: dict,
    ah: dict,
    endpoint_key: tuple[str, str],
) -> tuple[str, str, int, bool]:
    """Work out who initiated, and whether traffic was UDP encapsulated.

    The IKE Initiator flag is authoritative when cleartext IKE was captured. With
    only ESP to go on there is no way to tell initiator from responder, so the
    addresses are reported in the stable sorted order rather than guessed at.
    """
    flows = list(esp.values()) + list(ah.values())
    ip_version = flows[0].ip_version if flows else 4
    udp_encap = any(getattr(f, "udp_encapsulated", False) for f in flows)

    if primary:
        for message in primary.messages:
            if message.header.is_initiator and message.header.is_request:
                return (
                    message.src,
                    message.dst,
                    message.ip_version if hasattr(message, "ip_version") else ip_version,
                    udp_encap or message.udp_encapsulated,
                )
        first = primary.messages[0]
        return first.src, first.dst, ip_version, udp_encap or first.udp_encapsulated

    return endpoint_key[0], endpoint_key[1], ip_version, udp_encap


def _attach_child_sas(record: SessionRecord, esp: dict, ah: dict) -> None:
    """Pair up the ESP and AH flows and attach them as child SAs."""
    for flows, protocol in ((esp, "ESP"), (ah, "AH")):
        if not flows:
            continue
        pairs = pair_flows(flows)
        intervals = {flow.spi: interval for flow, interval in detect_rekeys(pairs)}
        for flow, reverse in pairs:
            record.child_sas.append(_build_child_sa(flow, reverse, protocol, intervals))

    record.child_sas.sort(key=lambda sa: (sa.first_seen or 0.0, sa.spi))
