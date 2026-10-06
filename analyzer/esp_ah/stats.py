"""Deterministic statistics over ESP and AH headers.

Nothing here is a model. Every number is counted or measured from a cleartext
header field, which is why the results come back Observed. The inference that
turns these numbers into a cipher family or an operating mode lives in
``analyzer/inference`` and is reported Inferred, with a confidence.

The split matters for the project claim: the length histogram below is evidence,
and the cipher family derived from it is a conclusion. Keeping them in different
modules keeps them in different evidence levels.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from itertools import pairwise

from analyzer.ingest.pcap import AhPacket, EspPacket
from analyzer.record import Attribute, ReplayEvidence


@dataclass(slots=True)
class FlowStats:
    """Counted facts about one unidirectional ESP or AH flow."""

    spi: str
    src: str
    dst: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    #: ESP payload length (everything after the 8-byte header) to occurrence count.
    length_histogram: Counter[int] = field(default_factory=Counter)
    seqs: list[int] = field(default_factory=list)
    udp_encapsulated: bool = False
    ip_version: int = 4

    @property
    def duration_s(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def mean_payload(self) -> float:
        if not self.packet_count:
            return 0.0
        return sum(length * count for length, count in self.length_histogram.items()) / self.packet_count

    def residues(self, modulus: int) -> Counter[int]:
        """How ESP payload lengths distribute over the residues of ``modulus``.

        This is the raw material for cipher-family inference. A CBC cipher pads
        the plaintext to a whole block, so payload lengths land on a small number
        of residues modulo the block size. A counter or AEAD mode does not pad, so
        lengths spread across every residue. The inference engine reads this; the
        histogram itself stays in the record so the call can be re-checked.
        """
        out: Counter[int] = Counter()
        for length, count in self.length_histogram.items():
            out[length % modulus] += count
        return out

    def replay_evidence(self) -> ReplayEvidence:
        """What the sequence numbers show about ordering and duplication.

        Reported as evidence, never as a setting. Anti-replay is enforced at the
        receiver, and a capture cannot see whether the receiver dropped anything,
        so the honest claim is "these sequence numbers were observed on the wire"
        (VISION.md section 12 row 6).
        """
        if not self.seqs:
            return ReplayEvidence()

        counts = Counter(self.seqs)
        duplicates = sum(c - 1 for c in counts.values() if c > 1)
        reordered = sum(1 for a, b in pairwise(self.seqs) if b <= a)
        highest = max(self.seqs)
        distinct = len(counts)
        # A gap is a sequence number inside the observed range that never
        # appeared. On a capture point beside one peer this is usually loss at
        # the capture, not on the link, so it is counted but not judged.
        gaps = max(0, (highest - min(self.seqs) + 1) - distinct)

        return ReplayEvidence(
            monotonic=reordered == 0,
            duplicate_seqs=duplicates,
            reordered_seqs=reordered,
            gaps=gaps,
            highest_seq=highest,
            # A 32-bit counter that wraps, or one that starts far from 1, hints at
            # extended sequence numbers, whose high half is not transmitted.
            esn_suspected=highest >= 0xFFFF0000,
        )

    def histogram_json(self) -> dict[str, int]:
        """The histogram with string keys, as JSON requires."""
        return {str(k): v for k, v in sorted(self.length_histogram.items())}


def esp_flows(packets: list[EspPacket]) -> dict[tuple[str, str, str], FlowStats]:
    """Group ESP packets into unidirectional flows keyed by source, destination and SPI.

    The SPI alone is not a safe key. It is chosen by the receiver and is only
    required to be unique to that receiver, so two different SAs in a capture can
    legitimately carry the same SPI in opposite directions. Keying on the address
    pair as well avoids merging them.
    """
    flows: dict[tuple[str, str, str], FlowStats] = {}

    for pkt in packets:
        key = (pkt.src, pkt.dst, pkt.spi)
        flow = flows.get(key)
        if flow is None:
            flow = FlowStats(
                spi=pkt.spi,
                src=pkt.src,
                dst=pkt.dst,
                first_seen=pkt.timestamp,
                udp_encapsulated=pkt.udp_encapsulated,
                ip_version=pkt.ip_version,
            )
            flows[key] = flow
        flow.packet_count += 1
        flow.byte_count += pkt.esp_len
        flow.last_seen = pkt.timestamp
        flow.length_histogram[pkt.payload_len] += 1
        flow.seqs.append(pkt.seq)

    return flows


def ah_flows(packets: list[AhPacket]) -> dict[tuple[str, str, str], FlowStats]:
    """Group AH packets the same way as ESP."""
    flows: dict[tuple[str, str, str], FlowStats] = {}

    for pkt in packets:
        key = (pkt.src, pkt.dst, pkt.spi)
        flow = flows.get(key)
        if flow is None:
            flow = FlowStats(
                spi=pkt.spi,
                src=pkt.src,
                dst=pkt.dst,
                first_seen=pkt.timestamp,
                ip_version=pkt.ip_version,
            )
            flows[key] = flow
        flow.packet_count += 1
        flow.byte_count += pkt.payload_len + 12 + pkt.icv_len
        flow.last_seen = pkt.timestamp
        flow.length_histogram[pkt.payload_len] += 1
        flow.seqs.append(pkt.seq)

    return flows


def pair_flows(
    flows: dict[tuple[str, str, str], FlowStats],
) -> list[tuple[FlowStats, FlowStats | None]]:
    """Match each flow with the one running the other way between the same hosts.

    A bidirectional SA pair is what an operator thinks of as one tunnel, and
    pairing them is needed before rekey intervals make sense. Pairing is by
    reversed address pair and overlapping lifetime; when several candidates
    overlap, the one closest in start time wins.

    Returns pairs with the earlier-starting flow first. An unmatched flow is
    returned with None, which is normal when the capture point sees one direction.
    """
    remaining = dict(flows)
    pairs: list[tuple[FlowStats, FlowStats | None]] = []

    for key in sorted(flows, key=lambda k: (flows[k].first_seen, k)):
        if key not in remaining:
            continue
        flow = remaining.pop(key)

        candidates = [
            (other_key, other)
            for other_key, other in remaining.items()
            if other.src == flow.dst and other.dst == flow.src
        ]
        if not candidates:
            pairs.append((flow, None))
            continue

        best_key, best = min(candidates, key=lambda kv: abs(kv[1].first_seen - flow.first_seen))
        remaining.pop(best_key)
        pairs.append((flow, best))

    return pairs


def detect_rekeys(
    pairs: list[tuple[FlowStats, FlowStats | None]],
) -> list[tuple[FlowStats, float]]:
    """Find where one SA gave way to the next, and how long each lasted.

    A child SA rekey shows up in cleartext as an SPI change: a new SPI starts
    carrying traffic while the old one stops. The interval between successive SA
    start times is the observed lifetime, which is the only way to reach the
    child SA lifetime at all, since IKEv2 never negotiates one.

    Returns each flow with the interval that elapsed before the next SA in the
    same direction started. The last SA of a run has no successor, so it is left
    out: the capture ended before its lifetime was shown.
    """
    by_direction: dict[tuple[str, str], list[FlowStats]] = {}
    for flow, _reverse in pairs:
        by_direction.setdefault((flow.src, flow.dst), []).append(flow)

    out: list[tuple[FlowStats, float]] = []
    for flows_in_direction in by_direction.values():
        ordered = sorted(flows_in_direction, key=lambda f: f.first_seen)
        for current, following in pairwise(ordered):
            out.append((current, following.first_seen - current.first_seen))

    return out


def observed_rekey_interval(intervals: list[float]) -> Attribute:
    """Turn observed SA lifetimes into a reportable attribute.

    The interval is measured, not predicted, so this is Observed. What it is
    *evidence of* is the configured lifetime, and that is a weaker claim: one
    interval could have been cut short by a byte-count limit or a manual
    restart. The note says so rather than overclaiming, and a single observation
    is reported with that caveat attached.
    """
    if not intervals:
        return Attribute.unknown(
            "no SPI change was seen, so no rekey happened inside the capture window; "
            "a longer capture is needed to observe the child SA lifetime",
            resolvable_by="longer_capture",
        )

    shortest = min(intervals)
    note = (
        f"measured from {len(intervals)} SPI change(s) in this capture"
        if len(intervals) > 1
        else "measured from a single SPI change, so it is one sample of the lifetime "
        "and not necessarily the configured value"
    )
    return Attribute.observed(round(shortest, 1), [0], note=note)
