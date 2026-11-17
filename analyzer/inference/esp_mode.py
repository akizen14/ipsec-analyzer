"""Infer ESP Tunnel or Transport mode from packet lengths.

Tunnel mode wraps a whole inner IP packet, so every ESP payload carries 20
(IPv4) or 40 (IPv6) more bytes than the same traffic in Transport mode. The
size of the traffic itself is unknown, so the shift needs an anchor whose inner
size is known. A pure TCP ACK is one: 20 bytes of TCP header, or 32 with the
timestamps option, and in any TCP flow it is the most frequent small packet in
the direction that receives the data.

ESP payload = IV + pad_to_block(inner + 2) + ICV. The cipher family (from the
residue inference) fixes the IV and block; the ICV is narrowed by which values
keep every observed length aligned. The method enumerates every hypothesis
(mode x ACK size x ICV), keeps those that reproduce the anchor and fit the
smallest packet (a tunnel packet must hold an inner IP header plus 8 bytes),
and weighs them with the priors below. It answers only when one mode clearly
wins.

The priors are deployment knowledge, stated so they can be argued with. Some
combinations genuinely collide: AES-CBC with HMAC-SHA-512 in Transport mode
puts a timestamped ACK at the same length as HMAC-SHA-256 in Tunnel mode. The
prior then favours the commoner SHA-256 reading, and is wrong for that case.
"""

from __future__ import annotations

from analyzer.esp_ah.stats import FlowStats
from analyzer.record import Attribute

METHOD = "esp_tcp_ack_anchor"

#: cipher family -> (IV bytes, padding block, {ICV bytes: prior}).
STRUCTURE = {
    "BLOCK_16B_CBC_LIKE": (16, 16, {12: 0.25, 16: 0.55, 24: 0.1, 32: 0.1}),
    "BLOCK_8B_CBC_LIKE": (8, 8, {12: 0.6, 16: 0.3, 24: 0.05, 32: 0.05}),
    "AEAD_OR_COUNTER": (8, 4, {16: 0.75, 12: 0.15, 8: 0.05, 24: 0.025, 32: 0.025}),
}
#: TCP pure ACK header bytes -> prior. Timestamps are on by default on Linux,
#: macOS, iOS and Android; off by default on Windows.
ACK_TCP = {32: 0.7, 20: 0.3}
TUNNEL_IP_HEADER = {4: 20, 6: 40}
MIN_L4 = 8                  # smallest transport header after an inner IP header
ANCHOR_MAX_BYTES = 200      # an ACK is small whatever the cipher
ANCHOR_MIN_SHARE = 0.25     # and dominates its direction of a TCP flow
MIN_POSTERIOR = 0.8
MAX_CONFIDENCE = 0.99       # a deduction under the model, not certainty


def payload_bytes(iv: int, block: int, icv: int, inner: int) -> int:
    """ESP payload length for an inner packet of `inner` bytes (+2: pad length, next header)."""
    return iv + -(-(inner + 2) // block) * block + icv


def anchor(flow: FlowStats) -> int | None:
    """The flow's most common length, if it looks like an ACK stream."""
    if not flow.packet_count:
        return None
    length, count = flow.length_histogram.most_common(1)[0]
    if length <= ANCHOR_MAX_BYTES and count >= ANCHOR_MIN_SHARE * flow.packet_count:
        return length
    return None


def hypothesis_weights(flows: list[FlowStats], family: str,
                       ip_version: int) -> dict[tuple[str, int], float]:
    """Unnormalised weight of each (mode, ICV) over the hypotheses that fit the flows."""
    iv, block, icv_prior = STRUCTURE[family]
    lengths = [n for f in flows for n in f.length_histogram]
    smallest = min(lengths)
    icvs = {icv: p for icv, p in icv_prior.items()
            if all((n - iv - icv) % block == 0 for n in lengths)}
    anchors = {a for a in map(anchor, flows) if a is not None}

    weights: dict[tuple[str, int], float] = {}
    for mode, ip_header in (("transport", 0), ("tunnel", TUNNEL_IP_HEADER[ip_version])):
        for icv, p_icv in icvs.items():
            if mode == "tunnel" and payload_bytes(iv, block, icv, ip_header + MIN_L4) > smallest:
                continue
            for tcp, p_tcp in ACK_TCP.items():
                if anchors and payload_bytes(iv, block, icv, ip_header + tcp) not in anchors:
                    continue
                weights[(mode, icv)] = weights.get((mode, icv), 0.0) + 0.5 * p_icv * p_tcp
    return weights


def _marginal(weights: dict[tuple[str, int], float], index: int) -> dict:
    out: dict = {}
    for key, w in weights.items():
        out[key[index]] = out.get(key[index], 0.0) + w
    return out


def _decide(marginal: dict, what: str, features: dict, ambiguous_reason: str) -> Attribute:
    total = sum(marginal.values())
    best = max(marginal, key=marginal.get)
    posterior = marginal[best] / total
    if posterior < MIN_POSTERIOR:
        return Attribute.unknown(f"{ambiguous_reason} ({best} at {posterior:.0%})",
                                 resolvable_by="supply_keys")
    alternatives = [(k, round(w / total, 4)) for k, w in marginal.items() if k != best and w]
    return Attribute.inferred(
        best, min(posterior, MAX_CONFIDENCE), METHOD,
        features={**features, "posterior": round(posterior, 4)},
        alternatives=alternatives or None,
        note=f"{what} {best} best explains the TCP ACK length and the smallest packet",
    )


def infer_mode_and_icv(flows: list[FlowStats], family: Attribute | None,
                       ip_version: int) -> tuple[Attribute, Attribute]:
    """Tunnel or Transport, and the ICV length, for child SAs sharing one configuration."""
    if family is None or family.evidence == "unknown" or family.value not in STRUCTURE:
        unknown = Attribute.unknown(
            "the cipher structure is not known, so the IV and padding needed to "
            "size the inner packet are not either",
            resolvable_by="longer_capture",
        )
        return unknown, unknown
    weights = hypothesis_weights(flows, family.value, ip_version)
    if not weights:
        unknown = Attribute.unknown(
            "no combination of mode, ICV and TCP ACK size reproduces the most "
            "common small packet, so the traffic offers no usable anchor",
            resolvable_by="longer_capture",
        )
        return unknown, unknown
    features = {"anchors": ",".join(str(a) for a in sorted(filter(None, map(anchor, flows))))
                or "none",
                "smallest_payload": min(n for f in flows for n in f.length_histogram)}
    mode = _decide(_marginal(weights, 0), "mode", features,
                   "Tunnel and Transport both explain the packet lengths, because the "
                   "unknown ICV or TCP options can absorb the inner IP header")
    icv = _decide(_marginal(weights, 1), "ICV bytes", features,
                  "several ICV lengths explain the packet lengths equally well")
    return mode, icv
