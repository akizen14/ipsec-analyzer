"""Mode, ICV and PFS inference from sizes (analyzer/inference/esp_mode.py, pfs.py).

Inputs are built from the ESP and IKE size arithmetic, and the PFS sizes are
real CREATE_CHILD_SA response lengths seen on the testbed, so the expected
values come from the protocol, not from the code under test.
"""

from __future__ import annotations

from collections import Counter

from analyzer.esp_ah.stats import FlowStats
from analyzer.inference.esp_mode import infer_mode_and_icv, payload_bytes
from analyzer.inference.pfs import classify_response, infer_pfs
from analyzer.record import Attribute

GCM = Attribute.inferred("AEAD_OR_COUNTER", 0.95, "test")
AES_CBC = Attribute.inferred("BLOCK_16B_CBC_LIKE", 0.95, "test")


def flow(lengths: dict[int, int]) -> FlowStats:
    hist = Counter(lengths)
    return FlowStats("0x1", "10.0.0.1", "10.0.0.2", packet_count=sum(hist.values()),
                     length_histogram=hist)


def gcm16(inner: int) -> int:
    return payload_bytes(8, 4, 16, inner)


def test_gcm_tunnel_from_timestamped_ack_anchor():
    acks = flow({gcm16(20 + 32): 300, gcm16(20 + 100): 10})      # inner IPv4 + TCP ACK
    data = flow({gcm16(20 + n): 5 for n in range(8, 1400, 37)})  # never smaller than IP + 8
    mode, icv = infer_mode_and_icv([acks, data], GCM, 4)
    assert (mode.value, icv.value) == ("tunnel", 16)


def test_packet_too_small_for_an_inner_ip_header_means_transport():
    acks = flow({gcm16(32): 300, gcm16(4): 3})   # a 4-byte inner payload cannot be tunnelled
    mode, icv = infer_mode_and_icv([acks], GCM, 4)
    assert (mode.value, icv.value) == ("transport", 16)


def test_no_anchor_and_nothing_excluded_is_unknown():
    spread = flow({gcm16(28 + n): 2 for n in range(0, 1400, 41)})   # pings only, no ACK spike
    mode, _icv = infer_mode_and_icv([spread], GCM, 4)
    assert mode.evidence == "unknown"


def test_unknown_cipher_family_gives_unknown_mode():
    mode, icv = infer_mode_and_icv([flow({80: 100})], None, 4)
    assert mode.evidence == icv.evidence == "unknown"


# IKE SA AES-CBC-256 / HMAC-SHA2-256-128, 32-byte nonces, IPv4 traffic selectors.
IKE = {"iv": 16, "block": 16, "icv": 16, "nonce_len": 32, "ip_version": 4}


def test_rekey_response_sizes_seen_on_the_testbed():
    assert classify_response(192, **IKE) == (False, [])                 # no PFS
    assert classify_response(240, **IKE) == (True, ["CURVE_25519"])
    assert classify_response(464, **IKE) == (True, ["MODP_2048"])
    verdict, groups = classify_response(272, **IKE)                       # ECP-256
    assert verdict is True and "ECP_256" in groups


def test_size_window_straddling_the_line_is_undecided():
    assert classify_response(240, **{**IKE, "nonce_len": 40}) == (None, [])


def test_infer_pfs_needs_rekeys_a_known_cipher_and_agreement():
    kw = {"encr": "ENCR_AES_CBC", "integ": "AUTH_HMAC_SHA2_256_128", "nonce_len": 32,
          "ip_version": 4}
    assert infer_pfs([], **kw).evidence == "unknown"
    assert infer_pfs([464], **{**kw, "encr": "ENCR_SOMETHING"}).evidence == "unknown"
    assert infer_pfs([192, 464], **kw).evidence == "unknown"
    assert infer_pfs([464, 464], **kw).value is True
    assert infer_pfs([192], **kw).value is False
