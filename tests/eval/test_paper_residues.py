"""The paper's residue maths (Table II), checked against the analyzer's own code.

PLAN.md section 7, step E1a. Expected values come from the paper and must not be
edited to match the code. Where the code disagrees, the test is marked xfail
with the risk and decision IDs, so the disagreement stays visible.

The paper's L counts the 8-byte ESP header. FlowStats holds payload lengths
(L - 8), so the residues are shifted by 8 before they are compared.
"""

from __future__ import annotations

from collections import Counter

import pytest

from analyzer.esp_ah.stats import FlowStats
from analyzer.inference.esp_structure import infer_block_size

# suite, IV bytes v, padding granularity beta, ICV bytes t, residues of L mod 16
TABLE_II = [
    ("AES-CBC + HMAC-SHA1-96", 16, 16, 12, {4}),
    ("AES-CBC + HMAC-SHA-256-128", 16, 16, 16, {8}),
    ("AES-CBC + HMAC-SHA-384-192", 16, 16, 24, {0}),
    ("AES-CBC + HMAC-SHA-512-256", 16, 16, 32, {8}),
    ("3DES-CBC + HMAC-SHA1-96", 8, 8, 12, {4, 12}),
    ("AES-CTR + HMAC-SHA1-96", 8, 4, 12, {0, 4, 8, 12}),
    ("AES-GCM-16", 8, 4, 16, {0, 4, 8, 12}),
    ("ChaCha20-Poly1305", 8, 4, 16, {0, 4, 8, 12}),
    ("AES-CBC, no integrity", 16, 16, 0, {8}),
]

FAMILY_BY_RESIDUE_COUNT = {1: "BLOCK_16B_CBC_LIKE", 2: "BLOCK_8B_CBC_LIKE", 4: "AEAD_OR_COUNTER"}


def table_ii_lengths(v: int, beta: int, t: int, ks=range(41)) -> list[int]:
    """Full ESP lengths L = 8 + v + k*beta + t."""
    return [8 + v + k * beta + t for k in ks]


def flow_of(full_lengths: list[int], repeats: int = 5) -> FlowStats:
    """A flow carrying each length `repeats` times, as payload lengths."""
    hist = Counter({length - 8: repeats for length in full_lengths})
    return FlowStats(
        spi="0x00000001",
        src="10.0.0.1",
        dst="10.0.0.2",
        first_packet=1,
        packet_count=sum(hist.values()),
        length_histogram=hist,
    )


@pytest.mark.parametrize(("suite", "v", "beta", "t", "residues"), TABLE_II, ids=[s[0] for s in TABLE_II])
def test_residue_sets_match_table_ii(suite, v, beta, t, residues):
    flow = flow_of(table_ii_lengths(v, beta, t))
    seen = {(r + 8) % 16 for r in flow.residues(16)}
    assert seen == residues


@pytest.mark.parametrize(("suite", "v", "beta", "t", "residues"), TABLE_II, ids=[s[0] for s in TABLE_II])
def test_family_from_a_full_length_spread(suite, v, beta, t, residues):
    _block, family, _ev = infer_block_size(flow_of(table_ii_lengths(v, beta, t)))
    assert family.evidence == "inferred"
    assert family.value == FAMILY_BY_RESIDUE_COUNT[len(residues)]


def test_cbc_without_integrity_is_indistinguishable_from_16_byte_icv():
    """t = 0 lands on the same residue as a 16-byte ICV, so the length channel
    cannot tell ESP-001 (no integrity) apart from HMAC-SHA-256-128."""
    a = infer_block_size(flow_of(table_ii_lengths(16, 16, 0)))
    b = infer_block_size(flow_of(table_ii_lengths(16, 16, 16)))
    assert [x.to_json() for x in a[:2]] == [x.to_json() for x in b[:2]]


def test_too_few_distinct_lengths_is_unknown():
    _block, family, _ev = infer_block_size(flow_of(table_ii_lengths(16, 16, 16, ks=range(3)), repeats=10))
    assert family.evidence == "unknown"


def _3des_on_one_residue(m: int) -> list[int]:
    """m distinct 3DES lengths that all happen to land on one residue mod 16
    (even k only), which looks exactly like AES-CBC."""
    return table_ii_lengths(8, 8, 12, ks=range(0, 2 * m, 2))


def test_single_residue_from_18_lengths_concludes_16_byte_block():
    _block, family, _ev = infer_block_size(flow_of(_3des_on_one_residue(18)))
    assert family.value == "BLOCK_16B_CBC_LIKE"


@pytest.mark.xfail(
    strict=True,
    reason="R12 / D10: the code concludes a 16-byte block from 4 distinct lengths; "
    "the paper requires 18 before separating AES-CBC from 3DES",
)
def test_single_residue_below_18_lengths_does_not_claim_aes_cbc():
    """3DES puts each distinct length on one of two residues, so m lengths all
    share one residue with probability 2^(1-m). The paper bounds that at 1e-5,
    which needs m >= 18 (2^-17 is about 7.6e-6)."""
    for m in range(4, 18):
        _block, family, _ev = infer_block_size(flow_of(_3des_on_one_residue(m)))
        assert family.value != "BLOCK_16B_CBC_LIKE", f"concluded AES-CBC-like from {m} lengths"


# Table III: KE payload size 8 + |g| for each group, against the sizes the PFS
# inference uses (analyzer/inference/pfs.py).
TABLE_III = {"MODP_1024": 136, "MODP_1536": 200, "MODP_2048": 264,
             "ECP_256": 72, "ECP_384": 104, "CURVE_25519": 40}


@pytest.mark.parametrize(("group", "ke_payload"), TABLE_III.items())
def test_ke_payload_sizes_match_table_iii(group, ke_payload):
    from analyzer.inference.pfs import KE_BYTES

    assert 8 + KE_BYTES[group] == ke_payload


@pytest.mark.parametrize(("tcp_header", "transport", "tunnel"), [(20, 72, 88), (32, 88, 104)])
def test_mode_example_bare_tcp_ack_over_ipv4(tcp_header, transport, tunnel):
    """AES-CBC + HMAC-SHA-256-128 over IPv4: a bare TCP ACK is 72 bytes of ESP in
    transport mode and 88 in tunnel mode; 88 and 104 with TCP timestamps. The
    paper's L includes the 8-byte ESP header; payload_bytes does not."""
    from analyzer.inference.esp_mode import payload_bytes

    assert 8 + payload_bytes(16, 16, 16, tcp_header) == transport
    assert 8 + payload_bytes(16, 16, 16, 20 + tcp_header) == tunnel
