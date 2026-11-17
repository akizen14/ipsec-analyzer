"""Ingest robustness on captures that are legal but untidy (PLAN.md phase 8)."""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from analyzer.ingest.pcap import read_capture


@pytest.mark.xfail(
    strict=True,
    reason="found by eval/bench_speed.py: duration is last minus first timestamp, so "
    "out-of-order packets give a negative duration that fails schema validation; "
    "awaiting approval to fix",
)
def test_out_of_order_timestamps_give_a_non_negative_duration(tmp_path):
    """pcapng files merged from several interfaces are not always time-ordered."""
    def pkt():
        return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
            src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500)

    later, earlier = pkt(), pkt()
    later.time, earlier.time = 1_700_000_010.0, 1_700_000_000.0
    path = tmp_path / "unordered.pcap"
    wrpcap(str(path), [later, earlier])

    assert read_capture(path).duration_s == pytest.approx(10.0)
