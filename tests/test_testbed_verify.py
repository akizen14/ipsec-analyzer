"""The xfrm log parser behind testbed/verify_truth.py. No Docker needed."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "testbed"))

from verify_truth import parse_xfrm

MONITOR = """\
Updated src 10.81.0.20 dst 10.81.0.10
\tproto esp spi 0xC5D9A75B reqid 1 mode tunnel
\treplay-window 32 flag af-unspec
\tauth-trunc hmac(sha256) 0x7cca 128
\tenc cbc(aes) 0x306b
src fd81::10 dst fd81::20
\tproto esp spi 0x0000abcd reqid 2 mode transport
\taead rfc4106(gcm(aes)) 0x11223344 128
Deleted src 10.81.0.20 dst 10.81.0.10
\tproto esp spi 0xc5d9a75b reqid 1 mode tunnel
\tauth-trunc hmac(sha256) 0x7cca 128
\tenc cbc(aes) 0x306b
src 10.81.2.0/24 dst 10.81.1.0/24
\tdir in priority 375423 ptype main
"""


def test_parses_cbc_and_aead_sas_and_skips_policies():
    sas = parse_xfrm(MONITOR)
    assert set(sas) == {"c5d9a75b", "0000abcd"}

    cbc = sas["c5d9a75b"]
    assert (cbc["src"], cbc["dst"], cbc["mode"]) == ("10.81.0.20", "10.81.0.10", "tunnel")
    assert cbc["enc"] == ["cbc(aes)", "0x306b"]
    assert cbc["auth-trunc"] == ["hmac(sha256)", "0x7cca", "128"]

    gcm = sas["0000abcd"]
    assert (gcm["src"], gcm["mode"]) == ("fd81::10", "transport")
    assert gcm["aead"] == ["rfc4106(gcm(aes))", "0x11223344", "128"]
    assert "enc" not in gcm
