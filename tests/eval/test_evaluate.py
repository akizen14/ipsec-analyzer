"""The evaluator's ground-truth parsing and scoring arithmetic (eval/evaluate.py)."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eval"))

from evaluate import ike_truth, outcome, rate


def test_ike_truth_reads_the_responders_selected_proposal(tmp_path):
    (tmp_path / "gw-b").mkdir()
    (tmp_path / "gw-b" / "charon.log").write_text(
        "2026-11-17 13:12:35 12[CFG] selected proposal: "
        "IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_1024\n"
        "2026-11-17 13:12:35 09[CFG] selected proposal: ESP:AES_CBC_128/HMAC_SHA2_256_128/NO_EXT_SEQ\n",
        encoding="utf-8",
    )
    assert ike_truth(tmp_path) == {"encr": "ENCR_AES_CBC", "encr_key_bits": 256,
                                   "integ": "AUTH_HMAC_SHA2_256_128",
                                   "prf": "PRF_HMAC_SHA2_256", "dh_group": 2}


def test_unknown_counts_as_wrong_but_is_reported_apart():
    c = Counter(outcome(p, "tunnel") for p in ("tunnel", "tunnel", "transport", None))
    r = rate(c)
    assert (r["accuracy"], r["coverage"], r["accuracy_answered"]) == (0.5, 0.75, round(2 / 3, 4))
    assert (r["right"], r["wrong"], r["unknown"], r["n"]) == (2, 1, 1, 4)
