"""Freeze the evaluation splits before any metric exists (PLAN.md section 7, rule 5).

Derived from testbed/matrix.yaml, not from results, so the split cannot be
shaped by what the data turned out to say. Two rules, applied together:

- by repeat: repeats 1 and 2 of a configuration are validation (thresholds may
  be tuned on them), repeat 3 is test;
- by configuration: about 20% of configurations, chosen by hash of their name,
  are held out entirely, every repeat test. This is the "held-out
  configurations" split Table V's mode row asks for.

A run is validation only if both rules allow it.

    python eval/split.py [--corpora cipher pfs weak_ike]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "testbed"))
from run_matrix import ROOT, expand

HELD_OUT_SHARE = 5  # 1 in 5 configurations
TEST_REPEAT = 3


def config_of(run_id: str) -> str:
    return run_id.rsplit("-r", 1)[0]


def held_out(config: str) -> bool:
    return int(hashlib.sha256(config.encode()).hexdigest(), 16) % HELD_OUT_SHARE == 0


def build(corpora: list[str]) -> dict:
    runs = {}
    for corpus in corpora:
        for r in expand(corpus):
            config = config_of(r["run_id"])
            test = r["repeat"] == TEST_REPEAT or held_out(config)
            runs[r["run_id"]] = {"config": config, "split": "test" if test else "validation",
                                 "held_out_config": held_out(config)}
    split = {
        "rule": f"test if repeat == {TEST_REPEAT} or sha256(config) % {HELD_OUT_SHARE} == 0",
        "corpora": corpora,
        "held_out_configs": sorted({v["config"] for v in runs.values() if v["held_out_config"]}),
        "counts": {s: sum(v["split"] == s for v in runs.values()) for s in ("validation", "test")},
        "runs": runs,
    }
    # Self-check: no held-out configuration leaks into validation, no test repeat either.
    for run_id, v in runs.items():
        assert v["split"] == "test" or not (v["held_out_config"] or run_id.endswith(f"-r{TEST_REPEAT}"))
    return split


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpora", nargs="+", default=["cipher", "pfs", "weak_ike"])
    ap.add_argument("--out", type=Path, default=ROOT / "eval" / "results" / "split.json")
    args = ap.parse_args()

    split = build(args.corpora)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(split, indent=2) + "\n", encoding="utf-8")
    print(f"{split['counts']}, {len(split['held_out_configs'])} held-out configurations "
          f"-> {args.out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
