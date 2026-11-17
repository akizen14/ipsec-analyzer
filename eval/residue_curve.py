"""Residue inference accuracy against the number of distinct ESP lengths, m (PLAN.md E3).

Tests the paper's equation (2) and its 18-length bound for telling 3DES from
AES-CBC. For each ESP SA of the chosen split, draw m distinct payload lengths
from the SA's own observed lengths (200 draws per m, m = 1..30), give each
enough packets to pass the packet-count guard, and call the analyzer's own
infer_block_size on them. Nothing is reimplemented.

    python eval/residue_curve.py [--split test]
"""

from __future__ import annotations

import argparse
import csv
import math
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate import FAMILY, RESULTS, ROOT, RUNS_DIR, load_runs

from analyzer.esp_ah.stats import FlowStats, esp_flows
from analyzer.inference.esp_structure import MIN_PACKETS, infer_block_size
from analyzer.ingest.pcap import read_capture

M_VALUES = range(1, 31)
DRAWS = 200
SEED = 20261118


def curve(runs: list[dict]) -> list[dict]:
    rng = random.Random(SEED)
    tally: dict[tuple[int, str], Counter] = {}
    for r in runs:
        if r["corpus"] != "cipher":
            continue
        truth = FAMILY[r["truth"]["esp_encr"]]
        group = "3DES" if truth == "BLOCK_8B_CBC_LIKE" else "other"
        for f in esp_flows(read_capture(RUNS_DIR / r["run_id"] / "capture.pcap").esp).values():
            lengths = sorted(f.length_histogram)
            for m in M_VALUES:
                if m > len(lengths):
                    continue
                per_length = math.ceil(MIN_PACKETS / m)
                c = tally.setdefault((m, group), Counter())
                for _ in range(DRAWS):
                    sample = Counter({n: per_length for n in rng.sample(lengths, m)})
                    flow = FlowStats(f.spi, f.src, f.dst, packet_count=sum(sample.values()),
                                     length_histogram=sample)
                    _, family, _ = infer_block_size(flow)
                    c["unknown" if family.evidence == "unknown"
                      else "right" if family.value == truth else "wrong"] += 1
    rows = []
    for m in M_VALUES:
        for group in ("3DES", "other", "all"):
            c = (tally.get((m, "3DES"), Counter()) + tally.get((m, "other"), Counter())
                 if group == "all" else tally.get((m, group), Counter()))
            n = sum(c.values())
            if n:
                rows.append({"m": m, "group": group, "n": n,
                             "accuracy": round(c["right"] / n, 5),
                             "unknown_rate": round(c["unknown"] / n, 5),
                             "error_rate": round(c["wrong"] / n, 5)})
    return rows


def plot(rows: list[dict], path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def series(group, key):
        pts = [(r["m"], r[key]) for r in rows if r["group"] == group]
        return [p[0] for p in pts], [p[1] for p in pts]

    fig, ax = plt.subplots(figsize=(6.5, 3.6))
    ax.plot(*series("all", "accuracy"), label="accuracy, all SAs", color="#1f5fbf")
    ax.plot(*series("all", "unknown_rate"), label="Unknown rate, all SAs", color="#888888",
            linestyle="--")
    ax.plot(*series("3DES", "error_rate"), label="error rate, 3DES SAs", color="#c0392b")
    for m, label in ((10, "m = 10"), (18, "m = 18")):
        ax.axvline(m, color="#bbbbbb", linewidth=0.8)
        ax.text(m + 0.3, 0.5, label, fontsize=8, color="#555555")
    ax.set_xlabel("distinct ESP payload lengths observed (m)")
    ax.set_ylabel("share of draws")
    ax.set_ylim(-0.02, 1.02)
    ax.set_xlim(1, 30)
    ax.legend(fontsize=8, loc="center right")
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    fig.savefig(path.with_suffix(".png"), dpi=200)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--split", default="test", choices=["test", "validation", "all"])
    args = ap.parse_args()

    rows = curve(load_runs(args.split)[0])
    suffix = "" if args.split == "test" else f"_{args.split}"
    with (RESULTS / f"residue_curve{suffix}.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    plot(rows, ROOT / "eval" / "figures" / f"residue_vs_m{suffix}.pdf")
    for r in rows:
        if r["group"] != "other" and r["m"] in (1, 4, 5, 8, 10, 12, 15, 18, 20, 30):
            print(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
