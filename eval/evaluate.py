"""Score the analyzer against the testbed ground truth and write Table V (PLAN.md E3).

Uses only runs that passed testbed/verify_truth.py, and only the split asked
for (test by default; the split is frozen in eval/results/split.json).
Unknown counts as wrong for accuracy; coverage and accuracy-on-answered are
reported beside it.

    python eval/evaluate.py [--split test|validation|all]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "testbed"))
from adapter import predict
from run_matrix import MANIFEST, PFS_GROUPS, ROOT, RUNS_DIR

from analyzer.inference.pfs import KE_BYTES
from analyzer.ingest.pcap import read_capture
from analyzer.sessions.builder import parse_ike_messages

RESULTS = ROOT / "eval" / "results"
CORPORA = ("cipher", "pfs", "weak_ike")
FAMILY = {"AES_CBC": "BLOCK_16B_CBC_LIKE", "3DES_CBC": "BLOCK_8B_CBC_LIKE",
          "AES_CTR": "AEAD_OR_COUNTER", "AES_GCM_16": "AEAD_OR_COUNTER",
          "CHACHA20_POLY1305": "AEAD_OR_COUNTER"}
CHARON_DH = {"MODP_1024": 2, "MODP_1536": 5, "MODP_2048": 14, "ECP_256": 19, "CURVE_25519": 31}
CHARON_ENCR = {"AES_CBC": "ENCR_AES_CBC", "3DES_CBC": "ENCR_3DES"}


def ike_truth(run_dir: Path) -> dict:
    """The IKE suite as the responder's charon logged it when it selected the proposal."""
    log = (run_dir / "gw-b" / "charon.log").read_text(encoding="utf-8", errors="replace")
    encr, integ, prf, dh = re.search(r"selected proposal: IKE:(\S+)", log)[1].split("/")
    name, bits = encr.rsplit("_", 1)
    return {"encr": CHARON_ENCR[name], "encr_key_bits": int(bits), "integ": f"AUTH_{integ}",
            "prf": prf, "dh_group": CHARON_DH[dh]}


def load_runs(split_name: str) -> tuple[list[dict], Counter]:
    split = json.loads((RESULTS / "split.json").read_text(encoding="utf-8"))["runs"]
    latest: dict[str, dict] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r["corpus"] in CORPORA:
            latest[r["run_id"]] = r
    excluded: Counter = Counter()
    runs = []
    for r in latest.values():
        verify = RUNS_DIR / r["run_id"] / "verify.json"
        if r["status"] != "ok":
            excluded["run failed"] += 1
        elif not verify.exists() or not json.loads(verify.read_text(encoding="utf-8"))["ok"]:
            excluded["labels not verified"] += 1
        elif split_name == "all" or split[r["run_id"]]["split"] == split_name:
            runs.append({**r, "held_out_config": split[r["run_id"]]["held_out_config"]})
    return sorted(runs, key=lambda r: r["run_id"]), excluded


def rate(c: Counter) -> dict:
    total = sum(c.values())
    right, unknown = c["right"], c["unknown"]
    answered = total - unknown
    return {"accuracy": round(right / total, 4) if total else None, "n": total,
            "right": right, "wrong": c["wrong"], "unknown": unknown,
            "coverage": round(answered / total, 4) if total else None,
            "accuracy_answered": round(right / answered, 4) if answered else None}


def outcome(predicted, truth) -> str:
    return "unknown" if predicted is None else ("right" if predicted == truth else "wrong")


def pct(r: dict) -> str:
    return "n/a" if r["accuracy"] is None else f"{r['accuracy']:.1%}"


def evaluate(runs: list[dict]) -> dict:
    ike_fields, ike_by_field = Counter(), defaultdict(Counter)
    family, icv, joint, mode, mode_held = Counter(), Counter(), Counter(), Counter(), Counter()
    pfs, pfs_group = Counter(), Counter()
    conf_cipher, conf_mode = Counter(), Counter()
    mismatches, bands = [], defaultdict(set)

    for r in runs:
        run_dir = RUNS_DIR / r["run_id"]
        t, p = r["truth"], predict(run_dir / "capture.pcap")
        bands[r["run_id"].rsplit("-r", 1)[0]].add(p["risk"])

        for field, want in ike_truth(run_dir).items():
            o = outcome(p["ike"][field], want)
            ike_fields[o] += 1
            ike_by_field[field][o] += 1
            if o != "right":
                mismatches.append(f"{r['run_id']}: IKE {field} {p['ike'][field]} != {want}")

        for sa in p["sas"]:
            of = outcome(sa["cipher_family"], FAMILY[t["esp_encr"]])
            oi = outcome(sa["icv_bytes"], t["icv_bytes"])
            om = outcome(sa["mode"], t["mode"])
            family[of] += 1
            icv[oi] += 1
            joint["right" if of == oi == "right" else
                  "unknown" if "unknown" in (of, oi) else "wrong"] += 1
            mode[om] += 1
            if r["held_out_config"]:
                mode_held[om] += 1
            conf_cipher[(r["params"]["suite"], sa["cipher_family"] or "Unknown")] += 1
            conf_mode[(t["mode"], sa["mode"] or "Unknown")] += 1
            for name, o, got in (("family", of, sa["cipher_family"]), ("icv", oi, sa["icv_bytes"]),
                                 ("mode", om, sa["mode"])):
                if o == "wrong":
                    mismatches.append(f"{r['run_id']} SA {sa['sa_spi']}: {name} {got}")

        if t["child_rekey_s"]:
            want = t["pfs_group"] is not None
            o = outcome(p["pfs"], want)
            pfs[o] += 1
            if o == "wrong":
                mismatches.append(f"{r['run_id']}: PFS {p['pfs']} != {want}")
            if want and p["pfs"] is True:
                group = PFS_GROUPS[r["params"]["pfs"]][1]
                pfs_group["right" if group in p["pfs_groups"].split(",") else "wrong"] += 1

    return {
        "ike": {**rate(ike_fields), "by_field": {f: rate(c) for f, c in ike_by_field.items()}},
        "cipher_family": rate(family), "icv": rate(icv), "cipher_family_and_icv": rate(joint),
        "mode": rate(mode), "mode_held_out_configs": rate(mode_held),
        "pfs": rate(pfs), "pfs_group_contains_truth": rate(pfs_group),
        "risk_band_stable_configs": f"{sum(len(b) == 1 for b in bands.values())}/{len(bands)}",
        "mismatches": mismatches,
        "_confusion_cipher": conf_cipher, "_confusion_mode": conf_mode,
    }


def pfs_sizes(runs: list[dict]) -> list[dict]:
    """CREATE_CHILD_SA request and response sizes per suite and PFS group, against 8+|g|."""
    sizes: dict[tuple, list[int]] = defaultdict(list)
    for r in runs:
        if r["corpus"] != "pfs":
            continue
        msgs, _ = parse_ike_messages(read_capture(RUNS_DIR / r["run_id"] / "capture.pcap"))
        for m in msgs:
            if m.header.exchange_type == 36:
                key = (r["params"]["suite"], r["params"]["pfs"],
                       "response" if m.header.is_response else "request")
                sizes[key].append(m.header.length)
    rows = []
    for (suite, pfs, direction), lengths in sorted(sizes.items()):
        base = sizes.get((suite, "none", direction))
        group = PFS_GROUPS[pfs][1]
        rows.append({
            "suite": suite, "pfs": pfs, "direction": direction, "n": len(lengths),
            "median_bytes": statistics.median(lengths),
            "increase_over_no_pfs": statistics.median(lengths) - statistics.median(base) if base else "",
            "predicted_ke_payload": 8 + KE_BYTES[group] if group else 0,
            "predicted_with_dh_transform": 16 + KE_BYTES[group] if group else 0,
        })
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        if rows:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)


def confusion_rows(c: Counter, row_name: str) -> list[dict]:
    cols = sorted({k[1] for k in c})
    return [{row_name: row, **{col: c[(row, col)] for col in cols}}
            for row in sorted({k[0] for k in c})]


def table_v(m: dict, split_name: str) -> list[dict]:
    det = json.loads((RESULTS / "determinism.json").read_text(encoding="utf-8"))
    speed = json.loads((RESULTS / "speed.json").read_text(encoding="utf-8"))

    def note(r):
        return (f"coverage {r['coverage']:.0%}, {r['accuracy_answered']:.1%} of answered, "
                f"{r['wrong']} wrong" if r["n"] and r["accuracy_answered"] is not None else "")

    return [
        {"row": "IKE parser", "measure": "Field-level exact match with ground truth",
         "target": "100%", "result": pct(m["ike"]), "n": f"{m['ike']['n']} fields",
         "notes": "encr, key bits, integ, PRF, DH group vs charon's selected proposal"},
        {"row": "ESP cipher family, ICV", "measure": f"Accuracy per SA, {split_name} runs",
         "target": ">= 95%",
         "result": f"family {pct(m['cipher_family'])}, ICV {pct(m['icv'])}, both {pct(m['cipher_family_and_icv'])}",
         "n": f"{m['cipher_family']['n']} SAs",
         "notes": f"family: {note(m['cipher_family'])}; ICV: {note(m['icv'])}"},
        {"row": "ESP mode", "measure": "Accuracy per SA, held-out configurations",
         "target": ">= 90%", "result": f"{pct(m['mode_held_out_configs'])} (all {split_name}: {pct(m['mode'])})",
         "n": f"{m['mode_held_out_configs']['n']} SAs ({m['mode']['n']} all)",
         "notes": note(m["mode"])},
        {"row": "PFS on rekey", "measure": "Accuracy on runs with a rekey", "target": ">= 90%",
         "result": pct(m["pfs"]), "n": f"{m['pfs']['n']} runs",
         "notes": f"{note(m['pfs'])}; group among fitting candidates in "
                  f"{m['pfs_group_contains_truth']['right']}/{m['pfs_group_contains_truth']['n']}"},
        {"row": "Traffic type", "measure": "Macro F1, held-out runs", "target": ">= 0.85",
         "result": "Future work", "n": "", "notes": "classifier not built"},
        {"row": "Generalization", "measure": "Macro F1 drop, held-out implementation",
         "target": "<= 10 points", "result": "Future work", "n": "", "notes": ""},
        {"row": "Calibration", "measure": "ECE per inferred attribute", "target": "<= 0.05",
         "result": "Future work", "n": "", "notes": "confidences are uncalibrated"},
        {"row": "Scoring", "measure": "Same output on repeated analysis", "target": "Identical",
         "result": "Identical" if det["pass"] else "Differs",
         "n": f"{det['runs_per_capture']} runs x {len(det['captures'])} captures",
         "notes": f"risk band stable across repeats in {m['risk_band_stable_configs']} configurations"},
        {"row": "Speed", "measure": "100 MB capture to both reports", "target": "< 2 min",
         "result": f"{speed['median_s']:.0f} s median", "n": f"{len(speed['runs_s'])} runs",
         "notes": f"range {speed['min_s']:.0f}-{speed['max_s']:.0f} s, {speed['machine']['os']}"},
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--split", default="test", choices=["test", "validation", "all"])
    args = ap.parse_args()

    runs, excluded = load_runs(args.split)
    metrics = evaluate(runs)
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True, cwd=ROOT).stdout.strip()
    rows = table_v(metrics, args.split)
    suffix = "" if args.split == "test" else f"_{args.split}"

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = {"split": args.split, "runs": len(runs), "excluded": dict(excluded),
           "analyzer_commit": commit, "generated": datetime.now(UTC).isoformat(timespec="seconds"),
           "table_v": rows, "metrics": {k: v for k, v in metrics.items() if not k.startswith("_")}}
    (RESULTS / f"table_v{suffix}.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    md = [f"# Table V ({args.split} split, {len(runs)} runs, analyzer {commit})", "",
          "| Row | Measure | Target | Result | N | Notes |", "|---|---|---|---|---|---|"]
    md += [f"| {r['row']} | {r['measure']} | {r['target']} | {r['result']} | {r['n']} | {r['notes']} |"
           for r in rows]
    if metrics["mismatches"]:
        md += ["", "## Mismatches", ""] + [f"- {x}" for x in metrics["mismatches"]]
    (RESULTS / f"table_v{suffix}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    write_csv(RESULTS / f"confusion_cipher{suffix}.csv", confusion_rows(metrics["_confusion_cipher"], "suite"))
    write_csv(RESULTS / f"confusion_mode{suffix}.csv", confusion_rows(metrics["_confusion_mode"], "mode"))
    # Sizes describe the protocol, not the analyzer, so every verified run counts.
    write_csv(RESULTS / "pfs_sizes.csv", pfs_sizes(load_runs("all")[0]))

    print("\n".join(md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
