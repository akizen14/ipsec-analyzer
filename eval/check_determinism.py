"""Scoring determinism: same capture, same record, every time (PLAN.md section 7, E1b).

Runs the CLI in a fresh process per run, each with a different PYTHONHASHSEED,
so set or dict ordering that leaks into the output shows up here even though
the in-process test in tests/test_golden.py cannot see it.

    python eval/check_determinism.py [CAPTURE ...] [--runs 10] [--out eval/results/determinism.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
#: Fields that legitimately change between runs, removed before comparing.
VOLATILE = ("generated_at",)


def analyse_once(capture: Path, seed: int) -> str:
    """Hash of every record the CLI writes for `capture`, volatile fields removed."""
    with tempfile.TemporaryDirectory() as out:
        env = {**os.environ, "PYTHONHASHSEED": str(seed)}
        subprocess.run(
            [sys.executable, "-m", "analyzer.cli", "analyse", str(capture),
             "--out", out, "--no-reports", "--quiet"],
            check=True, capture_output=True, env=env, cwd=ROOT,
        )
        records = []
        for path in sorted(Path(out).glob("*.json")):
            record = json.loads(path.read_text(encoding="utf-8"))
            for field in VOLATILE:
                record.pop(field, None)
            records.append(record)
    blob = json.dumps(records, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("captures", nargs="*", type=Path,
                    default=sorted((ROOT / "tests" / "golden").glob("*.pcapng")))
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--out", type=Path, default=ROOT / "eval" / "results" / "determinism.json")
    args = ap.parse_args()

    results = {}
    for capture in args.captures:
        hashes = [analyse_once(capture, seed) for seed in range(args.runs)]
        results[capture.name] = {"identical": len(set(hashes)) == 1, "hashes": hashes}
        print(f"{capture.name}: {'identical' if results[capture.name]['identical'] else 'DIFFERS'}"
              f" across {args.runs} runs")

    report = {
        "pass": all(r["identical"] for r in results.values()),
        "runs_per_capture": args.runs,
        "removed_fields": list(VOLATILE),
        "hash_seeds": list(range(args.runs)),
        "captures": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{'PASS' if report['pass'] else 'FAIL'} -> {args.out.relative_to(ROOT)}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
