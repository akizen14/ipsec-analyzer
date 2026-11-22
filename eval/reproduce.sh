#!/bin/sh
# Regenerate every number and figure behind Table V from the runs on disk.
#
#   sh eval/reproduce.sh            (after the testbed corpora have run)
#
# Order matters: labels are verified before anything is scored, and the split
# is rebuilt (deterministically, from matrix.yaml) before any metric.
set -e
cd "$(dirname "$0")/.."
PY=${PY:-.venv/Scripts/python}
[ -x "$PY" ] || PY=.venv/bin/python

"$PY" testbed/verify_truth.py          # labels three ways, padding audit
"$PY" eval/split.py                    # frozen validation/test split
"$PY" eval/check_determinism.py        # Scoring row
"$PY" eval/bench_speed.py              # Speed row
"$PY" eval/evaluate.py --split test    # Table V, confusion matrices, PFS sizes
"$PY" eval/residue_curve.py --split test
echo "results in eval/results/, figure in eval/figures/"
