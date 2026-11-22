"""Build a wheel and check the installed CLI from a separate directory."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import venv
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "golden"


def run_cli(executable: Path, cwd: Path, *args: str, expected_exit: int = 0) -> None:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    result = subprocess.run(
        [str(executable), *args], cwd=cwd, env=env, check=False,
    )
    if result.returncode != expected_exit:
        raise RuntimeError(
            f"{args[0]} exited with {result.returncode}, expected {expected_exit}"
        )


def check_session(executable: Path, root: Path, name: str, expected: dict) -> None:
    capture = root / f"{name}.pcapng"
    shutil.copyfile(FIXTURES / capture.name, capture)
    output = root / "results" / name
    start = time.perf_counter()
    run_cli(
        executable, root, "analyse", str(capture), "--out", str(output),
        "--fail-on", "high", expected_exit=2 if expected["risk_level"] == "high" else 0,
    )
    elapsed = time.perf_counter() - start
    (record,) = output.glob("*.json")
    payload = json.loads(record.read_text(encoding="utf-8"))
    score = payload["score"]
    if score["risk_level"] != expected["risk_level"]:
        raise RuntimeError(f"{name}: unexpected risk level {score['risk_level']}")
    if not expected.get("score_at_least", 0) <= score["value"] <= expected.get("score_at_most", 100):
        raise RuntimeError(f"{name}: unexpected score {score['value']}")

    capture.unlink()
    for kind in ("executive", "technical"):
        original = output / f"{record.stem}-{kind}.html"
        regenerated = root / "recreated" / original.name
        run_cli(executable, root, "report", str(record), "--kind", kind, "--out", str(regenerated))
        if regenerated.read_bytes() != original.read_bytes():
            raise RuntimeError(f"{name}: regenerated {kind} report differs from the original")
    print(f"Verified {name}: {score['risk_level']} ({score['value']}/100), {elapsed:.2f}s", flush=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ipsec-wheel-smoke-") as workspace:
        root = Path(workspace)
        dist = root / "dist"
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(dist), str(REPO)],
            cwd=root, check=True,
        )
        (wheel,) = dist.glob("*.whl")
        env_root = root / "venv"
        venv.EnvBuilder(with_pip=True).create(env_root)
        if os.name == "nt":
            python = env_root / "Scripts" / "python.exe"
            executable = env_root / "Scripts" / "ipsec-analyzer.exe"
        else:
            python = env_root / "bin" / "python"
            executable = env_root / "bin" / "ipsec-analyzer"
        subprocess.run([str(python), "-m", "pip", "install", str(wheel)], cwd=root, check=True)

        expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
        for fixture in sorted(FIXTURES.glob("*.pcapng")):
            check_session(executable, root, fixture.stem, expected[fixture.stem])

        bad = root / "invalid.pcap"
        bad.write_bytes(b"not a capture")
        bad_output = root / "invalid-results"
        run_cli(executable, root, "analyse", str(bad), "--out", str(bad_output), expected_exit=1)
        if bad_output.exists():
            raise RuntimeError("Corrupt capture produced a result directory")


if __name__ == "__main__":
    main()
