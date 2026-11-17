"""Speed: a ~100 MB capture to both reports (PLAN.md section 7, E1c; target < 2 min).

Builds the capture by concatenating the golden captures until the target size
is reached, shifting timestamps so each copy follows the last. That stands in
for mergecap, which is not on every host. The copies repeat SPIs and sequence
numbers, so the analysis output is meaningless; only the timing counts. Swap in
a real testbed capture with --capture once phase 1 produces one.

    python eval/bench_speed.py [--capture big.pcap] [--target-mb 100] [--runs 5]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET_S = 120


def build_capture(sources: list[Path], target_bytes: int, out: Path) -> dict:
    """Write a classic pcap of repeated `sources` packets, at least `target_bytes` long."""
    from scapy.all import conf, rdpcap

    # Lay sources end to end so timestamps only move forward.
    frames: list[tuple[float, bytes]] = []
    linktypes = set()
    span = 0.0
    for src in sources:
        packets = rdpcap(str(src))
        linktypes |= {conf.l2types.layer2num.get(type(p)) for p in packets}
        t0 = float(packets[0].time)
        frames += [(span + float(p.time) - t0, bytes(p)) for p in packets]
        span = frames[-1][0] + 1.0
    if len(linktypes) != 1 or None in linktypes:
        raise SystemExit(f"sources must share one known link type, got {linktypes}")

    copies = written = count = 0
    with out.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktypes.pop()))
        while written < target_bytes:
            base = 1_700_000_000 + copies * span
            for offset, raw in frames:
                ts = base + offset
                fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(raw), len(raw)))
                fh.write(raw)
                written += 16 + len(raw)
                count += 1
            copies += 1
    return {"bytes": out.stat().st_size, "packets": count, "copies": copies,
            "sources": [s.name for s in sources]}


def time_run(capture: Path) -> float:
    """Wall-clock seconds for the CLI to analyse `capture` and write both reports."""
    with tempfile.TemporaryDirectory() as out:
        start = time.perf_counter()
        subprocess.run(
            [sys.executable, "-m", "analyzer.cli", "analyse", str(capture), "--out", out, "--quiet"],
            check=True, capture_output=True, cwd=ROOT,
        )
        return time.perf_counter() - start


def total_ram_gb() -> float:
    if hasattr(os, "sysconf") and "SC_PHYS_PAGES" in os.sysconf_names:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30
    import ctypes

    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [
            (name, ctypes.c_ulonglong) for name in (
                "ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile",
                "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual")
        ]

    status = MemoryStatusEx(dwLength=ctypes.sizeof(MemoryStatusEx))
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
    return status.ullTotalPhys / 2**30


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--capture", type=Path, help="use this capture instead of building one")
    ap.add_argument("--target-mb", type=float, default=100)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out", type=Path, default=ROOT / "eval" / "results" / "speed.json")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        capture = args.capture
        if capture is None:
            capture = Path(tmp) / "bench.pcap"
            sources = sorted((ROOT / "tests" / "golden").glob("*.pcapng"))
            info = build_capture(sources, int(args.target_mb * 2**20), capture)
            info["synthetic"] = True
        else:
            info = {"bytes": capture.stat().st_size, "path": str(capture), "synthetic": False}
        print(f"capture: {info['bytes'] / 2**20:.1f} MB")

        times = []
        for i in range(args.runs):
            times.append(round(time_run(capture), 2))
            print(f"run {i + 1}/{args.runs}: {times[-1]} s")

    median = statistics.median(times)
    report = {
        "pass": median < TARGET_S,
        "target_s": TARGET_S,
        "median_s": median,
        "min_s": min(times),
        "max_s": max(times),
        "runs_s": times,
        "capture": info,
        "machine": {
            "cpu": platform.processor() or platform.machine(),
            "cpu_count": os.cpu_count(),
            "ram_gb": round(total_ram_gb(), 1),
            "os": platform.platform(),
            "python": platform.python_version(),
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"median {median} s, target < {TARGET_S} s: {'PASS' if report['pass'] else 'FAIL'}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
