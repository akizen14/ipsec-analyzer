"""Testbed orchestrator: one labelled capture per parameter set (PLAN.md phase 1).

For each run in a corpus of testbed/matrix.yaml:

1. render both gateways' swanctl.conf and write manifest.json from the same
   parameter set, so the label cannot drift from the configuration;
2. bring up testbed/compose/lab.yml, start key logging (ip xfrm monitor) on both
   gateways and the capture on the host side of the wan bridge;
3. initiate, wait for the child SA to be INSTALLED (60 s), generate traffic;
4. dump xfrm state and SAs, stop the capture, tear down, and append the result
   to dataset/manifest.jsonl.

Resumable: a run already in the manifest with status "ok" is skipped.

    sh scripts/testbed-bootstrap.sh            # once per Docker restart
    docker build -t ipsec-analyzer/strongswan:5.9 -f testbed/Dockerfile.strongswan testbed
    python testbed/run_matrix.py smoke [--dry-run] [--limit N] [--duration S]
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import random
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined

ROOT = Path(__file__).resolve().parent.parent
TESTBED = ROOT / "testbed"
COMPOSE = ["docker", "compose", "-f", str(TESTBED / "compose" / "lab.yml")]
IMAGE = "ipsec-analyzer/strongswan:5.9"
RUNS_DIR = ROOT / "dataset" / "runs"
MANIFEST = ROOT / "dataset" / "manifest.jsonl"
SKIPPED = ROOT / "eval" / "results" / "skipped.json"
CAPTURE_CONTAINER = "lab-capture"
WAN_BRIDGE = "tb-wan"

#: suite keyword -> (ESP encryption, key bits, integrity, ICV bytes). The ground truth.
SUITES = {
    "aes128-sha1": ("AES_CBC", 128, "HMAC_SHA1_96", 12),
    "aes128-sha256": ("AES_CBC", 128, "HMAC_SHA2_256_128", 16),
    "aes256-sha384": ("AES_CBC", 256, "HMAC_SHA2_384_192", 24),
    "aes256-sha512": ("AES_CBC", 256, "HMAC_SHA2_512_256", 32),
    "3des-sha1": ("3DES_CBC", 192, "HMAC_SHA1_96", 12),
    "aes128ctr-sha1": ("AES_CTR", 128, "HMAC_SHA1_96", 12),
    "aes128gcm16": ("AES_GCM_16", 128, None, 16),
    "chacha20poly1305": ("CHACHA20_POLY1305", 256, None, 16),
}
#: PFS keyword -> (IANA group number, strongSwan log name).
PFS_GROUPS = {"none": (None, None), "modp2048": (14, "MODP_2048"),
              "ecp256": (19, "ECP_256"), "curve25519": (31, "CURVE_25519")}

ADDR = {
    4: {"gw-a": "10.81.0.10", "gw-b": "10.81.0.20",
        "lan-a": "10.81.1.0/24", "lan-b": "10.81.2.0/24",
        "client-a": "10.81.1.100", "client-b": "10.81.2.100"},
    6: {"gw-a": "fd81::10", "gw-b": "fd81::20",
        "lan-a": "fd81:1::/64", "lan-b": "fd81:2::/64",
        "client-a": "fd81:1::100", "client-b": "fd81:2::100"},
}


def load_matrix() -> dict:
    return yaml.safe_load((TESTBED / "matrix.yaml").read_text(encoding="utf-8"))


def expand(corpus: str) -> list[dict]:
    """Every parameter set in `corpus`, with its run_id, including unavailable suites."""
    matrix = load_matrix()
    spec = {**matrix["defaults"], **matrix["corpora"][corpus]}
    factors = spec.pop("factors")
    repeats = spec.pop("repeats")
    runs = []
    for values in itertools.product(*factors.values()):
        params = {**spec, **dict(zip(factors, values))}
        if params["suite"] not in SUITES or params["pfs"] not in PFS_GROUPS:
            raise SystemExit(f"{corpus}: no ground truth for {params}")
        slug = "-".join(str(v) for v in values)
        for repeat in range(1, repeats + 1):
            runs.append({**params, "corpus": corpus, "repeat": repeat,
                         "run_id": f"{corpus}-{slug}-r{repeat}"})
    return runs


def truth_of(p: dict) -> dict:
    encr, key_bits, integ, icv = SUITES[p["suite"]]
    group, _ = PFS_GROUPS[p["pfs"]]
    return {"esp_encr": encr, "esp_key_bits": key_bits, "esp_integ": integ,
            "icv_bytes": icv, "mode": p["mode"], "pfs_group": group,
            "ip_version": p["ip_version"], "auth": p["auth"],
            "ike_proposal": p["ike_proposal"], "child_rekey_s": p["child_rekey_s"]}


def render_configs(p: dict, run_dir: Path) -> None:
    env = Environment(loader=FileSystemLoader(TESTBED / "templates"), undefined=StrictUndefined)
    template = env.get_template("swanctl.conf.j2")
    a = ADDR[p["ip_version"]]
    esp = p["suite"] + (f"-{p['pfs']}" if p["pfs"] != "none" else "")
    for me, peer, my_lan, peer_lan in (("gw-a", "gw-b", "lan-a", "lan-b"),
                                       ("gw-b", "gw-a", "lan-b", "lan-a")):
        tunnel = p["mode"] == "tunnel"
        host = "128" if p["ip_version"] == 6 else "32"
        conf = template.render(
            run_id=p["run_id"], role=me, local_addr=a[me], remote_addr=a[peer],
            local_id=f"{me}.testbed", remote_id=f"{peer}.testbed",
            ike_proposal=p["ike_proposal"], esp_proposal=esp, auth=p["auth"],
            mode=p["mode"], child_rekey_s=p["child_rekey_s"],
            local_ts=a[my_lan] if tunnel else f"{a[me]}/{host}",
            remote_ts=a[peer_lan] if tunnel else f"{a[peer]}/{host}",
        )
        (run_dir / me).mkdir(parents=True, exist_ok=True)
        (run_dir / me / "swanctl.conf").write_text(conf, encoding="utf-8", newline="\n")


def sh(*cmd: str, check: bool = True, timeout: float = 120) -> str:
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {out.returncode}: {out.stderr.strip() or out.stdout.strip()}")
    return out.stdout


def dexec(container: str, script: str, *, detach: bool = False, timeout: float = 120) -> str:
    return sh("docker", "exec", *(["-d"] if detach else []), container, "sh", "-c", script,
              timeout=timeout)


def wait_for(predicate, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(1)
    raise RuntimeError(f"timed out after {timeout:.0f}s waiting for {what}")


def traffic(p: dict, seed: int) -> None:
    """Random-size pings for a spread of ESP lengths, a TCP burst, then light
    pings until duration_s has passed so rekeys carry traffic too."""
    a = ADDR[p["ip_version"]]
    src, dst = (("lab-client-a", a["client-b"]) if p["mode"] == "tunnel"
                else ("lab-gw-a", a["gw-b"]))
    server = "lab-client-b" if p["mode"] == "tunnel" else "lab-gw-b"
    rng = random.Random(seed)
    start = time.monotonic()

    burst = " ".join(str(rng.randint(0, 1400)) for _ in range(200))
    dexec(src, f"for s in {burst}; do ping -q -c1 -W1 -s $s {dst} >/dev/null 2>&1; done",
          timeout=600)
    dexec(server, "iperf3 -s -D -1")
    time.sleep(1)
    # Rate-capped so a run's capture stays a few MB; the burst only needs to add
    # full-size TCP segments and ACKs to the length mix.
    dexec(src, f"iperf3 -c {dst} -t 5 -b 10M >/dev/null", timeout=60)

    remaining = max(0, int(p["duration_s"] - (time.monotonic() - start)))
    tail = " ".join(str(rng.randint(0, 1400)) for _ in range(remaining * 2))
    if tail:
        dexec(src, f"for s in {tail}; do ping -q -c1 -W1 -s $s {dst} >/dev/null 2>&1; "
                   "sleep 0.5; done", timeout=remaining * 3 + 60)


def run_one(p: dict, keep_up: bool = False) -> dict:
    run_dir = RUNS_DIR / p["run_id"]
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    seed = int(hashlib.sha256(p["run_id"].encode()).hexdigest()[:8], 16)
    record = {"run_id": p["run_id"], "corpus": p["corpus"], "repeat": p["repeat"],
              "params": {k: v for k, v in p.items() if k not in ("run_id", "corpus", "repeat")},
              "truth": truth_of(p), "seed": seed, "image": IMAGE,
              "started_at": datetime.now(UTC).isoformat(timespec="seconds")}
    render_configs(p, run_dir)
    (run_dir / "manifest.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    env = {**os.environ, "RUN_DIR": run_dir.as_posix()}
    vol = f"{run_dir.as_posix()}:/out"
    try:
        subprocess.run([*COMPOSE, "up", "-d"], check=True, capture_output=True, env=env, timeout=120)
        for gw in ("lab-gw-a", "lab-gw-b"):
            wait_for(lambda gw=gw: dexec(gw, "test -S /var/run/charon.vici") == "", 20, f"{gw} charon")
            # SA events only: per-packet replay events flood the netlink buffer and
            # can drop the SA events that carry the keys.
            dexec(gw, "ip xfrm monitor SA > /out/xfrm-monitor.log 2>&1", detach=True)

        # Written inside the container and copied out at the end: the Windows bind
        # mount is too slow for tcpdump to write to directly without dropping.
        sh("docker", "run", "-d", "--name", CAPTURE_CONTAINER, "--net=host",
           "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "-v", vol, "--entrypoint", "sh", IMAGE,
           "-c", f"ethtool -K {WAN_BRIDGE} gso off gro off tso off >/out/ethtool.log 2>&1; "
                 f"exec tcpdump -i {WAN_BRIDGE} -B 16384 -w /tmp/capture.pcap")
        wait_for(lambda: "listening on" in subprocess.run(
            ["docker", "logs", CAPTURE_CONTAINER], capture_output=True, text=True).stderr,
            15, "tcpdump")

        for gw in ("lab-gw-a", "lab-gw-b"):
            dexec(gw, "swanctl --load-all >/out/load.log 2>&1")
        dexec("lab-gw-a", "swanctl --initiate --child net --timeout 60 >/out/initiate.log 2>&1",
              timeout=90)
        wait_for(lambda: "INSTALLED" in dexec("lab-gw-a", "swanctl --list-sas"), 60, "child SA")

        traffic(p, seed)
        time.sleep(2)
        for gw in ("lab-gw-a", "lab-gw-b"):
            dexec(gw, "ip xfrm state > /out/xfrm-state.txt; swanctl --list-sas > /out/sas.txt")
        record["status"] = "ok"
    except (RuntimeError, subprocess.SubprocessError) as exc:
        record["status"], record["error"] = "failed", str(exc)
    finally:
        sh("docker", "kill", "--signal", "INT", CAPTURE_CONTAINER, check=False)
        sh("docker", "wait", CAPTURE_CONTAINER, check=False)
        sh("docker", "cp", f"{CAPTURE_CONTAINER}:/tmp/capture.pcap", str(run_dir), check=False)
        log = subprocess.run(["docker", "logs", CAPTURE_CONTAINER], capture_output=True, text=True)
        (run_dir / "capture.log").write_text(log.stdout + log.stderr, encoding="utf-8")
        record["capture_dropped"] = _dropped(log.stderr)
        sh("docker", "rm", "-f", CAPTURE_CONTAINER, check=False)
        if not keep_up:
            subprocess.run([*COMPOSE, "down"], capture_output=True, env=env, timeout=120)

    record["finished_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    (run_dir / "manifest.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    with MANIFEST.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def _dropped(tcpdump_stderr: str) -> int | None:
    """Packets tcpdump reports as dropped by the kernel; None if it never said."""
    for line in tcpdump_stderr.splitlines():
        if "dropped by kernel" in line:
            return int(line.split()[0])
    return None


def completed() -> set[str]:
    if not MANIFEST.exists():
        return set()
    lines = (json.loads(line) for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line)
    return {r["run_id"] for r in lines if r.get("status") == "ok"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("corpus")
    ap.add_argument("--dry-run", action="store_true", help="list runs and estimated time")
    ap.add_argument("--limit", type=int, help="stop after this many new runs")
    ap.add_argument("--duration", type=int, help="override duration_s (for quick checks)")
    ap.add_argument("--keep-up", action="store_true", help="leave the lab running after the run")
    args = ap.parse_args()

    runs = expand(args.corpus)
    unavailable = load_matrix().get("unavailable") or {}
    skipped = [{"run_id": r["run_id"], "suite": r["suite"], "reason": unavailable[r["suite"]]}
               for r in runs if r["suite"] in unavailable]
    runs = [r for r in runs if r["suite"] not in unavailable]
    if skipped:
        print(f"skipping {len(skipped)} run(s) with unavailable suites: "
              f"{', '.join(sorted({s['suite'] for s in skipped}))}")
        if not args.dry_run:
            SKIPPED.parent.mkdir(parents=True, exist_ok=True)
            prior = json.loads(SKIPPED.read_text(encoding="utf-8")) if SKIPPED.exists() else []
            merged = {s["run_id"]: s for s in prior + skipped}
            SKIPPED.write_text(json.dumps(sorted(merged.values(), key=lambda s: s["run_id"]),
                                          indent=2) + "\n", encoding="utf-8")
    if args.duration:
        runs = [{**r, "duration_s": args.duration} for r in runs]
    done = completed()
    pending = [r for r in runs if r["run_id"] not in done]
    todo = pending[: args.limit]
    # ~40 s of setup and teardown per run on top of its traffic duration.
    estimate = sum(r["duration_s"] + 40 for r in todo) / 60
    print(f"{args.corpus}: {len(runs)} runs, {len(runs) - len(pending)} done, "
          f"{len(todo)} to run now, about {estimate:.0f} min")
    if args.dry_run:
        for r in todo:
            print(f"  {r['run_id']}")
        return 0

    failed = 0
    for i, p in enumerate(todo, 1):
        rec = run_one(p, keep_up=args.keep_up)
        failed += rec["status"] != "ok"
        print(f"[{i}/{len(todo)}] {p['run_id']}: {rec['status']}"
              + (f" ({rec['error']})" if rec["status"] != "ok" else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
