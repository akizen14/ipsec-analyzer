"""Check each run's manifest labels against what actually happened (PLAN.md phase 1/3).

Three independent witnesses, each compared with manifest.json["truth"]:

1. charon's "selected proposal" log lines: the ESP suite and, on rekeys, the PFS group;
2. the kernel's xfrm SAs (ip xfrm monitor + final state): algorithms, key size, mode;
3. tshark decrypting the capture with those xfrm keys: proves the keys are the
   ones that protected the captured packets.

A run that fails any check is excluded from scoring and listed in
eval/results/truth_mismatches.json.

    python testbed/verify_truth.py [RUN_ID ...]      # default: every ok run in the manifest
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_matrix import IMAGE, MANIFEST, PFS_GROUPS, ROOT, RUNS_DIR

#: manifest ESP encryption -> (xfrm algorithm, salt/nonce bytes in the xfrm key, Wireshark label)
XFRM_ENCR = {
    "AES_CBC": ("cbc(aes)", 0, "AES-CBC [RFC3602]"),
    "3DES_CBC": ("cbc(des3_ede)", 0, "TripleDES-CBC [RFC2451]"),
    "AES_CTR": ("rfc3686(ctr(aes))", 4, "AES-CTR [RFC3686]"),
    "AES_GCM_16": ("rfc4106(gcm(aes))", 4, "AES-GCM with 16 octet ICV [RFC4106]"),
    # Wireshark 4.2 has no ESP ChaCha20-Poly1305 decryption; checks 1 and 2 still apply.
    "CHACHA20_POLY1305": ("rfc7539esp(chacha20,poly1305)", 4, None),
}
#: manifest integrity -> (xfrm algorithm, truncation bits, Wireshark label)
XFRM_INTEG = {
    "HMAC_SHA1_96": ("hmac(sha1)", 96, "HMAC-SHA-1-96 [RFC2404]"),
    "HMAC_SHA2_256_128": ("hmac(sha256)", 128, "HMAC-SHA-256-128 [RFC4868]"),
    "HMAC_SHA2_384_192": ("hmac(sha384)", 192, "HMAC-SHA-384-192 [RFC4868]"),
    "HMAC_SHA2_512_256": ("hmac(sha512)", 256, "HMAC-SHA-512-256 [RFC4868]"),
}
#: manifest ESP encryption -> how charon names it in "selected proposal"
CHARON_ENCR = {"AES_CBC": "AES_CBC_{bits}", "3DES_CBC": "3DES_CBC", "AES_CTR": "AES_CTR_{bits}",
               "AES_GCM_16": "AES_GCM_16_{bits}", "CHACHA20_POLY1305": "CHACHA20_POLY1305_{bits}"}

#: suite -> the alignment ESP pads to: the cipher block, or 4 bytes for stream and AEAD modes.
PAD_BLOCK = {"aes128-sha1": 16, "aes128-sha256": 16, "aes256-sha384": 16, "aes256-sha512": 16,
             "3des-sha1": 8, "aes128ctr-sha1": 4, "aes128gcm16": 4, "chacha20poly1305": 4}

#: Share of ESP packets that must decrypt for the logged keys to count as the real ones.
MIN_DECRYPTED = 0.99

SA_HEADER = re.compile(r"^(?:Updated |Deleted )?src (\S+) dst (\S+)$")


def parse_xfrm(text: str) -> dict[str, dict]:
    """ESP SAs by SPI from `ip xfrm state` or `ip xfrm monitor SA` output."""
    sas: dict[str, dict] = {}
    current: dict | None = None
    for line in text.splitlines():
        if m := SA_HEADER.match(line):
            current = {"src": m[1], "dst": m[2]}
            continue
        if current is None:
            continue
        words = line.split()
        if words[:2] == ["proto", "esp"]:
            current.update(spi=words[3][2:].lower(), mode=words[words.index("mode") + 1])
            sas[current["spi"]] = current
        elif words and words[0] in ("enc", "auth-trunc", "aead"):
            current[words[0]] = words[1:]
        elif not line.startswith("\t"):
            current = None
    return sas


def check_run(run_dir: Path) -> dict:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    truth = manifest["truth"]
    problems: list[str] = []

    # 1. charon's view of the negotiation.
    log = "".join((run_dir / gw / "charon.log").read_text(encoding="utf-8", errors="replace")
                  for gw in ("gw-a", "gw-b"))
    esp_selected = re.findall(r"selected proposal: ESP:(\S+)", log)
    want_encr = CHARON_ENCR[truth["esp_encr"]].format(bits=truth["esp_key_bits"])
    want_integ = truth["esp_integ"]
    for proposal in esp_selected:
        parts = proposal.split("/")
        if parts[0] != want_encr or (want_integ and want_integ not in parts):
            problems.append(f"charon selected ESP:{proposal}, manifest says {want_encr}/{want_integ}")
    if not esp_selected:
        problems.append("charon logged no selected ESP proposal")
    _, group_name = PFS_GROUPS[manifest["params"]["pfs"]]
    rekeys = [p for p in esp_selected if any(g and g in p for _, g in PFS_GROUPS.values())]
    if group_name is None and rekeys:
        problems.append(f"manifest says no PFS but charon negotiated {rekeys[0]}")
    if group_name and truth["child_rekey_s"] and not any(group_name in p for p in esp_selected):
        problems.append(f"manifest says PFS {group_name} but no rekey negotiated it")

    # 2. the kernel's SAs.
    sas: dict[str, dict] = {}
    for gw in ("gw-a", "gw-b"):
        for name in ("xfrm-monitor.log", "xfrm-state.txt"):
            path = run_dir / gw / name
            if path.exists():
                sas.update(parse_xfrm(path.read_text(encoding="utf-8", errors="replace")))
    xfrm_encr, salt, ws_encr = XFRM_ENCR[truth["esp_encr"]]
    for spi, sa in sas.items():
        if sa["mode"] != truth["mode"]:
            problems.append(f"SA {spi}: kernel mode {sa['mode']}, manifest {truth['mode']}")
        enc = sa.get("aead") or sa.get("enc")
        if not enc or enc[0] != xfrm_encr:
            problems.append(f"SA {spi}: kernel cipher {enc and enc[0]}, manifest {xfrm_encr}")
            continue
        key_bits = (len(enc[1]) - 2) * 4 - salt * 8
        if key_bits != truth["esp_key_bits"]:
            problems.append(f"SA {spi}: kernel key {key_bits} bits, manifest {truth['esp_key_bits']}")
        if want_integ and sa.get("auth-trunc", [None])[0] != XFRM_INTEG[want_integ][0]:
            problems.append(f"SA {spi}: kernel integrity {sa.get('auth-trunc')}, manifest {want_integ}")
    if not sas:
        problems.append("no ESP SAs found in the xfrm logs")

    # 3. decrypt the capture with those keys.
    decrypted = esp_total = None
    pads: Counter[int] = Counter()
    if ws_encr and sas:
        decrypted, esp_total, pads = decrypt_counts(run_dir, sas, ws_encr, want_integ)
        # Not "> 0": a wrong key still yields ~1% of packets whose garbage parses as
        # ICMP or TCP. Measured on the smoke run: right key 100%, wrong key 0.8%.
        if not esp_total or decrypted / esp_total < MIN_DECRYPTED:
            problems.append(f"tshark decrypted only {decrypted} of {esp_total} ESP packets "
                            "with the logged keys")

    result = {"run_id": manifest["run_id"], "suite": manifest["params"]["suite"],
              "ok": not problems, "problems": problems,
              "esp_sas": len(sas), "esp_proposals_selected": esp_selected,
              "esp_packets": esp_total, "esp_decrypted": decrypted,
              "pad_len_hist": {str(k): v for k, v in sorted(pads.items())}}
    (run_dir / "verify.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def decrypt_counts(run_dir: Path, sas: dict, ws_encr: str,
                   integ: str | None) -> tuple[int, int, Counter[int]]:
    """(ESP packets tshark decrypted to an inner packet, all ESP packets,
    histogram of the decrypted ESP Pad Length fields)."""
    ws_dir = run_dir / "wireshark"
    ws_dir.mkdir(exist_ok=True)
    ws_auth = XFRM_INTEG[integ][2] if integ else "NULL"
    rows = []
    for sa in sas.values():
        proto = "IPv6" if ":" in sa["src"] else "IPv4"
        enc_key = (sa.get("aead") or sa["enc"])[1]
        auth_key = sa["auth-trunc"][1] if integ else ""
        rows.append(f'"{proto}","{sa["src"]}","{sa["dst"]}","0x{sa["spi"]}",'
                    f'"{ws_encr}","{enc_key}","{ws_auth}","{auth_key}"')
    (ws_dir / "esp_sa").write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
    (ws_dir / "preferences").write_text("esp.enable_encryption_decode: TRUE\n", encoding="utf-8",
                                        newline="\n")
    out = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{run_dir.as_posix()}:/run", "-e",
         "WIRESHARK_CONFIG_DIR=/run/wireshark", "--entrypoint", "sh", IMAGE, "-c",
         "tshark -r /run/capture.pcap -Y esp -T fields -e frame.number | wc -l; "
         # ipv6.fraghdr: large pings in an IPv6 tunnel are fragmented before encryption.
         "tshark -r /run/capture.pcap -Y 'esp && (icmp || icmpv6 || tcp || udp.port != 4500 "
         "|| ipv6.fraghdr)' -T fields -e esp.pad_len"],
        capture_output=True, text=True, timeout=300, check=True,
    )
    total, *pad_lines = out.stdout.split()
    return len(pad_lines), int(total), Counter(int(p) for p in pad_lines)


def padding_audit(results: list[dict]) -> dict[str, dict]:
    """Pad Length distribution per suite, and whether padding was minimal (R13).

    Minimal padding is the unique pad that aligns to the block, so it is always
    smaller than the block; any Pad Length >= block size is extra padding.
    """
    audit: dict[str, dict] = {}
    for r in results:
        if not r.get("pad_len_hist"):
            continue
        a = audit.setdefault(r["suite"], {"block_bytes": PAD_BLOCK[r["suite"]], "runs": 0,
                                          "pad_len_hist": Counter()})
        a["runs"] += 1
        a["pad_len_hist"].update({int(k): v for k, v in r["pad_len_hist"].items()})
    for a in audit.values():
        a["max_pad_len"] = max(a["pad_len_hist"])
        a["minimal"] = a["max_pad_len"] < a["block_bytes"]
        a["pad_len_hist"] = {str(k): v for k, v in sorted(a["pad_len_hist"].items())}
    return audit


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_ids", nargs="*")
    ap.add_argument("--out", type=Path, default=ROOT / "eval" / "results" / "truth_mismatches.json")
    args = ap.parse_args()

    run_ids = args.run_ids or [
        r["run_id"] for r in map(json.loads, MANIFEST.read_text(encoding="utf-8").splitlines())
        if r.get("status") == "ok"]
    results = [check_run(RUNS_DIR / rid) for rid in dict.fromkeys(run_ids)]
    for r in results:
        dec = f", decrypted {r['esp_decrypted']}/{r['esp_packets']} ESP" if r["esp_packets"] else ""
        print(f"{'ok  ' if r['ok'] else 'FAIL'} {r['run_id']}: {r['esp_sas']} SAs{dec}")
        for p in r["problems"]:
            print(f"       {p}")

    mismatches = [r for r in results if not r["ok"]]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(mismatches, indent=2) + "\n", encoding="utf-8")

    audit = padding_audit(results)
    (args.out.parent / "padding_audit.json").write_text(json.dumps(audit, indent=2) + "\n",
                                                         encoding="utf-8")
    for suite, a in audit.items():
        if not a["minimal"]:
            print(f"WARNING {suite}: pad lengths up to {a['max_pad_len']} on a {a['block_bytes']}-byte "
                  "block, beyond minimal padding; the residue inference assumes minimal (R13)")
    print(f"{len(results) - len(mismatches)}/{len(results)} runs verified")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
