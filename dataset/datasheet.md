# Datasheet: ipsec-analyzer testbed dataset v1

PLAN.md phase 3. This describes how the dataset was made, what each label means, what it cannot support, and how to regenerate it. Whether the dataset is released publicly is still open (decision D6).

## Motivation

The dataset measures how well the analyzer recovers IPsec configuration from captured traffic: the cleartext IKE fields, and the ESP properties hidden by encryption (cipher family, ICV size, mode, PFS on rekey). Each capture comes with labels taken from the configuration that produced it, checked independently three ways.

## Composition

| Corpus | Varies | Runs designed | Runs available |
|---|---|---|---|
| `cipher` | 8 ESP suites x tunnel/transport x IPv4/IPv6 x 3 repeats, no PFS, 120 s | 96 | 84 (ChaCha20 unavailable) |
| `pfs` | none/MODP-2048/ECP-256/Curve25519 x 3 suites x 3 repeats, child rekey every 60 s, 150 s | 36 | 24 (ChaCha20 unavailable) |
| `weak_ike` | IKE group MODP-1024/MODP-1536 x 3 repeats, 30 s | 6 | 6 |

Final counts, after verification, are in `dataset/manifest.jsonl` and `eval/results/truth_mismatches.json`.

Each run directory `dataset/runs/<run_id>/` holds:

| File | Content |
|---|---|
| `capture.pcap` | Every frame on the WAN bridge between the gateways: IKE (UDP 500/4500) and ESP |
| `manifest.json` | Parameters, ground truth, seed, timings, status, tcpdump drop count |
| `gw-a/`, `gw-b/` | Rendered `swanctl.conf`, `charon.log`, `xfrm-monitor.log` and `xfrm-state.txt` (ESP keys), `sas.txt` |
| `wireshark/esp_sa` | The logged keys in Wireshark's format, to decrypt the capture |
| `verify.json` | The three-way label check and the ESP Pad Length histogram |

## Labels

All labels are in `manifest.json` under `truth`, written by `testbed/run_matrix.py` from the same parameter set that rendered both gateways' configurations.

| Label | Meaning |
|---|---|
| `esp_encr`, `esp_key_bits` | ESP cipher and key size, for example `AES_CBC`/128 or `AES_GCM_16`/128 |
| `esp_integ`, `icv_bytes` | ESP integrity algorithm and ICV length. `esp_integ` is null for AEAD suites. |
| `mode` | `tunnel` (client-to-client traffic) or `transport` (gateway-to-gateway traffic) |
| `pfs_group` | IANA group used on child SA rekeys, or null for no PFS |
| `ip_version`, `auth`, `ike_proposal`, `child_rekey_s` | As configured |

**Verification.** `testbed/verify_truth.py` compares every label with three independent witnesses:
1. charon's "selected proposal" log lines;
2. the kernel's installed SAs (algorithm, key size, mode);
3. tshark decrypting the capture with the logged keys. At least 99% of ESP packets must decrypt; a wrong key decrypts about 1% by chance.

A run that fails any check is excluded from evaluation.

## Collection process

Hardware and software: Windows 11 with Docker Desktop on WSL2 (kernel 6.18.58.1), Alpine 3.20, strongSwan 5.9.13, Linux kernel IPsec (XFRM).

Topology: client-a, gw-a, gw-b, client-b on three Docker bridges, dual-stack. The capture runs on the host side of the WAN bridge, with GSO, GRO and TSO off, so captured lengths are on-wire lengths.

Traffic per run: 200 pings with payload sizes drawn uniformly from 0 to 1400 bytes (seeded by the run ID), a 5-second iperf3 TCP burst capped at 10 Mbit/s, then one random-size ping every 0.5 s until the run's duration has passed.

## Known limits

- **One implementation.** Every run is strongSwan on the Linux kernel's ESP code. Libreswan shares that ESP code, so the held-out-implementation result needs a different ESP stack (PLAN.md E5, risk R14).
- **ChaCha20-Poly1305 is missing.** The WSL2 kernel has no transform for it (risk R16).
- **Synthetic traffic.** Pings and iperf3 give a deliberately wide spread of packet lengths. Real application traffic is usually narrower, and the residue inference needs more distinct lengths to answer on it. This dataset tests the method under favourable length spread; it does not measure coverage on real traffic.
- **No NAT, no fragmentation of ESP, no packet loss.** Those robustness cases are phase 8.
- **Certificate authentication and IKEv1** are not in v1. Every run uses a pre-shared key and IKEv2.
- **Ping-heavy.** Large pings in IPv6 tunnels are fragmented before encryption, so those runs include ESP packets that carry inner IPv6 fragments.
- **Padding.** Every suite pads minimally (`eval/results/padding_audit.json`), so the residue assumption holds here. Other implementations may differ.

## Splits

`eval/split.py` derives the splits from `testbed/matrix.yaml` before any result exists: repeat 3 of every configuration is test, and about one configuration in five (chosen by SHA-256 of its name) is held out entirely. Thresholds may be tuned only on validation runs.

## Regenerating

```sh
sh scripts/testbed-bootstrap.sh
docker build -t ipsec-analyzer/strongswan:5.9 -f testbed/Dockerfile.strongswan testbed
python testbed/run_matrix.py cipher        # and pfs, weak_ike
python testbed/verify_truth.py
```

A run is reproducible from its manifest entry. The configuration is rendered from the stored parameters and the traffic sizes come from the stored seed. Keys, SPIs and timing differ on every run by design.

Captures and keys stay out of git (PLAN.md section 9). Checksums go in `dataset/MANIFEST.sha256` when v1 is frozen.
