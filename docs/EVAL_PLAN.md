# Evaluation Plan: IPsec VPN Analyzer (for Claude Code)

> **Superseded.** Merged into [PLAN.md](../PLAN.md) on 2026-11-17. Kept unchanged below as the historical record.

This file tells Claude Code how to build an evaluation harness on top of the existing IPsec analyzer and produce the results for Table V of the paper "Observed, Inferred, or Unknown: Evidence-Graded Security Assessment of IPsec VPNs from Network Traffic".

Work through the phases in order. Finish each phase's acceptance checks, then stop and report to the human before starting the next phase.

---

## 1. Context

**What the analyzer already does** (per the paper, Section X):

- Ingests pcap/pcapng (IPv4 and IPv6), separates IKE (UDP 500/4500) from ESP/AH (IP protocols 50/51), and handles the non-ESP marker on UDP 4500.
- Parses IKEv2 deterministically (IKE_SA_INIT proposals, selected proposal, KE group, notifications, Vendor IDs).
- Infers ESP cipher family and ICV size from ESP length residues modulo 16.
- Runs a YAML rule engine, then scoring, coverage, threat matrix and HTML reports.
- Labels every attribute in a JSON session record as Observed, Inferred, Assisted or Unknown, with confidence and source.

**Not built yet:** IKEv1 parsing, the traffic classifier, calibration, the dashboard, PDF export and the active prober. Do not build these in this plan unless a phase says so.

**Table V targets.** These were fixed before any data was collected. Never change them after seeing results.

| Row | Measure | Target |
| --- | --- | --- |
| IKE parser | Exact match with ground truth (field level) | 100% |
| ESP cipher family, ICV | Accuracy per SA, held-out runs | >= 95% |
| ESP mode | Accuracy, held-out configurations | >= 90% |
| PFS on rekey | Accuracy on runs with a rekey | >= 90% |
| Traffic type | Macro F1, held-out runs | >= 0.85 (future work) |
| Generalization | Macro F1 drop, held-out implementation | <= 10 points (future work) |
| Calibration | ECE per inferred attribute | <= 0.05 (future work) |
| Scoring | Same output on repeated analysis | Identical |
| Speed | 100 MB capture to both reports | < 2 min |

This plan produces numbers for the IKE parser, ESP cipher family and ICV, ESP mode, PFS, Scoring and Speed rows. The three rows marked "future work" stay out of scope.

---

## 2. Ground rules (read before doing anything)

1. **Never fabricate or hand-edit a result.** Every number in a results file must come from a script run on raw files that stay on disk. If a run fails, record the failure; do not fill the gap.
2. **Report misses honestly.** If a target is not met, report the measured value and investigate. Do not change the target, the split, or the test data to make it pass.
3. **Do not tune on test data.** Any threshold (for example, the minimum number of distinct lengths before the residue rule answers) is set on a validation split and then frozen.
4. **Ground truth comes from the config that created the run**, written to the manifest by the same code that wrote the config. Then it is cross-checked by decrypting the capture with the session keys.
5. **Ask the human before you:** install system packages with sudo, build strongSwan from source, load kernel modules, delete any data, or push to a remote.
6. **Keep the analyzer's behavior unchanged** unless a phase explicitly asks for a fix. If you find a bug, write a failing test, report it, and wait for approval before fixing it.
7. **Git hygiene:** work on a branch named `eval-harness` and commit after each step that passes. Do not commit pcaps, keys or large files: put them under `data/` (git-ignored) and commit a `data/MANIFEST.sha256` of checksums instead.
8. **Lab only.** The testbed runs on an isolated Docker bridge. Never point any tool at an address outside the lab.

---

## 3. Target layout

Adapt the names if the repo already has a convention, and record the choice in `docs/repo_map.md`.

```
eval/
  adapter.py            # turns analyzer output into a normalized prediction record
  oracle_tshark.py      # ground truth for public captures, from tshark
  evaluate.py           # compares predictions with the manifest, writes Table V
  residue_curve.py      # accuracy vs number of distinct lengths (m)
  bench_speed.py        # speed benchmark
  check_determinism.py  # repeated-run comparison
  results/              # JSON + Markdown outputs (committed)
  figures/              # PNG/PDF figures (committed)
testbed/
  docker/               # Dockerfile(s) for gateway and client images
  templates/            # swanctl.conf and strongswan.conf templates (Jinja2)
  matrix.yaml           # the parameter matrix
  run_matrix.py         # orchestrator: one run per parameter set
  verify_truth.py       # decrypts each capture and confirms the manifest
  docker-compose.yml
data/                   # git-ignored
  public/               # downloaded public captures + SOURCES.md
  runs/<run_id>/        # capture.pcapng, keys/, manifest.json, logs/
  manifest.jsonl        # one line per run
tests/eval/             # unit tests for the harness itself
docs/
  repo_map.md
  RESULTS_FOR_PAPER.md
```

---

## Phase 0: Understand the repo (no code changes)

**Do:**

1. Find the analyzer's entry point (CLI or function), its inputs, and where it writes the JSON session record and reports.
2. Document the JSON schema: attribute names for IKE version, proposals, selected suite, KE group, ESP cipher family, ICV size, mode, PFS, the evidence level and confidence fields, the score and the coverage.
3. Find the residue inference function and check whether it can be called directly with a list of ESP lengths. If it can, note its signature.
4. List the existing tests and run them. Record which pass.
5. Note the language, the dependency manager, and the OS this machine runs.

**Write:** `docs/repo_map.md`, covering each of the points above with file paths.

**Acceptance:** the human confirms the map is right. Ask them about anything you could not find.

---

## Phase 1: Quick wins (no testbed needed)

### 1a. Unit tests from the paper's math

The paper's tables are known to be correct, so they make good test fixtures for the existing code. Add tests in `tests/eval/` that check:

- **Table II residues.** Generate lengths from L = 8 + v + k*beta + t for k = 0..40 and confirm that the residue sets mod 16 are:

  | Suite | v | beta | t | Residues |
  | --- | --- | --- | --- | --- |
  | AES-CBC + HMAC-SHA1-96 | 16 | 16 | 12 | {4} |
  | AES-CBC + HMAC-SHA-256-128 | 16 | 16 | 16 | {8} |
  | AES-CBC + HMAC-SHA-384-192 | 16 | 16 | 24 | {0} |
  | AES-CBC + HMAC-SHA-512-256 | 16 | 16 | 32 | {8} |
  | 3DES-CBC + HMAC-SHA1-96 | 8 | 8 | 12 | {4, 12} |
  | AES-CTR + HMAC-SHA1-96 | 8 | 4 | 12 | {0, 4, 8, 12} |
  | AES-GCM-16 | 8 | 4 | 16 | {0, 4, 8, 12} |
  | ChaCha20-Poly1305 | 8 | 4 | 16 | {0, 4, 8, 12} |
  | AES-CBC, no integrity (t = 0) | 16 | 16 | 0 | {8} (must stay ambiguous with 16-byte ICVs) |

- **The analyzer's residue function** returns Unknown when there are too few distinct lengths, and never reports AES-CBC versus 3DES with fewer than 18 distinct lengths at the paper's 10^-5 level.
- **Table III KE payload sizes:** group 2 = 136, 5 = 200, 14 = 264, 19 = 72, 20 = 104, 31 = 40 bytes.
- **Mode example:** AES-CBC + HMAC-SHA-256-128 over IPv4, bare TCP ACK = 72 bytes (transport) and 88 bytes (tunnel); with TCP timestamps, 88 and 104.

If the analyzer disagrees with any of these, stop and report. Do not change the expected values.

### 1b. Scoring determinism

`eval/check_determinism.py`: run the analyzer 10 times on the same capture. Compare the session record and the score after removing fields that are legitimately time-dependent (generation timestamps). List the removed fields in the output.

**Output:** `eval/results/determinism.json`, containing pass/fail and a hash per run.

### 1c. Speed

`eval/bench_speed.py`: build a capture of about 100 MB by merging the existing captures with `mergecap`, or testbed captures once Phase 2 exists. Time the full run to both reports 5 times and report the median and the range. Record the CPU, RAM and OS.

**Output:** `eval/results/speed.json`.

### 1d. IKE parser on public captures

1. Download, with the human's approval:
   - the IKEv2 test captures from the Wireshark source repository, `test/captures/ikev2-decrypt-*`, which come with keys;
   - the IKEv1 and IPsec traces used by the Zeek IPsec analyzer tests (github.com/corelight/zeek-spicy-ipsec, or zeek/spicy-analyzers).

   Record the URL, commit and license of each file in `data/public/SOURCES.md`.
2. `eval/oracle_tshark.py`: IKE_SA_INIT is cleartext, so tshark decodes the same fields the parser reads. Find the exact field names with `tshark -G fields | grep -i isakmp` rather than guessing them. Extract per message: exchange type, initiator and responder SPI, every proposal with its transforms and key lengths, the KE group, notify types and Vendor IDs.
3. Compare the analyzer's Observed attributes with the oracle field by field.

**Report:**

- field-level exact-match percentage, overall and per field type;
- a list of every mismatch with the file and frame number;
- IKEv1 captures as "not supported (expected)", not as failures, because IKEv1 parsing is not implemented yet.

**Output:** `eval/results/parser_public.json` and `parser_public_mismatches.md`.

**Phase 1 acceptance:** all four outputs exist, were produced by scripts, and pass a re-run. Stop and report.

---

## Phase 2: Two-gateway strongSwan testbed

**Requirement:** a Linux host with Docker (Ubuntu 22.04 or 24.04 works; a VM is fine). Containers share the host kernel's IPsec (XFRM) stack, so the host needs these modules loaded: `esp4`, `esp6`, `xfrm_user`, `xfrm4_tunnel`, `af_key`, plus `ah4`/`ah6` if AH is tested. Ask the human before running `modprobe`. Docker Desktop on Windows or macOS may not support this, so use a Linux VM.

### 2a. Images and topology

- **Gateway image:** Ubuntu with strongSwan, using swanctl/vici, and these plugins: openssl, gcm, ctr, chapoly, curve25519 and save-keys. Confirm availability with `swanctl --list-algs` and write the list to `testbed/available_algs.txt`.
- **Getting session keys:**
  - If the distro build lacks save-keys, ask the human: either build strongSwan from source with `--enable-save-keys`, or use the fallback.
  - Fallback: dump `ip xfrm state` inside each gateway after the SA comes up. It shows the ESP keys and algorithms, which is enough to decrypt ESP in Wireshark.
- **Containers:** client-a, gw-a, gw-b, client-b.
- **Networks:** gw-a and gw-b share a "wan" bridge; each client sits on its gateway's LAN.
- **Capture:** run tcpdump on the host side of the wan bridge, not inside a gateway. First disable offloads on that interface with `ethtool -K <iface> gso off gro off tso off`, so captured lengths equal on-wire lengths.

### 2b. Parameter matrix (`testbed/matrix.yaml`)

| Factor | Values |
| --- | --- |
| IKE version | IKEv2 (IKEv1 Main and Aggressive later, parser coverage only) |
| ESP suite | aes128-sha1, aes128-sha256, aes256-sha384, aes256-sha512, 3des-sha1, aes128ctr-sha1, aes128gcm16, chacha20poly1305 |
| Mode | tunnel, transport (transport = gateway-to-gateway traffic, no clients) |
| PFS group on child rekey | none, modp2048 (14), ecp256 (19), curve25519 (31) |
| IKE DH group | modp2048 by default; modp1024 and modp1536 in a small "weak" set if the build allows them |
| IP version | IPv4, IPv6 |
| Authentication | psk, pubkey (certificates) |
| Repeats | 3 |

Do not run the full product. Use:

- **Cipher corpus:** 8 suites x 2 modes x 2 IP versions x 3 repeats = 96 runs, PSK, no PFS, about 2 minutes each.
- **PFS corpus:** 4 PFS settings x 3 suites (aes128gcm16, aes128-sha256, chacha20poly1305) x 3 repeats = 36 runs, rekey_time = 60s, about 4 minutes each.
- **Auth corpus:** a small set with pubkey authentication, to show the parser handles both methods.

Any suite or group that the build cannot offer is skipped and listed in `eval/results/skipped.json` with the reason.

The suites and auth methods actually run are the values the paper still needs (Section VIII placeholders). Write them to `docs/RESULTS_FOR_PAPER.md`.

### 2c. Orchestrator (`testbed/run_matrix.py`)

For each parameter set:

1. Generate a `run_id`. Render the swanctl.conf and strongswan.conf files from the templates using only this parameter set.
2. Write `data/runs/<run_id>/manifest.json` from the same parameter set. It is the ground truth: suite, encryption algorithm and key length, integrity algorithm, ICV bytes, mode, PFS group, IP version, auth method, rekey_time.
3. Start the containers, initiate the child SA, and wait until `swanctl --list-sas` shows it INSTALLED (timeout 60s, otherwise mark the run failed).
4. Start the capture, then generate traffic with varied packet sizes:
   - ping with random payload sizes between 0 and 1400 bytes;
   - a few HTTP downloads between the clients;
   - optional iperf3 bursts.
5. For PFS runs, wait for at least two child rekeys.
6. Stop the capture and collect the session keys (save-keys files or `ip xfrm state` dumps), charon logs and container logs.
7. Tear down, and append the manifest line to `data/manifest.jsonl`.
8. Make the orchestrator resumable: skip run_ids that already completed.

### 2d. Verify ground truth (`testbed/verify_truth.py`)

For every run:

- Decrypt with the saved keys using tshark and confirm the negotiated suite, mode and PFS match the manifest. Any mismatch excludes the run from scoring and is listed in `eval/results/truth_mismatches.json`.
- **Padding audit:** read the ESP Pad Length from the decrypted trailers and report its distribution per suite. If any suite pads beyond the minimum, flag it prominently, because the residue analysis assumes minimal padding.

**Output:** `eval/results/padding_audit.json`.

**Phase 2 acceptance:** at least one complete run per suite, verified by decryption. Stop and report the available algorithms, skipped items and the padding audit before running the full corpus.

---

## Phase 3: Evaluation

### 3a. Adapter (`eval/adapter.py`)

Run the analyzer on each run's capture and normalize its output to:

`{run_id, sa_spi, cipher_family, icv_bytes, mode, pfs, pfs_group, evidence, confidence}`

Unknown is a valid prediction and must be preserved.

### 3b. Metrics (`eval/evaluate.py`)

- **Splits:** split by run, never by packet or window. Hold out 1 of the 3 repeats of every configuration as the test set; use the other repeats only to set any threshold that needs tuning. Save the split to `eval/results/split.json` before computing any metric.
- **ESP cipher family and ICV:** per-SA accuracy, counting Unknown as wrong for accuracy. Also report coverage (the share not Unknown) and accuracy on answered SAs. Include a confusion matrix over the suites.
- **ESP mode:** per-SA accuracy and confusion, with the same Unknown handling.
- **PFS:** per-rekey-event accuracy. Report the observed size increase of CREATE_CHILD_SA next to the predicted 8 + |g| bytes, request and response separately, per group.
- **IKE parser (testbed):** field-level exact match of Observed attributes against the manifest.
- **Do not train any model** in this phase.

### 3c. Residue curve (`eval/residue_curve.py`)

For each test SA, randomly sample m distinct ESP lengths, for m = 1..30 with 200 draws each. Call the analyzer's own residue function on each sample and plot accuracy and Unknown rate against m. Mark m = 10 and m = 18 on the plot.

This tests the paper's equation (2) and the 18-length bound for 3DES versus AES-CBC.

If the function cannot be called directly, report that and ask the human. Do not reimplement it for the curve.

**Output:** `eval/figures/residue_vs_m.pdf`.

### 3d. Outputs

- `eval/results/table_v.json` and `table_v.md`, with columns Row, Measure, Target, Result, N (number of SAs or events), Notes.
- `eval/results/confusion_cipher.csv` and `confusion_mode.csv`.
- `eval/results/pfs_sizes.csv`.

**Phase 3 acceptance:**

- Every number in `table_v.md` traces to a script and to raw runs.
- Re-running `evaluate.py` reproduces the same numbers.
- Stop and report the results, including any row below its target.

---

## Phase 4: Paper integration (text only, no new experiments)

Write `docs/RESULTS_FOR_PAPER.md` containing:

1. **Table V** with results filled in for the measured rows. The rows for traffic type, generalization and calibration are relabeled "Future work".
2. A short **Results** paragraph per row, giving the number, N, and one sentence on any miss.
3. **Values for the paper's placeholders:**
   - the list of ESP suites actually tested;
   - the two authentication methods;
   - the observed padding behavior, which confirms or refutes the minimal-padding assumption.
4. The **residue figure** with a one-sentence caption.
5. A **list of claims the results contradict**, if any, so the authors can revise the text.

Do not edit the paper's .docx yourself unless the human asks.

---

## Phase 5: Later work (only when the human asks)

- **Held-out IKE daemon:** a Libreswan gateway pair, same matrix subset. Note that Libreswan and strongSwan both use the Linux kernel's XFRM ESP code, so this tests IKE behavior, not ESP framing.
- **Held-out ESP stack:** a FreeBSD-based gateway (pfSense or OPNsense) or OpenBSD iked in a VM, or strongSwan's user-space libipsec backend. This is the real test of whether the residue and mode inference generalize.
- **IKEv1 parsing,** using the Main and Aggressive Mode captures from Phase 1 as tests.
- **Traffic corpus and classifier,** then calibration (per-attribute ECE, reliability diagrams, risk-coverage curve).
- **Edge cases:** RFC 7383 fragmentation, RFC 8750 implicit-IV suites, IP-TFS (RFC 9347).

---

## Kickoff message for Claude Code

> Read docs/EVAL_PLAN.md fully. Follow its ground rules. Do Phase 0 now and stop after writing docs/repo_map.md. Ask me about anything you could not find.
