# PLAN

**Project:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework (SIH26160, NTRO)
**Team:** Chaitanya Sawant, Vansh Jangra, Aditya Sonawane. **Guide:** Dr. Chaya Nayak
**Last updated:** 2026-11-17
**Companion documents:** [VISION.md](VISION.md) (what is being built and why), [docs/decisions.md](docs/decisions.md) (what was decided and why)

This is the single plan for the project. It merges two earlier plans, both kept for the record:

- [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md): the original build plan (testbed, analyzer, product, schedule).
- [docs/EVAL_PLAN.md](docs/EVAL_PLAN.md): the evaluation harness that produces Table V for the paper *Observed, Inferred, or Unknown: Evidence-Graded Security Assessment of IPsec VPNs from Network Traffic*.

**Numbering is deliberate.** Sections 1 to 15 and phases 0 to 8 keep the numbers of the original build plan, because the code cites them ("PLAN.md section 7", "PLAN.md phase 4"). The evaluation harness lives in section 7 as steps E0 to E5. Do not renumber.

---

## 1. Where things stand (2026-11-17)

Status is taken from the repository, not from memory. Week 7 of 16.

| Area | State | Evidence |
|---|---|---|
| Foundations: repo, licence, README, CI, schema | Done | `.github/workflows/ci.yml`, `dataset/schemas/session_record.schema.json` |
| Decisions D1 to D8 | Implemented as provisional, awaiting guide sign-off | `docs/decisions.md` |
| Risk R1, kernel IPsec in containers | Retired. Works on WSL2 after a one-time module load. | `scripts/testbed-bootstrap.sh` |
| Testbed | Partial. Two peers on one bridge, two hand-written configs (healthy and weak), IPv4 only. No orchestrator, manifest, key export or traffic generators. | `testbed/compose/`, `testbed/configs/` |
| Vertical slice, milestone M1 | Done 2026-10-06 | commit `9c5a4b8`, `tests/test_golden.py` |
| IKEv2 parser, session builder, ingest | Done for IKEv2 | `analyzer/ike/`, `analyzer/sessions/`, `analyzer/ingest/` |
| ESP residue inference | Done, rule-based, abstains on uniform traffic | `analyzer/inference/esp_structure.py` |
| Rule catalogue | 16 of 20 rules. Missing AH-001, SA-001, META-002, ACT-001. | `analyzer/rules/catalogue/baseline.yaml` |
| Score, coverage, risk, threat matrix | Done | `analyzer/scoring/` |
| Reports | Executive and technical HTML done. PDF not started. | `reports/` |
| Dataset v1, milestone M2 (due 15 Nov) | **Missed.** Not started. | |
| IKEv1 parser, mode and PFS inference, traffic classifier, calibration | Not started | |
| Dashboard, active prober | Not started (`analyzer/probe/` is an empty package) | |
| Evaluation harness (section 7) | Not started. No `eval/` directory. | |

### 1.1 Where the two source plans disagreed, and what this plan does

| Topic | Build plan said | Eval plan said | This plan |
|---|---|---|---|
| Data directory | `dataset/runs/`, `dataset/captures/` (git-ignored) | `data/` (git-ignored) | Keep `dataset/`. Its ignore rules already exist. |
| Manifest | Goes in git | `data/manifest.jsonl`, ignored, with checksums committed | `dataset/manifest.jsonl` and `dataset/MANIFEST.sha256` both committed. Run directories stay ignored. |
| Evaluation results | `eval/results/` is in `.gitignore` | `eval/results/` is committed | Commit them: the paper's numbers must be traceable. Remove the ignore line when the harness lands (D9). |
| Residue threshold | Code answers from 4 distinct lengths and 20 packets | Paper: never separate AES-CBC from 3DES with fewer than 18 distinct lengths | Open conflict. E1 tests it, the guide decides (D10). Do not change either side before the test result. |
| Testbed host | WSL2 works (R1 retired) | Docker Desktop may not work, use a Linux VM | WSL2 stays. Offload settings and module loads go through the same privileged `nsenter` route as the bootstrap. |
| Session keys | strongSwan save-keys. Alpine lacks it. | save-keys, or dump `ip xfrm state` as a fallback | Use the `ip xfrm state` dump now. Move to save-keys only if a source build is approved. |
| Dataset design | All-pairs handshake corpus plus traffic corpus | Cipher corpus (96 runs), PFS corpus (36 runs), auth corpus | The eval corpora are the first part of dataset v1. The handshake and traffic corpora extend it. |
| Testbed layout | `testbed/compose/`, `testbed/configs/` exist | `testbed/docker/`, `templates/`, `matrix.yaml` | Keep the existing directories and add `templates/`, `matrix.yaml`, `run_matrix.py`, `verify_truth.py`. |
| Splits | Run, configuration and implementation splits | Hold out one of three repeats | Define every split in `eval/results/split.json` before any metric is computed. With no trained model, the splits only guard threshold tuning. |

## 2. Key dates

Fill these in first. The whole schedule depends on them.

| Event | Date | Status |
|---|---|---|
| PBL guide approval of draft report | | To confirm with Dr. Nayak |
| PBL mid-term review | | To confirm |
| PBL final review and submission | | To confirm |
| SIH 2026 idea submission | Reported as 30 September 2026 | Confirm with the college SPOC whether the team was nominated |
| SIH 2026 shortlist announcement | Reported as October 2026 | Confirm on the official portal |
| SIH 2026 grand finale | Reported as December 2026 | Confirm on the official portal. If shortlisted, M3 is the version to take. |
| Paper submission deadline and venue | | To decide (D11) |
| Semester exams and holidays | | Block these out of section 4 |

Team composition to check: SIH has required six students per team with at least one woman, and the documents list three. Confirm the 2026 rule and the roster with the SPOC.

## 3. Architecture

```
                         +-------------------------------+
                         |  TESTBED (lab only)           |
                         |  orchestrator -> VPN peers    |
                         |  -> traffic generators        |
                         |  -> capture + manifest + keys |
                         +---------------+---------------+
                                         | pcapng + labels
                                         v
  pcap / live iface  -->  [1 INGEST] --> [2 SESSION BUILDER]
                                               |
                         +---------------------+---------------------+
                         v                                           v
                [3 IKE PARSER]                              [4 ESP / AH ANALYZER]
                deterministic (Observed)                    deterministic statistics (Observed)
                         |                                           v
                         |                                  [5 INFERENCE ENGINE]
                         |                                  cipher family, mode, PFS,
                         |                                  traffic type, calibration (Inferred)
  authorised target -->  [6 ACTIVE PROBER] ---+                      |
                         (Observed)           v                      v
                       +----------------------------------------------+
                       |  SESSION RECORD (one JSON document per VPN)  |
                       |  every attribute: value, evidence, confidence|
                       +----------------------+-----------------------+
                                              v
                                     [7 RULE ENGINE] -> findings
                                              v
                                     [8 SCORING + THREAT MATRIX]
                                              v
                            [9 DASHBOARD]  [10 REPORT GENERATOR]

                       eval/ harness (section 7) sits beside this:
                       session records + manifest -> Table V
```

The session record is the contract between the analysis half and the product half. The dashboard, the report generator and the evaluation adapter read nothing else.

### 3.1 Session record

The authoritative definition is `dataset/schemas/session_record.schema.json`. One record per endpoint pair, not per IKE SA (see `docs/decisions.md`). Every attribute carries a value, an evidence level (Observed, Inferred, Assisted, Unknown), a confidence, and either the source packets or the reason it is unknown. `analyzer/record/attribute.py` enforces this in code.

### 3.2 Technology choices

| Layer | Choice | Status |
|---|---|---|
| Language | Python 3.11 or newer | In use |
| VPN endpoints | strongSwan (swanctl) first, Libreswan as the second implementation | strongSwan in use |
| Testbed runtime | Docker Compose on WSL2, with modules loaded by `scripts/testbed-bootstrap.sh` | In use |
| Testbed image | Alpine strongSwan 5.9.13 today. Add an image with the gcm, ctr, chapoly and curve25519 plugins if Alpine lacks any. | Check with `swanctl --list-algs` in E2 |
| Capture | tcpdump on the host side of the WAN bridge, offloads disabled | Planned (E2) |
| Ground-truth keys | `ip xfrm state` dump per run. save-keys only after an approved source build. | Planned |
| Parsing | Own parsers, with tshark as the test oracle | In use; oracle planned (E1d) |
| Classical ML | scikit-learn (Random Forest first) | Phase 4 |
| Deep learning | PyTorch 1D CNN, only if it beats the baseline on held-out data | Optional |
| Data | JSON session records, JSONL manifest, Parquet feature tables, SQLite for dashboard history | Records in use |
| Dashboard | Streamlit with Plotly (D4) | Phase 6 |
| Reports | Jinja2 to HTML, then PDF with WeasyPrint | HTML done, PDF pending |
| Tests | pytest with golden captures, `-m "not testbed"` in CI | In use |

### 3.3 Repository layout

What exists, plus what this plan adds (marked `+`).

```
ipsec-analyzer/
  VISION.md  PLAN.md  README.md
  analyzer/       ingest, sessions, ike, esp_ah, inference, record, rules, scoring, probe (empty), cli.py
  reports/        generator and templates
  dataset/
    schemas/      session record schema
  + manifest.jsonl  MANIFEST.sha256  datasheet.md   (committed)
  + runs/<run_id>/  capture.pcapng, keys/, manifest.json, logs/   (ignored)
  + public/         downloaded public captures (ignored) + SOURCES.md (committed)
  testbed/
    compose/  configs/  Dockerfile.strongswan  entrypoint.sh  strongswan-testbed.conf
  + templates/      swanctl.conf and strongswan.conf (Jinja2)
  + matrix.yaml     parameter matrix
  + run_matrix.py   orchestrator, resumable
  + verify_truth.py decrypts each run and checks the manifest
  + eval/
    adapter.py  oracle_tshark.py  evaluate.py  residue_curve.py
    bench_speed.py  check_determinism.py
    results/      JSON and Markdown (committed)
    figures/      PNG and PDF (committed)
  + app/          dashboard
  scripts/        testbed-bootstrap.sh
  tests/          unit tests, golden captures
  + tests/eval/   tests for the harness and the paper's maths
  docs/           decisions.md, BUILD_PLAN.md, EVAL_PLAN.md
  + docs/repo_map.md  docs/RESULTS_FOR_PAPER.md  docs/demo_script.md
```

## 4. Schedule

Sixteen working weeks from 5 October 2026, ending 24 January 2027. The original dates slipped after M1, so the milestones are re-planned from week 7. Confirm the revised dates at the next weekly sync and against the exam dates in section 2.

| Phase | Original weeks | Revised | Outcome |
|---|---|---|---|
| 0. Foundations | 1 | Done, except dates, owners and doc fixes | Decisions made, repo up, schema agreed |
| 1. Testbed MVP | 1 to 3 | Weeks 7 to 8 | One command: tunnel up, traffic, labelled capture, keys, manifest row |
| 2. Vertical slice | 2 to 4 | Done (M1) | Capture in, scored HTML report out, IKEv2 |
| 3. Dataset at scale | 4 to 6 | Weeks 8 to 10 | Dataset v1: eval corpora first, then handshake and traffic corpora |
| 4. ESP inference and classifier | 5 to 8 | Weeks 8 to 12 | Mode, PFS, IKEv1, then traffic type with measured accuracy |
| 5. Scoring v2, threat matrix, calibration | 7 to 9 | Weeks 9 to 11 | Full rule catalogue, calibrated confidence |
| 6. Dashboard and reports | 7 to 10 | Weeks 8 to 12 | Dashboard, executive PDF, technical PDF |
| 7. Active probing | 10 to 12 | Weeks 12 to 14 | Proposal enumeration merged into the session record |
| 8. Evaluation, hardening, documentation, video | 12 to 16 | Weeks 13 to 16 | Final numbers, paper results, documentation, video |
| E. Evaluation harness (section 7) | Not in original | E0 to E1 week 7, E2 to E3 weeks 8 to 11, E4 week 12 | Table V |

### Milestones

| ID | Original date | Revised date | Demonstrable result | Status |
|---|---|---|---|---|
| M1 | 1 Nov 2026 | | Tool prints the correct configuration and flags weak captures | **Done 6 Oct** |
| ME1 | | 22 Nov 2026 | E1 outputs exist: paper-maths tests, determinism, speed, parser on public captures | |
| M2 | 15 Nov 2026 | 6 Dec 2026 | Dataset v1 (cipher, PFS and auth corpora, verified by decryption). Anyone can regenerate a run from its manifest entry. | Missed, re-planned |
| M3 | 29 Nov 2026 | 13 Dec 2026 | **Demo cut.** Dashboard v0 shows configuration, score, findings and inferred attributes for a capture chosen live. The version for an SIH finale. | |
| ME2 | | 20 Dec 2026 | Table V measured rows filled from the testbed corpora (E3) | |
| M4 | 13 Dec 2026 | 27 Dec 2026 | Passive pipeline feature-complete, both reports as PDF | |
| M5 | 27 Dec 2026 | 10 Jan 2027 | Active probing results appear beside passive results | |
| M6 | 24 Jan 2027 | 24 Jan 2027 | Evaluation complete, `docs/RESULTS_FOR_PAPER.md`, documentation and video delivered | |

**Cut order if time runs short:** live capture, vendor fingerprinting, CNN model, mixed-traffic tunnels, third implementation, traffic classifier (becomes future work, as Table V already allows), active probing beyond proposal enumeration.
**Never cut:** the dataset manifest, ground-truth verification, held-out evaluation, the evidence levels, Table V's measured rows.

## 5. Ownership

One owner per track. Owners review each other's pull requests. Write the names in.

| Track | Owner | Covers |
|---|---|---|
| A. Testbed and data | ________ | Phases 1 and 3, capture, manifest, keys, datasheet, traffic generators, E2 |
| B. Analysis and ML | ________ | Parsers, ESP and AH analyzer, inference, calibration, E1 and E3 |
| C. Product | ________ | Rule catalogue, scoring, threat matrix, dashboard, reports, active probing |
| E. Evaluation and paper | ________ (Claude Code may do the work, gated per step) | Section 7, `docs/RESULTS_FOR_PAPER.md` |

If the team grows to six for SIH, add: a second person on Track B for evaluation, a front-end person on Track C, and one person for active probing, documentation and the demo video.

## 6. Phase detail

`[x]` means done and visible in the repository.

### Phase 0. Foundations

- [ ] Fill in section 2 (key dates) and section 5 (owners)
- [ ] Get D1 to D5 signed off by the guide (implemented as provisional, see `docs/decisions.md`)
- [x] Repository with layout, licence, README, CI running lint and tests
- [x] Session record schema agreed and committed
- [x] Testbed host can do kernel IPsec in containers (R1 retired)
- [ ] Update the report, synopsis and deck per section 13

### Phase 1. Testbed MVP

Topology: client-a, gw-a, gw-b, client-b. The gateways share a WAN bridge, and each client sits on its gateway's LAN. Tunnel mode carries client traffic. Transport mode carries gateway-to-gateway traffic with no clients. `bypass-lan` stays disabled (`docs/decisions.md`).

- [x] Two-peer compose file, IPv4, healthy and weak configs
- [x] Short lifetimes so every run contains a rekey (`rekey_time = 60s` / `45s`)
- [ ] Four-container topology, IPv4 and IPv6
- [ ] Config templates (`testbed/templates/`) that render swanctl.conf and strongswan.conf from one parameter set
- [ ] `swanctl --list-algs` written to `testbed/available_algs.txt`. Anything missing is listed in `eval/results/skipped.json` with the reason.
- [ ] Capture on the host side of the WAN bridge, with `ethtool -K <iface> gso off gro off tso off` so captured lengths equal on-wire lengths
- [ ] Key export per run: `ip xfrm state` dump inside each gateway after the SA installs
- [ ] Orchestrator `testbed/run_matrix.py`: render config, write `dataset/runs/<run_id>/manifest.json` from the same parameter set, start, wait for INSTALLED (60 s timeout, else mark failed), capture, generate traffic, wait for rekeys on PFS runs, collect keys and logs, tear down, append to `dataset/manifest.jsonl`. Resumable: skip completed run IDs.
- [ ] Traffic generators. For the eval corpora: ping with random payloads from 0 to 1400 bytes, HTTP downloads between clients, optional iperf3. For the traffic corpus: web, VoIP, email, messaging, video, ICMP, idle.

**Done when:** one command produces a capture, a key dump and a manifest row, and tshark decrypts the run with those keys.

### Phase 2. Vertical slice. Done (M1).

- [x] Ingest pcap and pcapng, IPv4 and IPv6, UDP 500 and 4500, ESP and AH, non-ESP marker
- [x] Session builder: IKE by SPI pair, ESP and AH by endpoint pair and SPI, child SAs linked to IKE SAs
- [x] IKEv2 parser: IKE_SA_INIT proposals, selected proposal, KE group, notifications, vendor IDs, INVALID_KE_PAYLOAD retry
- [x] First rules, score v1, HTML reports
- [x] Golden captures with expected findings, checked in CI

### Phase 3. Dataset at scale

Build in this order, so the eval numbers arrive first.

**3a. Eval corpora (IKEv2, ESP, PSK unless stated). These are M2.**

| Corpus | Design | Runs |
|---|---|---|
| Cipher | 8 suites (aes128-sha1, aes128-sha256, aes256-sha384, aes256-sha512, 3des-sha1, aes128ctr-sha1, aes128gcm16, chacha20poly1305) x tunnel, transport x IPv4, IPv6 x 3 repeats. No PFS, about 2 min each. | 96 |
| PFS | none, modp2048 (14), ecp256 (19), curve25519 (31) x 3 suites (aes128gcm16, aes128-sha256, chacha20poly1305) x 3 repeats. `rekey_time = 60s`, about 4 min each, at least two child rekeys. | 36 |
| Auth | A small set with certificate authentication, to show the parser handles both methods | a few |
| Weak IKE | modp1024 and modp1536 IKE groups, if the build allows them | a few |

**3b. Handshake corpus** (short runs, one rekey). All-pairs coverage over: IKEv2, IKEv1 Main, IKEv1 Aggressive; ESP, AH; tunnel, transport; the ESP suites above plus DES or MD5 where the build allows; DH groups 2, 5, 14, 19, 31; PFS on or off; IPv4, IPv6; PSK, certificate. If a current build refuses a weak algorithm, keep an older image or craft the handshake with Scapy (R5).

**3c. Traffic corpus** (3 to 5 min runs). A covering subset of suite, mode and IP version, crossed with every traffic class, three repeats each under different netem conditions (delay, jitter, loss).

- [ ] `testbed/matrix.yaml` generating all corpora
- [ ] Estimate run count and wall-clock time before starting. Runs can go in parallel, one network namespace each.
- [ ] Unattended runs with retry and a failure log
- [ ] `testbed/verify_truth.py`: decrypt each run with its keys and confirm suite, mode and PFS match the manifest. Mismatches are excluded and listed in `eval/results/truth_mismatches.json`.
- [ ] Padding audit: ESP Pad Length distribution per suite from decrypted trailers, to `eval/results/padding_audit.json`. Flag any suite that pads beyond the minimum, because the residue analysis assumes minimal padding (R13).
- [ ] Libreswan subset as the held-out implementation
- [ ] `dataset/datasheet.md`: how it was made, what each label means, known limits, how to regenerate
- [ ] Splits by run ID, plus held-out configuration and held-out implementation, written to `eval/results/split.json`
- [ ] Freeze dataset v1 with `dataset/MANIFEST.sha256`

**Done when:** milestone M2, at least for 3a.

### Phase 4. ESP inference and traffic classifier

- [x] ESP length-residue analysis: block size and ICV candidates from residues modulo 16, abstaining on uniform traffic
- [x] ESP flow statistics per SA (`analyzer/esp_ah/`)
- [ ] Settle the residue threshold against the paper's 18-length bound (D10, from E1a)
- [ ] Mode inference from minimum and typical overhead and from how many flows share an SA. Check: AES-CBC with HMAC-SHA-256-128 over IPv4, a bare TCP ACK is 72 bytes in transport mode and 88 in tunnel mode (88 and 104 with TCP timestamps).
- [ ] PFS inference from the size of the encrypted CREATE_CHILD_SA exchange. A KE payload adds 8 + |g| bytes: 136 (group 2), 200 (5), 264 (14), 72 (19), 104 (20), 40 (31).
- [ ] AH analyzer: mode from next header, integrity candidates from ICV length
- [ ] IKEv1 parser (Main and Aggressive Mode, Phase 1 attributes including auth method and lifetime). Test against the public IKEv1 captures from E1d.
- [ ] Traffic-type features per SA and time window: length statistics, inter-arrival, burst shape, direction ratio, byte rate
- [ ] Baselines: majority class, packet-size-only, then Random Forest. SVM and 1D CNN only as comparisons.
- [ ] Calibration (Platt or isotonic), reliability plots, abstain threshold that maps low confidence to Unknown

**Done when:** every inferred attribute has a measured accuracy on held-out data and a calibrated confidence.

### Phase 5. Scoring v2, threat matrix, confidence

Rule catalogue: one YAML entry per rule with ID, title, severity, standard reference, threat, remediation and weight. The predicate lives in `analyzer/rules/engine.py` (`docs/decisions.md`).

| ID | Condition | Severity | Basis | State |
|---|---|---|---|---|
| IKE-001 | IKEv1 in use | High | RFC 9395 deprecates IKEv1 | In catalogue |
| IKE-002 | IKEv1 Aggressive Mode with PSK | Critical | Identity in cleartext, offline attack on the key | In catalogue |
| IKE-010 | DES | Critical | RFC 8247, RFC 8221: MUST NOT | In catalogue |
| IKE-011 | 3DES | High | 64-bit block. RFC 8221: SHOULD NOT | In catalogue |
| IKE-020 | MD5 for PRF or integrity | Critical | RFC 8247, RFC 8221: MUST NOT | In catalogue |
| IKE-021 | SHA-1 for PRF or integrity | Low | RFC 8247, RFC 8221: "MUST-" | In catalogue |
| IKE-030 | DH group 1 or 22 | Critical | RFC 8247: MUST NOT | In catalogue |
| IKE-031 | DH group 2, 5, 23 or 24 | High | RFC 8247: SHOULD NOT | In catalogue |
| IKE-040 | Responder selected weaker than strongest offered | Medium | Downgrade surface | In catalogue |
| IKE-041 | Initiator offers weak proposals beside strong ones | Low | Downgrade surface | In catalogue |
| ESP-001 | Encryption without integrity | Critical | RFC 8221: MUST NOT | In catalogue |
| ESP-010 | 8-byte block cipher inferred on ESP | High | 3DES or DES | In catalogue |
| AH-001 | AH only, no confidentiality | Medium | Payload readable | **To add** |
| SA-001 | No PFS on child SA rekey | Medium | NIST SP 800-77 Rev. 1 PFS guidance (check wording) | **To add** after PFS inference |
| SA-002 | No rekey observed, or interval beyond policy | Low | Key lifetime | In catalogue |
| SA-003 | Duplicate or out-of-window sequence numbers | Medium | Replay evidence | In catalogue |
| META-001 | Vendor ID discloses implementation or version | Low | Fingerprinting | In catalogue |
| META-002 | Traffic type predictable with high confidence | Informational | Traffic analysis exposure | **To add** after the classifier |
| PQ-001 | No post-quantum protection signalled | Informational | RFC 8784, RFC 9370 | In catalogue |
| ACT-001 | Responder accepts a weak proposal when probed | High | Active evidence | **To add** in phase 7 |

Check each row against its cited document before freezing the catalogue. Severities are for the team and guide to tune.

**Scoring** (implemented): 0 to 100, higher is better, fixed deduction per finding by severity with a cap per category. Any Critical finding caps the score in the lowest band. Risk level follows the worst finding, not the score band. Unknowns are not scored and lower a separate coverage figure. No randomness.
**Confidence:** 1.0 for Observed and Assisted, calibrated probability for Inferred. A finding inherits the lowest confidence among its attributes. The overall figure is a severity-weighted mean.
**Threat matrix:** offline PSK cracking, downgrade, record-now-decrypt-later, traffic analysis, replay, integrity forgery, targeted exploitation after fingerprinting.

- [x] Rule engine and catalogue (16 rules)
- [x] Score, coverage, risk level
- [x] Threat matrix builder
- [x] Repeatability test on golden captures
- [ ] Remaining four rules as their inputs land
- [ ] Score stability across repeated runs of a fixed configuration (same risk band every time), from dataset v1

### Phase 6. Dashboard and reports

Dashboard views: overview (score, risk, coverage, confidence, top findings); configuration (each attribute with evidence level, confidence, source packet); traffic (SA timeline, rekeys, traffic-type predictions); findings (filterable, with reference and remediation); threat matrix; compare two captures.

- [x] Executive and technical HTML report templates
- [ ] PDF export with WeasyPrint
- [ ] Streamlit dashboard reading session records (`app/`)
- [ ] Upload flow: capture in, results in the browser, reports downloadable
- [ ] Usability check: two or three readers without IPsec expertise name the top three risks from the executive report

**Done when:** milestone M4.

### Phase 7. Active probing

1. Proposal enumeration: IKE_SA_INIT and IKEv1 Phase 1 requests one proposal at a time, recording which the responder accepts.
2. IKEv1 and Aggressive Mode check.
3. Fingerprint features: vendor IDs, payload order, retransmission back-off.
4. Learned fingerprinting (stretch, needs three or more implementations).

Guard rails from the first commit:
- [ ] Target allowlist in a config file, lab subnets by default
- [ ] Explicit authorisation flag for any address outside the allowlist
- [ ] Rate limit and a hard cap on probes per target
- [ ] Every probe logged

**Done when:** milestone M5. Evaluated by: the accepted-proposal set matches the endpoint's configured proposals.

### Phase 8. Evaluation, hardening, documentation, video

- [ ] Final evaluation run (section 7, E3), Table V and `docs/RESULTS_FOR_PAPER.md` (E4)
- [ ] Robustness: truncated captures, captures starting mid-session, NAT traversal, IKE fragmentation (RFC 7383), packet loss
- [ ] Performance on large captures (shares `eval/bench_speed.py`)
- [ ] Live capture mode, if time allows
- [ ] Technical documentation: testbed, dataset, analyzer, scoring method, limits
- [ ] Demo video, 3 to 5 min, scripted around one strong and one weak deployment (`docs/demo_script.md`)
- [ ] Final PBL report and updated deck

## 7. Evaluation plan

The harness in `eval/` turns raw runs into the paper's Table V. It is built in steps E0 to E5, and each step ends with a stop-and-report to the team before the next one starts.

### 7.1 Targets (Table V)

Fixed before any data was collected, and the same as VISION.md section 9. **Never change a target after seeing results.**

| Row | Measure | Target | In scope now |
|---|---|---|---|
| IKE parser | Field-level exact match with ground truth | 100% | Yes |
| ESP cipher family, ICV | Accuracy per SA, held-out runs | >= 95% | Yes |
| ESP mode | Accuracy, held-out configurations | >= 90% | Yes, after phase 4 mode inference |
| PFS on rekey | Accuracy on runs with a rekey | >= 90% | Yes, after phase 4 PFS inference |
| Traffic type | Macro F1, held-out runs | >= 0.85 | Future work unless phase 4 finishes the classifier |
| Generalisation | Macro F1 drop, held-out implementation | <= 10 points | Future work |
| Calibration | ECE per inferred attribute | <= 0.05 | Future work |
| Scoring | Same output on repeated analysis; same risk band across repeats | Identical | Yes |
| Speed | 100 MB capture to both reports | < 2 min | Yes |
| Usability | Test readers name the top three risks | Yes | Phase 6 |

### 7.2 Ground rules

1. **Never fabricate or hand-edit a result.** Every number comes from a script run on raw files that stay on disk. A failed run is recorded as a failure, not filled in.
2. **Report misses honestly.** A missed target is reported with its measured value and investigated. Never change the target, the split or the test data to make it pass.
3. **No tuning on test data.** Any threshold is set on the validation split and then frozen.
4. **Ground truth comes from the config that created the run**, written by the same code, then cross-checked by decrypting the capture with the run's keys.
5. **Split by run and by configuration.** Never split packets or windows from one run across train and test. Write the splits to `eval/results/split.json` before computing any metric.
6. **Check for leakage.** The traffic classifier must not key on cipher overhead, and the mode classifier must not key on which hosts appear. Test by holding those out.
7. **Always report the simple baseline next to the model.**
8. **Report the held-out implementation result even if it is poor.** That number shows whether the model learned IPsec or learned strongSwan.
9. **Unknown is a valid prediction.** Count it as wrong for accuracy, and report coverage and accuracy-on-answered beside it.
10. **The analyzer's behaviour stays unchanged during evaluation.** A bug found by the harness gets a failing test and a report first, and is fixed only after approval.

### 7.3 Harness steps

**E0. Repo map (no code changes).** Write `docs/repo_map.md`: the entry point (`analyzer/cli.py`, `analyse`), where records and reports are written, the schema fields for every attribute Table V measures, the residue function's signature (`analyzer/inference/esp_structure.py`) and whether it can be called directly with a list of lengths, the test status, and the toolchain. Acceptance: the team confirms the map.

**E1. Quick wins (no testbed needed).** Milestone ME1.
- **E1a. Paper maths as tests** in `tests/eval/`:
  - Table II residues. Lengths L = 8 + v + k·β + t for k = 0 to 40 give these residue sets mod 16: AES-CBC + HMAC-SHA1-96 {4}; + HMAC-SHA-256-128 {8}; + HMAC-SHA-384-192 {0}; + HMAC-SHA-512-256 {8}; 3DES-CBC + HMAC-SHA1-96 {4, 12}; AES-CTR + HMAC-SHA1-96, AES-GCM-16, ChaCha20-Poly1305 {0, 4, 8, 12}; AES-CBC with no integrity {8}, which must stay ambiguous with 16-byte ICVs.
  - The residue function returns Unknown on too few distinct lengths, and never separates AES-CBC from 3DES with fewer than 18 distinct lengths at the paper's 10⁻⁵ level. **The current code answers from 4 distinct lengths, so expect this test to fail.** Report the result and take it to D10. Do not change the expected value.
  - Table III KE payload sizes and the mode example from phase 4.
- **E1b. Determinism** (`eval/check_determinism.py`): analyse the same capture 10 times, compare records and scores with time-dependent fields removed (list them). Output `eval/results/determinism.json`.
- **E1c. Speed** (`eval/bench_speed.py`): merge captures to about 100 MB with `mergecap`, time the full run to both reports 5 times, report median and range with CPU, RAM and OS. Output `eval/results/speed.json`.
- **E1d. IKE parser on public captures**. Ask before downloading. Sources: the Wireshark repository's `test/captures/ikev2-decrypt-*` (these come with keys), and the IKEv1 and IPsec traces from the Zeek IPsec analyzer tests. Record URL, commit and licence in `dataset/public/SOURCES.md`. `eval/oracle_tshark.py` extracts exchange type, SPIs, proposals and transforms with key lengths, KE group, notify types and vendor IDs. Find field names with `tshark -G fields | grep -i isakmp`, not by guessing. Report field-level exact match, overall and per field type, and every mismatch by file and frame. Report IKEv1 as "not supported (expected)" until the IKEv1 parser lands. Outputs `eval/results/parser_public.json`, `parser_public_mismatches.md`.
- Acceptance: all four outputs exist, come from scripts, and reproduce on re-run.

**E2. Testbed corpora.** This is phase 1 plus phase 3a. Acceptance: at least one complete, decryption-verified run per suite, then stop and report available algorithms, skipped items and the padding audit **before** running the full corpus.

**E3. Metrics.** Milestone ME2.
- `eval/adapter.py` normalises each record to `{run_id, sa_spi, cipher_family, icv_bytes, mode, pfs, pfs_group, evidence, confidence}`, keeping Unknown.
- `eval/evaluate.py`: test set is one held-out repeat of every configuration, plus the held-out configuration split for mode. Cipher family and ICV: per-SA accuracy, coverage, accuracy on answered SAs, confusion matrix. Mode: the same. PFS: per-rekey-event accuracy, plus the observed CREATE_CHILD_SA size increase next to the predicted 8 + |g| bytes, request and response separately, per group. IKE parser on the testbed: field-level exact match against the manifest. No model training in this step.
- `eval/residue_curve.py`: for each test SA, sample m distinct ESP lengths for m = 1 to 30, 200 draws each, call the analyzer's own residue function, plot accuracy and Unknown rate against m, and mark m = 10 and m = 18. If the function cannot be called directly, stop and ask. Do not reimplement it.
- Outputs: `eval/results/table_v.json` and `table_v.md` (Row, Measure, Target, Result, N, Notes), `confusion_cipher.csv`, `confusion_mode.csv`, `pfs_sizes.csv`, `eval/figures/residue_vs_m.pdf`.
- Acceptance: every number traces to a script and raw runs, and re-running reproduces it.

**E4. Paper integration (text only).** `docs/RESULTS_FOR_PAPER.md`: Table V with measured rows filled in and out-of-scope rows marked "Future work"; one paragraph per row with the number, N and one sentence on any miss; values for the paper's placeholders (ESP suites actually tested, the two auth methods, observed padding behaviour); the residue figure with a caption; and a list of claims the results contradict. Do not edit the paper's .docx unless asked.

**E5. Later, only when the team asks.**
- Held-out IKE daemon: Libreswan with the same matrix subset. Libreswan and strongSwan share the kernel XFRM ESP code, so this tests IKE behaviour, not ESP framing.
- Held-out ESP stack: FreeBSD-based gateway (pfSense or OPNsense), OpenBSD iked in a VM, or strongSwan's userspace libipsec. This is the real test of whether residue and mode inference generalise (R14).
- Traffic corpus and classifier, then calibration (per-attribute ECE, reliability diagrams, risk-coverage curve).
- Edge cases: RFC 7383 fragmentation, RFC 8750 implicit-IV suites, IP-TFS (RFC 9347).

## 8. Risks

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Containers cannot do kernel IPsec | Retired | | Works on WSL2 via `scripts/testbed-bootstrap.sh` |
| R2 | Mode or PFS inference misses its target | Medium | Medium | Report the measured number with calibrated confidence, fall back to Unknown. An honest negative result still counts. |
| R3 | Model learns testbed artefacts | High | High | netem variation, second implementation, held-out splits, leakage tests |
| R4 | Evaluators see deterministic parsing as "not AI" | Medium | Medium | Lead with the evidence-level table and the three places ML is necessary |
| R5 | Weak algorithms disabled in current builds | Medium | Medium | Check with `swanctl --list-algs` in E2. Older image or Scapy-crafted handshakes. Skips listed in `skipped.json`. |
| R6 | Dataset generation slower than planned | Medium | Medium | Eval corpora first (132 runs), unattended and resumable, freeze v1 with what is complete |
| R7 | Real tunnels carry mixed traffic | High | Medium | State the limit, predict per time window, mixed runs as a stretch |
| R8 | Scope creep (probing, live capture, LLM narrative) | High | Medium | All after M4 and first to cut |
| R9 | Active probing against unauthorised targets | Low | High | Allowlist, authorisation flag, rate limit, logging |
| R10 | Three people, exams, schedule already slipped (M2 missed) | High | High | Re-planned milestones, demo cut at M3, explicit cut order, weekly check |
| R11 | Key lifetime not assessable from short captures | High | Low | Report Unknown with the capture duration needed |
| R12 | The residue threshold (4 lengths) contradicts the paper's 18-length bound | High | Medium | E1a measures it, E3's residue curve shows the real trade-off, D10 settles it |
| R13 | An implementation pads beyond the minimum, breaking the residue assumption | Low | High | Padding audit in E2 before the full corpus |
| R14 | Libreswan shares strongSwan's kernel ESP, so "held-out implementation" does not test ESP framing | High | Medium | Say so in the paper. A BSD or libipsec stack in E5 is the real test. |
| R15 | Offload settings in the WSL2 Docker VM distort captured lengths | Medium | High | Disable GSO, GRO and TSO on the bridge before capture. Check lengths against the decrypted padding audit. |

## 9. Working agreements

- One weekly sync against the milestone table. Update the checkboxes in this file in the same commit as the work.
- Every module has tests. The parser and the scoring path have golden files.
- Captures and keys stay out of git. The manifest, checksums, `SOURCES.md` and the scripts that regenerate runs go in.
- No finding without a rule ID, no rule without a reference.
- Changes to the session record schema need all three owners to agree.
- Evaluation work happens on the `eval-harness` branch, one commit per passing step, and stops for review at the end of each step from E0 to E4.
- Ask the team before: installing system packages with sudo, building strongSwan from source, loading kernel modules, deleting any data, pushing to a remote, or downloading third-party captures.
- Lab only. Tools never point at an address outside the testbed bridge.

## 10. Hardware and software needed

- One Linux or WSL2 machine with 16 GB RAM and 50 GB free disk. The eval corpora are about 132 runs of 2 to 4 minutes each, so roughly 6 hours serially.
- No GPU for the Random Forest baseline. A GPU or a free cloud notebook only if the CNN comparison goes ahead.
- All software is open source: strongSwan, Libreswan, Docker, tcpdump, Wireshark and tshark, mergecap, Scapy, scikit-learn, PyTorch, Streamlit, WeasyPrint.

## 11. Decisions

D1 to D8 are recorded in `docs/decisions.md`. Summary and new items:

| ID | Decision | Recommendation or outcome | Status | Due |
|---|---|---|---|---|
| D1 | Evidence-level model | Yes | Provisional, needs guide sign-off | Now |
| D2 | Active probing in scope | Yes, phase 7, enumeration first | Provisional | Now |
| D3 | Standards baseline | NIST SP 800-77 Rev. 1, RFC 8247, RFC 8221, RFC 9395 | Provisional | Now |
| D4 | Dashboard stack | Streamlit with Plotly | Provisional | Before phase 6 |
| D5 | IKEv1 in scope | Yes | Provisional | Now |
| D6 | Release the dataset publicly | Decide before the datasheet | Open | Week 9 |
| D7 | Project short name | `ipsec-analyzer` | Settled | |
| D8 | Local language model for report narrative | Deferred | Open | After M4 |
| D9 | Commit `eval/results/` | Yes. Remove it from `.gitignore` when the harness lands. | Open | E1 |
| D10 | Residue answering threshold | Decide from E1a and the E3 residue curve. Either raise it toward 18 distinct lengths for the CBC-versus-3DES call, or keep 4 and state the error rate in the paper. | Open | After E1 |
| D11 | Paper venue and deadline | | Open | Week 8 |

## 12. Deliverables checklist

| Deliverable | Produced in | Done |
|---|---|---|
| Working software prototype | Phases 2 to 6 | Partial |
| VPN testbed | Phase 1 | Partial |
| Training and testing datasets, with datasheet | Phase 3 | [ ] |
| AI classification engine | Phase 4 | Partial (rule-based residue inference) |
| Security assessment engine | Phase 5 | Mostly done |
| Interactive dashboard | Phase 6 | [ ] |
| Executive and technical security reports | Phase 6 | HTML done, PDF pending |
| Active IKE probing module | Phase 7 | [ ] |
| Evaluation results (Table V) and `docs/RESULTS_FOR_PAPER.md` | Section 7 | [ ] |
| Research paper | E4 plus author writing | [ ] |
| Technical documentation | Phase 8 | [ ] |
| Demonstration video | Phase 8 | [ ] |
| Final PBL report and presentation | Phase 8 | [ ] |

## 13. Fixes to the existing documents

**PBL draft report**
- [ ] Objective 2 and section 6: replace the "AI engine that works out IPsec settings" wording with a deterministic parser for cleartext IKE plus an inference engine for encrypted parameters, and add the evidence levels
- [ ] Section 6, Security Assessment: name the standards baseline
- [ ] Section 6, Evaluation: add the Table V targets and the held-out splits
- [ ] State that ESP key length cannot be recovered passively
- [ ] Explain how key lifetime and replay protection are observed
- [ ] Add messaging to the traffic types
- [ ] References: add ike-scan, iker, strongSwan, Libreswan, NIST SP 800-77 Rev. 1 and the RFCs. Complete references 3 and 9 (no authors).

**Deck**
- [ ] Slide 4, objective 02: "Parse IKE deterministically: version, IKE cipher suite, DH group". Mode and PFS are not cleartext for ESP.
- [ ] Slide 4: add an active-probing objective, or remove probing from slide 3
- [ ] Slide 5: add the active prober to the architecture
- [ ] Slide 6: show the evidence levels, with mode and PFS on the inferred side
- [ ] Slide 8: add RFC 8221 and RFC 9395
- [ ] Slide 9: add the testbed and active probing to the deliverables
- [ ] Add a targets slide (Table V) and a timeline slide (section 4)

**Synopsis**
- [ ] Align with the report and deck, or retire it in favour of VISION.md

**Paper**
- [ ] Fill the section VIII placeholders from E4
- [ ] Revise any claim E4 lists as contradicted, including the residue threshold (D10) and the Libreswan generalisation caveat (R14)

## 14. Next seven days (from 2026-11-17)

1. Fill in key dates and owners (sections 2 and 5). Take D1, D2, D3, D5 to the guide, and decide D11.
2. Confirm the revised milestones in section 4 against the exam dates.
3. E0: write `docs/repo_map.md`.
4. E1a: paper-maths tests. Report the residue-threshold result for D10.
5. E1b and E1c: determinism and speed scripts.
6. E1d: with approval, download the public captures and run the tshark oracle.
7. Start phase 1: four-container topology, config templates, `ip xfrm state` key dump, one orchestrated run verified by decryption.

## 15. References

Standards baseline:
- NIST SP 800-77 Rev. 1, Guide to IPsec VPNs: https://doi.org/10.6028/NIST.SP.800-77r1
- RFC 7296, IKEv2: https://www.rfc-editor.org/rfc/rfc7296.html
- RFC 8247, algorithm requirements for IKEv2: https://www.rfc-editor.org/rfc/rfc8247.html
- RFC 8221, algorithm requirements for ESP and AH: https://www.rfc-editor.org/rfc/rfc8221.html
- RFC 9395, deprecation of IKEv1 and obsoleted algorithms: https://www.rfc-editor.org/rfc/rfc9395.html
- RFC 4301 (architecture), RFC 4302 (AH), RFC 4303 (ESP), RFC 2409 (IKEv1), RFC 3948 (ESP in UDP), RFC 4106 (AES-GCM in ESP), RFC 7383 (IKEv2 fragmentation), RFC 8750 (implicit IV), RFC 9347 (IP-TFS), RFC 8784 and RFC 9370 (post-quantum measures for IKEv2)

Tools and data:
- strongSwan save-keys plugin: https://docs.strongswan.org/docs/5.9/plugins/save-keys.html
- ike-scan: https://github.com/royhills/ike-scan
- Wireshark test captures (`test/captures/ikev2-decrypt-*`): https://gitlab.com/wireshark/wireshark
- Zeek IPsec analyzer test traces: https://github.com/corelight/zeek-spicy-ipsec

Problem statement:
- SIH26160 on an unofficial explorer: https://sih-explorer.amanuniyal47.workers.dev/problem/SIH26160 (verify against the official SIH portal)

Project documents: the synopsis, the PBL draft report (with its 15 literature references), the presentation deck, and the two superseded plans in `docs/`.
