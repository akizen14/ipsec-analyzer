# PLAN

**Project:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework (SIH26160, NTRO)
**Team:** Chaitanya Sawant, Vansh Jangra, Aditya Sonawane. **Guide:** Dr. Chaya Nayak
**Last updated:** 2026-10-06
**Companion document:** VISION.md (what is being built and why)

This plan turns VISION.md into work. It assumes the starting point the three source documents describe: a proposal, a literature review and a design direction, with no testbed, dataset or code referenced as existing yet. If any of that already exists, strike the matching tasks.

---

## 1. Starting point

| Asset | State | Notes |
|---|---|---|
| Synopsis (framework document) | Written | Mirrors the SIH problem statement. Treats all identification as AI. Oldest thinking. |
| PBL draft report | Written. Guide approval page is unsigned in this copy. | 15-paper literature review, 5 objectives, adds active IKE probing, lists candidate tools |
| Presentation deck (10 slides) | Written | Newest thinking: deterministic IKE parsing plus ML for ESP. Names NIST SP 800-77 and RFC 8247. |
| Testbed, dataset, code, dashboard | Not referenced in any document | Everything is in the future tense |
| Schedule, task ownership, numeric targets | Not in any document | Supplied here and in VISION.md section 9 |

## 2. Key dates

Fill these in first. The whole schedule hangs on them.

| Event | Date | Status |
|---|---|---|
| PBL guide approval of draft report | | To confirm with Dr. Nayak |
| PBL mid-term review | | To confirm |
| PBL final review and submission | | To confirm |
| SIH 2026 idea submission | Reported by third-party guides as 30 September 2026 | Confirm with the college SPOC whether the team was nominated |
| SIH 2026 shortlist announcement | Reported as October 2026 | Confirm on the official portal |
| SIH 2026 grand finale | Reported as December 2026 | Confirm on the official portal |
| Semester exams and holidays | | Block these out of the schedule below |

Team composition to check: SIH has required six students per team with at least one woman, and the documents list three members. Confirm the 2026 rule and the team roster with the SPOC.

## 3. Architecture

```
                         +-------------------------------+
                         |  TESTBED (lab only)           |
                         |  orchestrator -> VPN peers    |
                         |  -> traffic generators        |
                         |  -> capture + manifest        |
                         +---------------+---------------+
                                         | pcapng + labels
                                         v
  pcap / live iface  -->  [1 INGEST] --> [2 SESSION BUILDER]
                                               |
                         +---------------------+---------------------+
                         |                                           |
                         v                                           v
                [3 IKE PARSER]                              [4 ESP / AH ANALYZER]
                deterministic                               deterministic statistics
                (Observed)                                  (Observed)
                         |                                           |
                         |                                           v
                         |                                  [5 INFERENCE ENGINE]
                         |                                  cipher family, mode, PFS,
                         |                                  traffic type, calibration
                         |                                  (Inferred)
                         |                                           |
  authorised target -->  [6 ACTIVE PROBER] ---+                      |
                         (Observed)           |                      |
                         v                    v                      v
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
```

The session record is the contract between the analysis half and the product half. Agree its schema in week 1 so both halves can be built in parallel against sample files.

### 3.1 Session record, abbreviated

```json
{
  "session_id": "run-0412",
  "endpoints": {"initiator": "10.1.0.2", "responder": "10.2.0.2", "ip_version": 4, "nat_t": false},
  "ike": {
    "version":   {"value": "IKEv2", "evidence": "observed", "confidence": 1.0, "packets": [1]},
    "encr":      {"value": "AES_CBC_256", "evidence": "observed", "confidence": 1.0, "packets": [2]},
    "dh_group":  {"value": 14, "evidence": "observed", "confidence": 1.0, "packets": [2]},
    "auth":      {"value": null, "evidence": "unknown", "reason": "IKE_AUTH is encrypted"},
    "offered":   ["..."], "selected": "..."
  },
  "child_sas": [{
    "protocol":      {"value": "ESP", "evidence": "observed", "confidence": 1.0},
    "cipher_family": {"value": "AEAD_or_CTR_16B_ICV", "evidence": "inferred", "confidence": 0.97},
    "key_length":    {"value": null, "evidence": "unknown", "reason": "not visible in ciphertext"},
    "mode":          {"value": "tunnel", "evidence": "inferred", "confidence": 0.91},
    "pfs_on_rekey":  {"value": true, "evidence": "inferred", "confidence": 0.88},
    "rekey_interval_s": {"value": 3540, "evidence": "inferred", "confidence": 0.8},
    "traffic_type":  {"value": "voip", "evidence": "inferred", "confidence": 0.93}
  }],
  "findings": [], "score": null
}
```

### 3.2 Technology choices

| Layer | Choice | Reason | Status |
|---|---|---|---|
| Language | Python 3.11 or newer | One language across testbed, analysis, ML and dashboard | Proposed |
| VPN endpoints | strongSwan (swanctl) as primary, Libreswan as second implementation | Both named in the report. Two implementations are needed to test generalisation. | From report |
| Testbed runtime | Docker Compose on a Linux host | Fast to rebuild hundreds of configurations | Proposed. See risk R1. |
| Capture | tcpdump or dumpcap on the link between the peers | Named in all three documents | From documents |
| Parsing and packet crafting | Scapy, with tshark output as a test oracle | Scapy does both reading and crafting. Move the hot path to dpkt if speed becomes a problem. | Proposed |
| Classical ML | scikit-learn (Random Forest, gradient boosting, SVM) | Deck: Random Forest baseline first | From deck |
| Deep learning | PyTorch, only if a 1D CNN beats the baseline on held-out data | Deck: CNN only if it clearly performs better | From deck |
| Features and data | Parquet for feature tables, JSON for session records, SQLite for dashboard history | Simple and file-based | Proposed |
| Dashboard | Streamlit with Plotly first | Quickest path to an interactive dashboard for three people | Proposed. See decision D4. |
| Reports | Jinja2 templates to HTML, then PDF with WeasyPrint | Deterministic and works offline | Proposed |
| Tests | pytest with golden capture files | Guards the parser and the score against regressions | Proposed |

### 3.3 Repository layout

```
ipsec-analyzer/
  VISION.md  PLAN.md  README.md
  testbed/        compose files, config templates, orchestrator, traffic generators
  dataset/        manifest, datasheet, download or regeneration scripts (captures kept out of git)
  analyzer/
    ingest/       pcap reader, live capture wrapper
    sessions/     IKE and SA reconstruction
    ike/          IKEv1 and IKEv2 parsers
    esp_ah/       header statistics, length residues, AH parsing
    inference/    feature extraction, models, calibration
    probe/        active IKE prober
    rules/        rule catalogue (YAML) and engine
    scoring/      score, risk level, threat matrix, confidence
  app/            dashboard
  reports/        templates and generator
  eval/           evaluation scripts, notebooks, results
  tests/          unit tests and golden captures
  docs/           technical documentation, demo script
```

## 4. Schedule

Sixteen working weeks from the week of 5 October 2026. Dates are indicative and do not yet account for exams or holidays. Phases overlap because three people work in parallel.

| Phase | Weeks | Indicative dates | Outcome |
|---|---|---|---|
| 0. Foundations | 1 | 5 Oct to 11 Oct | Decisions made, repository up, schema agreed |
| 1. Testbed MVP | 1 to 3 | 5 Oct to 25 Oct | One command brings up a tunnel, generates traffic, saves a labelled capture |
| 2. Vertical slice | 2 to 4 | 12 Oct to 1 Nov | Capture in, scored HTML report out, IKEv2 only |
| 3. Dataset at scale | 4 to 6 | 26 Oct to 15 Nov | Dataset v1 frozen with manifest and datasheet |
| 4. ESP inference and classifier | 5 to 8 | 2 Nov to 29 Nov | Cipher family, mode, PFS and traffic type inferred with measured accuracy |
| 5. Scoring v2, threat matrix, calibration | 7 to 9 | 16 Nov to 6 Dec | Full rule catalogue, calibrated confidence |
| 6. Dashboard and reports | 7 to 10 | 16 Nov to 13 Dec | Dashboard, executive PDF, technical PDF |
| 7. Active probing | 10 to 12 | 7 Dec to 27 Dec | Proposal enumeration against the testbed, merged into the session record |
| 8. Evaluation, hardening, documentation, video | 12 to 16 | 21 Dec to 24 Jan 2027 | Final numbers, documentation, demo video, live capture if time allows |

### Milestones

| ID | End of week | Date | Demonstrable result |
|---|---|---|---|
| M1 | 4 | 1 Nov 2026 | Run the tool on 6 to 8 hand-picked IKEv2 captures. It prints the correct configuration and flags the weak ones. |
| M2 | 6 | 15 Nov 2026 | Dataset v1 exists and anyone on the team can regenerate a run from its manifest entry. |
| M3 | 8 | 29 Nov 2026 | **Demo cut.** Dashboard v0 shows configuration, score, findings and traffic-type prediction for a capture chosen live. This is the version to take to an SIH finale if shortlisted. |
| M4 | 10 | 13 Dec 2026 | Passive pipeline feature-complete, both reports generated. |
| M5 | 12 | 27 Dec 2026 | Active probing results appear alongside passive results. |
| M6 | 16 | 24 Jan 2027 | Evaluation complete, documentation and video delivered. |

If time is lost, cut in this order: live capture, vendor fingerprinting, CNN model, mixed-traffic tunnels, third implementation. Do not cut the dataset manifest, the held-out evaluation or the evidence levels.

## 5. Ownership

Three tracks, one owner each. Owners review each other's pull requests. Write the names in.

| Track | Owner | Covers |
|---|---|---|
| A. Testbed and data | ________ | Phases 1 and 3, capture, manifest, datasheet, traffic generators |
| B. Analysis and ML | ________ | Session builder, IKE parser, ESP and AH analyzer, inference, evaluation |
| C. Product | ________ | Rule catalogue, scoring, threat matrix, dashboard, reports, then active probing |

If the team grows to six for SIH, the cleanest additions are: a second person on Track B for ML evaluation, a front-end person on Track C, and one person for active probing plus documentation and the demo video.

## 6. Phase detail

### Phase 0. Foundations (week 1)

- [ ] Fill in section 2 (key dates) and section 5 (owners)
- [ ] Resolve decisions D1 to D5 in section 11 with the guide
- [ ] Create the repository with the layout in 3.3, a licence, a README and CI running lint and tests
- [ ] Agree the session record schema (3.1) and commit three hand-written sample records
- [ ] Verify the testbed host can do kernel IPsec inside containers (risk R1)
- [ ] Update the report, synopsis and deck per section 13

**Done when:** a new team member can clone the repository, read VISION.md and PLAN.md, and know what to build.

### Phase 1. Testbed MVP (weeks 1 to 3)

Topology: two gateways with a client subnet behind each for Tunnel mode, two hosts talking directly for Transport mode, and a capture point on the link between them.

- [ ] Compose file for the topology, IPv4 and IPv6
- [ ] Configuration template that renders a strongSwan config from one parameter set
- [ ] Orchestrator: render config, start peers, wait for the SA, run a traffic generator for a fixed time, stop capture, tear down
- [ ] Manifest writer: one row per run, written by the orchestrator from the same parameter set that built the config, so labels can never drift from reality
- [ ] Export session keys from the endpoints for each run (strongSwan save-keys plugin) so Wireshark can decrypt and the labels can be verified independently
- [ ] Traffic generators, one per class: web (HTTP client against a local server), VoIP (RTP call or an equivalent constant-rate UDP profile), email (SMTP and IMAP exchange), messaging (short intermittent chat messages), video (segment streaming), ICMP, plus an idle run
- [ ] Short lifetimes in lab configs (rekey every 60 to 120 seconds) so every run contains at least one rekey

**Done when:** `make run CONFIG=...` produces a capture, a key file and a manifest row, and Wireshark decrypts the run using the exported keys.

### Phase 2. Vertical slice (weeks 2 to 4)

Build the thinnest end-to-end path before widening any stage.

- [ ] Ingest pcap and pcapng, IPv4 and IPv6, UDP 500 and 4500, ESP and AH by protocol number, ESP-in-UDP told apart from IKE by the non-ESP marker
- [ ] Session builder: group IKE messages by SPI pair, group ESP and AH by endpoint pair and SPI, link child SAs to their IKE SA
- [ ] IKEv2 parser: IKE_SA_INIT offered and selected proposals, DH group, notifications, vendor IDs
- [ ] First 8 rules (weak cipher, weak hash, weak DH group, responder chose weaker than offered)
- [ ] Score v1 and a single HTML report
- [ ] Golden captures with expected findings, checked in CI

**Done when:** milestone M1.

### Phase 3. Dataset at scale (weeks 4 to 6)

A full factorial is not needed. The eight negotiation dimensions below multiply out to close to 3,000 runs before traffic class is even considered. Use two corpora and combinatorial coverage instead.

**Handshake corpus** (short runs, a few seconds of traffic plus one rekey). Every value of every dimension appears, with all-pairs coverage as the minimum and three-way coverage if time allows:

| Dimension | Values |
|---|---|
| Key exchange | IKEv2, IKEv1 Main Mode, IKEv1 Aggressive Mode |
| Protection | ESP, AH |
| Mode | Tunnel, Transport |
| ESP suite | AES-128-CBC with HMAC-SHA-256, AES-256-CBC with HMAC-SHA-256, AES-256-CBC with HMAC-SHA-1, AES-128-GCM, AES-256-GCM, plus weak cases (3DES, MD5) where the build supports them |
| DH group | 2, 5, 14, 19, 31 (weak, weak, baseline, elliptic curve, Curve25519) |
| PFS on rekey | On, off |
| IP version | IPv4, IPv6 |
| Authentication | Pre-shared key, certificate |

**Traffic corpus** (longer runs, 3 to 5 minutes each). A covering subset of ESP suite, mode and IP version, crossed with every traffic class, three repeats each under different network conditions (added delay, jitter and loss with netem).

- [ ] Parameter matrix file that generates both corpora
- [ ] Estimate run count and wall-clock time before starting. Runs can execute in parallel because each tunnel lives in its own network namespace.
- [ ] Run the matrix unattended, with retry and a failure log
- [ ] Second implementation (Libreswan) for a subset of the traffic corpus, kept aside as a held-out test set
- [ ] Dataset datasheet: how it was made, what each label means, known limits, how to regenerate
- [ ] Fixed train, validation and test split by run ID, plus a held-out configuration split and the held-out implementation split
- [ ] Freeze as dataset v1 with checksums

**Done when:** milestone M2.

### Phase 4. ESP inference and traffic classifier (weeks 5 to 8)

- [ ] IKEv1 parser (Main and Aggressive Mode, Phase 1 attributes including authentication method and lifetime)
- [ ] AH analyzer: mode from the next-header field, integrity algorithm candidates from ICV length
- [ ] ESP header statistics: sequence continuity, duplicates, SPI changes and rekey intervals
- [ ] Length-residue analysis: block size and ICV size candidates from the distribution of ESP packet lengths (a 16-byte block cipher in CBC leaves one residue modulo 16, an 8-byte block cipher leaves two, and AEAD or counter modes leave four)
- [ ] Mode inference: features from minimum and typical packet overhead and from how many flows share one SA
- [ ] PFS inference: size of the encrypted rekey exchange with and without a key-exchange payload
- [ ] Traffic-type features per SA and time window: packet length statistics, inter-arrival statistics, burst shape, direction ratio, byte rate
- [ ] Baselines: majority class, packet-size-only, then Random Forest. Add SVM and a 1D CNN only as comparisons.
- [ ] Calibration (Platt or isotonic), reliability plots, abstain threshold that maps low confidence to Unknown
- [ ] Evaluation on all three splits

**Done when:** every inferred attribute has a measured accuracy on held-out data and a calibrated confidence. Milestone M3 at the end of week 8.

### Phase 5. Scoring v2, threat matrix, confidence (weeks 7 to 9)

**Rule catalogue.** One YAML entry per rule: ID, title, condition on the session record, severity, standard reference, threat it enables, remediation text. Starter set:

| ID | Condition | Severity | Basis |
|---|---|---|---|
| IKE-001 | IKEv1 in use | High | RFC 9395 deprecates IKEv1 |
| IKE-002 | IKEv1 Aggressive Mode with pre-shared key | Critical | Identity in cleartext and offline attack on the key |
| IKE-010 | DES encryption | Critical | RFC 8247 and RFC 8221: MUST NOT |
| IKE-011 | 3DES | High | 64-bit block. RFC 8221: SHOULD NOT for ESP |
| IKE-020 | MD5 for PRF or integrity | Critical | RFC 8247 and RFC 8221: MUST NOT |
| IKE-021 | SHA-1 for PRF or integrity | Low | RFC 8247 and RFC 8221 status "MUST-", meaning expected to be downgraded |
| IKE-030 | DH group 1 or 22 | Critical | RFC 8247: MUST NOT |
| IKE-031 | DH group 2, 5, 23 or 24 | High | RFC 8247: SHOULD NOT |
| IKE-040 | Responder selected a weaker proposal than the strongest offered | Medium | Downgrade surface |
| IKE-041 | Initiator offers weak proposals alongside strong ones | Low | Downgrade surface |
| ESP-001 | Encryption without integrity protection | Critical | RFC 8221: MUST NOT be used |
| ESP-010 | 8-byte block cipher inferred on ESP | High | 3DES or DES |
| AH-001 | AH only, no confidentiality | Medium | Payload is readable |
| SA-001 | No PFS observed on child SA rekey | Medium | Compromise of the IKE SA keys exposes all child SA traffic. Cite the PFS guidance in NIST SP 800-77 Rev. 1 once checked. |
| SA-002 | No rekey observed, or interval beyond policy | Low | Key lifetime |
| SA-003 | Duplicate or out-of-window sequence numbers observed | Medium | Replay evidence |
| META-001 | Vendor ID discloses implementation or version | Low | Fingerprinting |
| META-002 | Traffic type predictable with high confidence | Informational | Traffic analysis exposure |
| PQ-001 | No post-quantum protection signalled | Informational | RFC 8784, RFC 9370 |
| ACT-001 | Responder accepts a weak proposal when probed | High | Active evidence |

Check each row against the cited document before freezing the catalogue. Severities are proposals for the team and guide to tune.

**Scoring, proposed.**
- Security score from 0 to 100, higher is better. Start at 100, subtract a fixed deduction per finding by severity, with a cap per category so one area cannot consume the whole score.
- Any Critical finding caps the score in the lowest band.
- Risk level (Low, Medium, High, Critical) follows the worst finding.
- Unknown attributes are not scored. They lower a separate **coverage** figure, shown next to the score: "Score 82, coverage 70 percent".
- No randomness anywhere in the scoring path, so the same record always gives the same score.

**Confidence, proposed.** Per attribute: 1.0 for Observed and Assisted, calibrated probability for Inferred. A finding inherits the lowest confidence among the attributes it depends on. The overall figure is a severity-weighted average across findings.

**Threat matrix.** Rows are threats, each linked to the findings that enable it, with likelihood, impact, rating and mitigation: offline pre-shared key cracking, downgrade to a weak proposal, record-now-decrypt-later, traffic analysis, replay, integrity forgery, targeted exploitation after fingerprinting.

- [ ] Rule engine and catalogue
- [ ] Score, coverage, risk level
- [ ] Threat matrix builder
- [ ] Repeatability tests

### Phase 6. Dashboard and reports (weeks 7 to 10)

Dashboard views:
1. Overview: score, risk level, coverage, confidence, top findings
2. Configuration: every attribute with its evidence level, confidence and source packet
3. Traffic: SA timeline, rekeys, traffic-type predictions over time
4. Findings: filterable list with standard reference and remediation
5. Threat matrix
6. Compare: two captures or two endpoints side by side

Reports:
- **Executive**, one to two pages: posture in a sentence, score, top three risks in plain language, recommended actions
- **Technical**: full configuration table, all findings with evidence, threat matrix, method and limits, appendix of unknowns

- [ ] Dashboard reading session records
- [ ] Both report templates
- [ ] Upload flow: capture in, results in the browser, reports downloadable

**Done when:** milestone M4.

### Phase 7. Active probing (weeks 10 to 12)

Order of work, most valuable first:

1. **Proposal enumeration.** Send IKE_SA_INIT and IKEv1 Phase 1 requests with one proposal at a time and record which the responder accepts. This is the strongest security evidence the tool can produce.
2. **IKEv1 and Aggressive Mode check.** Does the endpoint still answer them.
3. **Fingerprint features.** Vendor IDs, payload order, retransmission back-off timing.
4. **Learned fingerprinting (stretch).** Only worthwhile with three or more implementations in the testbed.

Guard rails, built in from the first commit:
- [ ] Target allowlist in a config file, lab subnets by default
- [ ] Explicit authorisation flag required for any address outside the allowlist
- [ ] Rate limit and a hard cap on probes per target
- [ ] Every probe logged

**Done when:** milestone M5.

### Phase 8. Evaluation, hardening, documentation, video (weeks 12 to 16)

- [ ] Final evaluation run and results tables (section 7)
- [ ] Robustness: truncated captures, captures that start mid-session, NAT traversal, IKE fragmentation, packet loss
- [ ] Performance on large captures
- [ ] Live capture mode, if time allows
- [ ] Technical documentation: testbed, dataset, analyzer, scoring method, limits
- [ ] Demonstration video, 3 to 5 minutes, scripted around one strong and one weak deployment
- [ ] Final PBL report and updated deck

## 7. Evaluation plan

| What | Metric | Split |
|---|---|---|
| IKE parser | Exact field match against the manifest, and agreement with tshark | Whole handshake corpus |
| Cipher family, ICV size | Accuracy per SA | Held-out runs |
| Mode, PFS | Accuracy, confusion matrix | Held-out configurations |
| Traffic type | Macro F1, per-class recall, confusion matrix | Held-out runs, held-out configurations, held-out implementation |
| Confidence | Expected calibration error, reliability plot | All inferred attributes |
| Scoring | Identical output on re-run, same band across repeats | Repeated captures of fixed configurations |
| Active probing | Accepted-proposal set matches the endpoint's configured proposals | Testbed endpoints |
| Speed | Seconds per 100 MB | Largest captures |

Rules for honest numbers, following the warning in the SoK paper the report cites as reference 11:
- Split by run and by configuration. Never split packets or windows from one run across train and test.
- Check for leakage: the traffic classifier must not be able to key on cipher overhead, and the mode classifier must not be able to key on which hosts appear. Test by holding those out.
- Always report the simple baseline next to the model.
- Report the held-out implementation result even if it is poor. That number is the one that says whether the model learned IPsec or learned strongSwan.

## 8. Risks

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Containers cannot do kernel IPsec on the available machines (Windows, macOS or WSL2 hosts) | Medium | High | Test in week 1. Fall back to Linux virtual machines, a native Linux host, or strongSwan's userspace IPsec plugin. |
| R2 | Mode or PFS inference does not reach target accuracy | Medium | Medium | Report the measured number with calibrated confidence and fall back to Unknown. A negative result with honest evaluation is still a contribution. |
| R3 | Model learns testbed artefacts and fails on other implementations | High | High | Network condition variation, second implementation, held-out splits, leakage tests |
| R4 | Evaluators see deterministic parsing as "not AI" | Medium | Medium | Lead with the evidence-level table. Show the three places ML is necessary. |
| R5 | Weak algorithms needed for negative examples are disabled in current VPN software builds | Medium | Medium | Check in week 2. Keep an older image for legacy cases, or craft those handshakes with Scapy. |
| R6 | Dataset generation takes longer than planned | Medium | Medium | Two-corpus design, unattended runs, freeze v1 at week 6 with whatever is complete and extend later |
| R7 | Real tunnels carry mixed traffic, lab runs carry one application | High | Medium | State the limit. Add mixed runs as a stretch. Predict per time window, not per SA. |
| R8 | Scope creep from active probing, live capture and LLM narrative | High | Medium | All three are scheduled after M4 and are first to be cut |
| R9 | Active probing used against unauthorised targets | Low | High | Allowlist, authorisation flag, rate limit, logging, clear statement in the documentation |
| R10 | Three people, sixteen weeks, exams in between | High | High | Demo cut at M3, explicit cut order in section 4, weekly check against milestones |
| R11 | Key lifetime cannot be assessed from short captures | High | Low | Report as Unknown with the capture duration needed. Short lifetimes in lab runs. |

## 9. Working agreements

- One weekly sync against the milestone table. Update the checkboxes in this file in the same commit as the work.
- Every module has tests. The parser and the scoring path have golden files.
- Captures stay out of git. The manifest and the scripts that regenerate them go in.
- No finding without a rule ID, no rule without a reference.
- Changes to the session record schema need all three owners to agree.

## 10. Hardware and software needed

- One Linux machine (or VM) with 16 GB RAM and 50 GB free disk for the testbed and captures
- No GPU required for the Random Forest baseline. A GPU or a free cloud notebook only if the CNN comparison goes ahead.
- All software is open source: strongSwan, Libreswan, Docker, tcpdump, Wireshark, Scapy, scikit-learn, PyTorch, Streamlit

## 11. Decisions needed

| ID | Decision | Recommendation | Owner | Due |
|---|---|---|---|---|
| D1 | Adopt the evidence-level model (Observed, Inferred, Assisted, Unknown) | Yes. It resolves the conflict between the report and the deck. | Team and guide | Week 1 |
| D2 | Is active IKE probing in scope | Yes, as phase 7, enumeration first | Team and guide | Week 1 |
| D3 | Standards baseline | NIST SP 800-77 Rev. 1, RFC 8247, RFC 8221, RFC 9395 | Team | Week 1 |
| D4 | Dashboard stack | Streamlit first. Move to an API plus front end only if a sixth-person front-end skill is available. | Track C | Week 2 |
| D5 | Is IKEv1 in scope | Yes. It is deprecated, so detecting it is itself a finding, and it exposes more in cleartext. | Team | Week 1 |
| D6 | Is the dataset released publicly | Decide before the datasheet is written | Team and guide | Week 5 |
| D7 | Project short name | Pick one for the repository, dashboard and reports | Team | Week 1 |
| D8 | Is a local language model used for report narrative | Defer until after M4 | Track C | Week 10 |

## 12. Deliverables checklist

| Deliverable (SIH26160 and PBL) | Produced in | Done |
|---|---|---|
| Working software prototype | Phases 2 to 6 | [ ] |
| VPN testbed | Phase 1 | [ ] |
| Training and testing datasets, with datasheet | Phase 3 | [ ] |
| AI classification engine | Phase 4 | [ ] |
| Security assessment engine | Phase 5 | [ ] |
| Interactive dashboard | Phase 6 | [ ] |
| Executive and technical security reports | Phase 6 | [ ] |
| Active IKE probing module | Phase 7 | [ ] |
| Technical documentation | Phase 8 | [ ] |
| Demonstration video | Phase 8 | [ ] |
| Final PBL report and presentation | Phase 8 | [ ] |

## 13. Fixes to the existing documents

Do these in phase 0 so all three say the same thing.

**PBL draft report**
- [ ] Objective 2: change "AI engine that can work out IPsec settings" to a deterministic parser for cleartext IKE fields plus an inference engine for encrypted parameters
- [ ] Section 6, AI Protocol Identification Engine: same change, and add the evidence levels
- [ ] Section 6, Security Assessment: name the standards baseline
- [ ] Section 6, Evaluation approach: add the numeric targets and the held-out splits
- [ ] State that ESP key length is not recoverable passively
- [ ] Explain how key lifetime and replay protection are observed
- [ ] Add messaging to the traffic types
- [ ] References: add ike-scan, iker, strongSwan, Libreswan, NIST SP 800-77 Rev. 1 and the RFCs. They are relied on in the text but not cited.
- [ ] References 3 and 9 have no authors. Complete them.

**Deck**
- [ ] Slide 4, objective 02: mode and PFS are not read from cleartext for ESP. Reword to "Parse IKE deterministically: version, IKE cipher suite, DH group".
- [ ] Slide 4: add an objective for active probing, or remove it from slide 3
- [ ] Slide 5: add the active prober to the architecture if it stays in scope
- [ ] Slide 6: replace the two-track picture with the evidence levels, and move mode and PFS to the "learned" side
- [ ] Slide 8: add RFC 8221 and RFC 9395 beside NIST SP 800-77 and RFC 8247
- [ ] Slide 9: add the testbed and the active probing module to the deliverables
- [ ] Add a slide with measurable targets and a slide with the timeline

**Synopsis**
- [ ] Align the objectives and architecture with the report and deck, or retire it in favour of VISION.md

## 14. First seven days

1. Fill in key dates and owners (sections 2 and 5).
2. Take decisions D1, D2, D3, D5 and D7 to the guide.
3. Prove kernel IPsec works on the testbed machine: bring up one strongSwan IKEv2 tunnel between two containers, ping across it, capture it, open it in Wireshark.
4. Create the repository and commit VISION.md, PLAN.md and the session record schema.
5. Hand-write one session record for that capture. That file is the first test fixture.
6. Start the IKEv2 IKE_SA_INIT parser against that capture.
7. Apply the document fixes in section 13.

## 15. References

Standards baseline:
- NIST SP 800-77 Rev. 1, Guide to IPsec VPNs: https://doi.org/10.6028/NIST.SP.800-77r1
- RFC 7296, IKEv2: https://www.rfc-editor.org/rfc/rfc7296.html
- RFC 8247, algorithm requirements for IKEv2: https://www.rfc-editor.org/rfc/rfc8247.html
- RFC 8221, algorithm requirements for ESP and AH: https://www.rfc-editor.org/rfc/rfc8221.html
- RFC 9395, deprecation of IKEv1 and obsoleted algorithms: https://www.rfc-editor.org/rfc/rfc9395.html
- RFC 4301 (architecture), RFC 4302 (AH), RFC 4303 (ESP), RFC 2409 (IKEv1), RFC 3948 (ESP in UDP), RFC 4106 (AES-GCM in ESP), RFC 7383 (IKEv2 fragmentation), RFC 8784 and RFC 9370 (post-quantum measures for IKEv2)

Tools:
- strongSwan save-keys plugin: https://docs.strongswan.org/docs/5.9/plugins/save-keys.html
- ike-scan: https://github.com/royhills/ike-scan

Problem statement:
- SIH26160 as listed on an unofficial problem statement explorer: https://sih-explorer.amanuniyal47.workers.dev/problem/SIH26160 (verify wording against the official SIH portal)

Project documents analysed: the synopsis, the PBL draft report (including its 15 literature references), and the presentation deck.
