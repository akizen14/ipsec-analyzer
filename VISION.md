# VISION

**Project:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
**Problem statement:** SIH26160, National Technical Research Organisation (NTRO), Software category, theme "Blockchain & Cybersecurity"
**Also submitted as:** Final Year Project (PBL), B.Tech Computer Science & IT (Cybersecurity)
**Team:** Chaitanya Sawant, Vansh Jangra, Aditya Sonawane
**Guide:** Dr. Chaya Nayak
**Last updated:** 2026-10-06
**Companion document:** PLAN.md (how and when this gets built)

This document was written after reading the three existing project documents (the synopsis, the PBL draft report, and the presentation deck) and the published SIH26160 problem statement. Where it goes beyond those documents, the addition is listed in section 12 so the team and guide can accept or reject it explicitly.

---

## 1. The vision in one sentence

Give a security analyst a capture file or an authorised target, and return a defensible verdict on the IPsec VPN behind it: what is configured, how we know, how sure we are, what is weak, and what to change.

## 2. The problem

IPsec protects the links that enterprises, government, military and cloud platforms rely on. Its real strength is decided by configuration: cipher, integrity algorithm, authentication method, key exchange group, operating mode, key lifetime, and whether Perfect Forward Secrecy is on. A deployment that looks correctly set up can be quietly weak.

Three things make this hard today, as the project's own literature review establishes:

1. **Packet tools stop at the packet.** Wireshark and tcpdump show what is on the wire. Turning that into "this deployment is unsafe, and here is why" still needs an IPsec expert.
2. **Machine-learning research stops at "VPN or not".** The 15 papers in the literature review cover VPN detection, application and traffic-type classification, and surveys of that field. None of them recovers the IPsec configuration itself.
3. **Active scanners stop at the fingerprint.** ike-scan and iker identify vendors from fixed signature lists. They do not learn, and they are not combined with traffic analysis.

No existing tool joins these into one pipeline that ends in a risk score, a threat matrix and a confidence figure an analyst can act on. Checking VPN endpoints by hand does not scale across an organisation that runs many of them.

## 3. Who it is for

| User | What they need from the tool |
|---|---|
| Security analyst or auditor | A fast, repeatable assessment of an IPsec deployment from a capture, with evidence behind every finding |
| Network or VPN administrator | A concrete list of what to change in the configuration, in priority order |
| Security manager | A one to two page executive view: overall posture, top risks, trend across endpoints |
| Researcher | A labelled IPsec dataset and a reproducible testbed that the field currently lacks |

Deployment context: lab testbed first, then real traffic that the user is authorised to capture, in enterprise, government, cloud or research environments.

## 4. What the product does

1. **Ingest** a pcap or pcapng file (later: a live interface), or actively probe an authorised IKE endpoint.
2. **Reconstruct** IKE exchanges and ESP or AH security associations from the packets.
3. **Identify** the configuration: IKE version and exchange type, IKE cipher suite, DH group, authentication method where visible, ESP or AH protection, operating mode, PFS behaviour, rekey behaviour, and the type of traffic carried inside the tunnel.
4. **Assess** the identified configuration against a named standards baseline and produce findings.
5. **Score** the deployment and build a threat matrix.
6. **Report** through an interactive dashboard, an executive report and a technical report, each carrying confidence information.

## 5. The core design idea: every fact carries its evidence

The three source documents disagree about how the configuration is identified. The synopsis and the report say an AI engine predicts it. The deck says IKE is parsed deterministically and machine learning is used only for encrypted ESP. Neither is fully right, because IPsec exposes different parameters in different ways. This project adopts one rule that settles it:

> Parse what the protocol shows in cleartext. Infer what it hides. Say "unknown" when neither is possible. Never present an inference as an observation.

Every attribute the tool reports is tagged with one of four evidence levels:

| Evidence level | Meaning | How confidence is expressed |
|---|---|---|
| **Observed** | Read directly from cleartext protocol fields by a deterministic parser | Certain, with the packet number as proof |
| **Inferred** | Derived from metadata of encrypted traffic (sizes, timing, residues) by statistics or a trained model | Calibrated probability, with the features that drove it |
| **Assisted** | Read from material the user supplied: session keys exported from an endpoint, or a configuration file | Certain, with the source named |
| **Unknown** | Not determinable from the evidence available | Stated plainly, and excluded from the score rather than assumed safe |

This is what gives the "AI confidence score" in the problem statement a real meaning. It is also the honest answer to the question an evaluator will ask: "IKE is cleartext and Wireshark already dissects it, so where is the AI?"

### 5.1 What is actually visible on the wire

This table is the technical foundation of the project. It corrects one statement in the deck (slide 6 says mode, cipher, DH group and PFS are "read directly from the SA proposal"), which holds for the IKE SA but not for the ESP child SA.

| Parameter | IKEv2 | IKEv1 | Evidence level |
|---|---|---|---|
| IKE version, exchange type | Cleartext header | Cleartext header (Main or Aggressive) | Observed |
| IKE SA cipher, key length, PRF, integrity | Cleartext in IKE_SA_INIT (offered and selected) | Cleartext in Phase 1 SA payload | Observed |
| DH group for the IKE SA | Cleartext in IKE_SA_INIT | Cleartext in Phase 1 | Observed |
| Authentication method (PSK, certificate) | Inside encrypted IKE_AUTH | Cleartext SA attribute in Phase 1 | IKEv1 Observed, IKEv2 Unknown or Assisted |
| Peer identities | Encrypted | Cleartext in Aggressive Mode only | Observed in Aggressive Mode, itself a finding |
| IKE SA lifetime | Not negotiated at all (local policy) | Cleartext SA attribute in Phase 1 | IKEv1 Observed, IKEv2 Inferred from rekey timing |
| Vendor ID payloads, NAT traversal detection | Cleartext | Cleartext | Observed |
| Post-quantum support notifications (RFC 8784, RFC 9370) | Cleartext in IKE_SA_INIT | Not applicable | Observed |
| ESP or AH in use, SPI, sequence numbers | Cleartext ESP and AH headers | Same | Observed |
| ESP cipher family and ICV size | Child SA proposal is encrypted | Quick Mode is encrypted | Inferred from ESP length residues |
| ESP key length (AES-128 versus AES-256) | Encrypted | Encrypted | **Unknown passively.** Ciphertext does not reveal key size. Assisted only. |
| Tunnel versus Transport mode (ESP) | Transport-mode notification is encrypted | Encapsulation attribute is encrypted | Inferred from packet-size overhead and flow structure |
| Tunnel versus Transport mode (AH) | AH does not encrypt, so the next-header field shows it | Same | Observed |
| PFS on child SA rekey | Rekey exchange is encrypted, but its message size reveals whether a key-exchange payload is present | Same idea for Quick Mode | Inferred, needs a rekey in the capture |
| Child SA lifetime | Not negotiated | Encrypted | Inferred from observed SPI change interval |
| Anti-replay | Sequence numbers are visible, enforcement is receiver-side | Same | Evidence only: monotonic sequence, duplicates seen or not |
| Traffic type inside ESP | Never visible | Never visible | Inferred by the ML classifier |
| Which proposals a responder will accept | Not visible passively | Not visible passively | Observed by active probing |

Two consequences the team should be ready to defend:

- The tool will sometimes say "unknown". That is a feature. A tool that claims to tell AES-128 from AES-256 by looking at ESP ciphertext is reporting an artefact of its training data.
- Active probing is not a side feature. It is the only way to learn what a gateway would accept, as opposed to what one session happened to negotiate.

## 6. Where AI is used, and where it is deliberately not

**Not used:** parsing IKE headers and proposals, checking algorithms against standards, computing the score. These are deterministic so they are exact, explainable and repeatable.

**Used:**

1. **Encapsulated traffic-type classification.** Predicting web, VoIP, email, messaging, video or ICMP inside an ESP tunnel from packet sizes, timing, direction and burst patterns. Random Forest baseline first, a 1D CNN only if it clearly wins on held-out data.
2. **Hidden-parameter inference.** Recovering ESP cipher family, operating mode and PFS behaviour from encrypted traffic metadata, where no cleartext exists.
3. **Calibrated confidence.** Making the reported probability mean what it says, and abstaining to "unknown" below a threshold.
4. **Learned implementation fingerprinting (stretch).** Replacing fixed signature lists with a model over IKE response behaviour and retransmission timing.
5. **Report narrative (optional stretch).** A locally hosted language model may phrase the executive summary from the structured findings. It never produces a finding or a number.

## 7. Scope

### In scope for the first complete version

- Reproducible IPsec testbed covering Tunnel and Transport mode, AES-128, AES-256, AES-GCM, AES-CBC with HMAC, multiple DH groups, PFS on and off, IPv4 and IPv6, ESP and AH, IKEv1 and IKEv2
- Labelled dataset with a machine-written manifest, including deliberately weak configurations
- Offline analysis of capture files
- Deterministic IKEv1 and IKEv2 parser
- ESP and AH analyzer with hidden-parameter inference
- Traffic-type classifier with calibrated confidence
- Rule-based security assessment against a named baseline
- Security score, risk level, threat matrix, per-finding confidence
- Interactive web dashboard
- Executive and technical reports
- Technical documentation and a demonstration video

### Stretch

- Active IKE probing module (the report lists it as objective 3; see section 12, row 4, for the decision needed)
- Live capture mode
- Second and third IPsec implementations in the testbed for generalisation tests
- Mixed-traffic tunnels (several applications in one SA)
- Post-quantum readiness checks
- Fleet view across many endpoints

### Not goals

- Decrypting traffic or recovering keys. The tool reads metadata only, unless the user supplies keys from their own endpoint.
- Exploiting weaknesses. The tool reports them.
- WireGuard, OpenVPN, SSL VPN or other non-IPsec protocols.
- Probing any system the operator is not authorised to test.
- Replacing a full configuration audit. Parameters that never appear on the wire need the device configuration.

## 8. What makes this different

| Compared with | What they do | What this project adds |
|---|---|---|
| Wireshark, tcpdump | Dissect packets | A verdict, a score, a remediation list, and inference for what is encrypted |
| ML traffic classifiers in the literature | VPN versus non-VPN, application identity | Configuration-level inference specific to IPsec, with calibrated confidence |
| ike-scan, iker | Vendor fingerprint from fixed signatures | Combined with passive analysis, and assessed against a standards baseline |
| Public datasets (ISCX VPN-nonVPN, VNAT) | App-level and VPN-level labels | Labels for cipher, mode, DH group, PFS, IP version and traffic type |

A quick look at public repositories for the same problem statement shows that most entries implement IKE parsing, a rule-based score and a dashboard. The places where this project can stand apart are therefore: a real testbed with a properly labelled dataset, honest evaluation of inference on held-out configurations, the evidence-level model, and active probing.

## 9. What success looks like

Targets below are proposed starting points. Revisit them once the first baseline numbers exist.

| Area | Measure | Proposed target |
|---|---|---|
| IKE parsing | Exact match with testbed ground truth on every cleartext field | 100 percent. Any miss is a bug. |
| ESP cipher family and ICV size | Correct per SA on held-out runs | 95 percent or better |
| Mode inference (ESP) | Accuracy on held-out configurations | 90 percent or better |
| PFS at rekey | Accuracy on runs containing a rekey | 90 percent or better |
| Traffic type | Macro F1 on held-out runs | 0.85 or better |
| Generalisation | Drop in macro F1 on an IPsec implementation never seen in training | No more than 10 points |
| Confidence quality | Expected calibration error on inferred attributes | 0.05 or lower |
| Score repeatability | Same capture analysed twice | Identical score and findings |
| Score stability | Same configuration captured on different runs | Same risk band every time |
| Speed | 100 MB capture to both reports on a laptop | Under 2 minutes |
| Usability | A reader without IPsec packet expertise can state the top three risks from the executive report | Yes, checked with two to three test readers |

## 10. Principles

1. **Evidence before claims.** Every reported attribute carries its evidence level and source packets.
2. **Deterministic first.** Use a model only where a parser cannot reach.
3. **Unknown is an answer.** Never fill a gap with a guess, and never score an unknown as secure.
4. **Explainable scoring.** Every point lost traces to a rule, and every rule traces to a standard.
5. **Honest evaluation.** Split by capture run and by configuration, never by packet. Test on configurations and implementations the model has not seen.
6. **Works offline.** No cloud calls. Suitable for an air-gapped environment.
7. **Authorised use only.** Captures come from networks the user may monitor. Active probing has an explicit target allowlist and rate limit.
8. **Reproducible.** Testbed, dataset and results can be regenerated from the repository.

## 11. How this maps to the SIH26160 requirements

| Problem statement requirement | Covered by |
|---|---|
| A. VPN testbed (modes, AES variants, DH groups, PFS, IPv4/IPv6, traffic types) | Testbed and orchestrator |
| B. Traffic acquisition (IKE, ESP, AH, normal traffic) | Capture module and dataset manifest |
| C. AI protocol identification (protocol, IKE version, modes, algorithms, key exchange, encapsulated traffic type) | IKE parser (Observed) plus inference engine and classifier (Inferred) |
| D. Security assessment (crypto strength, compliance, key lifetime, replay, PFS, cipher suite) | Rule engine against the standards baseline |
| E. Reports (score, traffic analysis, metadata inference, executive and technical reports, risk score, threat matrix, confidence) | Scoring, threat matrix, dashboard, report generator |
| Deliverables: prototype, AI engine, dashboard, reports, video, documentation, datasets | All in scope, see PLAN.md section 12 |

One gap to close: the problem statement lists **messaging** as a traffic type. The team's documents list ICMP in its place. Generate both.

## 12. What this document adds to, or changes in, the source documents

These need a yes or no from the team and the guide.

| # | Topic | What the documents say | What this vision decides |
|---|---|---|---|
| 1 | Who identifies IKE parameters | Synopsis and report: the AI engine predicts them. Deck: a deterministic parser reads them. | Deterministic parser. Update report objective 2 and the synopsis to match the deck. |
| 2 | What the parser can reach | Deck slides 4 and 6: mode, cipher, DH group and PFS come straight from the SA proposal. | True for the IKE SA only. ESP cipher, mode and PFS are encrypted and must be inferred. Adopt the evidence levels in section 5. |
| 3 | AES-128 versus AES-256 on ESP | All three list both as things to identify. | Observed for the IKE SA. Unknown for ESP unless assisted. State this openly. |
| 4 | Active IKE probing | Absent from the synopsis. Objective 3 in the report. On the deck's gap slide but missing from its objectives, architecture and deliverables. | Keep it, as a later phase, focused first on which proposals a responder accepts and on Aggressive Mode. Vendor fingerprinting second. |
| 5 | Standards baseline | Only the deck names any (NIST SP 800-77, RFC 8247). | Named baseline: NIST SP 800-77 Rev. 1, RFC 8247 (IKEv2), RFC 8221 (ESP and AH), RFC 9395 (IKEv1 deprecation). RFC 8247 alone does not cover ESP. |
| 6 | Key lifetime and replay protection | All three list them as checks. None says how they are observed. | Lifetime is inferred from rekey intervals (IKEv2 does not negotiate it). Replay is reported as sequence-number evidence, not as a setting. |
| 7 | Traffic types | Web, ICMP, VoIP, email, video. | Add messaging to match the problem statement. |
| 8 | Number of objectives | Nine in the synopsis, five in the report, four in the deck. | One canonical list, in section 4 and section 7 of this document. |
| 9 | Measurable targets | None in any document. | Section 9. |
| 10 | Confidence score | Named everywhere, defined nowhere. | Evidence level plus calibrated probability, section 5. |
| 11 | Live traffic | Mentioned in synopsis and report, not in the deck. | Stretch, after offline analysis works. |
| 12 | Ethics and authorisation | "Authorised network traffic" appears once in the report. | Made a principle, with technical guard rails on active probing. |

## 13. Longer-term direction

If the core works, the natural extensions are: continuous monitoring of a fleet of gateways with drift alerts when a configuration weakens, importing device configurations to close the "unknown" gaps, post-quantum readiness reporting, and releasing the dataset and testbed for other researchers.
