# ipsec-analyzer

AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework.

Give it a capture file and it returns a defensible verdict on the IPsec VPN
behind it: what is configured, how we know, how sure we are, what is weak, and
what to change.

**SIH26160** (National Technical Research Organisation) and a B.Tech CSIT
(Cybersecurity) final-year PBL project.
Team: Chaitanya Sawant, Vansh Jangra, Aditya Sonawane. Guide: Dr. Chaya Nayak.

Read [VISION.md](VISION.md) for what is being built and why, and
[PLAN.md](PLAN.md) for how and when.

## The one idea worth knowing

IPsec exposes different parameters in different ways, so every attribute this
tool reports carries the evidence behind it:

| Level | Meaning | Confidence |
|---|---|---|
| **Observed** | Read from a cleartext protocol field by a deterministic parser | Certain, cites the packet |
| **Inferred** | Derived from the metadata of encrypted traffic | A stated probability, with the features that drove it |
| **Assisted** | Read from material the operator supplied | Certain, names the source |
| **Unknown** | Not determinable from the available evidence | Said plainly, and excluded from the score |

> Parse what the protocol shows in cleartext. Infer what it hides.
> Say "unknown" when neither is possible. Never present an inference as an
> observation.

That rule is enforced in code, not by convention: `Attribute` has no public
constructor, and each of its four builders demands the proof its level requires.
See `analyzer/record/attribute.py`.

Unknowns never cost score points. They lower a separate **coverage** figure
reported beside the score, so a capture that revealed little reads as incomplete
rather than as clean.

## Quick start

```sh
python -m venv .venv
. .venv/Scripts/activate        # Windows; use .venv/bin/activate on Linux
pip install -e ".[dev]"

ipsec-analyzer analyse tests/golden/ikev2-3des-sha1-dh2-downgrade.pcapng --out results/
```

Output:

```
  weak-config-01  10.80.0.2 -> 10.80.0.3
    score 16/100   risk HIGH   coverage 48% (10/21 attributes)
    suite  IKEv2 ENCR_3DES / AUTH_HMAC_SHA1_96 / DH2
    findings:
      !  ESP-010  A 64-bit block cipher is in use on ESP (60% confidence)
      !  IKE-011  3DES encryption negotiated for the IKE SA
      !  IKE-031  A weak key exchange group was negotiated
      ~  IKE-040  The responder selected a weaker proposal than the strongest offered
      ...
```

Other commands:

```sh
ipsec-analyzer inspect capture.pcapng       # what the ingest stage found
ipsec-analyzer rules                        # the rule catalogue
ipsec-analyzer analyse c.pcapng --fail-on high   # exit 2 to gate a pipeline
```

## Pipeline

```
pcap -> [ingest] -> [session builder] -> [IKE parser]      (Observed)
                                      -> [ESP/AH analyzer] (Observed)
                                      -> [inference]       (Inferred)
                            |
                            v
                   session record (JSON, one per endpoint pair)
                            |
              [rule engine] -> findings -> [scoring + threat matrix]
                            |
                  [dashboard]   [report generator]
```

The session record (`dataset/schemas/session_record.schema.json`) is the
contract between the analysis half and the product half. The dashboard and the
report generator read nothing else, so a report cannot disagree with the record
it came from.

## Testbed

Two strongSwan peers in Docker with a capture point, producing captures whose
configuration is known exactly.

```sh
sh scripts/testbed-bootstrap.sh                          # once per Docker restart
docker compose -f testbed/compose/ikev2-basic.yml up -d   # healthy config
docker compose -f testbed/compose/ikev2-weak.yml up -d    # weak config
```

The bootstrap step exists because the WSL2 kernel has `CONFIG_XFRM=y` built in
but ships ESP, AH and PF_KEY as modules that are not loaded at boot. A container
cannot `modprobe` for itself, so one privileged container loads them into the
Docker VM; after that, ordinary containers with `CAP_NET_ADMIN` install xfrm
states normally.

**Known issue:** Alpine does not build the strongSwan `save-keys` plugin, so
independent key-based label verification (PLAN.md phase 1) needs strongSwan
built from source. Manifest labels still come from the config generator, which
PLAN.md treats as authoritative.

## Tests

```sh
pytest -q                     # all of it
pytest -q tests/test_golden.py   # end-to-end against known-configuration captures
ruff check analyzer/ reports/ tests/
```

The golden captures in `tests/golden/` are committed deliberately as test
oracles, and their expected values come from what strongSwan reported when each
tunnel came up rather than from analyzer output. So the tests check the analyzer
against reality, not against itself.

## Scope

**In scope:** offline analysis of IKEv1 and IKEv2 captures, ESP and AH, hidden
parameter inference, traffic-type classification, a rule-based assessment
against a named standards baseline, scoring, a dashboard, and both reports.

**Not goals:** decrypting traffic or recovering keys; exploiting anything;
WireGuard, OpenVPN or SSL VPN; probing any system the operator is not authorised
to test.

Standards baseline: NIST SP 800-77 Rev. 1, RFC 8247, RFC 8221, RFC 9395.

## Authorised use only

Captures must come from networks you are permitted to monitor. The active
probing module (phase 7) requires a target allowlist and an explicit
authorisation flag, and logs every probe.
