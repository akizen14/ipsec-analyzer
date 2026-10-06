# Decisions log

PLAN.md section 11 lists eight decisions. This records what was decided, by
whom, and what is still provisional, so the guide can accept or reject each one
explicitly.

**Status key:** *provisional* means implemented to the PLAN.md recommendation and
awaiting sign-off from Dr. Nayak; *settled* means confirmed.

| ID | Decision | Outcome | Status | Where it shows up |
|---|---|---|---|---|
| D1 | Adopt the evidence-level model | Yes | provisional | `analyzer/record/attribute.py`, enforced in code |
| D2 | Active IKE probing in scope | Yes, as phase 7 | provisional | `analyzer/probe/` reserved; rule ACT-001 not yet in the catalogue |
| D3 | Standards baseline | NIST SP 800-77 Rev. 1, RFC 8247, RFC 8221, RFC 9395 | provisional | `analyzer/rules/catalogue/baseline.yaml` |
| D4 | Dashboard stack | Streamlit with Plotly | provisional | `app/` reserved, built in phase 6 |
| D5 | IKEv1 in scope | Yes | provisional | registries present in `transforms.py`; parser is phase 4 |
| D6 | Dataset released publicly | not yet decided | open | due before the datasheet, week 5 |
| D7 | Project short name | `ipsec-analyzer`, package `analyzer` | settled | `pyproject.toml` |
| D8 | Local language model for report narrative | deferred | open | revisit after M4 |

## Decisions taken while building, not in PLAN.md section 11

These came up in implementation. Each is recorded because a future reader will
otherwise wonder why the code does what it does.

### Rule conditions live in Python, not YAML

PLAN.md phase 5 says a rule catalogue entry carries its "condition on the
session record". The catalogue holds everything tunable (severity, wording,
standard reference, remediation, scoring weight), but the predicate lives in
`analyzer/rules/engine.py`.

A declarative condition language in YAML was considered and rejected: the
conditions have to reason about evidence levels and confidence, and expressing
that in YAML would make it neither readable nor testable. So metadata in YAML,
logic in Python, one rule ID joining them. The team can still retune severities
and rewrite remediation text without touching code, which was the point of
putting the catalogue in YAML at all.

### Risk level follows the worst finding, not the score band

PLAN.md phase 5 says risk follows the worst finding. Deriving it from the score
was tried first, and produced a report reading CRITICAL on a capture whose worst
finding was High: eight lesser findings summed to a score of 16, which lands in
the Critical band. A report that says Critical while no finding is Critical
cannot answer the obvious question, which one, so it breaks the
explainable-scoring principle in VISION.md.

The two numbers now say different things and both are reported. Risk names the
most severe single problem and always points at a finding. The score carries the
aggregate, so a pile of lesser findings shows up there instead.

### One session record per endpoint pair, not per IKE SA

An operator thinks of one VPN between two gateways. A capture long enough to
contain an IKE SA rekey holds two or more IKE SAs for that one VPN with
unrelated SPIs, and emitting a record each would report the same deployment
several times over, most of them nearly empty.

The consequence: a rekeyed IKE SA cannot be linked to its parent from the wire,
because the rekey is negotiated inside an encrypted CREATE_CHILD_SA exchange. So
the link is Inferred from timing and endpoints at confidence 0.85, and the SA
carrying a readable IKE_SA_INIT is the one whose configuration gets reported.

### ESP key length is reported Unknown, always

All three source documents list AES-128 against AES-256 as something to
identify. It is not recoverable from a capture: the two differ in round count,
not in block or output size, so they produce byte-for-byte indistinguishable ESP
payloads. VISION.md section 12 row 3 settles this, and
`analyzer/inference/esp_structure.py::key_length_attribute` implements it.

Worth being ready to defend at a review. A tool that claims to tell them apart
from ciphertext is reporting an artefact of its training data.

### The ESP residue inference abstains on uniform traffic

The length-residue argument separates cipher modes only when the traffic carries
a spread of plaintext sizes. A flow of identically sized packets, which is what
a constant-rate ping or a VoIP stream looks like, lands on one residue whatever
cipher is in use.

Concluding AES-CBC from that would read a property of the traffic as a property
of the cipher. It would also often be right by luck, which is worse, because the
same logic reports AES-CBC for an AES-GCM tunnel carrying VoIP. So the inference
requires at least 4 distinct payload lengths and 20 packets before it answers,
and the two golden captures exist to test both paths: one abstains, one
concludes.

## Findings from the build worth carrying forward

### Risk R1 is retired: kernel IPsec works in Docker on Windows

The WSL2 kernel (6.6.114.1) has `CONFIG_XFRM=y` built in and ships
`CONFIG_INET_ESP`, `CONFIG_INET_AH` and `CONFIG_NET_KEY` as modules that are not
loaded at boot. A container cannot `modprobe` for itself, so
`scripts/testbed-bootstrap.sh` loads them once into the Docker VM through a
privileged `nsenter` container. After that, ordinary containers with
`CAP_NET_ADMIN` install xfrm states and policies normally, and the peers
themselves never need privileged mode.

### strongSwan bypass-lan silently defeats a single-bridge lab

`bypass-lan` installs xfrm pass policies for every directly connected subnet, at
a numerically lower, and so higher, priority than the connection policy:

```
src 10.80.0.0/24 dst 10.80.0.0/24  dir out  priority 175423   <- bypass wins
src 10.80.0.2/32 dst 10.80.0.3/32  dir out  priority 367231   <- ESP policy
```

On a real gateway that is correct behaviour. In a lab where both peers sit on one
bridge it means IKE completes, the SAs install, and not one packet is encrypted.
The first capture taken here had a perfect handshake and zero ESP bytes.

That is the worst kind of wrong for a labelled dataset, because the capture looks
almost right. Now disabled in `testbed/strongswan-testbed.conf`.

### Alpine does not build the save-keys plugin

PLAN.md phase 1 wants session keys exported per run, so Wireshark can decrypt and
the labels can be verified independently. Alpine strongSwan 5.9.13 is not built
with `--enable-save-keys`, so this needs strongSwan from source.

Not blocking: manifest labels come from the same parameter set that renders the
configuration, which PLAN.md treats as authoritative. It does block independent
verification of those labels, which is a real gap to close before dataset v1 is
frozen.

### Two parser bugs that real captures found and hand-built packets did not

1. **The IKEv2 Encrypted payload ends the outer chain.** Its Next Payload field
   names the first payload *inside* the ciphertext, not a sibling. Walking past
   it lands at the end of the message and reports a truncation that is not there.
   Every SK-bearing message in the first capture carried a false defect.

2. **There can be several IKE_SA_INIT responses.** When the initiator offers a key
   exchange group the responder will not take, the responder sends a bare
   `INVALID_KE_PAYLOAD` notify and the exchange restarts. Only the final response
   carries an SA payload, so taking the first reads the rejection and concludes
   nothing was agreed. This appeared immediately on the weak-config capture,
   where the responder supported only DH group 2.

Both are now covered by tests. The second also produces a useful warning: a
rejected group means the group finally used was the responder choice rather than
the initiator preference, which is worth checking against policy.
