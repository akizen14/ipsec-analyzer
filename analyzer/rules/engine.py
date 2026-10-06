"""The rule engine: turn a session record into findings.

Deterministic throughout. No rule consults a model, and the same record always
produces the same findings in the same order, which is what makes the
repeatability requirement in PLAN.md section 7 achievable.

Two invariants hold across every predicate here, and both come straight from
VISION.md principle 3:

**A rule never fires on an Unknown.** An attribute the analysis could not
determine is not evidence of weakness any more than it is evidence of strength.
Unknowns lower coverage; they never create findings and never cost score points.
Every predicate therefore tests ``is_known`` before reading a value.

**A finding is never surer than its evidence.** ``Finding.from_rule`` takes the
attributes the rule rested on and inherits the lowest confidence among them, so a
conclusion drawn from a 0.88-confidence inference is reported at 0.88.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from analyzer.ike import transforms as tf
from analyzer.record import Attribute, Finding, Proposal, SessionRecord

CATALOGUE_PATH = Path(__file__).parent / "catalogue" / "baseline.yaml"

#: Approximate work factor in bits of each encryption transform, for comparing
#: the strength of one proposal against another. Not a policy judgement: the
#: policy lives in the catalogue, these numbers only order the suites.
ENCR_STRENGTH_BITS: dict[str, int] = {
    "ENCR_NULL": 0,
    "ENCR_DES": 56,
    "ENCR_DES_IV32": 56,
    "ENCR_DES_IV64": 56,
    "ENCR_3DES": 112,
    "ENCR_IDEA": 128,
    "ENCR_CAST": 128,
    "ENCR_BLOWFISH": 128,
    "ENCR_RC5": 128,
}

#: Work factor of the integrity and PRF algorithms, by collision resistance.
INTEG_STRENGTH_BITS: dict[str, int] = {
    "AUTH_NONE": 0,
    "AUTH_HMAC_MD5_96": 64,
    "AUTH_HMAC_MD5_128": 64,
    "AUTH_KPDK_MD5": 64,
    "AUTH_HMAC_SHA1_96": 80,
    "AUTH_HMAC_SHA1_160": 80,
    "AUTH_DES_MAC": 56,
    "AUTH_AES_XCBC_96": 128,
    "AUTH_AES_CMAC_96": 128,
    "AUTH_HMAC_SHA2_256_128": 128,
    "AUTH_HMAC_SHA2_384_192": 192,
    "AUTH_HMAC_SHA2_512_256": 256,
    "AUTH_AES_128_GMAC": 128,
    "AUTH_AES_192_GMAC": 192,
    "AUTH_AES_256_GMAC": 256,
    "AEAD_INTEGRAL": 128,
    "PRF_HMAC_MD5": 64,
    "PRF_HMAC_SHA1": 80,
    "PRF_AES128_XCBC": 128,
    "PRF_AES128_CMAC": 128,
    "PRF_HMAC_SHA2_256": 128,
    "PRF_HMAC_SHA2_384": 192,
    "PRF_HMAC_SHA2_512": 256,
}

#: Transform names containing these substrings are the ones the catalogue calls
#: out by name. Matched on substring because IKEv1 and IKEv2 spell them
#: differently (ENCR_3DES against 3DES_CBC) and both must be caught.
DES_MARKERS = ("ENCR_DES", "DES_CBC")
TRIPLE_DES_MARKERS = ("3DES",)
MD5_MARKERS = ("MD5",)
SHA1_MARKERS = ("SHA1", "SHA_1")

#: Groups the catalogue names, by rule.
DH_GROUPS_MUST_NOT = frozenset({1, 22})
DH_GROUPS_SHOULD_NOT = frozenset({2, 5, 23, 24})

#: A proposal below this many bits in any component counts as weak for the
#: downgrade-surface rules.
WEAK_PROPOSAL_BITS = 112


@dataclass(slots=True)
class RuleHit:
    """One occurrence of a rule firing, with what it rested on."""

    #: Attributes the conclusion depends on. Their lowest confidence becomes the
    #: confidence of the finding.
    attributes: list[Attribute] = field(default_factory=list)
    #: JSON pointers into the record, so a reader can find the field.
    evidence: list[str] = field(default_factory=list)
    detail: str = ""


Predicate = Callable[[SessionRecord], list[RuleHit]]

#: Rule ID to predicate. Populated by the @rule decorator below.
PREDICATES: dict[str, Predicate] = {}


def rule(rule_id: str) -> Callable[[Predicate], Predicate]:
    """Register a predicate against a catalogue rule ID."""

    def wrap(fn: Predicate) -> Predicate:
        PREDICATES[rule_id] = fn
        return fn

    return wrap


@functools.lru_cache(maxsize=1)
def load_catalogue(path: str | None = None) -> dict[str, Any]:
    """Read and cache the rule catalogue."""
    target = Path(path) if path else CATALOGUE_PATH
    data = yaml.safe_load(target.read_text(encoding="utf-8"))

    missing = sorted(set(PREDICATES) - {r["id"] for r in data["rules"]})
    if missing:
        raise ValueError(f"predicates with no catalogue entry: {missing}")

    return data


def catalogue_entry(rule_id: str) -> dict[str, Any]:
    for entry in load_catalogue()["rules"]:
        if entry["id"] == rule_id:
            return entry
    raise KeyError(f"rule {rule_id} is not in the catalogue")


def _contains(name: str | None, markers: tuple[str, ...]) -> bool:
    return bool(name) and any(m in name for m in markers)


def encr_bits(encr: str | None, key_bits: int | None) -> int | None:
    """Work factor of an encryption transform, in bits.

    For AES the strength is the key length, which arrives as a separate
    transform attribute, so the two have to be read together. When AES carries
    no key length attribute the answer is genuinely unknown rather than 128:
    guessing the default here would quietly turn an Unknown into a finding.
    """
    if not encr:
        return None
    if encr in ENCR_STRENGTH_BITS:
        return ENCR_STRENGTH_BITS[encr]
    if "AES" in encr or "CAMELLIA" in encr:
        return key_bits
    if "CHACHA20" in encr:
        return 256
    return key_bits


def proposal_strength(p: Proposal) -> int | None:
    """The weakest link in a proposal, in bits, or None if it cannot be judged.

    A suite is only as strong as its weakest component, so this is a minimum
    over cipher, integrity and key exchange. Returning None when any component
    is unreadable keeps the comparison honest: a proposal that cannot be scored
    is left out of the comparison rather than treated as strong or weak.
    """
    parts: list[int] = []

    bits = encr_bits(p.encr, p.encr_key_bits)
    if bits is None:
        return None
    parts.append(bits)

    if p.integ:
        integ = INTEG_STRENGTH_BITS.get(p.integ)
        if integ is None:
            return None
        parts.append(integ)
    elif p.encr and tf.is_aead(p.encr):
        parts.append(128)

    if p.prf:
        prf = INTEG_STRENGTH_BITS.get(p.prf)
        if prf is not None:
            parts.append(prf)

    if p.dh_group is not None:
        dh = tf.dh_strength_bits(p.dh_group)
        if dh is None:
            return None
        parts.append(dh)

    return min(parts) if parts else None


# ------------------------------------------------------------------ predicates


@rule("IKE-001")
def _ikev1_in_use(r: SessionRecord) -> list[RuleHit]:
    v = r.ike.version
    if v is None or not v.is_known or v.value != "IKEv1":
        return []
    return [RuleHit([v], ["/ike/version"], "The exchange used IKEv1.")]


@rule("IKE-002")
def _aggressive_mode_psk(r: SessionRecord) -> list[RuleHit]:
    version, mode, auth = r.ike.version, r.ike.exchange_mode, r.ike.auth_method
    if not (version and version.is_known and version.value == "IKEv1"):
        return []
    if not (mode and mode.is_known and "AGGRESSIVE" in str(mode.value)):
        return []
    # The PSK half has to be Observed too. In IKEv1 it is a cleartext Phase 1
    # attribute, so when it is Unknown the capture did not show it and the rule
    # must stay silent rather than assume the worst case.
    if not (auth and auth.is_known and "PRE_SHARED" in str(auth.value)):
        return []
    return [
        RuleHit(
            [version, mode, auth],
            ["/ike/exchange_mode", "/ike/auth_method"],
            "Aggressive Mode was used with pre-shared key authentication, so the "
            "identity and a hash over the key were both sent in cleartext.",
        )
    ]


@rule("IKE-010")
def _des_on_ike(r: SessionRecord) -> list[RuleHit]:
    e = r.ike.encr
    if e is None or not e.is_known:
        return []
    name = str(e.value)
    if not _contains(name, DES_MARKERS) or _contains(name, TRIPLE_DES_MARKERS):
        return []
    return [RuleHit([e], ["/ike/encr"], f"The IKE SA negotiated {name}.")]


@rule("IKE-011")
def _triple_des_on_ike(r: SessionRecord) -> list[RuleHit]:
    e = r.ike.encr
    if e is None or not e.is_known or not _contains(str(e.value), TRIPLE_DES_MARKERS):
        return []
    return [RuleHit([e], ["/ike/encr"], f"The IKE SA negotiated {e.value}.")]


@rule("IKE-020")
def _md5_on_ike(r: SessionRecord) -> list[RuleHit]:
    hits = []
    for name, attr in (("integ", r.ike.integ), ("prf", r.ike.prf)):
        if attr and attr.is_known and _contains(str(attr.value), MD5_MARKERS):
            hits.append(
                RuleHit([attr], [f"/ike/{name}"], f"The IKE SA {name} is {attr.value}.")
            )
    return hits


@rule("IKE-021")
def _sha1_on_ike(r: SessionRecord) -> list[RuleHit]:
    hits = []
    for name, attr in (("integ", r.ike.integ), ("prf", r.ike.prf)):
        if attr and attr.is_known and _contains(str(attr.value), SHA1_MARKERS):
            hits.append(
                RuleHit([attr], [f"/ike/{name}"], f"The IKE SA {name} is {attr.value}.")
            )
    return hits


@rule("IKE-030")
def _dh_must_not(r: SessionRecord) -> list[RuleHit]:
    g = r.ike.dh_group
    if g is None or not g.is_known or g.value not in DH_GROUPS_MUST_NOT:
        return []
    bits = tf.dh_strength_bits(int(g.value))
    return [
        RuleHit(
            [g],
            ["/ike/dh_group"],
            f"Key exchange used group {g.value} ({tf.dh_group_name(int(g.value))}), "
            f"about {bits} bits of security.",
        )
    ]


@rule("IKE-031")
def _dh_should_not(r: SessionRecord) -> list[RuleHit]:
    g = r.ike.dh_group
    if g is None or not g.is_known or g.value not in DH_GROUPS_SHOULD_NOT:
        return []
    bits = tf.dh_strength_bits(int(g.value))
    return [
        RuleHit(
            [g],
            ["/ike/dh_group"],
            f"Key exchange used group {g.value} ({tf.dh_group_name(int(g.value))}), "
            f"about {bits} bits of security.",
        )
    ]


@rule("IKE-040")
def _downgrade_selected(r: SessionRecord) -> list[RuleHit]:
    """The responder picked a suite weaker than the strongest on offer.

    Only fires when both the selected proposal and at least one offered proposal
    can be scored. A capture missing the request cannot support this finding, and
    the session builder already warns about that case.
    """
    selected = r.ike.selected_proposal
    if selected is None or not r.ike.offered_proposals:
        return []

    chosen = proposal_strength(selected)
    if chosen is None:
        return []

    scored = [(p, s) for p in r.ike.offered_proposals if (s := proposal_strength(p)) is not None]
    if not scored:
        return []

    best_proposal, best = max(scored, key=lambda ps: ps[1])
    if best <= chosen:
        return []

    attrs = [a for a in (r.ike.encr, r.ike.dh_group, r.ike.integ) if a and a.is_known]
    return [
        RuleHit(
            attrs,
            ["/ike/selected_proposal", "/ike/offered_proposals"],
            f"The responder selected {selected.label()} at about {chosen} bits, "
            f"while {best_proposal.label()} at about {best} bits was offered.",
        )
    ]


@rule("IKE-041")
def _weak_proposals_offered(r: SessionRecord) -> list[RuleHit]:
    """Weak suites were offered alongside acceptable ones.

    Silent when every offer is weak: that is a different problem, already covered
    by whichever algorithm rule fired, and reporting it as downgrade surface too
    would double-count.
    """
    scored = [(p, s) for p in r.ike.offered_proposals if (s := proposal_strength(p)) is not None]
    if len(scored) < 2:
        return []

    weak = [(p, s) for p, s in scored if s < WEAK_PROPOSAL_BITS]
    strong = [(p, s) for p, s in scored if s >= WEAK_PROPOSAL_BITS]
    if not weak or not strong:
        return []

    listed = ", ".join(f"{p.label()} (~{s} bits)" for p, s in weak)
    return [
        RuleHit(
            [],
            ["/ike/offered_proposals"],
            f"{len(weak)} of {len(scored)} offered proposals are below "
            f"{WEAK_PROPOSAL_BITS} bits: {listed}.",
        )
    ]


@rule("ESP-001")
def _esp_without_integrity(r: SessionRecord) -> list[RuleHit]:
    """ESP encrypting with no integrity protection.

    Needs the child SA integrity algorithm, which is negotiated inside the
    encrypted exchange, so this normally only fires when keys or a device
    configuration were supplied. An AEAD cipher is not a hit: its integrity is
    part of the transform.
    """
    hits = []
    for index, sa in enumerate(r.child_sas):
        integ, family = sa.integ, sa.cipher_family
        if integ is None or not integ.is_known:
            continue
        if str(integ.value) not in ("AUTH_NONE", "NONE"):
            continue
        if family and family.is_known and "AEAD" in str(family.value):
            continue
        hits.append(
            RuleHit(
                [integ],
                [f"/child_sas/{index}/integ"],
                f"Child SA {sa.spi} encrypts with no integrity algorithm.",
            )
        )
    return hits


@rule("ESP-010")
def _esp_64bit_block(r: SessionRecord) -> list[RuleHit]:
    """A 64-bit block cipher on ESP, from the inferred block size.

    This is the first rule to fire on Inferred rather than Observed evidence, so
    the finding carries the inference confidence rather than 1.0.
    """
    hits = []
    for index, sa in enumerate(r.child_sas):
        block = sa.block_size_bytes
        if block is None or not block.is_known or block.value != 8:
            continue
        hits.append(
            RuleHit(
                [block],
                [f"/child_sas/{index}/block_size_bytes"],
                f"Child SA {sa.spi} shows the length signature of an 8-byte block "
                f"cipher, so DES or 3DES, at {block.confidence:.0%} confidence.",
            )
        )
    return hits


@rule("SA-002")
def _no_rekey_observed(r: SessionRecord) -> list[RuleHit]:
    """No child SA rekeyed inside the capture.

    Fires once for the session, not once per SA, because the cause is usually the
    capture length rather than any individual SA. The remediation text says so.
    """
    if not r.child_sas:
        return []
    if any(sa.rekey_interval_s and sa.rekey_interval_s.is_known for sa in r.child_sas):
        return []
    duration = r.source.capture_duration_s or 0.0
    return [
        RuleHit(
            [],
            ["/child_sas"],
            f"No SPI change was seen across {len(r.child_sas)} child SA(s) in "
            f"{duration:.0f}s of capture, so no rekey interval could be measured.",
        )
    ]


@rule("SA-003")
def _replay_evidence(r: SessionRecord) -> list[RuleHit]:
    hits = []
    for index, sa in enumerate(r.child_sas):
        ev = sa.replay_evidence
        if ev is None or ev.duplicate_seqs == 0:
            continue
        hits.append(
            RuleHit(
                [],
                [f"/child_sas/{index}/replay_evidence"],
                f"Child SA {sa.spi} showed {ev.duplicate_seqs} duplicate sequence "
                f"number(s) over {sa.packet_count} packets.",
            )
        )
    return hits


@rule("META-001")
def _vendor_id_disclosure(r: SessionRecord) -> list[RuleHit]:
    disclosed = [v for v in r.ike.vendor_ids if v.get("interpreted")]
    if not disclosed:
        return []
    names = ", ".join(sorted({str(v["interpreted"]) for v in disclosed}))
    return [
        RuleHit(
            [],
            ["/ike/vendor_ids"],
            f"{len(disclosed)} Vendor ID payload(s) carried readable text: {names}.",
        )
    ]


@rule("PQ-001")
def _no_post_quantum(r: SessionRecord) -> list[RuleHit]:
    """No post-quantum protection signalled.

    Needs cleartext IKE to have been seen at all: with no handshake in the
    capture the absence of a notification says nothing, so the rule stays silent
    rather than reporting a gap in the capture as a property of the deployment.
    """
    if r.ike.version is None or not r.ike.version.is_known:
        return []

    signalled = [n for n in r.ike.notifications if n.get("type") in tf.PQ_NOTIFIES]
    group = r.ike.dh_group
    pq_group = group and group.is_known and tf.is_post_quantum_group(int(group.value))
    if signalled or pq_group:
        return []

    return [
        RuleHit(
            [],
            ["/ike/notifications"],
            "No RFC 8784 post-quantum pre-shared key and no RFC 9370 additional "
            "key exchange was signalled, and the negotiated group is classical.",
        )
    ]


# -------------------------------------------------------------------- evaluate


def evaluate(record: SessionRecord) -> list[Finding]:
    """Run every catalogue rule against the record.

    Findings come back sorted worst first, then by rule ID, so the order is
    stable across runs. Rules are evaluated in catalogue order and a rule with no
    predicate is skipped rather than failing, which lets the catalogue carry
    entries for phases not yet implemented.
    """
    catalogue = load_catalogue()
    findings: list[Finding] = []

    for entry in catalogue["rules"]:
        predicate = PREDICATES.get(entry["id"])
        if predicate is None:
            continue

        for hit in predicate(record):
            findings.append(
                Finding.from_rule(
                    entry["id"],
                    entry["title"],
                    entry["severity"],
                    entry["standard"],
                    depends_on=hit.attributes,
                    remediation=" ".join(entry["remediation"].split()),
                    threat=entry.get("threat"),
                    evidence=hit.evidence,
                    detail=hit.detail,
                )
            )

    return sorted(findings, key=lambda f: (-f.severity_rank, f.rule_id))


def unimplemented_rules() -> list[str]:
    """Catalogue rules with no predicate yet.

    Surfaced in the technical report so a reader knows which checks the tool did
    not perform, rather than reading silence as a pass.
    """
    return sorted(
        entry["id"] for entry in load_catalogue()["rules"] if entry["id"] not in PREDICATES
    )
