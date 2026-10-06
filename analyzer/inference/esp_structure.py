"""Infer ESP cipher structure from packet lengths alone.

This is the first Inferred attribute in the pipeline, and it is deliberately not
a machine-learning model. The signal is a counting argument, so a deterministic
method with an honest confidence beats a classifier that would learn the same
thing less transparently. The learned work in PLAN.md phase 4 goes on top of
this, not instead of it.

**The signal.** An ESP payload is IV, then ciphertext, then the integrity check
value. ESP requires the plaintext to be padded so the ciphertext ends on a
4-byte boundary, and a block cipher pads further, to a whole block. So the
payload length modulo 16 separates the modes:

===========================  ====================  =========================
Cipher                       Payload structure     Residues seen modulo 16
===========================  ====================  =========================
AES-CBC (16-byte block)      16 + 16k + icv        one residue
3DES or DES CBC (8-byte)     8 + 8k + icv          two residues
AES-GCM, AES-CTR (no pad)    8 + 4k + icv          all four residues
===========================  ====================  =========================

**The trap, and why this module abstains so readily.** The argument only works
when the traffic carries a spread of plaintext sizes. A flow of identically
sized packets, which is exactly what a constant-rate ping or a VoIP stream looks
like, lands on one residue whatever cipher is in use. Concluding AES-CBC from
that would be reading a property of the traffic as a property of the cipher.

That failure mode is the easiest way to get an impressive-looking and wrong
result here, so the guard comes first: too few distinct lengths, or too few
packets, and the answer is Unknown with the reason stated. VISION.md principle 3
says unknown is an answer, and this is where it earns its keep.
"""

from __future__ import annotations

from dataclasses import dataclass

from analyzer.esp_ah.stats import FlowStats
from analyzer.record import Attribute

#: Below this many distinct ESP payload lengths, the residue argument cannot
#: separate a padded cipher from traffic that happens to be uniform.
MIN_DISTINCT_LENGTHS = 4

#: Below this many packets the residue counts are too sparse to trust, however
#: varied the lengths are.
MIN_PACKETS = 20

#: Name recorded on every Attribute this module produces, so a number in a
#: report traces back to the code that made it.
METHOD = "esp_length_residue_mod16"


@dataclass(slots=True)
class ResidueEvidence:
    """The counting that the inference rests on, kept so it can be re-checked."""

    packets: int
    distinct_lengths: int
    residues_mod_16: dict[int, int]
    residues_mod_4: dict[int, int]
    min_length: int
    max_length: int

    @property
    def distinct_residues_16(self) -> int:
        return len(self.residues_mod_16)

    @property
    def length_spread(self) -> int:
        return self.max_length - self.min_length

    def as_features(self) -> dict[str, object]:
        """The feature dict attached to the Attribute, for the report appendix."""
        return {
            "packets": self.packets,
            "distinct_lengths": self.distinct_lengths,
            "distinct_residues_mod_16": self.distinct_residues_16,
            "residues_mod_16": ",".join(str(r) for r in sorted(self.residues_mod_16)),
            "length_spread_bytes": self.length_spread,
        }


def gather_residues(flow: FlowStats) -> ResidueEvidence:
    """Count the residue evidence for one flow. No interpretation yet."""
    r16 = dict(flow.residues(16))
    r4 = dict(flow.residues(4))
    lengths = flow.length_histogram
    return ResidueEvidence(
        packets=flow.packet_count,
        distinct_lengths=len(lengths),
        residues_mod_16=r16,
        residues_mod_4=r4,
        min_length=min(lengths) if lengths else 0,
        max_length=max(lengths) if lengths else 0,
    )


def _sample_discount(packets: int) -> float:
    """Shrink confidence when there is little data to stand on.

    Approaches 1 as packets grow and stays visibly below it for small samples,
    so a conclusion drawn from 25 packets never reports the certainty of one
    drawn from 2000. Deliberately simple and monotone: the calibrated
    replacement comes from the reliability curves in PLAN.md phase 4, and
    ``calibrated=False`` on every Attribute here records that this is not it yet.
    """
    return 1.0 - 1.0 / (1.0 + packets / 25.0)


def infer_block_size(flow: FlowStats) -> tuple[Attribute, Attribute, ResidueEvidence]:
    """Infer the ESP cipher block size and family from payload length residues.

    Returns the block size attribute, the cipher family attribute, and the
    evidence both rest on. Either attribute may be Unknown.
    """
    ev = gather_residues(flow)

    if ev.packets < MIN_PACKETS:
        reason = (
            f"only {ev.packets} ESP packets on this SA, below the {MIN_PACKETS} "
            "needed before the length-residue argument carries any weight"
        )
        return (
            Attribute.unknown(reason, resolvable_by="longer_capture"),
            Attribute.unknown(reason, resolvable_by="longer_capture"),
            ev,
        )

    if ev.distinct_lengths < MIN_DISTINCT_LENGTHS:
        # The important abstention. Uniform traffic concentrates on one residue
        # whatever cipher is running, so the residue carries no cipher
        # information at all here.
        reason = (
            f"only {ev.distinct_lengths} distinct ESP payload length(s) over "
            f"{ev.packets} packets, so the residues describe the traffic shape "
            "rather than the cipher padding; this SA carries near-constant-size "
            "packets and needs varied plaintext sizes to tell the modes apart"
        )
        return (
            Attribute.unknown(reason, resolvable_by="longer_capture"),
            Attribute.unknown(reason, resolvable_by="longer_capture"),
            ev,
        )

    distinct = ev.distinct_residues_16
    confidence = _sample_discount(ev.packets)

    if distinct == 1:
        block = Attribute.inferred(
            16,
            confidence,
            METHOD,
            features=ev.as_features(),
            note="all payload lengths share one residue modulo 16, the signature "
            "of padding to a 16-byte block",
        )
        family = Attribute.inferred(
            "BLOCK_16B_CBC_LIKE",
            confidence,
            METHOD,
            features=ev.as_features(),
            alternatives=[("BLOCK_8B_CBC_LIKE", round(1.0 - confidence, 4))],
            note="consistent with AES-CBC or Camellia-CBC. The cipher itself is "
            "not recoverable from ciphertext, only its block structure.",
        )
        return block, family, ev

    if distinct == 2:
        block = Attribute.inferred(
            8,
            confidence,
            METHOD,
            features=ev.as_features(),
            note="payload lengths fall on two residues modulo 16, the signature "
            "of padding to an 8-byte block",
        )
        family = Attribute.inferred(
            "BLOCK_8B_CBC_LIKE",
            confidence,
            METHOD,
            features=ev.as_features(),
            alternatives=[("BLOCK_16B_CBC_LIKE", round(1.0 - confidence, 4))],
            note="a 64-bit block cipher, so 3DES or DES. This is what rule "
            "ESP-010 acts on.",
        )
        return block, family, ev

    # Three or four residues: no block padding is happening.
    family = Attribute.inferred(
        "AEAD_OR_COUNTER",
        confidence,
        METHOD,
        features=ev.as_features(),
        note=f"payload lengths occupy {distinct} residues modulo 16, so the "
        "plaintext is not padded to a block; consistent with AES-GCM, AES-CCM, "
        "AES-CTR or ChaCha20-Poly1305",
    )
    block = Attribute.unknown(
        "the cipher is a counter or AEAD mode, which has no block padding, so "
        "there is no block size to report",
        resolvable_by="not_resolvable",
    )
    return block, family, ev


def key_length_attribute() -> Attribute:
    """ESP key length is not recoverable from ciphertext. Always Unknown.

    Given its own function because it is the project most load-bearing negative
    result. All three source documents list AES-128 against AES-256 as something
    to identify; VISION.md section 12 row 3 settles that it cannot be done
    passively. AES-128 and AES-256 differ in round count, not in block size or
    output length, so they produce byte-for-byte indistinguishable ESP payloads.
    A tool that claims to tell them apart from a capture is reporting an artefact
    of its training data.
    """
    return Attribute.unknown(
        "ESP key length is not recoverable from ciphertext: AES-128 and AES-256 "
        "differ in round count, not in block or output size, so they produce "
        "identically shaped ESP payloads",
        resolvable_by="supply_keys",
    )
