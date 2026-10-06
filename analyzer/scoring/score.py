"""Security score, risk level, coverage and the threat matrix.

Four properties this module guarantees, because the score is the number everyone
will quote and an indefensible one would undermine the whole tool:

**Deterministic.** No randomness, no dict iteration order, no wall-clock input.
The same record always yields the same score, as PLAN.md section 7 requires.

**Every point traces to a rule.** The score is 100 minus a deduction per
finding, and each deduction is recorded with its rule ID and whether a category
cap absorbed it. Nothing is subtracted that a reader cannot look up.

**Capped per category.** One weak area cannot consume the whole score and mask
another. Without a cap, three key-exchange findings would drive the score to
zero and a critical ESP problem would then be invisible.

**Unknowns never cost points.** They lower coverage, which is reported beside
the score and never folded into it. A capture that reveals little scores high
with low coverage, which reads as incomplete rather than as clean. Scoring an
Unknown as a weakness would punish the analyst for a short capture; scoring it
as safe would be the dishonest half of the same mistake.
"""

from __future__ import annotations

from collections import defaultdict

from analyzer.record import Deduction, Finding, Score, SessionRecord, ThreatRow
from analyzer.rules.engine import catalogue_entry, load_catalogue

#: Any Critical finding caps the score into the lowest band, whatever the
#: arithmetic says (PLAN.md phase 5).
CRITICAL_SCORE_CAP = 20

#: Score thresholds for the risk bands, applied after the critical cap.
RISK_BANDS: tuple[tuple[int, str], ...] = (
    (85, "low"),
    (60, "medium"),
    (30, "high"),
    (0, "critical"),
)


def score_record(record: SessionRecord) -> Score:
    """Compute the score and risk level from the findings already attached."""
    catalogue = load_catalogue()
    points = catalogue["severity_points"]
    caps = {name: meta["cap"] for name, meta in catalogue["categories"].items()}

    spent: dict[str, float] = defaultdict(float)
    deductions: list[Deduction] = []

    # Worst first, so when a cap is reached it is the least severe findings that
    # get absorbed rather than whichever happened to be evaluated last.
    for finding in sorted(record.findings, key=lambda f: (-f.severity_rank, f.rule_id)):
        entry = catalogue_entry(finding.rule_id)
        category = entry["category"]
        asked = float(points[finding.severity])

        if asked == 0:
            deductions.append(Deduction(finding.rule_id, 0.0, category, capped=False))
            continue

        room = caps[category] - spent[category]
        granted = min(asked, max(0.0, room))
        spent[category] += granted
        deductions.append(
            Deduction(finding.rule_id, round(granted, 1), category, capped=granted < asked)
        )

    value = max(0, min(100, round(100 - sum(spent.values()))))

    worst = record.worst_severity
    if worst == "critical":
        value = min(value, CRITICAL_SCORE_CAP)

    return Score(
        value=value,
        risk_level=_risk_level(value, worst),
        deductions=deductions,
        overall_confidence=_overall_confidence(record.findings),
    )


def _risk_level(value: int, worst: str | None) -> str:
    """Risk follows the worst finding, exactly as PLAN.md phase 5 specifies.

    Deriving the band from the score instead was tried and rejected. A capture
    with eight High and Low findings and no Critical one scores 16, which lands
    in the Critical band, and a report that says Critical while no finding is
    Critical cannot answer the obvious question: which one? That breaks the
    explainable-scoring principle in VISION.md, where every part of a verdict has
    to trace back to a rule.

    So the two numbers say different things and both are reported. Risk names the
    most severe single problem and always points at a finding. The score carries
    the aggregate, and a pile of lesser findings shows up there instead.

    The score band is used only when there are no findings to follow.
    """
    if worst is None:
        return next(label for threshold, label in RISK_BANDS if value >= threshold)

    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        # An informational finding is not a risk, so it does not lift the band.
        "informational": "low",
    }[worst]


def _overall_confidence(findings: list[Finding]) -> float | None:
    """Severity-weighted mean confidence across findings (PLAN.md phase 5).

    Weighting by severity means a shaky Low finding cannot drag down the figure
    for a report whose Critical findings are all Observed.
    """
    if not findings:
        return None

    weights = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0, "informational": 1.0}
    total = sum(weights[f.severity] for f in findings)
    if total == 0:
        return None
    return sum(f.confidence * weights[f.severity] for f in findings) / total


#: The threat matrix rows, each linked to the rules that enable it. Likelihood
#: and impact are the team proposals from PLAN.md phase 5, to be tuned with the
#: guide. A row only appears in a report when at least one of its rules fired,
#: so the matrix describes this deployment rather than IPsec in general.
THREAT_MODEL: tuple[dict, ...] = (
    {
        "threat": "Offline cracking of the pre-shared key",
        "enabled_by": ["IKE-002"],
        "likelihood": "high",
        "impact": "high",
        "rating": "critical",
        "mitigation": "Disable Aggressive Mode, or move to certificate authentication.",
    },
    {
        "threat": "Downgrade to a weak cipher suite",
        "enabled_by": ["IKE-040", "IKE-041"],
        "likelihood": "medium",
        "impact": "high",
        "rating": "high",
        "mitigation": "Offer only acceptable suites at both ends.",
    },
    {
        "threat": "Recovery of the key exchange secret",
        "enabled_by": ["IKE-030", "IKE-031"],
        "likelihood": "medium",
        "impact": "high",
        "rating": "high",
        "mitigation": "Move to group 19, 31 or 14 at minimum.",
    },
    {
        "threat": "Record now, decrypt later with a quantum computer",
        "enabled_by": ["PQ-001", "IKE-030", "IKE-031"],
        "likelihood": "low",
        "impact": "high",
        "rating": "medium",
        "mitigation": "For long-lived secrets, add RFC 8784 or RFC 9370 protection.",
    },
    {
        "threat": "Cryptanalysis of a weak cipher",
        "enabled_by": ["IKE-010", "IKE-011", "ESP-010"],
        "likelihood": "medium",
        "impact": "high",
        "rating": "high",
        "mitigation": "Replace DES and 3DES with AES.",
    },
    {
        "threat": "Integrity forgery",
        "enabled_by": ["IKE-020", "ESP-001"],
        "likelihood": "medium",
        "impact": "high",
        "rating": "high",
        "mitigation": "Use HMAC-SHA2-256 or an AEAD cipher.",
    },
    {
        "threat": "Replay of captured packets",
        "enabled_by": ["SA-003"],
        "likelihood": "low",
        "impact": "medium",
        "rating": "medium",
        "mitigation": "Confirm anti-replay is enabled with an adequate window.",
    },
    {
        "threat": "Extended key exposure from a long SA lifetime",
        "enabled_by": ["SA-002"],
        "likelihood": "low",
        "impact": "medium",
        "rating": "low",
        "mitigation": "Set an SA lifetime appropriate to the traffic volume.",
    },
    {
        "threat": "Targeted exploitation after implementation fingerprinting",
        "enabled_by": ["META-001", "IKE-001"],
        "likelihood": "medium",
        "impact": "medium",
        "rating": "medium",
        "mitigation": "Suppress version disclosure and keep the implementation patched.",
    },
)


def build_threat_matrix(record: SessionRecord) -> list[ThreatRow]:
    """Build the threat matrix from the findings that actually fired.

    Rows with no triggering finding are left out. A matrix listing every
    conceivable IPsec threat regardless of what was found would be the same for
    every report and so carry no information.
    """
    fired = {f.rule_id for f in record.findings}
    rows: list[ThreatRow] = []

    for spec in THREAT_MODEL:
        triggering = sorted(set(spec["enabled_by"]) & fired)
        if not triggering:
            continue
        rows.append(
            ThreatRow(
                threat=spec["threat"],
                likelihood=spec["likelihood"],
                impact=spec["impact"],
                rating=spec["rating"],
                enabled_by=triggering,
                mitigation=spec["mitigation"],
            )
        )

    severity_order = ["informational", "low", "medium", "high", "critical"]
    return sorted(rows, key=lambda r: (-severity_order.index(r.rating), r.threat))


def assess(record: SessionRecord) -> SessionRecord:
    """Run the rules, score the record and build the threat matrix, in place.

    The one call the CLI, the dashboard and the report generator all use, so
    there is no way to produce a score without the findings that justify it.
    """
    from analyzer.rules.engine import evaluate

    record.findings = evaluate(record)
    record.threat_matrix = build_threat_matrix(record)
    record.score = score_record(record)
    return record
