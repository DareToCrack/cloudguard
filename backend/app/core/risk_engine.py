"""Risk scoring engine.

Converts a list of Findings into:
  - an overall 0-100 security posture score (100 = best)
  - a per-service breakdown
  - a severity distribution
  - a letter grade, for at-a-glance reporting

The scoring model is intentionally transparent and explainable (a common
requirement in real security tooling, where "black box" scores are hard to
defend to auditors and stakeholders):

    raw_risk   = sum(severity_weight for each open finding, with per-tier
                 diminishing returns - see below)
    score      = 100 * e^(-raw_risk / K)

Severity weights (see `Severity.weight`) are: info=1, low=3, medium=6,
high=9, critical=12. An exponential-decay curve is used instead of a linear
one deliberately: a linear model with a hard cap either (a) saturates to a
flat 0 for any account with a realistic number of mixed-severity findings,
which is uninformative, or (b) is too forgiving of a handful of criticals
if tuned to avoid (a). Exponential decay keeps the score strictly
monotonic and differentiable across the entire range of possible inputs -
five open criticals and fifty open criticals both score badly, but not
identically - while still dropping sharply for the first few high-severity
findings, matching how a security reviewer would actually react.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.core.enums import Severity
from app.core.finding import Finding

# Diminishing-returns caps: at most N findings of a given severity count at
# full weight; additional findings of that severity still add up, but at a
# reduced rate, so a long tail of repeated identical-severity findings
# (e.g. 40 buckets all missing versioning) doesn't dominate the score the
# way naive summation would.
DIMINISHING_RETURNS_THRESHOLD = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 8,
    Severity.MEDIUM: 12,
    Severity.LOW: 20,
    Severity.INFO: 30,
}
DIMINISHED_WEIGHT_FACTOR = 0.25

# Decay constant for the exponential scoring curve. Calibrated so that:
#   - a single low-severity finding barely moves the score (~96/100)
#   - 4-5 open criticals alone drop the score into "needs attention" (D/F)
#   - an account with dozens of mixed-severity findings converges toward
#     (but does not artificially floor at) a low single-digit score
DECAY_CONSTANT = 70.0


@dataclass
class RiskScoreResult:
    score: int                              # 0-100, 100 = best
    grade: str                              # A-F
    raw_penalty: float
    severity_counts: dict[str, int] = field(default_factory=dict)
    service_scores: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "raw_penalty": round(self.raw_penalty, 2),
            "severity_counts": self.severity_counts,
            "service_scores": self.service_scores,
            "total_findings": self.total_findings,
        }


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _weighted_penalty(findings: list[Finding]) -> float:
    """Sum severity weights with per-tier diminishing returns applied."""
    by_severity: dict[Severity, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    penalty = 0.0
    for severity, count in by_severity.items():
        threshold = DIMINISHING_RETURNS_THRESHOLD.get(severity, 10)
        full_weight_count = min(count, threshold)
        reduced_count = max(0, count - threshold)
        penalty += full_weight_count * severity.weight
        penalty += reduced_count * severity.weight * DIMINISHED_WEIGHT_FACTOR
    return penalty


def _score_from_penalty(raw_penalty: float) -> int:
    score = 100.0 * math.exp(-raw_penalty / DECAY_CONSTANT)
    return max(0, round(score))


def calculate_risk_score(findings: list[Finding]) -> RiskScoreResult:
    open_findings = [f for f in findings if f.status.value == "open"]

    raw_penalty = _weighted_penalty(open_findings)
    score = _score_from_penalty(raw_penalty)

    severity_counts = {s.value: 0 for s in Severity}
    for f in open_findings:
        severity_counts[f.severity.value] += 1

    # Per-service breakdown: score each service's findings independently
    # using the same model, so a dashboard can show "S3: 62, IAM: 40, ..."
    by_service: dict[str, list[Finding]] = {}
    for f in open_findings:
        by_service.setdefault(f.resource_type.value, []).append(f)

    service_scores: dict[str, int] = {}
    for service, service_findings in by_service.items():
        service_scores[service] = _score_from_penalty(_weighted_penalty(service_findings))

    return RiskScoreResult(
        score=score,
        grade=_grade_from_score(score),
        raw_penalty=raw_penalty,
        severity_counts=severity_counts,
        service_scores=service_scores,
        total_findings=len(open_findings),
    )

