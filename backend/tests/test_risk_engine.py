"""Unit tests for the risk scoring engine."""

from __future__ import annotations

from app.core.enums import ResourceType, Severity
from app.core.finding import Finding
from app.core.risk_engine import calculate_risk_score


def _finding(severity: Severity, resource_type: ResourceType = ResourceType.S3_BUCKET, name="res") -> Finding:
    return Finding(
        check_id="TEST_CHECK",
        title="Test finding",
        description="desc",
        severity=severity,
        resource_type=resource_type,
        resource_id=f"arn:test:{name}",
        resource_name=name,
        region="us-east-1",
        remediation="fix it",
    )


def test_no_findings_yields_perfect_score():
    result = calculate_risk_score([])
    assert result.score == 100
    assert result.grade == "A"
    assert result.total_findings == 0


def test_single_low_finding_barely_moves_score():
    result = calculate_risk_score([_finding(Severity.LOW)])
    assert 90 <= result.score < 100


def test_multiple_critical_findings_drop_score_significantly():
    findings = [_finding(Severity.CRITICAL, name=f"res-{i}") for i in range(5)]
    result = calculate_risk_score(findings)
    assert result.score < 50
    assert result.grade in ("D", "F")


def test_score_approaches_zero_for_a_severely_compromised_account():
    """The exponential decay model never hard-floors at a fixed penalty
    threshold, but with enough accumulated open criticals it should round
    down to 0."""
    findings = [_finding(Severity.CRITICAL, name=f"res-{i}") for i in range(300)]
    result = calculate_risk_score(findings)
    assert result.score == 0
    assert result.grade == "F"


def test_score_is_monotonically_non_increasing_with_more_criticals():
    score_5 = calculate_risk_score([_finding(Severity.CRITICAL, name=f"a{i}") for i in range(5)]).score
    score_50 = calculate_risk_score([_finding(Severity.CRITICAL, name=f"b{i}") for i in range(50)]).score
    assert score_50 <= score_5


def test_resolved_findings_are_excluded_from_scoring():
    from app.core.enums import FindingStatus

    f = _finding(Severity.CRITICAL)
    f.status = FindingStatus.RESOLVED
    result = calculate_risk_score([f])
    assert result.score == 100
    assert result.total_findings == 0


def test_service_scores_are_computed_independently():
    findings = [
        _finding(Severity.CRITICAL, resource_type=ResourceType.S3_BUCKET, name="bucket-1"),
        _finding(Severity.LOW, resource_type=ResourceType.RDS_INSTANCE, name="db-1"),
    ]
    result = calculate_risk_score(findings)
    assert result.service_scores["s3_bucket"] < result.service_scores["rds_instance"]


def test_grade_boundaries():
    from app.core.risk_engine import _grade_from_score

    assert _grade_from_score(95) == "A"
    assert _grade_from_score(85) == "B"
    assert _grade_from_score(75) == "C"
    assert _grade_from_score(65) == "D"
    assert _grade_from_score(40) == "F"


def test_diminishing_returns_reduces_marginal_penalty_of_excess_findings():
    """Findings beyond a severity tier's diminishing-returns threshold
    should contribute less penalty per finding than those under it -
    i.e. the 21st-30th LOW findings should add less total penalty than
    the first 20 did, even though both groups are the same size."""
    from app.core.risk_engine import _weighted_penalty

    first_20 = [_finding(Severity.LOW, name=f"res-{i}") for i in range(20)]
    next_10 = [_finding(Severity.LOW, name=f"res-{i}") for i in range(20, 30)]

    penalty_20 = _weighted_penalty(first_20)
    penalty_30 = _weighted_penalty(first_20 + next_10)
    marginal_penalty_of_next_10 = penalty_30 - penalty_20

    # Under the cap, 10 LOW findings would cost 10 * 3 = 30. Beyond the
    # cap they're worth 25% of that (per DIMINISHED_WEIGHT_FACTOR).
    assert marginal_penalty_of_next_10 < 30
    assert marginal_penalty_of_next_10 == 10 * Severity.LOW.weight * 0.25


def test_few_criticals_score_worse_than_few_lows():
    """With counts safely under each tier's diminishing-returns threshold,
    severity weighting should dominate: a handful of criticals should hurt
    the score far more than the same number of lows."""
    few_lows = [_finding(Severity.LOW, name=f"res-{i}") for i in range(4)]
    few_criticals = [_finding(Severity.CRITICAL, name=f"res-{i}") for i in range(4)]
    lows_result = calculate_risk_score(few_lows)
    criticals_result = calculate_risk_score(few_criticals)
    assert lows_result.score > criticals_result.score
