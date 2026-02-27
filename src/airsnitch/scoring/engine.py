"""Risk scoring engine: per-finding and aggregate scores."""

from __future__ import annotations

from datetime import datetime, timezone

from airsnitch.config import VULNERABLE_DEVICES
from airsnitch.core.types import APInfo, Finding, RiskLevel, RiskScore


def score_findings(findings: list[Finding], ap: APInfo | None = None) -> RiskScore:
    """Compute aggregate risk score from findings.

    Scoring:
    - Per-finding: severity * confidence
    - Aggregate: weighted average with max-severity bias (70% weighted avg, 30% max)
    - Known vulnerable device bonus: +10% confidence boost
    """
    if not findings:
        return RiskScore(overall=0.0, level=RiskLevel.LOW, findings=findings)

    scores = [f.score for f in findings]
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)

    # Weighted: 70% average, 30% max (bias toward worst finding)
    overall = 0.7 * avg_score + 0.3 * max_score

    # Known vulnerable device boost
    if ap and ap.vendor and ap.model:
        vendor_devices = VULNERABLE_DEVICES.get(ap.vendor, {})
        if ap.model in vendor_devices:
            overall = min(10.0, overall * 1.1)

    overall = round(min(10.0, overall), 2)
    level = RiskLevel.from_score(overall)

    return RiskScore(
        overall=overall,
        level=level,
        findings=findings,
        timestamp=datetime.now(timezone.utc),
    )
