from airsnitch.core.types import APInfo, Band, Finding, RiskLevel, Severity
from airsnitch.scoring.engine import score_findings


def test_score_empty():
    result = score_findings([])
    assert result.overall == 0.0
    assert result.level == RiskLevel.LOW


def test_score_single_critical():
    f = Finding(
        test_name="gtk_injection",
        severity=Severity.CRITICAL,
        confidence=0.9,
        description="bypass",
        evidence="ev",
        remediation="rem",
    )
    result = score_findings([f])
    # single finding: 0.7*6.3 + 0.3*6.3 = 6.3
    assert result.overall == 6.3
    assert result.level == RiskLevel.HIGH


def test_score_multiple_findings():
    findings = [
        Finding("test1", Severity.CRITICAL, 0.9, "d", "e", "r"),
        Finding("test2", Severity.LOW, 0.5, "d", "e", "r"),
        Finding("test3", Severity.HIGH, 0.8, "d", "e", "r"),
    ]
    result = score_findings(findings)
    assert result.overall > 0
    assert len(result.findings) == 3


def test_score_known_vulnerable_boost():
    f = Finding("gtk_injection", Severity.HIGH, 0.8, "d", "e", "r")
    ap = APInfo(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="Hotel WiFi",
        channel=6,
        band=Band.BAND_2_4,
        vendor="TP-Link",
        model="Archer AX55",
    )
    result_with_ap = score_findings([f], ap)
    result_without_ap = score_findings([f])
    # With known vulnerable device, score should be higher
    assert result_with_ap.overall >= result_without_ap.overall
