from airsnitch.core.types import (
    Band,
    ClientInfo,
    Finding,
    NetworkContext,
    RiskLevel,
    RiskScore,
    Severity,
)


def test_client_info_frozen():
    c = ClientInfo(mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.100")
    assert c.mac == "aa:bb:cc:dd:ee:ff"
    assert c.ip == "192.168.1.100"
    assert c.vendor is None


def test_finding_score():
    f = Finding(
        test_name="test",
        severity=Severity.CRITICAL,
        confidence=0.9,
        description="desc",
        evidence="ev",
        remediation="rem",
    )
    assert f.score == 7 * 0.9  # CRITICAL=7


def test_risk_level_from_score():
    assert RiskLevel.from_score(0) == RiskLevel.LOW
    assert RiskLevel.from_score(2.9) == RiskLevel.LOW
    assert RiskLevel.from_score(3.0) == RiskLevel.MEDIUM
    assert RiskLevel.from_score(5.0) == RiskLevel.HIGH
    assert RiskLevel.from_score(7.0) == RiskLevel.CRITICAL
    assert RiskLevel.from_score(10.0) == RiskLevel.CRITICAL


def test_network_context_defaults():
    ctx = NetworkContext(interface="wlan0")
    assert ctx.ssid is None
    assert ctx.clients == []
    assert ctx.aps == []


def test_band_values():
    assert Band.BAND_2_4.value == "2.4GHz"
    assert Band.BAND_5.value == "5GHz"
    assert Band.BAND_6.value == "6GHz"
