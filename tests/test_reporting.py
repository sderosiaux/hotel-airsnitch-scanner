import json
from pathlib import Path

from airsnitch.core.types import Finding, NetworkContext, RiskLevel, RiskScore, Severity
from airsnitch.reporting.json_report import generate_report


def test_generate_report_basic(tmp_path: Path):
    ctx = NetworkContext(
        interface="wlan0",
        ssid="Hotel WiFi",
        gateway_ip="192.168.1.1",
        gateway_mac="aa:bb:cc:dd:ee:ff",
    )
    findings = [
        Finding("gtk_injection", Severity.CRITICAL, 0.9, "bypass found", "evidence", "upgrade firmware"),
    ]
    score = RiskScore(overall=6.3, level=RiskLevel.HIGH, findings=findings)

    output = tmp_path / "report.json"
    report = generate_report(ctx, score, output_path=output)

    assert report["tool"] == "airsnitch"
    assert report["network"]["ssid"] == "Hotel WiFi"
    assert report["risk_score"]["overall"] == 6.3
    assert len(report["findings"]) == 1
    assert report["findings"][0]["test_name"] == "gtk_injection"

    # Verify file written
    saved = json.loads(output.read_text())
    assert saved == report


def test_generate_report_no_output():
    ctx = NetworkContext(interface="wlan0")
    score = RiskScore(overall=0.0, level=RiskLevel.LOW)
    report = generate_report(ctx, score)
    assert report["risk_score"]["overall"] == 0.0
