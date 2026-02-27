"""JSON report export."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from airsnitch import __version__
from airsnitch.core.types import APInfo, ClientInfo, Finding, NetworkContext, RiskScore


def generate_report(
    ctx: NetworkContext,
    score: RiskScore,
    ap: APInfo | None = None,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Generate structured JSON report."""
    report: dict[str, Any] = {
        "tool": "airsnitch",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "network": {
            "interface": ctx.interface,
            "ssid": ctx.ssid,
            "gateway_ip": ctx.gateway_ip,
            "gateway_mac": ctx.gateway_mac,
            "client_count": len(ctx.clients),
        },
        "access_point": _serialize_ap(ap) if ap else None,
        "risk_score": {
            "overall": score.overall,
            "level": score.level.value,
        },
        "findings": [_serialize_finding(f) for f in score.findings],
        "clients": [_serialize_client(c) for c in ctx.clients],
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2))

    return report


def _serialize_finding(f: Finding) -> dict[str, Any]:
    return {
        "test_name": f.test_name,
        "severity": f.severity.name,
        "severity_value": f.severity.value,
        "confidence": f.confidence,
        "score": f.score,
        "description": f.description,
        "evidence": f.evidence,
        "remediation": f.remediation,
    }


def _serialize_ap(ap: APInfo) -> dict[str, Any]:
    return {
        "bssid": ap.bssid,
        "ssid": ap.ssid,
        "channel": ap.channel,
        "band": ap.band.value,
        "vendor": ap.vendor,
        "model": ap.model,
        "firmware": ap.firmware,
    }


def _serialize_client(c: ClientInfo) -> dict[str, Any]:
    return {
        "mac": c.mac,
        "ip": c.ip,
        "vendor": c.vendor,
        "hostname": c.hostname,
    }
