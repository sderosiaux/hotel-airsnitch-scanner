from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 3
    HIGH = 5
    CRITICAL = 7
    EMERGENCY = 10


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        if score < 3:
            return cls.LOW
        if score < 5:
            return cls.MEDIUM
        if score < 7:
            return cls.HIGH
        return cls.CRITICAL


class Band(Enum):
    BAND_2_4 = "2.4GHz"
    BAND_5 = "5GHz"
    BAND_6 = "6GHz"


@dataclass(frozen=True)
class ClientInfo:
    mac: str
    ip: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    channel: int | None = None
    band: Band | None = None


@dataclass(frozen=True)
class APInfo:
    bssid: str
    ssid: str
    channel: int
    band: Band
    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None


@dataclass(frozen=True)
class Finding:
    test_name: str
    severity: Severity
    confidence: float  # 0.0 - 1.0
    description: str
    evidence: str
    remediation: str

    @property
    def score(self) -> float:
        return self.severity.value * self.confidence


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RiskScore:
    overall: float
    level: RiskLevel
    findings: list[Finding] = field(default_factory=list)
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class NetworkContext:
    interface: str
    ssid: str | None = None
    password: str | None = None
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    our_mac: str | None = None
    gtk: bytes | None = None
    clients: list[ClientInfo] = field(default_factory=list)
    aps: list[APInfo] = field(default_factory=list)
