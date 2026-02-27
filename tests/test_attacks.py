"""Test attack module preflight checks and graceful failures."""

from unittest.mock import MagicMock
from pathlib import Path

from airsnitch.attacks.gtk_injection import GTKInjectionTest
from airsnitch.attacks.gateway_bounce import GatewayBounceTest
from airsnitch.attacks.downlink_spoof import DownlinkSpoofTest
from airsnitch.attacks.uplink_impersonation import UplinkImpersonationTest
from airsnitch.core.types import NetworkContext
from airsnitch.safeguards.audit import AuditLogger


def _make_ctx(**overrides) -> NetworkContext:
    defaults = dict(interface="wlan0")
    defaults.update(overrides)
    return NetworkContext(**defaults)


def _make_engine():
    return MagicMock()


def _make_audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(tmp_path / "test.jsonl")


class TestGTKInjection:
    def test_preflight_no_password(self, tmp_path: Path):
        ctx = _make_ctx(gateway_mac="aa:bb:cc:dd:ee:ff")
        test = GTKInjectionTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, reason = test.preflight_check()
        assert not ok
        assert "password" in reason.lower()

    def test_preflight_no_gateway(self, tmp_path: Path):
        ctx = _make_ctx(password="secret123")
        test = GTKInjectionTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, reason = test.preflight_check()
        assert not ok
        assert "gateway" in reason.lower()

    def test_preflight_no_ssid(self, tmp_path: Path):
        ctx = _make_ctx(password="secret123", gateway_mac="aa:bb:cc:dd:ee:ff")
        test = GTKInjectionTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, reason = test.preflight_check()
        assert not ok
        assert "ssid" in reason.lower()

    def test_preflight_ok(self, tmp_path: Path):
        ctx = _make_ctx(password="secret123", gateway_mac="aa:bb:cc:dd:ee:ff", ssid="TestNetwork")
        test = GTKInjectionTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, _ = test.preflight_check()
        assert ok


class TestGatewayBounce:
    def test_preflight_no_gateway_mac(self, tmp_path: Path):
        ctx = _make_ctx(gateway_ip="192.168.1.1")
        test = GatewayBounceTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, reason = test.preflight_check()
        assert not ok

    def test_preflight_no_gateway_ip(self, tmp_path: Path):
        ctx = _make_ctx(gateway_mac="aa:bb:cc:dd:ee:ff")
        test = GatewayBounceTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, reason = test.preflight_check()
        assert not ok

    def test_preflight_ok(self, tmp_path: Path):
        ctx = _make_ctx(gateway_mac="aa:bb:cc:dd:ee:ff", gateway_ip="192.168.1.1")
        test = GatewayBounceTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, _ = test.preflight_check()
        assert ok


class TestDownlinkSpoof:
    def test_preflight_no_gateway(self, tmp_path: Path):
        ctx = _make_ctx(password="secret123")
        test = DownlinkSpoofTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, _ = test.preflight_check()
        assert not ok

    def test_preflight_no_password(self, tmp_path: Path):
        ctx = _make_ctx(gateway_mac="aa:bb:cc:dd:ee:ff")
        test = DownlinkSpoofTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, _ = test.preflight_check()
        assert not ok

    def test_preflight_ok(self, tmp_path: Path):
        ctx = _make_ctx(password="secret123", gateway_mac="aa:bb:cc:dd:ee:ff")
        test = DownlinkSpoofTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, _ = test.preflight_check()
        assert ok


class TestUplinkImpersonation:
    def test_preflight_no_gateway(self, tmp_path: Path):
        ctx = _make_ctx()
        test = UplinkImpersonationTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, _ = test.preflight_check()
        assert not ok

    def test_preflight_ok(self, tmp_path: Path):
        ctx = _make_ctx(gateway_mac="aa:bb:cc:dd:ee:ff", gateway_ip="192.168.1.1")
        test = UplinkImpersonationTest(ctx, _make_engine(), _make_audit(tmp_path))
        ok, _ = test.preflight_check()
        assert ok
