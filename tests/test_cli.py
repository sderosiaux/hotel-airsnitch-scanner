"""Test CLI command registration and help output."""

from click.testing import CliRunner

from airsnitch.cli import cli


runner = CliRunner()


def test_cli_help():
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "AirSnitch" in result.output
    assert "full-scan" in result.output
    assert "discover" in result.output
    assert "test-gtk" in result.output
    assert "test-gateway" in result.output
    assert "test-downlink" in result.output
    assert "test-uplink" in result.output


def test_cli_version():
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cli_requires_interface():
    result = runner.invoke(cli, ["discover"])
    assert result.exit_code != 0
    assert "interface" in result.output.lower() or "required" in result.output.lower()


def test_gen_auth_code():
    result = runner.invoke(cli, ["-i", "wlan0", "gen-auth-code", "--hotel-name", "Test Hotel"])
    assert result.exit_code == 0
    assert "AIRSNITCH-" in result.output


def test_full_scan_no_auth():
    """full-scan without auth-code should show disclaimer and fail (non-interactive)."""
    result = runner.invoke(cli, ["-i", "wlan0", "full-scan"], input="n\n")
    # Should fail because no auth code or root
    assert result.exit_code != 0
