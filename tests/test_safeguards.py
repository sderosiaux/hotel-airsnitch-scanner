import json
import time
from pathlib import Path

from airsnitch.safeguards.authorization import generate_auth_code, validate_auth_code
from airsnitch.safeguards.audit import AuditLogger
from airsnitch.safeguards.rate_limiter import RateLimiter


def test_validate_auth_code_valid():
    assert validate_auth_code("AIRSNITCH-AABBCCDD")
    assert validate_auth_code("AIRSNITCH-00112233")


def test_validate_auth_code_invalid():
    assert not validate_auth_code("WRONG-AABBCCDD")
    assert not validate_auth_code("AIRSNITCH-SHORT")
    assert not validate_auth_code("AIRSNITCH-TOOLONGCODE")
    assert not validate_auth_code("AIRSNITCH-GGHHIIJJ")  # non-hex
    assert not validate_auth_code("")


def test_generate_auth_code():
    code = generate_auth_code("Test Hotel")
    assert code.startswith("AIRSNITCH-")
    assert len(code) == len("AIRSNITCH-") + 8
    assert validate_auth_code(code)


def test_generate_auth_code_deterministic():
    c1 = generate_auth_code("Marriott Downtown")
    c2 = generate_auth_code("Marriott Downtown")
    assert c1 == c2


def test_audit_logger(tmp_path: Path):
    log_path = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_path)

    logger.log_test_start("gtk_injection", "aa:bb:cc:dd:ee:ff")
    logger.log_packet_send("gtk_injection", "ICMP echo", 3)
    logger.log_test_result("gtk_injection", "aa:bb:cc:dd:ee:ff", {"success": True})
    logger.log_error("test", "something failed")
    logger.log_session_end()

    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 6  # session_start + 4 events + session_end

    events = [json.loads(line)["event"] for line in lines]
    assert events == ["session_start", "test_start", "packet_send", "test_result", "error", "session_end"]


def test_rate_limiter_acquire():
    rl = RateLimiter(pps=100)
    # Should acquire immediately with high rate
    start = time.monotonic()
    for _ in range(10):
        rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 1.0  # 10 tokens at 100pps should be near-instant


def test_rate_limiter_try_acquire():
    rl = RateLimiter(pps=5)
    # First few should succeed
    assert rl.try_acquire()
    assert rl.try_acquire()
    # Eventually fails without refill
    results = [rl.try_acquire() for _ in range(10)]
    assert False in results  # At least some should fail
