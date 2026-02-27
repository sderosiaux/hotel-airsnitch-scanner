"""JSON-lines audit logger for all security test operations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSON-lines audit log."""

    def __init__(self, log_path: Path | None = None):
        if log_path is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            log_path = Path(f"audit_{timestamp}.jsonl")
        self._path = log_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._log_event("session_start", {})

    @property
    def path(self) -> Path:
        return self._path

    def _log_event(self, event_type: str, data: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            **data,
        }
        with self._path.open("a") as f:
            f.write(json.dumps(record) + "\n")

    def log_test_start(self, test_name: str, target: str, params: dict[str, Any] | None = None) -> None:
        self._log_event(
            "test_start",
            {"test": test_name, "target": target, "params": params or {}},
        )

    def log_test_result(self, test_name: str, target: str, result: dict[str, Any]) -> None:
        self._log_event(
            "test_result",
            {"test": test_name, "target": target, "result": result},
        )

    def log_packet_send(self, test_name: str, packet_summary: str, count: int = 1) -> None:
        self._log_event(
            "packet_send",
            {"test": test_name, "summary": packet_summary, "count": count},
        )

    def log_discovery(self, discovery_type: str, data: dict[str, Any]) -> None:
        self._log_event("discovery", {"type": discovery_type, **data})

    def log_error(self, context: str, error: str) -> None:
        self._log_event("error", {"context": context, "error": error})

    def log_session_end(self) -> None:
        self._log_event("session_end", {})
