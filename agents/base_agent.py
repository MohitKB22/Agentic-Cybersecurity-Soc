"""
Base Agent class providing shared infrastructure for all SOC agents.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, Optional


class BaseAgent:
    """
    Abstract base for all SOC pipeline agents.
    Subclasses override `analyze()` with their specialist logic.
    """

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.version = "1.0.0"
        self._run_log: list[Dict] = []

    # ──────────────────────────────────────────
    # Public interface
    # ──────────────────────────────────────────

    def run(self, data: Any) -> Dict:
        """
        Entry point.  Records timing, calls analyze(), wraps in standard envelope.
        """
        start = datetime.utcnow()
        try:
            result = self.analyze(data)
            status = "success"
            error = None
        except Exception as exc:                          # noqa: BLE001
            result = {}
            status = "error"
            error = str(exc)

        elapsed = (datetime.utcnow() - start).total_seconds()
        entry = {
            "agent": self.name,
            "timestamp": start.isoformat() + "Z",
            "elapsed_seconds": round(elapsed, 4),
            "status": status,
            "error": error,
            "result": result,
        }
        self._run_log.append(entry)
        return entry

    def analyze(self, data: Any) -> Dict:
        """Override in subclasses."""
        raise NotImplementedError(f"{self.name}.analyze() is not implemented")

    # ──────────────────────────────────────────
    # Shared helpers
    # ──────────────────────────────────────────

    @staticmethod
    def severity_score(label: str) -> int:
        """Map textual severity to integer for comparison / sorting."""
        return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            label.lower(), -1
        )

    @staticmethod
    def extract_ips(text: str) -> list[str]:
        pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        return list(set(re.findall(pattern, text or "")))

    @staticmethod
    def extract_domains(text: str) -> list[str]:
        pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        return list(set(re.findall(pattern, text or "")))

    @staticmethod
    def normalize_timestamp(raw: str) -> Optional[str]:
        """Try to parse a variety of timestamp formats; return ISO-8601 or None."""
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(raw.strip(), fmt).isoformat() + "Z"
            except ValueError:
                continue
        return raw  # return as-is if no format matched

    # ──────────────────────────────────────────
    # Serialisation helpers
    # ──────────────────────────────────────────

    def to_dict(self) -> Dict:
        return {"name": self.name, "description": self.description, "version": self.version}

    def get_run_history(self) -> list[Dict]:
        return self._run_log

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
