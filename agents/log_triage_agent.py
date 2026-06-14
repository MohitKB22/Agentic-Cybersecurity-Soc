"""
Agent 1 – Log Triage Agent
Parses raw logs, normalizes fields, classifies, filters noise, assigns severity.
"""

import json
import re
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent


# ──────────────────────────────────────────────────────────────────────────────
# Rule tables  (deterministic pattern-matching "model")
# ──────────────────────────────────────────────────────────────────────────────

# (regex_on_raw_log, event_type, noise_label, severity, escalation)
TRIAGE_RULES: List[tuple] = [
    # ── Authentication ──────────────────────────────────────────────────────
    (r"Failed password|authentication failure|invalid user|logon failure",
     "Authentication", "Suspicious", "High", "Escalate"),
    (r"EventID=4625|EventID=4771",
     "Authentication", "Suspicious", "High", "Escalate"),
    (r"EventID=4624|Accepted password|successful login",
     "Authentication", "Expected Activity", "Informational", "Close"),
    (r"MFA.*bypass|mfa=false.*ConsoleLogin|MFA.*failed",
     "Authentication", "Suspicious", "High", "Escalate"),

    # ── Privilege Management ─────────────────────────────────────────────────
    (r"EventID=4728|EventID=4732|net\.exe.*domain admins|added to.*admin",
     "Privilege Management", "High Priority", "Critical", "Escalate"),
    (r"EventID=4673|EventID=4674|sudo.*ALL",
     "Privilege Management", "Suspicious", "High", "Escalate"),

    # ── Endpoint ─────────────────────────────────────────────────────────────
    (r"powershell.*-enc|-nop.*-w hidden|IEX\(|Invoke-Expression|DownloadString",
     "Endpoint", "High Priority", "Critical", "Escalate"),
    (r"EventID=4688|process.?creat|NewProcessName",
     "Endpoint", "Requires Review", "Medium", "Monitor"),
    (r"mimikatz|lsass.*dump|procdump",
     "Endpoint", "High Priority", "Critical", "Escalate"),

    # ── Network ──────────────────────────────────────────────────────────────
    (r"base64.*\.com|dns.*tunnel|long.*subdomain|\bscan\b|nmap|dport=53.*query=|proto=UDP.*dport=53",
     "Network", "High Priority", "Critical", "Escalate"),
    (r"bytes=\d{7,}|large.*transfer|exfil",
     "Network", "Suspicious", "High", "Escalate"),
    (r"firewall.*DENY|blocked.*outbound",
     "Network", "Benign", "Low", "Monitor"),

    # ── Cloud ─────────────────────────────────────────────────────────────────
    (r"CreateAccessKey|AttachUserPolicy|Administrator.*Access|PutBucketPolicy.*Public",
     "Cloud", "High Priority", "Critical", "Escalate"),
    (r"ConsoleLogin.*mfa=false",
     "Cloud", "Suspicious", "High", "Escalate"),
    (r"s3.*GetObject|lambda.*invoke",
     "Cloud", "Expected Activity", "Informational", "Close"),

    # ── Malware ──────────────────────────────────────────────────────────────
    # Generic login failures not caught by specific rules
    (r"Action=Login.*Result=Failure|result=Failure.*Action=Login|login.*fail|LogonType.*Failure",
     "Authentication", "Suspicious", "High", "Escalate"),
    (r"trojan|ransomware|malware|eicar|cobalt.?strike|metasploit",
     "Malware", "High Priority", "Critical", "Escalate"),

    # ── Data Access ───────────────────────────────────────────────────────────
    (r"SELECT \*.*password|dump.*credentials|EventID=4663.*SAM",
     "Data Access", "High Priority", "Critical", "Escalate"),
]

# Field extraction patterns (key → regex group named 'val')
FIELD_PATTERNS = {
    "timestamp":      r"(?P<val>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2})",
    "hostname":       r"(?:host(?:name)?=|on\s)(?P<val>[\w\-]+)",
    "username":       r"(?:user(?:name)?=|for\s|Account=|User=)(?P<val>[A-Za-z0-9@\\\.\-_]+)",
    "source_ip":      r"(?:src(?:_ip)?=|from\s|SourceIP=|src=)(?P<val>\d{1,3}(?:\.\d{1,3}){3})",
    "destination_ip": r"(?:dst(?:_ip)?=|to\s|DestIP=|dst=)(?P<val>\d{1,3}(?:\.\d{1,3}){3})",
    "process":        r"(?:process=|NewProcessName=.*\\)(?P<val>[\w\.\-]+\.exe)",
    "event_id":       r"(?:EventID=|eventid=)(?P<val>\d+)",
    "file_path":      r"(?P<val>[A-Za-z]:\\(?:[\w\s\-\.]+\\)*[\w\s\-\.]+\.\w+)",
    "domain":         r"(?:domain=|CORP\\|@)(?P<val>[A-Za-z0-9\.\-_]+)",
    "url":            r"(?P<val>https?://[^\s'\"]+)",
    "action":         r"(?:action=|event=|Action=)(?P<val>[\w\s]+?)(?:\s|$|,)",
    "result":         r"(?:result=|Result=|status=)(?P<val>Success|Failure|DENY|ALLOW|Failed|Accepted)",
}


class LogTriageAgent(BaseAgent):
    """
    Parses and classifies security log lines using deterministic rule matching.
    """

    def __init__(self):
        super().__init__(
            name="LogTriageAgent",
            description="Parses raw security logs, extracts fields, classifies events, and assigns severity."
        )

    # ──────────────────────────────────────────────────────────────────────
    # Core analysis
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, data: Any) -> Dict:
        raw_log = self._get_raw_log(data)
        indicators = self._extract_indicators(raw_log)
        classification, noise, severity, escalation = self._classify(raw_log)

        return {
            "event_summary": self._build_summary(indicators, classification, severity),
            "extracted_indicators": indicators,
            "initial_assessment": {
                "classification": classification,
                "noise_level": noise,
            },
            "severity": severity,
            "escalation_recommendation": escalation,
            "reasoning": self._build_reasoning(raw_log, classification, noise, severity),
        }

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _get_raw_log(data: Any) -> str:
        if isinstance(data, dict):
            return str(data.get("raw_log", data.get("log", data.get("message", json.dumps(data)))))
        return str(data)

    def _extract_indicators(self, log: str) -> Dict:
        indicators: Dict[str, Optional[str]] = {}
        for field, pattern in FIELD_PATTERNS.items():
            m = re.search(pattern, log, re.IGNORECASE)
            indicators[field] = m.group("val") if m else None

        # Normalise timestamp
        if indicators.get("timestamp"):
            indicators["timestamp"] = self.normalize_timestamp(indicators["timestamp"])

        # Fallback: grab any bare IPs not already captured
        all_ips = self.extract_ips(log)
        if not indicators["source_ip"] and all_ips:
            indicators["source_ip"] = all_ips[0]
        if not indicators["destination_ip"] and len(all_ips) > 1:
            indicators["destination_ip"] = all_ips[1]

        return indicators

    @staticmethod
    def _classify(log: str):
        for pattern, classification, noise, severity, escalation in TRIAGE_RULES:
            if re.search(pattern, log, re.IGNORECASE):
                return classification, noise, severity, escalation
        return "Unknown", "Requires Review", "Low", "Monitor"

    @staticmethod
    def _build_summary(indicators: Dict, classification: str, severity: str) -> str:
        host = indicators.get("hostname") or "unknown host"
        user = indicators.get("username") or "unknown user"
        src = indicators.get("source_ip") or "unknown source"
        action = indicators.get("action") or "activity"
        return (
            f"[{severity}] {classification} event — "
            f"{action} detected on {host} for user {user} from {src}."
        )

    @staticmethod
    def _build_reasoning(log: str, classification: str, noise: str, severity: str) -> str:
        return (
            f"Log classified as '{classification}' based on pattern matching against known "
            f"triage rules. Noise level '{noise}' assigned. Severity '{severity}' determined "
            f"by rule priority and action keywords identified in the raw log entry."
        )
