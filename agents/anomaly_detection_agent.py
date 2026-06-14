"""
Agent 2 – Anomaly Detection Agent
Identifies suspicious behavioural patterns from batches of security events.
"""

from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent


# ──────────────────────────────────────────────────────────────────────────────
# Thresholds / knobs
# ──────────────────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 4           # failed logins from same IP within window
SPRAY_USER_THRESHOLD = 3            # distinct users tried from same IP
BEACON_REGULARITY_THRESHOLD = 0.85  # 0-1, how uniform the intervals are
LARGE_TRANSFER_MB = 100             # bytes → consider suspicious

# MITRE mapping for detected patterns
TECHNIQUE_MAP = {
    "brute_force":          ("T1110.001", "Brute Force: Password Guessing"),
    "password_spraying":    ("T1110.003", "Brute Force: Password Spraying"),
    "impossible_travel":    ("T1078",     "Valid Accounts"),
    "mfa_bypass":           ("T1556.006", "Modify Authentication Process: MFA"),
    "powershell_abuse":     ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "script_abuse":         ("T1059",     "Command and Scripting Interpreter"),
    "beaconing":            ("T1071.001", "Application Layer Protocol: Web Protocols"),
    "dns_tunneling":        ("T1071.004", "Application Layer Protocol: DNS"),
    "lateral_movement":     ("T1047",     "Windows Management Instrumentation"),
    "data_exfiltration":    ("T1041",     "Exfiltration Over C2 Channel"),
    "privilege_escalation": ("T1078.002", "Valid Accounts: Domain Accounts"),
    "cloud_iam_abuse":      ("T1098",     "Account Manipulation"),
    "credential_dumping":   ("T1003",     "OS Credential Dumping"),
    "persistence":          ("T1547",     "Boot or Logon Autostart Execution"),
    "process_injection":    ("T1055",     "Process Injection"),
    "off_hours_activity":   ("T1078",     "Valid Accounts – off-hours use"),
}


class AnomalyDetectionAgent(BaseAgent):
    """
    Runs a suite of heuristic detectors over a list of security events
    and returns structured anomaly findings.
    """

    def __init__(self):
        super().__init__(
            name="AnomalyDetectionAgent",
            description="Identifies suspicious behavioural patterns using heuristic detectors."
        )

    # ──────────────────────────────────────────────────────────────────────
    # Core analysis
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, data: Any) -> Dict:
        events: List[Dict] = self._normalise_input(data)
        anomalies: List[Dict] = []

        # Run every detector
        detectors = [
            self._detect_brute_force,
            self._detect_password_spray,
            self._detect_impossible_travel,
            self._detect_powershell_abuse,
            self._detect_beaconing,
            self._detect_large_transfer,
            self._detect_off_hours,
            self._detect_cloud_priv_escalation,
            self._detect_credential_dumping,
            self._detect_lateral_movement,
        ]
        for detector in detectors:
            try:
                found = detector(events)
                if found:
                    anomalies.extend(found if isinstance(found, list) else [found])
            except Exception:       # noqa: BLE001 — keep pipeline running
                pass

        overall_risk = self._overall_risk(anomalies)
        return {
            "detected_anomalies": anomalies,
            "total_anomalies": len(anomalies),
            "overall_threat_assessment": overall_risk,
            "recommended_next_steps": self._next_steps(anomalies),
        }

    # ──────────────────────────────────────────────────────────────────────
    # Input normalisation
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_input(data: Any) -> List[Dict]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("events", [data])
        return []

    # ──────────────────────────────────────────────────────────────────────
    # Detectors
    # ──────────────────────────────────────────────────────────────────────

    def _detect_brute_force(self, events: List[Dict]) -> Optional[List[Dict]]:
        """Same IP → many failed auth attempts against same user."""
        counter: Counter = Counter()
        for e in events:
            if str(e.get("result", "")).lower() in ("failed", "failure") and e.get("src_ip"):
                key = (e["src_ip"], e.get("user", e.get("username", "?")))
                counter[key] += 1

        findings = []
        for (ip, user), count in counter.items():
            if count >= BRUTE_FORCE_THRESHOLD:
                tid, tname = TECHNIQUE_MAP["brute_force"]
                findings.append(self._build_anomaly(
                    atype="Brute Force Authentication",
                    description=f"{count} failed login attempts for '{user}' from {ip}.",
                    evidence={"source_ip": ip, "target_user": user, "failed_attempts": count},
                    confidence=min(0.99, 0.70 + count * 0.03),
                    risk="Critical" if count > 10 else "High",
                    technique_id=tid, technique_name=tname,
                ))
        return findings or None

    def _detect_password_spray(self, events: List[Dict]) -> Optional[List[Dict]]:
        """Same IP, multiple distinct users failed."""
        ip_users: Dict[str, set] = {}
        for e in events:
            if str(e.get("result", "")).lower() in ("failed", "failure") and e.get("src_ip"):
                ip = e["src_ip"]
                user = e.get("user", e.get("username", "?"))
                ip_users.setdefault(ip, set()).add(user)

        findings = []
        for ip, users in ip_users.items():
            if len(users) >= SPRAY_USER_THRESHOLD:
                tid, tname = TECHNIQUE_MAP["password_spraying"]
                findings.append(self._build_anomaly(
                    atype="Password Spraying",
                    description=f"{len(users)} distinct accounts targeted from {ip}.",
                    evidence={"source_ip": ip, "targeted_accounts": list(users)},
                    confidence=0.90,
                    risk="High",
                    technique_id=tid, technique_name=tname,
                ))
        return findings or None

    def _detect_impossible_travel(self, events: List[Dict]) -> Optional[List[Dict]]:
        """Same user, two geographically distant locations in short window."""
        user_events: Dict[str, List[Dict]] = {}
        for e in events:
            user = e.get("user", e.get("username"))
            if user and e.get("location"):
                user_events.setdefault(user, []).append(e)

        findings = []
        for user, evts in user_events.items():
            locations = list({e["location"] for e in evts})
            if len(locations) >= 2:
                tid, tname = TECHNIQUE_MAP["impossible_travel"]
                findings.append(self._build_anomaly(
                    atype="Impossible Travel",
                    description=f"User '{user}' authenticated from {locations} — impossible without credential compromise.",
                    evidence={"user": user, "locations": locations},
                    confidence=0.95,
                    risk="Critical",
                    technique_id=tid, technique_name=tname,
                ))
        return findings or None

    @staticmethod
    def _detect_powershell_abuse(events: List[Dict]) -> Optional[List[Dict]]:
        """Suspicious PowerShell execution patterns."""
        import re
        SUSPICIOUS_PATTERNS = [
            r"-[Ee]nc(?:odedCommand)?",
            r"-[Nn][Oo][Pp](?:rofile)?",
            r"-[Ww]\s*[Hh]idden",
            r"IEX\s*\(",
            r"Invoke-Expression",
            r"DownloadString|DownloadFile|WebClient",
            r"FromBase64String",
            r"Net\.WebClient",
        ]
        findings = []
        for e in events:
            cmdline = e.get("cmdline", e.get("command_line", ""))
            proc = e.get("process", "")
            if "powershell" not in proc.lower() and "powershell" not in cmdline.lower():
                continue
            hits = [p for p in SUSPICIOUS_PATTERNS if re.search(p, cmdline, re.IGNORECASE)]
            if hits:
                findings.append({
                    "anomaly_type": "Suspicious PowerShell Execution",
                    "description": f"PowerShell executed with suspicious flags/patterns: {hits}",
                    "evidence": {"host": e.get("host"), "user": e.get("user"), "cmdline": cmdline},
                    "risk": "Critical",
                    "confidence": 0.97,
                    "mitre_technique": "T1059.001 – PowerShell",
                })
        return findings or None

    def _detect_beaconing(self, events: List[Dict]) -> Optional[List[Dict]]:
        """Detect regular periodic outbound connections (C2 beacon)."""
        # Group by (host, dst_ip)
        sessions: Dict[tuple, List] = {}
        for e in events:
            key = (e.get("host"), e.get("dst_ip"))
            if all(key):
                sessions.setdefault(key, []).append(e)

        findings = []
        for (host, dst), evts in sessions.items():
            if len(evts) < 4:
                continue
            intervals = [e.get("interval_sec") for e in evts]
            intervals = [i for i in intervals if isinstance(i, (int, float))]
            if not intervals:
                continue
            avg = sum(intervals) / len(intervals)
            regularity = 1 - (max(intervals) - min(intervals)) / (avg + 1e-9)
            if regularity >= BEACON_REGULARITY_THRESHOLD:
                tid, tname = TECHNIQUE_MAP["beaconing"]
                findings.append(self._build_anomaly(
                    atype="C2 Beaconing",
                    description=f"Host {host} beaconing to {dst} every ~{avg:.0f}s (regularity={regularity:.2f}).",
                    evidence={"host": host, "dst_ip": dst, "beacon_interval_sec": round(avg), "samples": len(evts)},
                    confidence=min(0.99, 0.70 + regularity * 0.29),
                    risk="High",
                    technique_id=tid, technique_name=tname,
                ))
        return findings or None

    def _detect_large_transfer(self, events: List[Dict]) -> Optional[List[Dict]]:
        findings = []
        for e in events:
            mb = e.get("size_mb") or (e.get("bytes", 0) / 1_000_000)
            if mb >= LARGE_TRANSFER_MB:
                tid, tname = TECHNIQUE_MAP["data_exfiltration"]
                findings.append(self._build_anomaly(
                    atype="Potential Data Exfiltration",
                    description=f"{mb:.1f} MB transferred from {e.get('host')} to {e.get('dst_ip')}.",
                    evidence={"host": e.get("host"), "dst_ip": e.get("dst_ip"), "size_mb": mb},
                    confidence=0.80,
                    risk="High",
                    technique_id=tid, technique_name=tname,
                ))
        return findings or None

    @staticmethod
    def _detect_off_hours(events: List[Dict]) -> Optional[List[Dict]]:
        """Logins between 22:00–05:00 for non-service accounts."""
        findings = []
        for e in events:
            t = e.get("time", "")
            user = e.get("user", e.get("username", ""))
            if not t or "svc_" in user.lower():
                continue
            try:
                hour = int(str(t).split(":")[0])
                if hour >= 22 or hour <= 5:
                    findings.append({
                        "anomaly_type": "Off-Hours Activity",
                        "description": f"User '{user}' active at {t} — outside business hours.",
                        "evidence": {"user": user, "time": t, "host": e.get("host")},
                        "risk": "Medium",
                        "confidence": 0.70,
                        "mitre_technique": "T1078 – Valid Accounts",
                    })
            except (ValueError, IndexError):
                pass
        return findings or None

    @staticmethod
    def _detect_cloud_priv_escalation(events: List[Dict]) -> Optional[List[Dict]]:
        HIGH_RISK_ACTIONS = {"createaccesskey", "attachuserpolicy", "putrolepolicy", "administeraccounts"}
        findings = []
        for e in events:
            action = str(e.get("action", "")).lower()
            policy = str(e.get("policy", "")).lower()
            if action in HIGH_RISK_ACTIONS or "administratoraccess" in policy:
                findings.append({
                    "anomaly_type": "Cloud Privilege Escalation",
                    "description": f"High-risk cloud IAM action '{e.get('action')}' by '{e.get('user')}'.",
                    "evidence": {"user": e.get("user"), "action": e.get("action"), "policy": e.get("policy")},
                    "risk": "Critical",
                    "confidence": 0.95,
                    "mitre_technique": "T1098 – Account Manipulation",
                })
        return findings or None

    @staticmethod
    def _detect_credential_dumping(events: List[Dict]) -> Optional[List[Dict]]:
        import re
        patterns = [r"mimikatz", r"lsass", r"procdump", r"sekurlsa", r"ntds\.dit", r"vssadmin"]
        findings = []
        for e in events:
            cmdline = e.get("cmdline", e.get("command_line", ""))
            hits = [p for p in patterns if re.search(p, cmdline, re.IGNORECASE)]
            if hits:
                findings.append({
                    "anomaly_type": "Credential Dumping",
                    "description": f"Credential-dumping tool indicators found: {hits}",
                    "evidence": {"host": e.get("host"), "user": e.get("user"), "cmdline": cmdline},
                    "risk": "Critical",
                    "confidence": 0.98,
                    "mitre_technique": "T1003 – OS Credential Dumping",
                })
        return findings or None

    @staticmethod
    def _detect_lateral_movement(events: List[Dict]) -> Optional[List[Dict]]:
        LM_METHODS = {"wmi", "psexec", "wmiexec", "smbexec", "pass-the-hash", "pass-the-ticket"}
        findings = []
        for e in events:
            method = str(e.get("method", "")).lower()
            if method in LM_METHODS:
                findings.append({
                    "anomaly_type": "Lateral Movement",
                    "description": f"Lateral movement via {e.get('method')} from {e.get('src_host')} to {e.get('dst_host')}.",
                    "evidence": {"src_host": e.get("src_host"), "dst_host": e.get("dst_host"), "method": e.get("method"), "user": e.get("user")},
                    "risk": "High",
                    "confidence": 0.90,
                    "mitre_technique": "T1047 – WMI / T1021 – Remote Services",
                })
        return findings or None

    # ──────────────────────────────────────────────────────────────────────
    # Aggregation helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_anomaly(atype, description, evidence, confidence, risk, technique_id, technique_name) -> Dict:
        return {
            "anomaly_type": atype,
            "description": description,
            "evidence": evidence,
            "risk": risk,
            "confidence": round(confidence, 2),
            "mitre_technique": f"{technique_id} – {technique_name}",
        }

    @staticmethod
    def _overall_risk(anomalies: List[Dict]) -> str:
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        if not anomalies:
            return "No anomalies detected"
        top = max(anomalies, key=lambda a: risk_order.get(a.get("risk", "").lower(), 0))
        return f"Overall Risk: {top['risk'].upper()} — highest-risk anomaly: {top['anomaly_type']}"

    @staticmethod
    def _next_steps(anomalies: List[Dict]) -> List[str]:
        steps = set()
        for a in anomalies:
            atype = a.get("anomaly_type", "").lower()
            if "brute force" in atype or "spray" in atype:
                steps.add("Block source IP at perimeter; enforce account lockout policy.")
            if "impossible travel" in atype:
                steps.add("Immediately revoke user session tokens and force re-authentication with MFA.")
            if "powershell" in atype:
                steps.add("Capture full process tree and memory dump from affected host.")
            if "beaconing" in atype or "exfiltration" in atype:
                steps.add("Block destination IP; capture full packet capture for forensic review.")
            if "cloud" in atype:
                steps.add("Revoke IAM access keys; audit all recent AWS CloudTrail events.")
            if "credential" in atype:
                steps.add("Force password reset for all potentially harvested accounts.")
            if "lateral" in atype:
                steps.add("Segment affected network zones; review SMB/WMI access control lists.")
        return sorted(steps) or ["No specific next steps — monitor for escalation."]
