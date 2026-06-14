"""
Agent 3 – Threat Correlation Agent
Connects anomalies into coherent attack narratives and maps to MITRE ATT&CK.
"""

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .base_agent import BaseAgent


# ──────────────────────────────────────────────────────────────────────────────
# ATT&CK Kill-chain stage ordering
# ──────────────────────────────────────────────────────────────────────────────

ATTACK_STAGES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]

STAGE_ORDER = {s: i for i, s in enumerate(ATTACK_STAGES)}

# Maps anomaly_type keywords → (attack_stage, mitre_technique_id, description)
ANOMALY_TO_STAGE: List[Tuple[str, str, str, str]] = [
    ("brute force",          "Initial Access",       "T1110.001", "Brute Force: Password Guessing"),
    ("password spray",       "Initial Access",       "T1110.003", "Brute Force: Password Spraying"),
    ("impossible travel",    "Initial Access",       "T1078",     "Valid Accounts"),
    ("phishing",             "Initial Access",       "T1566",     "Phishing"),
    ("powershell",           "Execution",            "T1059.001", "PowerShell"),
    ("script",               "Execution",            "T1059",     "Command and Scripting Interpreter"),
    ("wmi",                  "Execution",            "T1047",     "Windows Management Instrumentation"),
    ("persistence",          "Persistence",          "T1547",     "Boot/Logon Autostart Execution"),
    ("registry",             "Persistence",          "T1547.001", "Registry Run Keys"),
    ("scheduled task",       "Persistence",          "T1053",     "Scheduled Task/Job"),
    ("privilege escalation", "Privilege Escalation", "T1068",     "Exploitation for Privilege Escalation"),
    ("cloud priv",           "Privilege Escalation", "T1098",     "Account Manipulation"),
    ("domain admin",         "Privilege Escalation", "T1078.002", "Valid Accounts: Domain Accounts"),
    ("defense evasion",      "Defense Evasion",      "T1070",     "Indicator Removal"),
    ("log clear",            "Defense Evasion",      "T1070.001", "Clear Windows Event Logs"),
    ("credential dump",      "Credential Access",    "T1003",     "OS Credential Dumping"),
    ("mfa bypass",           "Credential Access",    "T1556.006", "Modify Authentication Process"),
    ("discovery",            "Discovery",            "T1083",     "File and Directory Discovery"),
    ("port scan",            "Discovery",            "T1046",     "Network Service Scanning"),
    ("lateral movement",     "Lateral Movement",     "T1021",     "Remote Services"),
    ("pass-the-hash",        "Lateral Movement",     "T1550.002", "Pass the Hash"),
    ("data staging",         "Collection",           "T1074",     "Data Staged"),
    ("collection",           "Collection",           "T1119",     "Automated Collection"),
    ("exfiltration",         "Exfiltration",         "T1041",     "Exfiltration Over C2 Channel"),
    ("dns tunnel",           "Exfiltration",         "T1071.004", "DNS Application Layer Protocol"),
    ("ransomware",           "Impact",               "T1486",     "Data Encrypted for Impact"),
    ("wiper",                "Impact",               "T1485",     "Data Destruction"),
    ("large transfer",       "Exfiltration",         "T1048",     "Exfiltration Over Alternative Protocol"),
    ("beaconing",            "Exfiltration",         "T1071.001", "Web Protocols C2"),
    ("off-hours",            "Defense Evasion",      "T1078",     "Valid Accounts – Unusual Hours"),
    # Raw event type= fields from training data
    ("brute_force",          "Initial Access",       "T1110.001", "Brute Force: Password Guessing"),
    ("data_staging",         "Collection",           "T1074",     "Data Staged"),
    ("process_creation",     "Execution",            "T1059",     "Command and Scripting Interpreter"),
    ("lateral_movement",     "Lateral Movement",     "T1021",     "Remote Services"),
    # Account & user creation
    ("user creation",        "Execution",            "T1136.001", "Create Account: Local Account"),
    ("net.exe",              "Execution",            "T1136.002", "Create Account: Domain Account"),
    ("net user",             "Execution",            "T1136.002", "Create Account: Domain Account"),
    ("group add",            "Privilege Escalation", "T1078.002", "Valid Accounts: Domain Accounts"),
    ("domain admins",        "Privilege Escalation", "T1078.002", "Valid Accounts: Domain Accounts"),
    ("admin group",          "Privilege Escalation", "T1078.002", "Valid Accounts: Domain Accounts"),
    # Additional lateral movement specifics
    ("wmiexec",              "Lateral Movement",     "T1047",     "Windows Management Instrumentation"),
    ("psexec",               "Lateral Movement",     "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ("rdp",                  "Lateral Movement",     "T1021.001", "Remote Services: Remote Desktop Protocol"),
    ("ssh",                  "Initial Access",       "T1021.004", "Remote Services: SSH"),
    # Data exfil specifics
    ("potential data exfil", "Exfiltration",         "T1041",     "Exfiltration Over C2 Channel"),
    ("data exfiltration",    "Exfiltration",         "T1041",     "Exfiltration Over C2 Channel"),
    ("c2 beaconing",         "Exfiltration",         "T1071.001", "Web Protocols C2"),
    # Cloud specifics
    ("cloud privilege",      "Privilege Escalation", "T1098",     "Account Manipulation"),
    ("iam",                  "Privilege Escalation", "T1098",     "Account Manipulation"),
    ("createaccesskey",      "Privilege Escalation", "T1098.001", "Account Manipulation: Additional Cloud Credentials"),
    # Credential access
    ("credential dumping",   "Credential Access",    "T1003",     "OS Credential Dumping"),
    ("lsass",                "Credential Access",    "T1003.001", "OS Credential Dumping: LSASS Memory"),
    ("mimikatz",             "Credential Access",    "T1003.001", "OS Credential Dumping: LSASS Memory"),
    # Off hours / evasion
    ("off-hours activity",   "Defense Evasion",      "T1078",     "Valid Accounts - Unusual Hours"),
    ("suspicious powershell","Execution",            "T1059.001", "PowerShell"),
    # Generic account/net commands
    ("net group",            "Privilege Escalation", "T1078.002", "Valid Accounts: Domain Accounts"),
    ("add.*admin",           "Privilege Escalation", "T1078.002", "Valid Accounts: Domain Accounts"),
]


class ThreatCorrelationAgent(BaseAgent):
    """
    Correlates anomalies and raw events by shared indicators (IPs, users, hosts)
    and constructs an ordered attack timeline with ATT&CK mapping.
    """

    def __init__(self):
        super().__init__(
            name="ThreatCorrelationAgent",
            description="Correlates anomalies into attack narratives and maps to MITRE ATT&CK."
        )

    # ──────────────────────────────────────────────────────────────────────
    # Core analysis
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, data: Any) -> Dict:
        anomalies, raw_events = self._parse_input(data)

        # Build shared indicator index
        indicator_index = self._build_indicator_index(anomalies + raw_events)

        # Map each item to ATT&CK stage
        staged = self._map_to_stages(anomalies, raw_events)

        # Build timeline
        timeline = self._build_timeline(staged, raw_events)

        # Deduplicate ATT&CK techniques
        mitre_map = self._deduplicate_mitre(staged)

        # Confidence + narrative
        confidence = self._calculate_confidence(staged)
        narrative = self._build_narrative(staged, indicator_index)
        objectives = self._infer_objectives(staged)

        return {
            "correlated_events": staged,
            "shared_indicators": indicator_index,
            "attack_timeline": timeline,
            "attack_narrative": narrative,
            "mitre_attack_mapping": mitre_map,
            "confidence_level": confidence,
            "potential_attacker_objectives": objectives,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Input parsing
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_input(data: Any) -> Tuple[List[Dict], List[Dict]]:
        if isinstance(data, dict):
            anomalies = data.get("anomalies", data.get("detected_anomalies", []))
            raw_events = data.get("events", data.get("raw_events", []))
            # If triage output passed directly, wrap it
            if "extracted_indicators" in data:
                raw_events = [data]
            # If events have "type" field (training data format), treat as raw_events
            return anomalies, raw_events
        if isinstance(data, list):
            anomalies = [x for x in data if "anomaly_type" in x]
            raw_events = [x for x in data if "anomaly_type" not in x]
            return anomalies, raw_events
        return [], []

    @classmethod
    def _event_to_lookup_text(cls, event: Dict) -> str:
        """Build lookup text from a raw event dict — include ALL relevant fields."""
        parts = []
        for key in ("type", "event_type", "classification", "action", "method",
                    "process", "cmdline", "args", "description", "anomaly_type",
                    "path", "query"):
            if event.get(key):
                parts.append(str(event[key]).lower())
        # Flatten nested evidence dict too
        ev = event.get("evidence", {})
        if isinstance(ev, dict):
            for k in ("cmdline", "description", "action"):
                if ev.get(k):
                    parts.append(str(ev[k]).lower())
        return " ".join(parts)

    # ──────────────────────────────────────────────────────────────────────
    # Indicator indexing
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_indicator_index(items: List[Dict]) -> Dict:
        index: Dict[str, set] = defaultdict(set)
        for item in items:
            # Flatten nested evidence/indicators dicts
            flat = {}
            flat.update(item)
            if "evidence" in item and isinstance(item["evidence"], dict):
                flat.update(item["evidence"])
            if "extracted_indicators" in item and isinstance(item["extracted_indicators"], dict):
                flat.update(item["extracted_indicators"])

            for key in ("src_ip", "source_ip", "ip"):
                if flat.get(key):
                    index["ips"].add(str(flat[key]))
            for key in ("user", "username", "target_user"):
                if flat.get(key):
                    index["users"].add(str(flat[key]))
            for key in ("host", "hostname", "src_host", "dst_host"):
                if flat.get(key):
                    index["hosts"].add(str(flat[key]))
            for key in ("dst_ip",):
                if flat.get(key):
                    index["external_ips"].add(str(flat[key]))
            for key in ("domain",):
                if flat.get(key):
                    index["domains"].add(str(flat[key]))

        return {k: sorted(v) for k, v in index.items() if v}

    # ──────────────────────────────────────────────────────────────────────
    # Stage mapping
    # ──────────────────────────────────────────────────────────────────────

    def _map_to_stages(self, anomalies: List[Dict], raw_events: List[Dict]) -> List[Dict]:
        staged = []
        for item in anomalies:
            atype = str(item.get("anomaly_type", "")).lower()
            stage, technique_id, technique_name = self._lookup_stage(atype)
            staged.append({
                "source": "anomaly",
                "attack_stage": stage,
                "stage_order": STAGE_ORDER.get(stage, 99),
                "technique_id": technique_id,
                "technique_name": technique_name,
                "description": item.get("description", atype),
                "evidence": item.get("evidence", {}),
                "confidence": item.get("confidence", 0.70),
                "risk": item.get("risk", "Medium"),
                "original": item,
            })

        for event in raw_events:
            # Try to infer stage from event classification or action or type
            lookup_text = self._event_to_lookup_text(event)
            classification = str(event.get("classification", "")).lower()
            action = str(event.get("action", event.get("event_type", event.get("type", "")))).lower()
            # Also check raw_log if present
            raw_log = str(event.get("raw_log", event.get("log", ""))).lower()
            combined = lookup_text + " " + classification + " " + action + " " + raw_log
            stage, technique_id, technique_name = self._lookup_stage(combined)
            if stage != "Unknown":
                staged.append({
                    "source": "raw_event",
                    "attack_stage": stage,
                    "stage_order": STAGE_ORDER.get(stage, 99),
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "description": f"{event.get('action', 'Event')} on {event.get('hostname', event.get('host', '?'))}",
                    "evidence": event,
                    "confidence": 0.65,
                    "risk": event.get("severity", "Medium"),
                    "original": event,
                })

        # Sort by kill-chain stage order
        staged.sort(key=lambda x: x["stage_order"])
        return staged

    @staticmethod
    def _lookup_stage(text: str) -> Tuple[str, str, str]:
        for keyword, stage, tid, tname in ANOMALY_TO_STAGE:
            if keyword in text:
                return stage, tid, tname
        return "Unknown", "T0000", "Unknown Technique"

    # ──────────────────────────────────────────────────────────────────────
    # Timeline builder
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_timeline(staged: List[Dict], raw_events: List[Dict]) -> List[Dict]:
        timeline = []
        for item in staged:
            ev = item.get("original", {})
            ts = (
                ev.get("time")
                or ev.get("timestamp")
                or ev.get("extracted_indicators", {}).get("timestamp")
                or "Unknown"
            )
            timeline.append({
                "time": ts,
                "stage": item["attack_stage"],
                "event": item["description"],
                "technique": f"{item['technique_id']} – {item['technique_name']}",
                "confidence": item["confidence"],
            })
        return timeline

    # ──────────────────────────────────────────────────────────────────────
    # MITRE deduplication
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _deduplicate_mitre(staged: List[Dict]) -> List[Dict]:
        seen = {}
        for item in staged:
            tid = item["technique_id"]
            if tid not in seen:
                seen[tid] = {
                    "technique_id": tid,
                    "technique_name": item["technique_name"],
                    "attack_stage": item["attack_stage"],
                    "confidence": item["confidence"],
                }
            else:
                # Keep highest confidence
                seen[tid]["confidence"] = max(seen[tid]["confidence"], item["confidence"])
        return list(seen.values())

    # ──────────────────────────────────────────────────────────────────────
    # Confidence calculation
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _calculate_confidence(staged: List[Dict]) -> str:
        if not staged:
            return "Low (0.00) — insufficient data"
        confidences = [s["confidence"] for s in staged]
        avg = sum(confidences) / len(confidences)
        # Boost confidence when multiple distinct stages are present (richer correlation)
        unique_stages = len({s["attack_stage"] for s in staged if s["attack_stage"] != "Unknown"})
        stage_boost = min(0.10, unique_stages * 0.02)
        avg = min(0.99, avg + stage_boost)
        label = "Low" if avg < 0.6 else "Medium" if avg < 0.8 else "High"
        return f"{label} ({avg:.2f})"

    # ──────────────────────────────────────────────────────────────────────
    # Narrative & objectives
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_narrative(staged: List[Dict], indicators: Dict) -> str:
        if not staged:
            return "No correlated attack narrative could be constructed from available data."

        stages_present = list(dict.fromkeys(s["attack_stage"] for s in staged))
        ips = indicators.get("ips", [])
        users = indicators.get("users", [])
        hosts = indicators.get("hosts", [])

        parts = [
            f"Attack progression identified across {len(stages_present)} kill-chain stage(s): "
            f"{', '.join(stages_present)}."
        ]
        if ips:
            parts.append(f"Threat actor operated from IP(s): {', '.join(ips[:3])}.")
        if users:
            parts.append(f"Compromised or targeted account(s): {', '.join(list(users)[:3])}.")
        if hosts:
            parts.append(f"Affected host(s): {', '.join(list(hosts)[:3])}.")

        # Describe first and last stage
        first = staged[0]
        last = staged[-1]
        parts.append(
            f"Attack began with '{first['attack_stage']}' ({first['technique_id']}) "
            f"and progressed to '{last['attack_stage']}' ({last['technique_id']})."
        )
        return " ".join(parts)

    @staticmethod
    def _infer_objectives(staged: List[Dict]) -> List[str]:
        stage_set = {s["attack_stage"] for s in staged}
        objectives = []
        if "Exfiltration" in stage_set:
            objectives.append("Data theft / intellectual property exfiltration")
        if "Impact" in stage_set:
            objectives.append("Destructive attack (ransomware / wiper)")
        if "Privilege Escalation" in stage_set and "Lateral Movement" in stage_set:
            objectives.append("Domain compromise / persistent access")
        if "Credential Access" in stage_set:
            objectives.append("Credential harvesting for further attacks")
        if not objectives:
            objectives.append("Objective unclear — insufficient stage coverage to infer")
        return objectives
