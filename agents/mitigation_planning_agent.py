"""
Agent 4 – Mitigation Planning Agent
Produces prioritised containment, remediation, and hardening recommendations.
"""

from typing import Any, Dict, List

from .base_agent import BaseAgent


# ──────────────────────────────────────────────────────────────────────────────
# Rule tables: (keyword_in_attack_type_or_stage, action_category, action_text)
# ──────────────────────────────────────────────────────────────────────────────

IMMEDIATE_RULES: List[tuple] = [
    ("brute force",          "P1", "Block source IP(s) at perimeter firewall and WAF immediately."),
    ("brute_force",          "P1", "Block source IP(s) at perimeter firewall and WAF immediately."),
    ("password spray",       "P1", "Enforce account lockout policy (≤5 failures / 15 min)."),
    ("impossible travel",    "P1", "Revoke all active sessions for affected user; force MFA re-enrolment."),
    ("lateral movement",     "P1", "Isolate affected hosts from the network to contain spread."),
    ("lateral_movement",     "P1", "Isolate affected hosts from the network to contain spread."),
    ("ransomware",           "P1", "Immediately disconnect affected systems from the network."),
    ("ransomware",           "P1", "Block IOC IPs and hashes at perimeter firewall and EDR."),
    ("ransomware",           "P1", "Disable compromised user accounts pending investigation."),
    ("ransomware",           "P2", "Preserve forensic evidence — snapshot VMs before remediation."),
    ("ransomware",           "P2", "Notify incident response team and management immediately."),
    ("exfiltration",         "P1", "Block egress to destination IPs; invoke DLP quarantine if available."),
    ("data exfil",           "P1", "Block egress to destination IPs; invoke DLP quarantine if available."),
    ("powershell",           "P1", "Kill malicious process tree; collect memory dump for forensics."),
    ("credential dump",      "P1", "Force domain-wide password reset for all privileged accounts."),
    ("credential dumping",   "P1", "Force domain-wide password reset for all privileged accounts."),
    ("cloud priv",           "P1", "Revoke compromised IAM access keys; disable affected cloud accounts."),
    ("createaccesskey",      "P1", "Revoke compromised IAM access keys; disable affected cloud accounts."),
    ("beaconing",            "P1", "Block C2 destination IP/domain at DNS and perimeter; isolate host."),
    ("c2 beaconing",         "P1", "Block C2 destination IP/domain at DNS and perimeter; isolate host."),
    ("mfa bypass",           "P2", "Re-enforce MFA on affected accounts; audit MFA configuration."),
    ("mfa=false",            "P2", "Re-enforce MFA on affected accounts; audit MFA configuration."),
    ("data staging",         "P2", "Preserve forensic image of staging host before remediation."),
    ("data_staging",         "P2", "Preserve forensic image of staging host before remediation."),
    ("off-hours",            "P2", "Investigate off-hours session; revoke if unauthorised."),
    ("privilege escalation", "P1", "Remove elevated privileges; audit group membership changes."),
    ("domain admin",         "P1", "Remove unauthorised accounts from Domain Admins group immediately."),
    ("domain admins",        "P1", "Remove unauthorised accounts from Domain Admins group immediately."),
    ("malware",              "P1", "Quarantine affected endpoint via EDR; preserve disk image."),
    ("ioc",                  "P1", "Block IOC IPs and hashes at perimeter firewall and EDR."),
    ("affected_hosts",       "P1", "Isolate all listed affected hosts from the network immediately."),
    ("lateral_movement_confirmed", "P1", "Isolate affected network segments — lateral movement confirmed."),
]

SHORT_TERM_RULES: List[tuple] = [
    ("brute force",          "Implement geo-blocking for high-risk originating countries."),
    ("brute force",          "Deploy CAPTCHA or progressive delay for repeated failed logins."),
    ("credential dump",      "Restrict LSASS access using Credential Guard (Windows)."),
    ("ransomware",           "Restore from clean, validated backup snapshots."),
    ("ransomware",           "Force password reset for all domain accounts post-incident."),
    ("ransomware",           "Patch vulnerability used for initial access before reconnecting systems."),
    ("ransomware",           "Deploy enhanced EDR rules for ransomware indicators across all endpoints."),
    ("lateral movement",     "Review and tighten SMB/WMI access control lists across all segments."),
    ("lateral_movement",     "Review and tighten SMB/WMI access control lists across all segments."),
    ("powershell",           "Enable PowerShell Constrained Language Mode and Script Block Logging."),
    ("cloud priv",           "Audit all CloudTrail / Azure Activity Logs for the past 30 days."),
    ("createaccesskey",      "Audit all CloudTrail / Azure Activity Logs for the past 30 days."),
    ("exfiltration",         "Deploy Data Loss Prevention (DLP) for sensitive file types."),
    ("data exfil",           "Deploy Data Loss Prevention (DLP) for sensitive file types."),
    ("beaconing",            "Update proxy/firewall rules to block known C2 infrastructure."),
    ("c2 beaconing",         "Update proxy/firewall rules to block known C2 infrastructure."),
    ("persistence",          "Audit scheduled tasks, registry run keys, and startup items."),
    ("mfa bypass",           "Enforce phishing-resistant MFA (FIDO2/hardware token)."),
    ("affected_hosts",       "Conduct thorough forensic investigation on all affected hosts."),
    ("ioc",                  "Perform threat hunt across the environment using identified IOCs."),
    ("domain admin",         "Conduct full Active Directory audit — review all privileged accounts."),
    ("domain admins",        "Conduct full Active Directory audit — review all privileged accounts."),
]

LONG_TERM_RULES: List[tuple] = [
    ("brute force",          "Implement Zero Trust Network Access (ZTNA) with continuous auth."),
    ("brute_force",          "Implement Zero Trust Network Access (ZTNA) with continuous auth."),
    ("lateral movement",     "Implement network segmentation to limit blast radius of future breaches."),
    ("lateral_movement",     "Implement network segmentation to limit blast radius of future breaches."),
    ("lateral_movement_confirmed", "Implement network segmentation to limit blast radius of future breaches."),
    ("credential dump",      "Roll out Privileged Access Workstations (PAWs) for admin tasks."),
    ("ransomware",           "Implement network segmentation to limit lateral movement blast radius."),
    ("ransomware",           "Deploy immutable backup solution (e.g., AWS S3 Object Lock, Veeam immutable repo)."),
    ("ransomware",           "Enforce MFA for all privileged accounts and remote access."),
    ("ransomware",           "Conduct regular ransomware tabletop exercises and IR simulations."),
    ("cloud priv",           "Apply least-privilege IAM policies; conduct quarterly access reviews."),
    ("createaccesskey",      "Apply least-privilege IAM policies; conduct quarterly access reviews."),
    ("powershell",           "Enrol all endpoints in EDR with behaviour-based detection enabled."),
    ("exfiltration",         "Deploy full-packet capture at network egress points."),
    ("data exfil",           "Deploy full-packet capture at network egress points."),
    ("beaconing",            "Integrate Threat Intelligence Platform (TIP) for automated IOC blocking."),
    ("c2 beaconing",         "Integrate Threat Intelligence Platform (TIP) for automated IOC blocking."),
    ("affected_hosts",       "Conduct post-incident security architecture review and gap assessment."),
    ("ioc",                  "Integrate IOC feeds into SIEM for continuous monitoring."),
    ("domain admin",         "Implement Just-In-Time (JIT) privileged access management."),
    ("domain admins",        "Implement Just-In-Time (JIT) privileged access management."),
    ("mfa",                  "Enforce MFA for all privileged accounts and remote access."),
]

DETECTION_RULES: List[tuple] = [
    ("brute force",    "Sigma rule: >5 EventID 4625 from same IP within 60 seconds."),
    ("password spray", "Sigma rule: >3 distinct accounts with EventID 4625 from same IP within 5 min."),
    ("powershell",     "Sigma rule: PowerShell with -EncodedCommand or IEX and DownloadString."),
    ("beaconing",      "Suricata rule: HTTP/HTTPS connections to same external IP every N seconds."),
    ("lateral movement","Sigma rule: WMI or PsExec process creation from remote host."),
    ("exfiltration",   "NetFlow alert: outbound traffic >100 MB to single external IP."),
    ("credential dump","Sigma rule: lsass.exe access by non-system process (EventID 10 Sysmon)."),
    ("cloud priv",     "AWS CloudWatch rule: CreateAccessKey + AttachUserPolicy within 5 minutes."),
    ("ransomware",     "EDR rule: mass file rename with extension change + shadow copy deletion."),
    ("persistence",    "Sigma rule: New scheduled task creation by non-admin user (EventID 4698)."),
]


class MitigationPlanningAgent(BaseAgent):
    """
    Generates prioritised containment and remediation plans based on
    correlated threat findings.
    """

    def __init__(self):
        super().__init__(
            name="MitigationPlanningAgent",
            description="Produces prioritised immediate, short-term, and long-term remediation plans."
        )

    # ──────────────────────────────────────────────────────────────────────
    # Core analysis
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, data: Any) -> Dict:
        keywords = self._extract_keywords(data)
        severity = self._infer_severity(data)
        scope = self._infer_scope(data)

        immediate = self._gather_actions(keywords, IMMEDIATE_RULES, keyed=True)
        short_term = self._gather_actions(keywords, SHORT_TERM_RULES, keyed=False)
        long_term = self._gather_actions(keywords, LONG_TERM_RULES, keyed=False)
        detection = self._gather_actions(keywords, DETECTION_RULES, keyed=False)

        # Always include universal baseline actions
        immediate.setdefault("P1", [])
        immediate["P1"] += self._universal_immediate(data)
        immediate["P1"] = list(dict.fromkeys(immediate["P1"]))  # deduplicate

        return {
            "immediate_actions": immediate,
            "short_term_remediation": list(dict.fromkeys(short_term)),
            "long_term_hardening": list(dict.fromkeys(long_term)),
            "detection_improvements": list(dict.fromkeys(detection)),
            "validation_steps": self._validation_steps(keywords),
            "residual_risk": self._residual_risk(severity, keywords),
            "scope_assessment": scope,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Keyword extraction
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_keywords(data: Any) -> List[str]:
        """Flatten all string values and split into lowercase tokens."""
        import json
        try:
            blob = json.dumps(data).lower()
        except TypeError:
            blob = str(data).lower()
        return blob.split()

    @staticmethod
    def _infer_severity(data: Any) -> str:
        import json
        try:
            blob = json.dumps(data).lower()
        except TypeError:
            blob = str(data).lower()
        for sev in ("critical", "high", "medium", "low"):
            if sev in blob:
                return sev
        return "medium"

    @staticmethod
    def _infer_scope(data: Any) -> str:
        import json
        try:
            blob = json.dumps(data)
        except TypeError:
            blob = str(data)
        hosts = len(set(
            h for h in ["host", "hostname", "src_host", "dst_host", "affected_hosts"]
            if h in blob
        ))
        return f"Estimated affected assets: {max(1, hosts)} system(s) identified in telemetry."

    # ──────────────────────────────────────────────────────────────────────
    # Action gathering helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _gather_actions(keywords: List[str], rules: List[tuple], keyed: bool):
        blob = " ".join(keywords)
        if keyed:
            result: Dict[str, List[str]] = {}
            for keyword, priority, action in rules:
                if keyword in blob:
                    result.setdefault(priority, []).append(action)
            return result
        else:
            result_list: List[str] = []
            for keyword, action in rules:
                if keyword in blob:
                    result_list.append(action)
            return result_list

    @staticmethod
    def _universal_immediate(data: Any) -> List[str]:
        return [
            "Preserve all relevant logs and forensic evidence before making changes.",
            "Notify the Incident Response team and initiate the IR runbook.",
            "Document all actions taken with timestamps for post-incident review.",
        ]

    # ──────────────────────────────────────────────────────────────────────
    # Validation & residual risk
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _validation_steps(keywords: List[str]) -> List[str]:
        blob = " ".join(keywords)
        steps = [
            "Confirm IOC IPs/domains are blocked at all perimeter control points.",
            "Verify compromised accounts have been locked or credentials rotated.",
            "Run a post-remediation vulnerability scan on affected systems.",
            "Validate backups are clean and restoration was successful (if applicable).",
            "Confirm SIEM alerts are firing correctly for newly deployed detection rules.",
        ]
        if "cloud" in blob or "aws" in blob or "azure" in blob:
            steps.append("Verify no residual IAM permissions exist for compromised cloud accounts.")
        if "ransomware" in blob:
            steps.append("Verify no encrypted files remain on restored systems before reconnecting.")
        return steps

    @staticmethod
    def _residual_risk(severity: str, keywords: List[str]) -> str:
        blob = " ".join(keywords)
        risks = []
        if "lateral movement" in blob:
            risks.append("Potential for additional hosts to be compromised if lateral movement was not fully contained.")
        if "credential dump" in blob or "credential" in blob:
            risks.append("Harvested credentials may still be in use by the attacker in other systems.")
        if "exfiltration" in blob:
            risks.append("Exfiltrated data cannot be recovered — assess regulatory notification obligations.")
        if "cloud" in blob:
            risks.append("Cloud misconfiguration may persist in other unreviewed accounts or regions.")
        if not risks:
            risks.append("Standard residual risk — monitor for indicator recurrence for 30 days.")
        return " | ".join(risks)
