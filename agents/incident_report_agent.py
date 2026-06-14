"""
Agent 5 – Incident Report Agent
Transforms all upstream findings into a professional, executive-ready incident report.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json

from .base_agent import BaseAgent


class IncidentReportAgent(BaseAgent):
    """
    Produces a structured, professional incident report from pipeline findings.
    """

    def __init__(self):
        super().__init__(
            name="IncidentReportAgent",
            description="Generates executive-ready incident reports from correlated findings."
        )
        self._incident_counter = 0

    # ──────────────────────────────────────────────────────────────────────
    # Core analysis
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, data: Any) -> Dict:
        self._incident_counter += 1
        ctx = self._build_context(data)

        report = {
            "incident_id": ctx["incident_id"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": self._executive_summary(ctx),
            "incident_overview": self._overview(ctx),
            "affected_assets": ctx["assets"],
            "indicators_of_compromise": ctx["iocs"],
            "timeline": ctx["timeline"],
            "technical_analysis": self._technical_analysis(ctx),
            "mitre_attack_mapping": ctx["mitre"],
            "impact_assessment": self._impact(ctx),
            "root_cause_analysis": self._root_cause(ctx),
            "recommendations": self._recommendations(ctx),
            "final_assessment": self._final_assessment(ctx),
        }

        # Also produce a plain-text markdown version
        report["markdown_report"] = self._to_markdown(report)
        return report

    # ──────────────────────────────────────────────────────────────────────
    # Context builder – unifies data from all upstream agents
    # ──────────────────────────────────────────────────────────────────────

    def _build_context(self, data: Any) -> Dict:
        blob = json.dumps(data) if not isinstance(data, str) else data
        d = data if isinstance(data, dict) else {}

        # Collect from triage
        triage = d.get("triage", d.get("log_triage", {}))
        # Collect from anomaly
        anomaly = d.get("anomaly", d.get("anomaly_detection", {}))
        # Collect from correlation
        correlation = d.get("correlation", d.get("threat_correlation", {}))
        # Collect from mitigation
        mitigation = d.get("mitigation", d.get("mitigation_planning", {}))

        severity = (
            d.get("severity")
            or self._find_key(triage, "severity")
            or self._find_key(anomaly, "risk")
            or "Unknown"
        )
        confidence = (
            d.get("confidence")
            or self._find_key(correlation, "confidence_level")
            or "Unknown"
        )
        # Normalise severity capitalisation
        if severity and severity[0].islower():
            severity = severity.capitalize()

        iocs = self._collect_iocs(d, triage, anomaly, correlation)
        assets = self._collect_assets(d, triage, correlation)
        timeline = self._collect_timeline(d, correlation)
        mitre = self._collect_mitre(d, correlation, anomaly)
        recommendations = self._collect_recommendations(d, mitigation)

        inc_id = d.get("incident_id") or f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{self._incident_counter:03d}"

        attack_type = (
            d.get("type")
            or d.get("attack_type")
            or self._find_key(anomaly, "anomaly_type")
            or "Security Incident"
        )

        return {
            "incident_id": inc_id,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "status": d.get("status", "Under Investigation"),
            "iocs": iocs,
            "assets": assets,
            "timeline": timeline,
            "mitre": mitre,
            "recommendations": recommendations,
            "triage": triage,
            "anomaly": anomaly,
            "correlation": correlation,
            "mitigation": mitigation,
            "raw": d,
        }

    # ──────────────────────────────────────────────────────────────────────
    # IOC, asset, timeline, MITRE collectors
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_iocs(d, triage, anomaly, correlation) -> Dict:
        iocs: Dict[str, list] = {"ips": [], "domains": [], "hashes": [], "accounts": [], "hostnames": []}

        def _add(key, val):
            if val and str(val) not in iocs[key]:
                iocs[key].append(str(val))

        # From explicit iocs key
        src = d.get("iocs", {})
        for k in iocs:
            for v in src.get(k, []):
                _add(k, v)

        # From shared indicators (correlation output)
        indicators = correlation.get("shared_indicators", {})
        for ip in indicators.get("ips", []):
            _add("ips", ip)
        for ip in indicators.get("external_ips", []):
            _add("ips", ip)
        for u in indicators.get("users", []):
            _add("accounts", u)
        for h in indicators.get("hosts", []):
            _add("hostnames", h)
        for dom in indicators.get("domains", []):
            _add("domains", dom)

        # From triage extracted_indicators
        ti = triage.get("extracted_indicators", {})
        for k in ("source_ip", "destination_ip"):
            if ti.get(k):
                _add("ips", ti[k])
        if ti.get("domain"):
            _add("domains", ti["domain"])
        if ti.get("username"):
            _add("accounts", ti["username"])
        if ti.get("hostname"):
            _add("hostnames", ti["hostname"])

        return iocs

    @staticmethod
    def _collect_assets(d, triage, correlation) -> List[str]:
        assets = list(d.get("affected_hosts", d.get("affected_assets", [])))
        ti = triage.get("extracted_indicators", {})
        if ti.get("hostname") and ti["hostname"] not in assets:
            assets.append(ti["hostname"])
        indicators = correlation.get("shared_indicators", {})
        for h in indicators.get("hosts", []):
            if h not in assets:
                assets.append(h)
        return assets or ["Undetermined"]

    @staticmethod
    def _collect_timeline(d, correlation) -> List[Dict]:
        tl = correlation.get("attack_timeline", d.get("timeline", []))
        if not tl:
            return [{"time": "Unknown", "event": "Timeline unavailable — insufficient telemetry"}]
        return tl

    @staticmethod
    def _collect_mitre(d, correlation, anomaly) -> List[Dict]:
        raw_mitre = correlation.get("mitre_attack_mapping", d.get("mitre", []))
        # Normalise: some inputs are plain strings, some are dicts
        mitre = []
        for m in raw_mitre:
            if isinstance(m, dict):
                mitre.append(m)
            elif isinstance(m, str):
                mitre.append({"technique_id": m, "technique_name": "", "confidence": "?"})
        if not mitre:
            # Build from anomalies
            for a in anomaly.get("detected_anomalies", []):
                t = a.get("mitre_technique", "")
                if t:
                    tid = t.split(" ")[0] if " " in t else t
                    if tid not in [m.get("technique_id") for m in mitre]:
                        mitre.append({"technique_id": tid, "technique_name": t, "confidence": a.get("confidence", 0.7)})
        return mitre

    @staticmethod
    def _collect_recommendations(d, mitigation) -> Dict:
        recs = {}
        # 1. Pull from direct input keys
        direct_recs = d.get("recommendations", {})
        if isinstance(direct_recs, dict):
            recs.update(direct_recs)
        
        # 2. Pull from mitigation agent output (overrides if richer)
        if mitigation:
            imm = mitigation.get("immediate_actions", {})
            # Flatten P1/P2/P3 dict into a flat list
            if isinstance(imm, dict):
                flat_imm = [v for vals in imm.values() for v in (vals if isinstance(vals, list) else [vals])]
            else:
                flat_imm = imm if isinstance(imm, list) else []
            if flat_imm:
                recs["immediate"] = flat_imm
            st = mitigation.get("short_term_remediation", [])
            if st:
                recs["short_term"] = st
            lt = mitigation.get("long_term_hardening", [])
            if lt:
                recs["long_term"] = lt

        # 3. Fallback to direct recommendations list (training data format)
        if not recs.get("immediate") and d.get("recommendations"):
            raw = d["recommendations"]
            if isinstance(raw, list):
                recs["immediate"] = raw
        
        return recs

    # ──────────────────────────────────────────────────────────────────────
    # Report section builders
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _executive_summary(ctx: Dict) -> str:
        severity = ctx["severity"]
        attack_type = ctx["attack_type"]
        assets = ctx["assets"]
        status = ctx["status"]
        asset_str = ", ".join(assets[:3]) + ("..." if len(assets) > 3 else "")
        return (
            f"A {severity.upper()} severity security incident of type '{attack_type}' was detected. "
            f"Affected asset(s) include: {asset_str}. "
            f"Current incident status: {status}. "
            f"Immediate containment and investigation are recommended."
        )

    @staticmethod
    def _overview(ctx: Dict) -> Dict:
        return {
            "incident_id": ctx["incident_id"],
            "detection_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "severity": ctx["severity"],
            "confidence": ctx["confidence"],
            "status": ctx["status"],
            "attack_type": ctx["attack_type"],
        }

    @staticmethod
    def _technical_analysis(ctx: Dict) -> str:
        anomalies = ctx["anomaly"].get("detected_anomalies", [])
        narrative = ctx["correlation"].get("attack_narrative", "")
        parts = []
        if narrative:
            parts.append(f"**Attack Narrative:** {narrative}")
        if anomalies:
            parts.append(f"**Detected Anomalies ({len(anomalies)}):**")
            for a in anomalies[:5]:
                parts.append(f"  - {a.get('anomaly_type', 'Unknown')}: {a.get('description', '')}")
        if not parts:
            parts.append("Technical analysis pending — additional telemetry required.")
        return "\n".join(parts)

    @staticmethod
    def _impact(ctx: Dict) -> Dict:
        severity = ctx["severity"].lower()
        iocs = ctx["iocs"]
        assets = ctx["assets"]
        exfil = any("exfil" in str(a).lower() for a in ctx["anomaly"].get("detected_anomalies", []))
        return {
            "operational_impact": (
                "Critical operational disruption" if severity == "critical"
                else "Moderate operational impact" if severity == "high"
                else "Minimal operational impact"
            ),
            "business_impact": (
                "Potential regulatory notification required (GDPR, PCI-DSS)"
                if exfil else
                "Business continuity may be affected — assess RTO/RPO"
            ),
            "potential_exposure": (
                f"Data exfiltration confirmed — {len(iocs.get('ips', []))} external IPs involved."
                if exfil else
                f"{len(assets)} system(s) potentially compromised."
            ),
        }

    @staticmethod
    def _root_cause(ctx: Dict) -> Dict:
        anomalies = ctx["anomaly"].get("detected_anomalies", [])
        corr_events = ctx["correlation"].get("correlated_events", [{}])
        first_stage = corr_events[0].get("attack_stage", "Unknown") if corr_events else "Unknown"
        attack_type = ctx.get("attack_type", "")
        iocs = ctx.get("iocs", {})
        
        known_facts = [
            f"Initial attack stage identified: {first_stage}",
            f"{len(anomalies)} behavioural anomaly/anomalies detected",
            f"Incident severity: {ctx['severity']}",
        ]
        if iocs.get("ips"):
            known_facts.append(f"Attacker IP(s) identified: {', '.join(iocs['ips'][:3])}")
        if iocs.get("accounts"):
            known_facts.append(f"Compromised account(s): {', '.join(iocs['accounts'][:3])}")
        if iocs.get("hostnames"):
            known_facts.append(f"Affected host(s): {', '.join(iocs['hostnames'][:3])}")
        
        assumptions = [
            "Attack may have begun earlier than first detected event.",
            "Additional systems may be affected but not yet discovered.",
        ]
        if "brute" in attack_type.lower() or "password" in attack_type.lower():
            assumptions.append("Absence of account lockout policy likely enabled the brute-force attack.")
        if "exfil" in attack_type.lower() or "data" in attack_type.lower():
            assumptions.append("Attacker had sufficient dwell time to identify and stage sensitive data.")
        
        return {
            "known_facts": known_facts,
            "assumptions": assumptions,
            "unknowns": [
                "Full scope of data accessed or exfiltrated",
                "Complete attacker toolset and persistence mechanisms",
                "Whether vulnerabilities have been patched on all systems",
                "Total dwell time of the attacker before detection",
            ],
        }

    @staticmethod
    def _recommendations(ctx: Dict) -> Dict:
        recs = ctx["recommendations"]
        if not recs or (not recs.get("immediate") and not recs.get("short_term") and not recs.get("long_term")):
            sev = ctx.get("severity", "").lower()
            attack = ctx.get("attack_type", "").lower()
            return {
                "immediate": [
                    "Initiate full Incident Response process immediately.",
                    "Isolate affected systems from the network.",
                    "Preserve all relevant forensic evidence before remediation.",
                    "Notify security leadership and legal/compliance teams.",
                ],
                "short_term": [
                    "Conduct thorough forensic investigation on all affected assets.",
                    "Force credential reset for all potentially compromised accounts.",
                    "Patch vulnerability used for initial access.",
                    "Deploy enhanced detection rules based on IOCs.",
                ],
                "long_term": [
                    "Review and update security policies based on lessons learned.",
                    "Conduct post-incident tabletop exercise to improve IR readiness.",
                    "Implement MFA for all privileged accounts.",
                    "Schedule quarterly security architecture reviews.",
                ],
            }
        return recs

    @staticmethod
    def _final_assessment(ctx: Dict) -> str:
        objectives = ctx["correlation"].get("potential_attacker_objectives", [])
        conf = ctx["confidence"]
        obj_str = "; ".join(objectives) if objectives else "Undetermined"
        return (
            f"Based on available evidence, this incident is assessed as a {ctx['severity'].upper()}-severity "
            f"event with confidence: {conf}. Likely attacker objective(s): {obj_str}. "
            f"Full containment and forensic investigation are required before resuming normal operations."
        )

    # ──────────────────────────────────────────────────────────────────────
    # Markdown serialiser
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _to_markdown(report: Dict) -> str:
        def ul(items):
            if isinstance(items, list):
                return "\n".join(f"- {i}" for i in items) if items else "- None"
            if isinstance(items, dict):
                return "\n".join(f"- **{k}**: {v}" for k, v in items.items())
            return str(items)

        def _mitre_row(m):
            if isinstance(m, dict):
                return f"| {m.get('technique_id','?')} | {m.get('technique_name','?')} | {m.get('confidence', '?')} |"
            return f"| {m} | — | — |"
        mitre_rows = "\n".join(
            _mitre_row(m) for m in report.get("mitre_attack_mapping", [])
        ) or "| - | No techniques mapped | - |"

        tl_rows = "\n".join(
            f"| {t.get('time','?')} | {t.get('stage','?')} | {t.get('event','?')} |"
            for t in report.get("timeline", [])
        ) or "| - | - | Timeline unavailable |"

        iocs = report.get("indicators_of_compromise", {})
        recs = report.get("recommendations", {})
        rca = report.get("root_cause_analysis", {})
        impact = report.get("impact_assessment", {})

        return f"""# INCIDENT REPORT

## Executive Summary
{report.get('executive_summary', '')}

## Incident Overview
| Field | Value |
|---|---|
| Incident ID | {report.get('incident_overview', {}).get('incident_id', '?')} |
| Detection Time | {report.get('incident_overview', {}).get('detection_time', '?')} |
| Severity | {report.get('incident_overview', {}).get('severity', '?')} |
| Confidence | {report.get('incident_overview', {}).get('confidence', '?')} |
| Status | {report.get('incident_overview', {}).get('status', '?')} |

## Affected Assets
{ul(report.get('affected_assets', []))}

## Indicators of Compromise
**IPs:** {', '.join(iocs.get('ips', [])) or 'None identified'}
**Domains:** {', '.join(iocs.get('domains', [])) or 'None identified'}
**Accounts:** {', '.join(iocs.get('accounts', [])) or 'None identified'}
**Hostnames:** {', '.join(iocs.get('hostnames', [])) or 'None identified'}
**Hashes:** {', '.join(iocs.get('hashes', [])) or 'None identified'}

## Timeline
| Time | Stage | Event |
|---|---|---|
{tl_rows}

## Technical Analysis
{report.get('technical_analysis', '')}

## MITRE ATT&CK Mapping
| Technique ID | Technique Name | Confidence |
|---|---|---|
{mitre_rows}

## Impact Assessment
- **Operational:** {impact.get('operational_impact', '?')}
- **Business:** {impact.get('business_impact', '?')}
- **Exposure:** {impact.get('potential_exposure', '?')}

## Root Cause Analysis
**Known Facts:**
{ul(rca.get('known_facts', []))}

**Assumptions:**
{ul(rca.get('assumptions', []))}

**Unknowns:**
{ul(rca.get('unknowns', []))}

## Recommendations
**Immediate:**
{ul(recs.get('immediate', {}))}

**Short-Term:**
{ul(recs.get('short_term', []))}

**Long-Term:**
{ul(recs.get('long_term', []))}

## Final Assessment
{report.get('final_assessment', '')}
"""

    # ──────────────────────────────────────────────────────────────────────
    # Tiny helper
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _find_key(d: Any, key: str):
        if isinstance(d, dict):
            return d.get(key)
        return None
