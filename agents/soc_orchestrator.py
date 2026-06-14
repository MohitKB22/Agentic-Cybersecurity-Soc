"""
Agent 6 – SOC Orchestrator (Master Agent)
Coordinates all 5 specialist agents in sequence, performs quality control,
and produces the final unified security report.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base_agent import BaseAgent
from .log_triage_agent import LogTriageAgent
from .anomaly_detection_agent import AnomalyDetectionAgent
from .threat_correlation_agent import ThreatCorrelationAgent
from .mitigation_planning_agent import MitigationPlanningAgent
from .incident_report_agent import IncidentReportAgent


class SOCOrchestrator(BaseAgent):
    """
    Master orchestrator that runs the full SOC pipeline:
      Step 1  →  Log Triage Agent
      Step 2  →  Anomaly Detection Agent
      Step 3  →  Threat Correlation Agent
      Step 4  →  Mitigation Planning Agent
      Step 5  →  Incident Report Agent
    then performs quality-control and returns the final unified report.
    """

    def __init__(self):
        super().__init__(
            name="SOCOrchestrator",
            description="Master SOC agent coordinating the full security analysis pipeline."
        )
        self.triage_agent      = LogTriageAgent()
        self.anomaly_agent     = AnomalyDetectionAgent()
        self.correlation_agent = ThreatCorrelationAgent()
        self.mitigation_agent  = MitigationPlanningAgent()
        self.report_agent      = IncidentReportAgent()

        self._pipeline_log: List[Dict] = []

    # ──────────────────────────────────────────────────────────────────────
    # Core pipeline
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, data: Any) -> Dict:
        self._pipeline_log = []
        start = datetime.now(timezone.utc)

        # ── Step 1: Log Triage ────────────────────────────────────────────
        self._log_step("Step 1: Log Triage", "starting")
        triage_result = self.triage_agent.run(data)
        triage_output = triage_result.get("result", {})
        self._log_step("Step 1: Log Triage", triage_result["status"],
                       severity=triage_output.get("severity"))

        # Only escalate if triage says so
        escalation = triage_output.get("escalation_recommendation", "Monitor")
        if escalation == "Close":
            return self._early_close(triage_output, start)

        # ── Step 2: Anomaly Detection ─────────────────────────────────────
        self._log_step("Step 2: Anomaly Detection", "starting")
        # Feed raw data + triage output together for richer context
        anomaly_input = self._merge_for_anomaly(data, triage_output)
        anomaly_result = self.anomaly_agent.run(anomaly_input)
        anomaly_output = anomaly_result.get("result", {})
        self._log_step("Step 2: Anomaly Detection", anomaly_result["status"],
                       anomalies=anomaly_output.get("total_anomalies", 0))

        # ── Step 3: Threat Correlation ────────────────────────────────────
        self._log_step("Step 3: Threat Correlation", "starting")
        correlation_input = {
            "anomalies": anomaly_output.get("detected_anomalies", []),
            "events":    self._extract_events(data),
            "triage":    triage_output,
        }
        correlation_result = self.correlation_agent.run(correlation_input)
        correlation_output = correlation_result.get("result", {})
        self._log_step("Step 3: Threat Correlation", correlation_result["status"],
                       stages=len(correlation_output.get("correlated_events", [])))

        # ── Step 4: Mitigation Planning ───────────────────────────────────
        self._log_step("Step 4: Mitigation Planning", "starting")
        mitigation_input = {
            "triage":      triage_output,
            "anomaly":     anomaly_output,
            "correlation": correlation_output,
            "severity":    triage_output.get("severity", "Medium"),
        }
        mitigation_result = self.mitigation_agent.run(mitigation_input)
        mitigation_output = mitigation_result.get("result", {})
        self._log_step("Step 4: Mitigation Planning", mitigation_result["status"])

        # ── Step 5: Incident Report ───────────────────────────────────────
        self._log_step("Step 5: Incident Report", "starting")
        report_input = {
            "triage":      triage_output,
            "anomaly":     anomaly_output,
            "correlation": correlation_output,
            "mitigation":  mitigation_output,
            "severity":    triage_output.get("severity", "Medium"),
        }
        report_result = self.report_agent.run(report_input)
        report_output = report_result.get("result", {})
        self._log_step("Step 5: Incident Report", report_result["status"])

        # ── Quality Control ───────────────────────────────────────────────
        qc_notes = self._quality_control(
            triage_output, anomaly_output, correlation_output,
            mitigation_output, report_output
        )

        # ── Assemble final output ─────────────────────────────────────────
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        return self._build_final_output(
            triage_output, anomaly_output, correlation_output,
            mitigation_output, report_output, qc_notes, elapsed
        )

    # ──────────────────────────────────────────────────────────────────────
    # Input preparation helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _merge_for_anomaly(raw_data: Any, triage_output: Dict) -> Dict:
        """Combine the original raw data with triage indicators for anomaly agent."""
        events = []
        if isinstance(raw_data, list):
            events = raw_data
        elif isinstance(raw_data, dict):
            events = raw_data.get("events", [raw_data])
        indicators = triage_output.get("extracted_indicators", {})
        return {"events": events, "triage_context": indicators}

    @staticmethod
    def _extract_events(data: Any) -> List[Dict]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("events", [data])
        return []

    # ──────────────────────────────────────────────────────────────────────
    # Quality control
    # ──────────────────────────────────────────────────────────────────────

    def _quality_control(
        self,
        triage: Dict,
        anomaly: Dict,
        correlation: Dict,
        mitigation: Dict,
        report: Dict,
    ) -> List[str]:
        notes = []

        # 1. Evidence check
        if not anomaly.get("detected_anomalies"):
            notes.append("QC-WARN: No anomalies detected — verify telemetry completeness.")

        # 2. Severity consistency
        triage_sev = triage.get("severity", "")
        report_sev = report.get("incident_overview", {}).get("severity", "")
        if triage_sev and report_sev and triage_sev.lower() != report_sev.lower():
            notes.append(
                f"QC-WARN: Severity mismatch — triage={triage_sev}, report={report_sev}. "
                "Using triage severity as authoritative."
            )

        # 3. MITRE mapping present
        mitre = correlation.get("mitre_attack_mapping", [])
        if not mitre:
            notes.append("QC-WARN: No MITRE ATT&CK techniques mapped — enrich with more telemetry.")

        # 4. Recommendations actionable
        immediate = mitigation.get("immediate_actions", {})
        if not immediate:
            notes.append("QC-WARN: No immediate actions generated — check mitigation agent input.")

        # 5. Investigation gaps
        unknowns = report.get("root_cause_analysis", {}).get("unknowns", [])
        if unknowns:
            notes.append(f"QC-INFO: {len(unknowns)} investigation gap(s) identified.")

        if not notes:
            notes.append("QC-PASS: All quality checks passed.")

        return notes

    # ──────────────────────────────────────────────────────────────────────
    # Final output assembly
    # ──────────────────────────────────────────────────────────────────────

    def _build_final_output(
        self,
        triage: Dict,
        anomaly: Dict,
        correlation: Dict,
        mitigation: Dict,
        report: Dict,
        qc_notes: List[str],
        elapsed: float,
    ) -> Dict:
        # Authoritative severity: highest of triage-assigned + max anomaly risk
        triage_sev = triage.get("severity", "Unknown")
        anomaly_risk = ""
        for _a in anomaly.get("detected_anomalies", []):
            r = _a.get("risk", "")
            if self.severity_score(r) > self.severity_score(anomaly_risk):
                anomaly_risk = r
        if self.severity_score(triage_sev) >= self.severity_score(anomaly_risk):
            severity = triage_sev
        else:
            severity = anomaly_risk
        if severity in ("", "Unknown") and anomaly_risk:
            severity = anomaly_risk
        confidence = correlation.get("confidence_level", "Unknown")
        timeline  = correlation.get("attack_timeline", [])
        mitre     = correlation.get("mitre_attack_mapping", [])
        immediate = mitigation.get("immediate_actions", {})
        anomalies = anomaly.get("detected_anomalies", [])

        key_findings = self._key_findings(triage, anomaly, correlation)
        telemetry_needed = self._additional_telemetry(triage, anomaly, correlation)

        return {
            # ── Top-level summary ──────────────────────────────────────────
            "executive_summary":      report.get("executive_summary", ""),
            "severity":               severity,
            "confidence":             confidence,
            "key_findings":           key_findings,
            "correlated_attack_timeline": timeline,
            "mitre_attack_mapping":   mitre,
            "recommended_actions":    immediate,

            # ── Full incident report ───────────────────────────────────────
            "incident_report":        report,

            # ── Investigation metadata ─────────────────────────────────────
            "investigation_gaps":     report.get("root_cause_analysis", {}).get("unknowns", []),
            "additional_telemetry_required": telemetry_needed,
            "quality_control_notes":  qc_notes,

            # ── Pipeline diagnostics ───────────────────────────────────────
            "pipeline_log":           self._pipeline_log,
            "pipeline_elapsed_sec":   round(elapsed, 4),

            # ── Per-agent outputs (for transparency) ───────────────────────
            "agent_outputs": {
                "log_triage":          triage,
                "anomaly_detection":   anomaly,
                "threat_correlation":  correlation,
                "mitigation_planning": mitigation,
            },
        }

    # ──────────────────────────────────────────────────────────────────────
    # Key findings builder
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _key_findings(triage: Dict, anomaly: Dict, correlation: Dict) -> List[str]:
        findings = []

        sev = triage.get("severity")
        if sev:
            findings.append(f"Severity assessed as {sev}.")

        n_anomalies = anomaly.get("total_anomalies", 0)
        if n_anomalies:
            findings.append(f"{n_anomalies} behavioural anomaly/anomalies detected.")

        stages = list(dict.fromkeys(
            e.get("attack_stage") for e in correlation.get("correlated_events", [])
            if e.get("attack_stage") and e["attack_stage"] != "Unknown"
        ))
        if stages:
            findings.append(f"Attack progression identified: {' → '.join(stages)}.")

        objectives = correlation.get("potential_attacker_objectives", [])
        if objectives:
            findings.append(f"Likely objective(s): {'; '.join(objectives)}.")

        assessment = anomaly.get("overall_threat_assessment", "")
        if assessment and assessment != "No anomalies detected":
            findings.append(assessment)

        return findings or ["Insufficient data for definitive findings."]

    @staticmethod
    def _additional_telemetry(triage: Dict, anomaly: Dict, correlation: Dict) -> List[str]:
        needed = []
        indicators = triage.get("extracted_indicators", {})

        if not indicators.get("source_ip"):
            needed.append("Source IP address — enable network flow logging.")
        if not indicators.get("username"):
            needed.append("Authenticated user identity — enable authentication logging.")
        if not indicators.get("hostname"):
            needed.append("Affected hostname — enable host-based logging (Sysmon / auditd).")

        if not anomaly.get("detected_anomalies"):
            needed.append("Extended telemetry window (>24 h) for behavioural baseline comparison.")

        if not correlation.get("attack_timeline"):
            needed.append("Timestamp-correlated events across multiple log sources.")

        return needed or ["All critical telemetry fields present."]

    # ──────────────────────────────────────────────────────────────────────
    # Early close path (benign / informational events)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _early_close(triage_output: Dict, start: datetime) -> Dict:
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        return {
            "executive_summary": f"[{triage_output.get('severity', 'Informational')}] Event triaged as benign / expected activity by Log Triage Agent. Classification: {triage_output.get('initial_assessment', {}).get('classification', 'Unknown')}. No further escalation required.",
            "severity":          triage_output.get("severity", "Informational"),
            "confidence":        "High (triage rules match known-good pattern)",
            "key_findings":      ["Event classified as expected activity by Log Triage Agent."],
            "correlated_attack_timeline": [],
            "mitre_attack_mapping":       [],
            "recommended_actions":        {"P1": ["No immediate action required."]},
            "incident_report":            {},
            "investigation_gaps":         [],
            "additional_telemetry_required": [],
            "quality_control_notes":      ["QC-PASS: Early close — benign event."],
            "pipeline_log":               [{"step": "Early Close", "reason": "Escalation=Close"}],
            "pipeline_elapsed_sec":       round(elapsed, 4),
            "agent_outputs":              {"log_triage": triage_output},
        }

    # ──────────────────────────────────────────────────────────────────────
    # Pipeline logger
    # ──────────────────────────────────────────────────────────────────────

    def _log_step(self, step: str, status: str, **kwargs):
        entry = {
            "step":      step,
            "status":    status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }
        self._pipeline_log.append(entry)
