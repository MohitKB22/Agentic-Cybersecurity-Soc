# SOC AI Multi-Agent System

A fully structured, rule-based multi-agent Security Operations Centre (SOC)
system built in pure Python. Six specialised agents form a sequential
analysis pipeline, from raw log ingestion to a professional incident report.

---

## Architecture

```
Raw Log / Events
       │
       ▼
┌─────────────────────┐
│ 1. Log Triage Agent │  Parse, extract indicators, classify, assign severity
└──────────┬──────────┘
           │  (if Escalate)
           ▼
┌──────────────────────────┐
│ 2. Anomaly Detection Agent│  Brute force, spraying, impossible travel,
│                           │  PowerShell abuse, beaconing, lateral movement,
│                           │  credential dumping, cloud IAM abuse …
└──────────┬───────────────┘
           │
           ▼
┌────────────────────────────┐
│ 3. Threat Correlation Agent│  ATT&CK kill-chain staging, MITRE mapping,
│                             │  attack timeline, attacker objective inference
└──────────┬─────────────────┘
           │
           ▼
┌──────────────────────────────┐
│ 4. Mitigation Planning Agent │  P1/P2/P3 immediate actions, short-term
│                              │  remediation, long-term hardening, Sigma rules
└──────────┬───────────────────┘
           │
           ▼
┌─────────────────────────────┐
│ 5. Incident Report Agent    │  Executive summary, IOCs, impact, RCA,
│                             │  Markdown report generation
└──────────┬──────────────────┘
           │
           ▼
┌──────────────────────────────┐
│ 6. SOC Orchestrator (Master) │  Coordinates pipeline, quality control,
│                              │  severity escalation, final unified output
└──────────────────────────────┘
```

---

## File Structure

```
soc_ai_system/
├── agents/
│   ├── __init__.py
│   ├── base_agent.py               # Abstract base class, shared utilities
│   ├── log_triage_agent.py         # Agent 1 – Log parsing & classification
│   ├── anomaly_detection_agent.py  # Agent 2 – Behavioural anomaly detection
│   ├── threat_correlation_agent.py # Agent 3 – MITRE ATT&CK correlation
│   ├── mitigation_planning_agent.py# Agent 4 – Remediation planning
│   ├── incident_report_agent.py    # Agent 5 – Professional report generation
│   └── soc_orchestrator.py        # Agent 6 – Master pipeline coordinator
├── data/
│   ├── training_data.py            # Synthetic labelled training samples
│   └── training_data.json          # Generated JSON dataset (33 samples)
├── models/
│   └── evaluator.py               # Training evaluation & scoring engine
├── tests/
│   └── test_agents.py             # 68-test pytest suite (all agents)
├── reports/
│   └── test_results.json          # Latest evaluation results
├── main.py                        # CLI entry point
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
# Install dependency
pip install pytest

# Run live demo (4 attack scenarios)
python main.py --mode demo

# Run training evaluation
python main.py --mode eval

# Run pytest suite (68 tests)
python main.py --mode test

# Interactive single-log analyser
python main.py --mode single
```

---

## Agents

### 1. Log Triage Agent
- Extracts: timestamp, hostname, username, IPs, process, event ID, file path, domain, URL, action, result
- Classifies: Authentication / Endpoint / Network / Cloud / Malware / Data Access / Privilege Management
- Noise filter: Expected Activity / Benign / Requires Review / Suspicious / High Priority
- Severity: Informational → Low → Medium → High → Critical
- Escalation: Close / Monitor / Escalate

### 2. Anomaly Detection Agent
Detects:
- Brute Force & Password Spraying
- Impossible Travel
- Suspicious PowerShell (IEX, -EncodedCommand, DownloadString)
- C2 Beaconing (regularity-based)
- Large Data Transfers / Exfiltration
- Off-Hours Activity
- Cloud Privilege Escalation (CreateAccessKey, AttachUserPolicy)
- Credential Dumping (mimikatz, lsass, procdump)
- Lateral Movement (WMI, PsExec, Pass-the-Hash)

### 3. Threat Correlation Agent
- Maps events to 11 ATT&CK kill-chain stages
- Deduplicates MITRE technique IDs
- Builds chronological attack timeline
- Generates attack narrative
- Infers attacker objectives

### 4. Mitigation Planning Agent
- P1/P2/P3 priority immediate containment actions
- Short-term remediation (≤7 days)
- Long-term hardening (30-90 days)
- Detection rule engineering (Sigma / Suricata)
- Validation checklist
- Residual risk assessment

### 5. Incident Report Agent
Generates:
- Executive Summary
- Incident Overview (ID, time, severity, confidence, status)
- Affected Assets
- Indicators of Compromise (IPs, domains, hashes, accounts, hostnames)
- Chronological Timeline
- Technical Analysis
- MITRE ATT&CK Mapping table
- Impact Assessment (operational, business, exposure)
- Root Cause Analysis (known facts / assumptions / unknowns)
- Recommendations (immediate, short-term, long-term)
- Final Assessment
- Full Markdown report

### 6. SOC Orchestrator
- Sequences all 5 agents
- Early-close path for benign events
- Severity escalation (triage + anomaly risk)
- Quality-control checks (evidence, severity consistency, MITRE, recommendations)
- Pipeline timing and logging
- Unified final output with all agent results

---

## Detection Coverage (MITRE ATT&CK)

| Technique | Name |
|---|---|
| T1110.001 | Brute Force: Password Guessing |
| T1110.003 | Brute Force: Password Spraying |
| T1078 | Valid Accounts (Impossible Travel) |
| T1059.001 | PowerShell |
| T1071.001 | Web Protocols (C2 Beaconing) |
| T1071.004 | DNS (Tunneling) |
| T1003 | OS Credential Dumping |
| T1047 | Windows Management Instrumentation |
| T1021 | Remote Services (Lateral Movement) |
| T1098 | Account Manipulation (Cloud IAM) |
| T1041 | Exfiltration Over C2 Channel |
| T1078.002 | Valid Accounts: Domain Accounts |
| T1074 | Data Staged |
| T1486 | Data Encrypted for Impact (Ransomware) |

---

## Test Results

- **Pytest**: 68/68 tests passing
- **Full pipeline integration**: A (0.875 / Very Good)
  - ✓ Brute-Force → Priv Esc → Exfiltration
  - ✓ Suspicious PowerShell + C2 Beaconing
  - ✓ Cloud IAM Privilege Escalation
  - ✓ Benign Login (early close)

---

## Using the API Programmatically

```python
from agents import SOCOrchestrator

orchestrator = SOCOrchestrator()

result = orchestrator.run({
    "raw_log": "Jun 01 02:14:33 dc01 sshd: Failed password for root from 198.51.100.22",
    "events": [
        {"time": "02:14:33", "user": "admin", "src_ip": "198.51.100.22",
         "action": "SSH login", "result": "Failed", "host": "dc01"},
        # ... more events
    ]
})

output = result["result"]
print(output["severity"])            # e.g. "Critical"
print(output["executive_summary"])  # Plain-English summary
print(output["key_findings"])       # List of key finding strings
print(output["recommended_actions"]["P1"])  # Immediate actions
print(output["incident_report"]["markdown_report"])  # Full MD report
```

---

## Extending the System

**Add a new detection rule** → `agents/log_triage_agent.py`: add a tuple to `TRIAGE_RULES`.

**Add a new anomaly detector** → `agents/anomaly_detection_agent.py`: add a `_detect_*` method and register it in the `detectors` list inside `analyze()`.

**Add a new ATT&CK stage mapping** → `agents/threat_correlation_agent.py`: add a tuple to `ANOMALY_TO_STAGE`.

**Add a new mitigation rule** → `agents/mitigation_planning_agent.py`: add a tuple to `IMMEDIATE_RULES`, `SHORT_TERM_RULES`, `LONG_TERM_RULES`, or `DETECTION_RULES`.

---
