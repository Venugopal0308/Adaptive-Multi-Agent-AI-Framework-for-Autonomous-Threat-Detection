import os
from pathlib import Path

import pandas as pd

from src.graph import compiled_framework
from src.time_utils import normalize_timestamp


def _resolve_backend_dir() -> Path:
    candidates = [Path(__file__).resolve().parent]
    for base in candidates:
        if (base / "data" / "raw" / "label_traffic.csv").exists():
            return base
        if (base.parent / "backend" / "data" / "raw" / "label_traffic.csv").exists():
            return base.parent / "backend"
    return candidates[0]


def run_framework_simulation():
    print("[System Ingress] Starting Multi-Agent Threat Ingress Loop...")

    workspace = _resolve_backend_dir()
    traffic_file = workspace / "data" / "raw" / "label_traffic.csv"

    if not traffic_file.exists():
        print("Error: Cannot run simulation stream without label_traffic.csv baseline.")
        return

    df = pd.read_csv(traffic_file, nrows=2)
    ignore_cols = ['Label', 'Label_Lifecycle', 'Label_Technique', 'Timestamp', 'StartTime', 'EndTime']
    feature_cols = [col for col in df.columns if col not in ignore_cols and df[col].dtype in ['int64', 'float64']]

    # Scenario: inject anomalous attack data
    attack_metrics = df[feature_cols].iloc[0].to_dict()
    for key in attack_metrics.keys():
        if "pkts" in key.lower() or "bytes" in key.lower() or "rate" in key.lower() or "dur" in key.lower():
            attack_metrics[key] = attack_metrics[key] * 5000

    raw_timestamp = df.iloc[0].get("StartTime", df.iloc[0].get("Timestamp", "unknown"))
    parsed_timestamp = normalize_timestamp(raw_timestamp)
    sample_ts = parsed_timestamp.isoformat() if not pd.isna(parsed_timestamp) else str(raw_timestamp)

    initial_attack_state = {
        "current_packet_metrics": attack_metrics,
        "anomaly_timestamp": sample_ts,
        "anomaly_detected": False,
        "detection_result": {},
        "validation_result": {},
        "rca_analysis": {},
        "mitigation_playbook": {},
        "incident_report": {},
        "agent_results": {},
        "execution_status": "ingress_received"
    }

    print("\n=== Triggering LangGraph Processing Loop (ATTACK SIMULATION) ===")
    final_output_state = compiled_framework.invoke(initial_attack_state)
    print("====================================================================\n")

    print("[Simulation Final Output Reports Summary]:")
    print(f"ML Anomaly Classification: {final_output_state['anomaly_detected']}")
    print(f"Workflow Termination Phase: {final_output_state['execution_status']}")
    print(f"Incident Summary: {final_output_state['incident_report'].get('summary', 'Unavailable')}")

    if final_output_state['anomaly_detected']:
        print("\n[RESPONSE RECOMMENDATIONS] Analyst review required:")
        for profile in final_output_state['mitigation_playbook']['threat_profiles']:
            print(f"  - {profile}")
        print("\nTarget Containment Actions:")
        for action in final_output_state['mitigation_playbook']['targeted_containment_actions']:
            print(f"  - {action}")
        print("\nManual, read-only verification commands (never run automatically):")
        for script in final_output_state['mitigation_playbook']['verification_execution_scripts']:
            print(f"  > {script}")

if __name__ == "__main__":
    run_framework_simulation()
