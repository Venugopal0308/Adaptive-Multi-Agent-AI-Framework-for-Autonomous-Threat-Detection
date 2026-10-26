import os
from pathlib import Path

import pandas as pd

from src.time_utils import normalize_timestamp, parse_timestamp_series


def _resolve_backend_dir() -> Path:
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "data" / "processed" / "rca_fused_lineage.csv").exists():
        return candidate
    repo_root = candidate.parent
    if (repo_root / "backend" / "data" / "processed" / "rca_fused_lineage.csv").exists():
        return repo_root / "backend"
    return candidate


class RCAAgent:
    def __init__(self, base_dir: str | os.PathLike[str] | None = None):
        resolved = Path(base_dir) if base_dir is not None else _resolve_backend_dir()
        self.base_dir = str(resolved)
        self.fused_log_path = os.path.join(self.base_dir, "data", "processed", "rca_fused_lineage.csv")

    def perform_rca(self, anomaly_timestamp: str, source_ip: str = None) -> dict:
        """Traces back through the fused tracking matrix to pinpoint Patient Zero."""
        print(f"[RCA Agent] Investigating anomaly event at timestamp: {anomaly_timestamp}...")

        if not os.path.exists(self.fused_log_path):
            return {
                "status": "error",
                "message": f"Fused alignment logs missing at {self.fused_log_path}. Run pipeline first."
            }

        df = pd.read_csv(self.fused_log_path)
        time_col = next((col for col in df.columns if 'time' in col.lower()), df.columns[0])
        df[time_col] = parse_timestamp_series(df[time_col])

        target_time = normalize_timestamp(anomaly_timestamp)
        if pd.isna(target_time):
            return {
                "status": "inconclusive",
                "message": "The alert timestamp could not be parsed for timeline correlation."
            }

        window_start = target_time - pd.Timedelta('5s')
        window_end = target_time + pd.Timedelta('1s')
        incident_window = df[(df[time_col] >= window_start) & (df[time_col] <= window_end)]

        if incident_window.empty:
            return {
                "status": "inconclusive",
                "message": "No concurrent system infrastructure or host logs matched this alert timestamp window."
            }

        print(f"Isolated {len(incident_window)} system log steps surrounding the threat trigger.")

        threat_indicators = []
        for col in incident_window.columns:
            if 'label' in col.lower() or 'technique' in col.lower() or 'message' in col.lower():
                active_threats = incident_window[incident_window[col].astype(str).str.lower() != 'normal'][col].unique()
                threat_indicators.extend(active_threats)

        threat_indicators = list(set([str(t) for t in threat_indicators if pd.notna(t)]))

        suspect_processes = []
        if 'CMD' in incident_window.columns:
            suspect_processes = incident_window['CMD'].dropna().unique().tolist()
        elif 'ProcessName' in incident_window.columns:
            suspect_processes = incident_window['ProcessName'].dropna().unique().tolist()

        rca_payload = {
            "status": "success",
            "detected_indicators": threat_indicators if threat_indicators else ["Generic Anomalous Pattern"],
            "suspect_infrastructure_nodes": suspect_processes[:5],
            "time_window_analyzed": f"{window_start.strftime('%Y-%m-%d %H:%M:%S')} to {window_end.strftime('%Y-%m-%d %H:%M:%S')}",
            "blast_radius_severity": "High" if len(incident_window) > 50 else "Medium"
        }

        print(f"Root Cause Identified: {rca_payload['detected_indicators']}")
        return rca_payload


if __name__ == "__main__":
    agent = RCAAgent()
    try:
        df_test = pd.read_csv(agent.fused_log_path, nrows=5)
        time_col = next((col for col in df_test.columns if 'time' in col.lower()), None)
        if time_col and not df_test.empty:
            test_ts = str(df_test[time_col].iloc[0])
            res = agent.perform_rca(anomaly_timestamp=test_ts)
            print("\nExecution Output Data Block:")
            print(res)
    except Exception as e:
        print(f"Could not automatically execute demo check: {e}")
