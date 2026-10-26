import json
import os
import zipfile
from pathlib import Path

import pandas as pd

from src.time_utils import parse_timestamp_series


class SecurityDataPipeline:
    def __init__(self, base_dir: str | os.PathLike[str]):
        """Initializes directory topologies using explicit absolute paths."""
        base_path = Path(base_dir).resolve()
        candidate = base_path
        if not (candidate / "data" / "raw").exists() and (candidate.parent / "backend" / "data" / "raw").exists():
            candidate = candidate.parent / "backend"
        self.base_dir = str(candidate)
        self.raw_dir = os.path.join(self.base_dir, "data", "raw")
        self.processed_dir = os.path.join(self.base_dir, "data", "processed")

        os.makedirs(self.raw_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)

    def extract_zip_archives(self, zip_dir: str) -> None:
        """Finds any zip file and extracts it. Aggressively maps folder names."""
        search_dir = os.path.abspath(zip_dir)
        print(f"Scanning folder: '{search_dir}' for ZIP files...")

        if not os.path.exists(search_dir):
            print(f"Error: The directory '{search_dir}' does not exist.")
            return

        zip_files = [f for f in os.listdir(search_dir) if f.endswith(".zip")]
        if not zip_files:
            print("No .zip files found directly in this directory! Checking if they are already unzipped manually...")
            return

        for file in zip_files:
            zip_path = os.path.join(search_dir, file)
            file_lower = file.lower()

            if "cic" in file_lower or "intrusion" in file_lower:
                folder_name = "cic_ids_2017"
            elif "creme" in file_lower:
                folder_name = "creme_v2"
            elif "playbook" in file_lower or "incident" in file_lower:
                folder_name = "incident_playbooks"
            else:
                folder_name = file.replace(".zip", "_extracted")

            extract_target = os.path.join(self.raw_dir, folder_name)
            os.makedirs(extract_target, exist_ok=True)

            print(f"Extracting {file} -> {extract_target}...")
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_target)
                print("Extracted successfully.")
            except Exception as e:
                print(f"Failed to extract {file}: {e}")

    def process_detection_telemetry(self) -> None:
        """Cleans and outputs optimized Parquet layers for the Detection Agent."""
        print("\nProcessing Detection Agent Data...")

        csv_files = []
        for root, _, files in os.walk(self.raw_dir):
            for f in files:
                if f.endswith('.csv') and ("cic" in root.lower() or "intrusion" in f.lower() or "thursday" in f.lower()):
                    csv_files.append(os.path.join(root, f))

        if not csv_files:
            print("Skipping: No network telemetry CSV found in data/raw/")
            return

        target_csv = csv_files[0]
        print(f"Reading CSV File: {os.path.basename(target_csv)}")

        try:
            df = pd.read_csv(target_csv, skipinitialspace=True, nrows=50000)
            df.columns = df.columns.str.strip().str.replace(' ', '_').str.replace('/', '_').str.replace('-', '_')
            df.replace([pd.NA, float('inf'), float('-inf')], pd.NA, inplace=True)
            df.dropna(inplace=True)

            output_path = os.path.join(self.processed_dir, "detection_telemetry.parquet")
            df.to_parquet(output_path, index=False)
            print(f"Saved clean Parquet data -> {output_path}")
        except Exception as e:
            print(f"Error processing detection CSV: {e}")

    def process_rca_lineage(self) -> None:
        """Fuses metrics from CREMEv2 for the RCA Agent."""
        print("\nAligning CREMEv2 logs for Forensic/RCA Agent...")

        csv_files = []
        for root, _, files in os.walk(self.raw_dir):
            for f in files:
                if f.endswith('.csv') and "creme" in root.lower():
                    csv_files.append(os.path.join(root, f))

        if len(csv_files) < 2:
            all_csvs = [os.path.join(r, f) for r, _, fs in os.walk(self.raw_dir) for f in fs if f.endswith('.csv')]
            csv_files = [c for c in all_csvs if "cic" not in c.lower()]

        if len(csv_files) < 2:
            print("Skipping: CREMEv2 processing requires at least 2 distinct csv files.")
            return

        print(f"Fusing: {os.path.basename(csv_files[0])} + {os.path.basename(csv_files[1])}")
        try:
            df_a = pd.read_csv(csv_files[0], nrows=20000)
            df_b = pd.read_csv(csv_files[1], nrows=20000)

            time_col_a = next((col for col in df_a.columns if 'time' in col.lower()), df_a.columns[0])
            time_col_b = next((col for col in df_b.columns if 'time' in col.lower()), df_b.columns[0])

            df_a[time_col_a] = parse_timestamp_series(df_a[time_col_a])
            df_b[time_col_b] = parse_timestamp_series(df_b[time_col_b])
            df_a.dropna(subset=[time_col_a], inplace=True)
            df_b.dropna(subset=[time_col_b], inplace=True)

            df_fused = pd.merge_asof(
                df_a.sort_values(time_col_a),
                df_b.sort_values(time_col_b),
                left_on=time_col_a,
                right_on=time_col_b,
                direction='nearest',
                tolerance=pd.Timedelta('5s')
            )

            output_path = os.path.join(self.processed_dir, "rca_fused_lineage.csv")
            df_fused.to_csv(output_path, index=False)
            print(f"Saved Fused RCA Lineage -> {output_path}")
        except Exception as e:
            print(f"Error processing RCA logic: {e}")

    def process_response_playbooks(self) -> None:
        """Transforms playbook parameters into clean JSON for the Response Agent."""
        print("\nStructuring Playbook Dataset for Response Agent...")

        json_files = []
        for root, _, files in os.walk(self.raw_dir):
            for f in files:
                if f.endswith('.json') or f.endswith('.jsonl'):
                    json_files.append(os.path.join(root, f))

        if not json_files:
            print("Skipping: No valid JSON/JSONL playbook structures found.")
            return

        target_json = json_files[0]
        formatted_playbooks = []
        print(f"Reading Playbook: {os.path.basename(target_json)}")

        try:
            with open(target_json, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if target_json.endswith('l') or (content and not content.startswith('[')):
                    lines = content.split('\n')
                    records = [json.loads(line) for line in lines if line.strip()]
                else:
                    raw_json = json.loads(content)
                    records = raw_json if isinstance(raw_json, list) else [raw_json]

            for item in records:
                formatted_playbooks.append({
                    "context_threat": item.get("attack_vector") or item.get("threat_type") or "Unknown Threat",
                    "mitigation_steps": item.get("playbook_steps") or item.get("actions") or [],
                    "verification_cmd": item.get("verification") or item.get("verification_command") or ""
                })

            output_path = os.path.join(self.processed_dir, "response_playbooks.json")
            with open(output_path, "w", encoding='utf-8') as out_f:
                json.dump(formatted_playbooks, out_f, indent=4)
            print(f"Saved Response Playbooks -> {output_path}")
        except Exception as e:
            print(f"Error parsing playbooks: {e}")

    def run_all(self, source_zip_dir: str) -> None:
        print("Starting Absolute Multi-Agent Preprocessing Pipeline...")
        self.extract_zip_archives(source_zip_dir)
        self.process_detection_telemetry()
        self.process_rca_lineage()
        self.process_response_playbooks()
        print("\nPipeline Execution Finished!")


if __name__ == "__main__":
    workspace = Path(__file__).resolve().parents[1]

    pipeline = SecurityDataPipeline(base_dir=workspace)
    pipeline.run_all(source_zip_dir=str(workspace))
