import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def _resolve_backend_dir() -> Path:
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "data" / "raw" / "label_traffic.csv").exists():
        return candidate
    repo_root = candidate.parent
    if (repo_root / "backend" / "data" / "raw" / "label_traffic.csv").exists():
        return repo_root / "backend"
    return candidate


class DetectionAgent:
    ignored_columns = {
        "label",
        "label_lifecycle",
        "label_technique",
        "timestamp",
        "starttime",
        "endtime",
        "lasttime",
    }

    def __init__(self, base_dir: str | os.PathLike[str] | None = None):
        resolved = Path(base_dir) if base_dir is not None else _resolve_backend_dir()
        self.base_dir = resolved
        self.raw_traffic_path = resolved / "data" / "raw" / "label_traffic.csv"
        self.model_dir = resolved / "data" / "processed"
        self.bundle_path = self.model_dir / "anomaly_bundle.pkl"
        self.metadata_path = self.model_dir / "anomaly_training.json"
        self.model_path = self.model_dir / "anomaly_detector.pkl"
        self.scaler_path = self.model_dir / "traffic_scaler.pkl"
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self._bundle: dict | None = None
        self._loaded_mtime: int | None = None
        self._bundle_lock = threading.Lock()

    @classmethod
    def _feature_columns(cls, frame: pd.DataFrame) -> list[str]:
        columns = []
        for column in frame.columns:
            if column.strip().lower() in cls.ignored_columns:
                continue
            if pd.api.types.is_numeric_dtype(frame[column]):
                columns.append(column)
        return columns

    def train_baseline(
        self,
        max_samples: int = 250_000,
        chunk_size: int = 50_000,
        progress_callback: Callable[[dict], None] | None = None,
    ) -> dict:
        """Train from a uniform reservoir sample while scanning the full traffic CSV."""
        if not self.raw_traffic_path.is_file():
            raise FileNotFoundError(f"Traffic dataset not found: {self.raw_traffic_path}")
        if max_samples < 1_000:
            raise ValueError("max_samples must be at least 1000.")
        if chunk_size < 1_000:
            raise ValueError("chunk_size must be at least 1000.")

        rng = np.random.default_rng(42)
        seen_rows = 0
        sample_size = 0
        reservoir: np.ndarray | None = None
        feature_columns: list[str] | None = None

        for chunk in pd.read_csv(self.raw_traffic_path, chunksize=chunk_size, low_memory=False):
            if feature_columns is None:
                feature_columns = self._feature_columns(chunk)
                if not feature_columns:
                    raise ValueError("The traffic dataset has no numeric model features.")
                reservoir = np.empty((max_samples, len(feature_columns)), dtype=np.float64)

            values = (
                chunk.reindex(columns=feature_columns)
                .apply(pd.to_numeric, errors="coerce")
                .to_numpy(dtype=np.float64, na_value=np.nan, copy=True)
            )
            np.nan_to_num(values, copy=False, nan=0.0, posinf=0.0, neginf=0.0)

            fill_count = min(max_samples - sample_size, len(values))
            if fill_count:
                reservoir[sample_size : sample_size + fill_count] = values[:fill_count]
                sample_size += fill_count

            replace_start = fill_count
            if replace_start < len(values) and sample_size == max_samples:
                positions = np.arange(seen_rows + replace_start + 1, seen_rows + len(values) + 1)
                slots = rng.integers(0, positions)
                eligible = slots < max_samples
                if eligible.any():
                    eligible_slots = slots[eligible]
                    eligible_rows = values[replace_start:][eligible]
                    reversed_unique, reversed_indices = np.unique(
                        eligible_slots[::-1], return_index=True
                    )
                    last_indices = len(eligible_slots) - 1 - reversed_indices
                    reservoir[reversed_unique] = eligible_rows[last_indices]

            seen_rows += len(values)
            if progress_callback:
                progress_callback(
                    {
                        "phase": "reading_dataset",
                        "rows_scanned": seen_rows,
                        "rows_sampled": sample_size,
                        "sample_limit": max_samples,
                    }
                )

        if reservoir is None or feature_columns is None or sample_size == 0:
            raise ValueError("The traffic dataset contains no usable rows.")

        training_rows = reservoir[:sample_size]
        scaler = StandardScaler()
        training_frame = pd.DataFrame(training_rows, columns=feature_columns)
        scaled_rows = scaler.fit_transform(training_frame)
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(scaled_rows)

        bundle = {
            "model": model,
            "scaler": scaler,
            "feature_columns": feature_columns,
        }
        temporary_bundle = self.bundle_path.with_suffix(".tmp")
        joblib.dump(bundle, temporary_bundle)
        os.replace(temporary_bundle, self.bundle_path)

        metadata = {
            "dataset": self.raw_traffic_path.name,
            "rows_scanned": seen_rows,
            "rows_sampled": sample_size,
            "feature_count": len(feature_columns),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "algorithm": "IsolationForest",
        }
        temporary_metadata = self.metadata_path.with_suffix(".tmp")
        temporary_metadata.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        os.replace(temporary_metadata, self.metadata_path)

        with self._bundle_lock:
            self._bundle = bundle
            self._loaded_mtime = self.bundle_path.stat().st_mtime_ns

        if progress_callback:
            progress_callback({"phase": "complete", **metadata})
        return metadata

    def _load_bundle(self) -> dict:
        if self.bundle_path.is_file():
            modified = self.bundle_path.stat().st_mtime_ns
            with self._bundle_lock:
                if self._bundle is None or self._loaded_mtime != modified:
                    self._bundle = joblib.load(self.bundle_path)
                    self._loaded_mtime = modified
                return self._bundle

        if self.model_path.is_file() and self.scaler_path.is_file():
            return {
                "model": joblib.load(self.model_path),
                "scaler": joblib.load(self.scaler_path),
                "feature_columns": None,
            }
        raise FileNotFoundError("No trained detector found. Train the model from the dashboard first.")

    def inspect_packet_details(self, operational_metrics: dict) -> dict:
        bundle = self._load_bundle()
        scaler = bundle["scaler"]
        feature_columns = bundle.get("feature_columns")
        frame = pd.DataFrame([operational_metrics])
        if feature_columns is None:
            feature_columns = list(getattr(scaler, "feature_names_in_", frame.columns))
        frame = frame.reindex(columns=feature_columns, fill_value=0)
        frame = frame.apply(pd.to_numeric, errors="coerce").fillna(0)
        if hasattr(scaler, "feature_names_in_"):
            scaled_row = scaler.transform(frame)
        else:
            scaled_row = scaler.transform(frame.to_numpy())
        model = bundle["model"]
        prediction = int(model.predict(scaled_row)[0])
        decision_score = float(model.decision_function(scaled_row)[0])
        return {
            "anomaly_detected": prediction == -1,
            "decision_score": decision_score,
            "feature_count": len(feature_columns),
        }

    def inspect_packet(self, operational_metrics_dict: dict) -> bool:
        return self.inspect_packet_details(operational_metrics_dict)["anomaly_detected"]

    def training_metadata(self) -> dict:
        if self.metadata_path.is_file():
            return json.loads(self.metadata_path.read_text(encoding="utf-8"))
        if self.bundle_path.is_file() or (self.model_path.is_file() and self.scaler_path.is_file()):
            return {"trained": True, "dataset": "existing model artifact", "rows_scanned": None}
        return {"trained": False}


if __name__ == "__main__":
    agent = DetectionAgent()
    print(agent.train_baseline())
