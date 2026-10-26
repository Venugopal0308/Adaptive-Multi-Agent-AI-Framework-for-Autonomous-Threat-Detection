import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.agents.detection_agent import DetectionAgent


class DetectionAgentTests(unittest.TestCase):
    def test_training_scans_in_chunks_and_inference_aligns_features(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            raw_dir = root / "data" / "raw"
            raw_dir.mkdir(parents=True)
            row_count = 1_500
            pd.DataFrame(
                {
                    "TotPkts": np.arange(row_count, dtype=float),
                    "TotBytes": np.arange(row_count, dtype=float) * 10,
                    "Rate": np.linspace(0, 1, row_count),
                    "Label": np.zeros(row_count, dtype=int),
                }
            ).to_csv(raw_dir / "label_traffic.csv", index=False)

            agent = DetectionAgent(root)
            progress = []
            metadata = agent.train_baseline(
                max_samples=1_000,
                chunk_size=1_000,
                progress_callback=progress.append,
            )

            self.assertEqual(metadata["rows_scanned"], row_count)
            self.assertEqual(metadata["rows_sampled"], 1_000)
            self.assertEqual(metadata["feature_count"], 3)
            self.assertEqual(progress[-1]["phase"], "complete")
            self.assertEqual(
                agent.inspect_packet_details(
                    {"Rate": 0.2, "TotBytes": 100, "TotPkts": 10, "extra": 5}
                )["feature_count"],
                3,
            )

    def test_training_requires_dataset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            agent = DetectionAgent(Path(temp_dir))

            with self.assertRaises(FileNotFoundError):
                agent.train_baseline()


if __name__ == "__main__":
    unittest.main()
