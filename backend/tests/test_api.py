import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from fastapi.testclient import TestClient

import app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app.app)

    def test_health_reports_five_agents(self):
        response = self.client.get("/api/v1/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["agents"]), 5)

    def test_simulation_rejects_negative_row_index(self):
        response = self.client.post(
            "/api/v1/simulation/run",
            json={"row_index": -1},
        )

        self.assertEqual(response.status_code, 422)

    def test_generate_metrics_reads_requested_row_and_validates_bounds(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = Path(temp_dir) / "traffic.csv"
            pd.DataFrame(
                {
                    "StartTime": [1681968375.0, 1681968376.0],
                    "TotPkts": [10, 20],
                    "Label": ["normal", "attack"],
                }
            ).to_csv(csv_path, index=False)

            with patch.object(app, "TRAFFIC_FILE", csv_path):
                metrics, timestamp = app.generate_metrics(1, 1.0)
                self.assertEqual(metrics, {"TotPkts": 20.0})
                self.assertTrue(timestamp.startswith("2023-"))
                with self.assertRaises(IndexError):
                    app.generate_metrics(2, 1.0)


if __name__ == "__main__":
    unittest.main()
