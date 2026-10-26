import math
import unittest

from src.agents.alert_validation_agent import AlertValidationAgent
from src.agents.incident_report_agent import IncidentReportAgent
from src.agents.response_agent import ResponseAgent


class AgentTests(unittest.TestCase):
    def test_alert_validation_rejects_non_finite_metrics(self):
        result = AlertValidationAgent().validate(
            {"packet_rate": math.inf},
            {"anomaly_detected": True, "feature_count": 1},
        )

        self.assertFalse(result["passed"])
        self.assertEqual(result["status"], "review_required")
        self.assertTrue(any("Non-finite" in item for item in result["findings"]))

    def test_response_is_recommendations_only(self):
        result = ResponseAgent().determine_mitigation(
            {"detected_indicators": ["1"]}
        )

        self.assertTrue(result["approval_required"])
        self.assertEqual(result["execution_status"], "not_executed")
        self.assertTrue(result["targeted_containment_actions"])

    def test_incident_report_handles_benign_traffic(self):
        report = IncidentReportAgent().create_report(
            {
                "anomaly_detected": False,
                "validation_result": {"status": "passed"},
            }
        )

        self.assertEqual(report["execution_status"], "recommendations_only")
        self.assertIn("No anomaly", report["summary"])
        self.assertEqual(report["rca_status"], "skipped")


if __name__ == "__main__":
    unittest.main()
