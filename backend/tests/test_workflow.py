import unittest
from unittest.mock import patch

from src import graph


def initial_state():
    return {
        "current_packet_metrics": {"TotPkts": 10.0, "Rate": 1.0},
        "anomaly_timestamp": "2023-04-20T05:26:15+00:00",
        "anomaly_detected": False,
        "detection_result": {},
        "validation_result": {},
        "rca_analysis": {},
        "mitigation_playbook": {},
        "incident_report": {},
        "agent_results": {},
        "execution_status": "ingress_received",
    }


class WorkflowTests(unittest.TestCase):
    def test_benign_record_is_validated_without_escalation(self):
        with (
            patch.object(
                graph.detection_worker,
                "inspect_packet_details",
                return_value={
                    "anomaly_detected": False,
                    "decision_score": 0.2,
                    "feature_count": 2,
                },
            ),
            patch.object(graph.rca_worker, "perform_rca") as rca,
            patch.object(graph.response_worker, "determine_mitigation") as response,
        ):
            result = graph.compiled_framework.invoke(initial_state())

        rca.assert_not_called()
        response.assert_not_called()
        self.assertEqual(
            set(result["agent_results"]),
            {"detection", "validation", "root_cause", "response", "report"},
        )
        self.assertEqual(result["agent_results"]["root_cause"]["status"], "skipped")
        self.assertFalse(result["anomaly_detected"])

    def test_validated_anomaly_reaches_recommendations_without_execution(self):
        with (
            patch.object(
                graph.detection_worker,
                "inspect_packet_details",
                return_value={
                    "anomaly_detected": True,
                    "decision_score": -0.2,
                    "feature_count": 2,
                },
            ),
            patch.object(
                graph.rca_worker,
                "perform_rca",
                return_value={"status": "success", "detected_indicators": ["1"]},
            ),
        ):
            result = graph.compiled_framework.invoke(initial_state())

        self.assertTrue(result["anomaly_detected"])
        self.assertEqual(result["rca_analysis"]["status"], "success")
        self.assertTrue(result["mitigation_playbook"]["approval_required"])
        self.assertEqual(result["mitigation_playbook"]["execution_status"], "not_executed")
        self.assertEqual(result["execution_status"], "analysis_complete")


if __name__ == "__main__":
    unittest.main()
