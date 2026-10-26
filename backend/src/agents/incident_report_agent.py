from datetime import datetime, timezone


class IncidentReportAgent:
    def create_report(self, state: dict) -> dict:
        detected = bool(state.get("anomaly_detected"))
        validation = state.get("validation_result", {})
        rca = state.get("rca_analysis", {})
        response = state.get("mitigation_playbook", {})

        if not detected:
            summary = "No anomaly was detected in the selected telemetry record."
        elif validation.get("status") != "passed":
            summary = "An anomaly candidate needs telemetry validation before escalation."
        else:
            summary = "An anomaly candidate was analyzed; review the response recommendations before taking action."

        return {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "anomaly_detected": detected,
            "validation_status": validation.get("status", "not_run"),
            "rca_status": rca.get("status", "skipped"),
            "response_status": response.get("status", "skipped"),
            "execution_status": "recommendations_only",
        }
