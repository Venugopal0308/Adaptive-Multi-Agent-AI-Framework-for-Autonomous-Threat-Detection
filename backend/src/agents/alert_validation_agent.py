import math


class AlertValidationAgent:
    def validate(self, metrics: dict, detection_result: dict) -> dict:
        findings = []
        if not metrics:
            findings.append("No telemetry features were provided.")

        non_numeric = []
        non_finite = []
        for key, value in metrics.items():
            try:
                numeric_value = float(value)
            except (TypeError, ValueError):
                non_numeric.append(key)
                continue
            if not math.isfinite(numeric_value):
                non_finite.append(key)

        if non_numeric:
            findings.append(f"Non-numeric telemetry fields: {', '.join(non_numeric[:5])}.")
        if non_finite:
            findings.append(f"Non-finite telemetry fields: {', '.join(non_finite[:5])}.")
        if not detection_result.get("feature_count"):
            findings.append("The detector did not evaluate any model features.")

        passed = not findings
        return {
            "status": "passed" if passed else "review_required",
            "passed": passed,
            "findings": findings,
            "checked_feature_count": len(metrics),
            "anomaly_candidate": bool(detection_result.get("anomaly_detected")),
        }
