from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from src.agents.alert_validation_agent import AlertValidationAgent
from src.agents.detection_agent import DetectionAgent
from src.agents.incident_report_agent import IncidentReportAgent
from src.agents.rca_agent import RCAAgent
from src.agents.response_agent import ResponseAgent


class AgentIncidentState(TypedDict):
    current_packet_metrics: dict[str, Any]
    anomaly_timestamp: str
    anomaly_detected: bool
    detection_result: dict[str, Any]
    validation_result: dict[str, Any]
    rca_analysis: dict[str, Any]
    mitigation_playbook: dict[str, Any]
    incident_report: dict[str, Any]
    agent_results: dict[str, dict[str, Any]]
    execution_status: str


detection_worker = DetectionAgent()
validation_worker = AlertValidationAgent()
rca_worker = RCAAgent()
response_worker = ResponseAgent()
report_worker = IncidentReportAgent()


def detection_node(state: AgentIncidentState) -> dict[str, Any]:
    result = detection_worker.inspect_packet_details(state["current_packet_metrics"])
    return {
        "detection_result": result,
        "anomaly_detected": result["anomaly_detected"],
        "execution_status": "anomaly_candidate" if result["anomaly_detected"] else "traffic_benign",
        "agent_results": {"detection": {"status": "complete", **result}},
    }


def validation_node(state: AgentIncidentState) -> dict[str, Any]:
    result = validation_worker.validate(
        state["current_packet_metrics"],
        state["detection_result"],
    )
    return {
        "validation_result": result,
        "agent_results": {"validation": {"status": result["status"], **result}},
    }


def rca_node(state: AgentIncidentState) -> dict[str, Any]:
    result = rca_worker.perform_rca(anomaly_timestamp=state["anomaly_timestamp"])
    return {
        "rca_analysis": result,
        "execution_status": "rca_completed",
        "agent_results": {"root_cause": {"status": result.get("status", "complete"), **result}},
    }


def response_node(state: AgentIncidentState) -> dict[str, Any]:
    result = response_worker.determine_mitigation(state["rca_analysis"])
    return {
        "mitigation_playbook": result,
        "execution_status": "recommendations_ready_for_review",
        "agent_results": {"response": {"status": "recommendations_ready", **result}},
    }


def report_node(state: AgentIncidentState) -> dict[str, Any]:
    report = report_worker.create_report(state)
    detection = state.get("detection_result", {})
    validation = state.get("validation_result", {})
    rca = state.get("rca_analysis", {})
    response = state.get("mitigation_playbook", {})
    agent_results = {
        "detection": {"status": "complete" if detection else "not_run", **detection},
        "validation": {
            "status": validation.get("status", "not_run"),
            **validation,
        },
        "root_cause": {"status": rca.get("status", "skipped"), **rca},
        "response": {"status": response.get("status", "skipped"), **response},
        "report": {"status": "complete", **report},
    }
    return {
        "incident_report": report,
        "agent_results": agent_results,
        "execution_status": "analysis_complete",
    }


workflow = StateGraph(AgentIncidentState)
workflow.add_node("detect_threat", detection_node)
workflow.add_node("validate_alert", validation_node)
workflow.add_node("trace_root_cause", rca_node)
workflow.add_node("generate_response", response_node)
workflow.add_node("create_incident_report", report_node)
workflow.set_entry_point("detect_threat")
workflow.add_edge("detect_threat", "validate_alert")


def routing_decision_gate(state: AgentIncidentState) -> str:
    if state["anomaly_detected"] and state["validation_result"]["passed"]:
        return "trace_root_cause"
    return "create_incident_report"


workflow.add_conditional_edges("validate_alert", routing_decision_gate)
workflow.add_edge("trace_root_cause", "generate_response")
workflow.add_edge("generate_response", "create_incident_report")
workflow.add_edge("create_incident_report", END)

compiled_framework = workflow.compile()
