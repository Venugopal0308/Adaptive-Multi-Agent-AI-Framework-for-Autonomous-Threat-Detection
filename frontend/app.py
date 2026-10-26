import json
import time

import requests
import streamlit as st


st.set_page_config(
    page_title="Adaptive Multi-Agent AI Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

with st.container(border=True):
    st.caption("DEFENSIVE SECURITY OPERATIONS · OFFLINE TELEMETRY")
    st.title(
        "Title: Adaptive Multi-Agent AI Framework for Autonomous Threat Detection, "
        "Root Cause Analysis, and Intelligent Response Recommendation"
    )
    st.caption("Five coordinated agents for offline telemetry analysis, with an analyst in control.")

with st.sidebar:
    st.markdown("## :material/security: Sentinel")
    api_base = st.text_input("Backend API", value="http://127.0.0.1:8000").strip().rstrip("/")
    st.caption("Start the API and dashboard using the project run instructions.")
    st.markdown("---")
    st.markdown("### Model training")
    with st.form("training_form"):
        max_samples = st.slider(
            "Training sample limit",
            min_value=10_000,
            max_value=500_000,
            value=250_000,
            step=10_000,
            help="The trainer scans the full traffic CSV in chunks and keeps a uniform, memory-bounded sample.",
        )
        chunk_size = st.select_slider(
            "CSV chunk size",
            options=[10_000, 25_000, 50_000, 75_000, 100_000],
            value=50_000,
        )
        train_button = st.form_submit_button(
            ":material/model_training: Train / refresh detector",
            width="stretch",
        )
    st.caption("Training can take several minutes for the supplied 1 GB+ traffic file.")
    st.caption("Training is unsupervised; this dashboard does not report benchmark accuracy.")

try:
    health_response = requests.get(f"{api_base}/api/v1/health", timeout=5)
    health_response.raise_for_status()
    health = health_response.json()
except requests.RequestException as error:
    health = None
    st.error(f"Cannot reach the backend at {api_base}: {error}")

detector_is_trained = False
if health:
    status_col, model_col, agent_col = st.columns(3)
    with status_col:
        st.metric("Backend", health.get("status", "unknown").upper(), border=True)
    with model_col:
        model_info = health.get("model", {})
        detector_is_trained = bool(
            model_info.get("trained")
            or model_info.get("rows_scanned")
            or model_info.get("dataset") == "existing model artifact"
        )
        model_state = "TRAINED" if detector_is_trained else "NOT TRAINED"
        st.metric("Detector", model_state, border=True)
    with agent_col:
        st.metric("Defensive agents", len(health.get("agents", [])), border=True)

training_notice = st.session_state.pop("training_notice", None)
if training_notice:
    st.success(training_notice)

if train_button:
    try:
        response = requests.post(
            f"{api_base}/api/v1/model/train",
            json={"max_samples": max_samples, "chunk_size": chunk_size},
            timeout=10,
        )
        response.raise_for_status()
        job = response.json()
        progress = st.progress(0)
        progress_text = st.empty()
        started_at = time.monotonic()

        while job.get("status") == "running":
            try:
                status_response = requests.get(f"{api_base}/api/v1/model/status", timeout=5)
                status_response.raise_for_status()
                job = status_response.json()
            except requests.RequestException as error:
                st.error(f"Lost contact with the training job: {error}")
                break

            scanned = int(job.get("rows_scanned", 0))
            sampled = int(job.get("rows_sampled", 0))
            limit = max(int(job.get("sample_limit", max_samples)), 1)
            fraction = min(sampled / limit, 0.95)
            progress.progress(fraction)
            progress_text.info(
                f"Phase: {job.get('phase', 'starting')} · "
                f"Rows scanned: {scanned:,} · Sampled: {sampled:,}/{limit:,}"
            )
            if time.monotonic() - started_at > 7_200:
                st.warning("Training is still running in the backend. Check back using the backend status endpoint.")
                break
            time.sleep(2)

        if job.get("status") == "complete":
            progress.progress(1.0)
            st.session_state["training_notice"] = (
                f"Detector trained from {job.get('rows_scanned', 0):,} scanned rows "
                f"({job.get('rows_sampled', 0):,} sampled; {job.get('feature_count', 0)} features)."
            )
            st.rerun()
        elif job.get("status") == "failed":
            st.error(f"Training failed: {job.get('detail', 'No error detail returned.')}")
    except requests.RequestException as error:
        st.error(f"Could not start model training: {error}")
    except (ValueError, json.JSONDecodeError) as error:
        st.error(f"The training API returned an invalid response: {error}")

st.markdown("---")
left, right = st.columns([0.9, 1.5], gap="large")

with left:
    with st.form("analysis_form", border=True):
        st.subheader("Analyze a dataset record")
        st.write("Analysis is performed against local, preloaded telemetry. No live network traffic is sent.")
        row_index = st.number_input("Traffic CSV row", min_value=0, value=0, step=1)
        multiplier = st.slider(
            "Offline feature stress multiplier",
            min_value=1.0,
            max_value=20.0,
            value=1.0,
            step=0.5,
            help="1.0 analyzes the stored record as-is. Higher values only scale selected numeric features for local testing.",
        )
        analyze_button = st.form_submit_button(
            ":material/analytics: Run five-agent analysis",
            type="primary",
            width="stretch",
            disabled=not detector_is_trained,
        )
    if detector_is_trained:
        st.caption("Response recommendations are not executed. Analyst review is required.")
    else:
        st.caption("Train the detector in the sidebar before analyzing records.")

with right:
    st.subheader("Agent workflow")
    agent_names = [
        "Detection",
        "Alert validation",
        "Root-cause analysis",
        "Response recommendations",
        "Incident reporting",
    ]
    agent_status_slots = []
    for agent_group in (agent_names[:3], agent_names[3:]):
        for slot, name in zip(st.columns(len(agent_group)), agent_group):
            slot.markdown(f"**{name}**")
            status_slot = slot.empty()
            status_slot.caption("Waiting")
            agent_status_slots.append(status_slot)

if analyze_button:
    output = st.empty()
    log_area = st.empty()
    output.info("Starting offline analysis…")
    accumulated_logs = []
    final_report = None
    try:
        with requests.post(
            f"{api_base}/api/v1/simulation/run",
            json={"row_index": int(row_index), "multiplier": multiplier},
            stream=True,
            timeout=(10, 1_800),
        ) as response:
            if not response.ok:
                st.error(f"Analysis API returned HTTP {response.status_code}: {response.text}")
            else:
                for line in response.iter_lines(decode_unicode=True):
                    if not line or not line.startswith("data: "):
                        continue
                    try:
                        event = json.loads(line[6:])
                    except json.JSONDecodeError as error:
                        st.error(f"Backend sent an invalid event: {error}")
                        break

                    if event.get("status") == "progress":
                        output.info(event.get("message", "Analysis is in progress."))
                    elif event.get("status") == "streaming_update":
                        agent = event.get("agent", "workflow")
                        accumulated_logs.append({"agent": agent, "result": event.get("data", {})})
                        log_area.json(accumulated_logs)
                        agent_order = {
                            "detect_threat": 0,
                            "validate_alert": 1,
                            "trace_root_cause": 2,
                            "generate_response": 3,
                            "create_incident_report": 4,
                        }
                        if agent in agent_order:
                            agent_status_slots[agent_order[agent]].caption("Complete")
                    elif event.get("status") == "completed":
                        final_report = event.get("final_report", {})
                    elif event.get("status") == "error":
                        output.error(f"Analysis failed: {event.get('detail', 'Unknown backend error.')}")

        if final_report:
            st.session_state["last_report"] = final_report
            agent_results = final_report.get("agent_results", {})
            for status_slot, key in zip(
                agent_status_slots,
                ["detection", "validation", "root_cause", "response", "report"],
            ):
                status_slot.caption(
                    str(agent_results.get(key, {}).get("status", "skipped"))
                    .replace("_", " ")
                    .title()
                )
            output.success("Analysis complete. Recommendations remain pending analyst review.")
    except requests.RequestException as error:
        output.error(f"Could not complete the analysis request: {error}")

report = st.session_state.get("last_report")
if report:
    st.markdown("---")
    st.subheader("Incident overview")
    report_data = report.get("incident_report", {})
    result_cols = st.columns(3)
    with result_cols[0]:
        st.metric(
            "Detection",
            "ANOMALY CANDIDATE" if report.get("anomaly_detected") else "NO ANOMALY",
            border=True,
        )
    with result_cols[1]:
        st.metric(
            "Workflow",
            report.get("execution_status", "unknown").replace("_", " ").upper(),
            border=True,
        )
    with result_cols[2]:
        st.metric("Action execution", "NOT EXECUTED", border=True)
    st.info(report_data.get("summary", "No incident summary was returned."))

    agent_results = report.get("agent_results", {})
    agent_keys = ["detection", "validation", "root_cause", "response", "report"]
    agent_index = 0
    for agent_group in (agent_names[:3], agent_names[3:]):
        for col, name in zip(st.columns(len(agent_group)), agent_group):
            key = agent_keys[agent_index]
            result = agent_results.get(key, {})
            col.markdown(f"**{name}**")
            col.caption(str(result.get("status", "skipped")).replace("_", " ").title())
            agent_index += 1

    with st.expander("Root-cause analysis"):
        st.json(report.get("rca_analysis") or {"status": "skipped"})
    with st.expander("Response recommendations — review before action"):
        playbook = report.get("mitigation_playbook", {})
        if playbook:
            st.warning("These are suggestions only. Nothing has been run or changed on a system.")
            st.write("**Threat profiles**")
            st.write(playbook.get("threat_profiles", []))
            st.write("**Recommended containment actions**")
            for action in playbook.get("targeted_containment_actions", []):
                st.markdown(f"- {action}")
            st.write("**Manual, read-only verification commands**")
            for command in playbook.get("verification_execution_scripts", []):
                st.code(command, language="powershell")
            st.caption("Approval required: " + str(playbook.get("approval_required", True)))
        else:
            st.write("No response recommendations were generated.")
    with st.expander("Full incident report and agent outputs"):
        st.json(report)

try:
    dataset_response = requests.get(f"{api_base}/api/v1/datasets", timeout=5)
    dataset_response.raise_for_status()
    datasets = dataset_response.json().get("datasets", [])
except requests.RequestException:
    datasets = []

if datasets:
    st.markdown("---")
    with st.expander("Local data inventory"):
        st.dataframe(
            [
                {
                    "Dataset": item["name"],
                    "Available": item["available"],
                    "Size (MB)": round(item["bytes"] / (1024 * 1024), 1),
                }
                for item in datasets
            ],
            hide_index=True,
            width="stretch",
            alt="Availability and size of local telemetry datasets",
        )

st.caption("Local defensive analysis only · No automatic containment")
st.link_button("Open API documentation", f"{api_base}/docs")
