import asyncio
import json
import threading
import uuid
from pathlib import Path

import pandas as pd
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.agents.detection_agent import DetectionAgent
from src.graph import compiled_framework
from src.time_utils import normalize_timestamp


def _resolve_backend_dir() -> Path:
    candidate = Path(__file__).resolve().parent
    if (candidate / "data" / "raw" / "label_traffic.csv").exists():
        return candidate
    repo_root = candidate.parent
    if (repo_root / "backend" / "data" / "raw" / "label_traffic.csv").exists():
        return repo_root / "backend"
    return candidate


WORKSPACE_PATH = _resolve_backend_dir()
TRAFFIC_FILE = WORKSPACE_PATH / "data" / "raw" / "label_traffic.csv"
DETECTOR = DetectionAgent(WORKSPACE_PATH)
_training_lock = threading.Lock()
_training_state: dict = {"status": "idle"}

app = FastAPI(
    title="Adaptive Multi-Agent SecOps Console",
    description="Defensive, offline telemetry analysis and analyst-reviewed incident recommendations.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class SimulationRequest(BaseModel):
    multiplier: float = Field(default=1.0, ge=1.0, le=20.0)
    row_index: int = Field(default=0, ge=0)


class TrainingRequest(BaseModel):
    max_samples: int = Field(default=250_000, ge=1_000, le=500_000)
    chunk_size: int = Field(default=50_000, ge=1_000, le=100_000)


def generate_metrics(row_index: int, multiplier: float) -> tuple[dict, str]:
    if not TRAFFIC_FILE.is_file():
        raise FileNotFoundError(f"Traffic dataset not found: {TRAFFIC_FILE}")

    frame = pd.read_csv(
        TRAFFIC_FILE,
        skiprows=lambda line_number: 0 < line_number <= row_index,
        nrows=1,
        low_memory=False,
    )
    if frame.empty:
        raise IndexError(f"Row index {row_index} is outside the available dataset.")

    row = frame.iloc[0]
    ignored = DetectionAgent.ignored_columns
    features = [
        column for column in frame.columns
        if column.strip().lower() not in ignored
        and pd.api.types.is_numeric_dtype(frame[column])
    ]
    if not features:
        raise ValueError("The selected record has no numeric telemetry features.")

    metrics = {}
    for key, value in row[features].items():
        number = float(value) if pd.notna(value) else 0.0
        if any(token in key.lower() for token in ("pkts", "bytes", "rate", "dur")):
            number *= multiplier
        metrics[key] = number

    raw_timestamp = row.get("StartTime", row.get("LastTime", "unknown"))
    parsed_timestamp = normalize_timestamp(raw_timestamp)
    timestamp = parsed_timestamp.isoformat() if not pd.isna(parsed_timestamp) else str(raw_timestamp)
    return metrics, timestamp


@app.get("/")
async def root():
    return {
        "service": app.title,
        "docs": "/docs",
        "health": "/api/v1/health",
    }


@app.get("/api/v1/health")
async def health_check():
    try:
        model_metadata = DETECTOR.training_metadata()
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=500, detail=f"Unable to read detector metadata: {error}") from error

    return {
        "status": "healthy" if TRAFFIC_FILE.is_file() else "degraded",
        "dataset_available": TRAFFIC_FILE.is_file(),
        "dataset_bytes": TRAFFIC_FILE.stat().st_size if TRAFFIC_FILE.is_file() else 0,
        "model": model_metadata,
        "agents": [
            "Detection",
            "Alert validation",
            "Root-cause analysis",
            "Response recommendations",
            "Incident reporting",
        ],
    }


@app.get("/api/v1/datasets")
async def dataset_summary():
    paths = [
        WORKSPACE_PATH / "data" / "raw" / "label_traffic.csv",
        WORKSPACE_PATH / "data" / "raw" / "label_accounting.csv",
        WORKSPACE_PATH / "data" / "raw" / "label_syslog.csv",
        WORKSPACE_PATH / "data" / "processed" / "rca_fused_lineage.csv",
    ]
    return {
        "datasets": [
            {
                "name": path.name,
                "available": path.is_file(),
                "bytes": path.stat().st_size if path.is_file() else 0,
            }
            for path in paths
        ]
    }


def _run_training(job_id: str, request: TrainingRequest) -> None:
    global _training_state

    def update_progress(progress: dict) -> None:
        with _training_lock:
            if _training_state.get("job_id") == job_id:
                _training_state.update(progress)

    try:
        metadata = DETECTOR.train_baseline(
            max_samples=request.max_samples,
            chunk_size=request.chunk_size,
            progress_callback=update_progress,
        )
        with _training_lock:
            _training_state = {"job_id": job_id, "status": "complete", **metadata}
    except Exception as error:
        with _training_lock:
            _training_state = {"job_id": job_id, "status": "failed", "detail": str(error)}


@app.post("/api/v1/model/train", status_code=202)
async def start_model_training(
    request: TrainingRequest,
    background_tasks: BackgroundTasks,
):
    global _training_state
    if not TRAFFIC_FILE.is_file():
        raise HTTPException(status_code=404, detail=f"Traffic dataset not found: {TRAFFIC_FILE}")

    with _training_lock:
        if _training_state.get("status") == "running":
            return dict(_training_state)
        job_id = str(uuid.uuid4())
        _training_state = {
            "job_id": job_id,
            "status": "running",
            "phase": "starting",
            "rows_scanned": 0,
            "rows_sampled": 0,
            "sample_limit": request.max_samples,
        }
    background_tasks.add_task(_run_training, job_id, request)
    return dict(_training_state)


@app.get("/api/v1/model/status")
async def model_training_status():
    with _training_lock:
        return dict(_training_state)


@app.post("/api/v1/simulation/run")
async def run_agent_simulation_stream(payload: SimulationRequest):
    try:
        metrics, sample_timestamp = await asyncio.to_thread(
            generate_metrics,
            payload.row_index,
            payload.multiplier,
        )
    except FileNotFoundError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except IndexError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    initial_state = {
        "current_packet_metrics": metrics,
        "anomaly_timestamp": sample_timestamp,
        "anomaly_detected": False,
        "detection_result": {},
        "validation_result": {},
        "rca_analysis": {},
        "mitigation_playbook": {},
        "incident_report": {},
        "agent_results": {},
        "execution_status": "ingress_received",
    }

    async def event_generator():
        try:
            yield f"data: {json.dumps({'status': 'progress', 'phase': 'System ingress', 'message': 'Analyzing the selected local telemetry record.'})}\n\n"
            final_state = dict(initial_state)
            async for update in compiled_framework.astream(initial_state, stream_mode="updates"):
                for node_name, node_update in update.items():
                    final_state.update(node_update)
                    yield (
                        "data: "
                        + json.dumps(
                            {
                                "status": "streaming_update",
                                "agent": node_name,
                                "data": node_update,
                            },
                            default=str,
                        )
                        + "\n\n"
                    )
            yield (
                "data: "
                + json.dumps({"status": "completed", "final_report": final_state}, default=str)
                + "\n\n"
            )
        except Exception as error:
            yield f"data: {json.dumps({'status': 'error', 'detail': str(error)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
