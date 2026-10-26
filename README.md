# Adaptive Multi-Agent AI Framework

This project is a local, defensive dashboard for analyzing authorized traffic and
system-log data. It includes five coordinated agents:

1. **Detection** — scores numeric network telemetry with an Isolation Forest.
2. **Alert validation** — checks telemetry quality before escalation.
3. **Root-cause analysis** — correlates an alert timestamp with the prepared local lineage data.
4. **Response recommendations** — creates a playbook for analyst review; it never executes actions.
5. **Incident reporting** — summarizes the analysis and agent results.

## Requirements

- Windows 10/11 or another supported Python platform
- Python 3.13
- The authorized input datasets described in
  [`backend/data/raw/README.md`](backend/data/raw/README.md)

Raw CSV and ZIP datasets are excluded from source control because of their size
and unverified redistribution terms. Obtain them from an authorized source and
record the appropriate citations and license information in your submission.
The trained detector and prepared RCA lineage are included under
`backend/data/processed/`.

## Run locally on Windows

From the project root in PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
```

Start the API in one PowerShell terminal from the project root:

```powershell
uvicorn app:app --app-dir backend --host 127.0.0.1 --port 8000
```

Start the dashboard in a second terminal:

```powershell
streamlit run frontend\app.py --server.address 127.0.0.1
```

Open `http://127.0.0.1:8501`. The API documentation is available at
`http://127.0.0.1:8000/docs`. Both services bind to localhost by default.

## Train the detector

Use **Train / refresh detector** in the dashboard. Training scans the entire `backend\data\raw\label_traffic.csv` file in configurable chunks and keeps a deterministic, uniform reservoir sample (250,000 rows by default). This avoids loading the full multi-gigabyte dataset into memory. Training progress is available from the dashboard and `/api/v1/model/status`.

The model bundle and training metadata are written to `backend\data\processed\anomaly_bundle.pkl` and `backend\data\processed\anomaly_training.json`. The existing model artifacts are retained as a compatibility fallback.

## Run tests

From the project root in PowerShell:

```powershell
Set-Location backend
python -m unittest discover -s tests -v
Set-Location ..
```

Tests use temporary fixtures; they do not retrain the full model or modify the
supplied datasets.

## Submission checklist

- Include the source, pinned direct dependencies, tests, trained detector, and
  prepared RCA lineage.
- Do not submit `.venv`, `.env`, or the raw multi-gigabyte data files by default.
- Confirm the dataset license permits the use and distribution required by the
  submission; add dataset citations and attribution where required.
- Run the test command above and verify the dashboard and `/api/v1/health`
  locally before packaging.

## Safety and scope

Analysis is local and dataset-based; it does not connect to monitored hosts or send traffic. The response agent produces recommendations only. No containment action or verification command is executed automatically; an authorized analyst must review any suggested action.
