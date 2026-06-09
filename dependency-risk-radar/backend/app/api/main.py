"""
api/main.py
FastAPI application with all routes: analysis, reports, SBOM, graph, export.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.pipeline import run_gradle_analysis, run_apk_analysis
from app.scoring.engine import compute_project_summary

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
settings = get_settings()

app = FastAPI(
    title="Dependency Risk Radar API",
    description="SBOM generation and dependency risk scoring for Android projects",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory report store (replace with DB in production)
_reports: dict[str, dict] = {}
_jobs: dict[str, dict] = {}        # job_id → {status, progress, report_id}
OUTPUT_BASE = Path(os.getenv("OUTPUT_DIR", "/tmp/drr_reports"))


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────

@app.get("/health")
@app.get("/api/v1/health")
def health():
    return {"status": "ok", "version": settings.APP_VERSION}


# ─────────────────────────────────────────────
# Analysis endpoints
# ─────────────────────────────────────────────

class GradleAnalysisRequest(BaseModel):
    project_path: str
    module: str = ":app"


@app.post("/api/v1/analyze/gradle")
async def analyze_gradle(request: GradleAnalysisRequest):
    """Start analysis of a Gradle project available on the server filesystem."""
    project_path = Path(request.project_path)
    if not project_path.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {project_path}")

    job_id = _create_job()
    asyncio.create_task(_run_gradle_job(job_id, project_path))
    return {"job_id": job_id, "status": "queued"}


@app.post("/api/v1/analyze/apk")
async def analyze_apk_upload(file: UploadFile = File(...)):
    """Upload and analyse an APK file."""
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="File must be an .apk")

    # Save uploaded file to temp location
    tmp_dir = Path(tempfile.mkdtemp())
    apk_path = tmp_dir / file.filename
    with open(apk_path, "wb") as f:
        content = await file.read()
        f.write(content)

    job_id = _create_job()
    asyncio.create_task(_run_apk_job(job_id, apk_path))
    return {"job_id": job_id, "status": "queued"}


# ─────────────────────────────────────────────
# Job status + WebSocket progress
# ─────────────────────────────────────────────

@app.get("/api/v1/jobs/{job_id}")
def get_job_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.websocket("/ws/analyze/{job_id}")
async def websocket_progress(websocket: WebSocket, job_id: str):
    """Stream analysis progress updates in real time."""
    await websocket.accept()
    try:
        last_pct = -1
        while True:
            job = _jobs.get(job_id)
            if not job:
                await websocket.send_json({"error": "Job not found"})
                break
            pct = job.get("progress", 0)
            if pct != last_pct:
                await websocket.send_json(job)
                last_pct = pct
            if job.get("status") in ("completed", "failed"):
                break
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass


# ─────────────────────────────────────────────
# Report endpoints
# ─────────────────────────────────────────────

@app.get("/api/v1/reports/{report_id}")
def get_report(report_id: str):
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {k: v for k, v in report.items() if not k.startswith("_")}


@app.get("/api/v1/reports/{report_id}/summary")
def get_report_summary(report_id: str):
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "report_id": report_id,
        "project_name": report["project_name"],
        "analyzed_at": report["analyzed_at"],
        "global_risk_score": report["global_risk_score"],
        "summary": report["summary"],
    }


@app.get("/api/v1/reports/{report_id}/components")
def get_components(
    report_id: str,
    min_score: float = 0,
    max_score: float = 100,
    is_direct: Optional[bool] = None,
    has_cve: Optional[bool] = None,
    sort_by: str = "global_score",
    order: str = "desc",
    limit: int = 100,
    offset: int = 0,
):
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    components = report["components"]

    # Filters
    if is_direct is not None:
        components = [c for c in components if c["is_direct"] == is_direct]
    if has_cve is not None:
        components = [c for c in components if bool(c["vulnerabilities"]) == has_cve]
    components = [
        c for c in components
        if min_score <= c["scores"]["global"] <= max_score
    ]

    # Sort
    reverse = order == "desc"
    if sort_by == "global_score":
        components.sort(key=lambda c: c["scores"]["global"], reverse=reverse)
    elif sort_by == "name":
        components.sort(key=lambda c: c["name"], reverse=reverse)
    elif sort_by == "depth":
        components.sort(key=lambda c: c["depth"], reverse=reverse)

    total = len(components)
    page = components[offset: offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "items": page}


@app.get("/api/v1/reports/{report_id}/update-plan")
def get_update_plan(report_id: str):
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.get("update_plan", {})


@app.get("/api/v1/reports/{report_id}/graph")
def get_graph(report_id: str):
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.get("graph", {"nodes": [], "edges": []})


@app.get("/api/v1/reports/{report_id}/graph/ego/{purl:path}")
def get_ego_graph(report_id: str, purl: str, radius: int = 2):
    """Return neighbourhood subgraph around a single component."""
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    graph_obj = report.get("_graph_obj")
    if not graph_obj:
        raise HTTPException(status_code=404, detail="Graph not available")
    return graph_obj.ego_graph(purl, radius=radius)


# ─────────────────────────────────────────────
# SBOM download
# ─────────────────────────────────────────────

@app.get("/api/v1/reports/{report_id}/sbom")
def download_sbom(report_id: str, format: str = "cyclonedx"):
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    output_dir = OUTPUT_BASE / report_id
    if format == "cyclonedx":
        path = output_dir / "sbom_cyclonedx.json"
        media_type = "application/json"
    elif format == "spdx":
        path = output_dir / "sbom_spdx.json"
        media_type = "application/json"
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'cyclonedx' or 'spdx'")

    if not path.exists():
        raise HTTPException(status_code=404, detail="SBOM file not found")
    return FileResponse(str(path), media_type=media_type, filename=path.name)


# ─────────────────────────────────────────────
# List reports
# ─────────────────────────────────────────────

@app.get("/api/v1/reports")
def list_reports(limit: int = 20):
    all_reports = sorted(
        _reports.values(),
        key=lambda r: r.get("analyzed_at", ""),
        reverse=True,
    )[:limit]
    return [
        {
            "report_id": r["report_id"],
            "project_name": r.get("project_name", "unknown"),
            "analyzed_at": r.get("analyzed_at", ""),
            "global_risk_score": r.get("global_risk_score", 0),
            "total_components": r.get("summary", {}).get("total_components", 0),
        }
        for r in all_reports
    ]


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _create_job() -> str:
    import uuid
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"job_id": job_id, "status": "queued", "progress": 0, "message": "Queued"}
    return job_id


def _update_job(job_id: str, message: str, progress: int):
    if job_id in _jobs:
        _jobs[job_id].update({"message": message, "progress": progress, "status": "running"})


async def _run_gradle_job(job_id: str, project_path: Path):
    try:
        def progress(msg, pct):
            _update_job(job_id, msg, pct)

        report = await run_gradle_analysis(project_path, OUTPUT_BASE, progress)
        _store_report(report, job_id)
    except Exception as e:
        logger.exception("Gradle analysis job %s failed", job_id)
        _jobs[job_id].update({"status": "failed", "error": str(e)})


async def _run_apk_job(job_id: str, apk_path: Path):
    try:
        def progress(msg, pct):
            _update_job(job_id, msg, pct)

        report = await run_apk_analysis(apk_path, OUTPUT_BASE, progress)
        _store_report(report, job_id)
    except Exception as e:
        logger.exception("APK analysis job %s failed", job_id)
        _jobs[job_id].update({"status": "failed", "error": str(e)})


def _store_report(report, job_id: str):
    from app.graph.dependency_graph import DependencyGraph
    from app.scoring.engine import compute_project_summary

    graph = DependencyGraph()
    graph.build(report.components)

    serialized_components = [c.to_dict() for c in report.components]

    report_dict = {
        "report_id": report.report_id,
        "project_name": report.project_name,
        "project_version": report.project_version,
        "analyzed_at": report.analyzed_at,
        "global_risk_score": report.global_risk_score,
        "summary": compute_project_summary(report.components),
        "components": serialized_components,
        "update_plan": report.update_plan,
        "graph": graph.to_json(),
        "_graph_obj": graph,   # not serialized — used for ego_graph endpoint
    }

    _reports[report.report_id] = report_dict
    _jobs[job_id].update({
        "status": "completed",
        "progress": 100,
        "report_id": report.report_id,
    })
