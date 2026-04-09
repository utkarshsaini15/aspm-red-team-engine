import json
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select
from pydantic import BaseModel
import asyncio

from src.database import create_db_and_tables, get_session
from src.models import ScanJob
from src.scanners import run_security_scan_generator

app = FastAPI(title="ASPM Red Team API v3", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

class ScanRequest(BaseModel):
    target_model: str
    system_prompt: str = ""
    temperature: float = 0.5

async def process_scan_background(
    job_id: str, target_model: str, system_prompt: str,
    temperature: float, session: Session
):
    try:
        job = session.get(ScanJob, job_id)
        if not job: return
        job.status = "IN_PROGRESS"
        session.add(job); session.commit()

        async for log_line, is_final, results_json in run_security_scan_generator(
            target_model, system_prompt, temperature
        ):
            job = session.get(ScanJob, job_id)
            if log_line:
                job.logs += log_line + "\n"
            if is_final:
                job.status       = "COMPLETED"
                job.results      = results_json
                job.completed_at = datetime.utcnow()
            session.add(job); session.commit()

        print(f"[Server] Job {job_id} completed.")

    except Exception as e:
        import traceback; traceback.print_exc()
        job = session.get(ScanJob, job_id)
        if job:
            job.status   = "FAILED"
            job.logs    += f"\n[CRITICAL ERROR] {str(e)}\n"
            job.results  = json.dumps({"error": str(e)})
            session.add(job); session.commit()

# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "3.0.0", "engine": "ASPM Red Team Engine v3.0"}

@app.post("/scan/start")
def start_scan(
    req: ScanRequest,
    bg: BackgroundTasks,
    session: Session = Depends(get_session)
):
    job = ScanJob(target_model=req.target_model, status="PENDING")
    session.add(job); session.commit(); session.refresh(job)
    bg.add_task(
        process_scan_background,
        job.id, req.target_model, req.system_prompt, req.temperature, session
    )
    return {"message": "Scan started", "job_id": job.id}

@app.post("/scan/harden-and-verify/{job_id}")
def harden_and_verify(
    job_id: str,
    bg: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """
    Autonomous Hardening Loop:
    Takes results of job_id, uses the auto-generated hardened_prompt,
    and starts a new verification scan automatically.
    """
    original = session.get(ScanJob, job_id)
    if not original or not original.results:
        raise HTTPException(404, "Original scan not found or incomplete")

    original_results = json.loads(original.results)
    hardened_prompt  = original_results.get("hardened_prompt", "")
    temperature      = original_results.get("temperature", 0.5)
    target_model     = original.target_model

    # Reduce temperature for the hardened scan
    safer_temp = min(temperature, 0.5)

    new_job = ScanJob(
        target_model=f"{target_model} [HARDENED]",
        status="PENDING"
    )
    session.add(new_job); session.commit(); session.refresh(new_job)

    bg.add_task(
        process_scan_background,
        new_job.id, new_job.target_model,
        hardened_prompt, safer_temp, session
    )
    return {
        "message":         "Hardened verification scan started",
        "job_id":          new_job.id,
        "hardened_prompt": hardened_prompt,
        "temperature":     safer_temp,
    }

@app.get("/scan/status/{job_id}")
def get_scan_status(job_id: str, session: Session = Depends(get_session)):
    job = session.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "job_id":       job.id,
        "target_model": job.target_model,
        "status":       job.status,
        "logs":         job.logs,
        "results":      json.loads(job.results) if job.results else None,
        "created_at":   job.created_at.isoformat() if job.created_at  else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }

@app.get("/scans/history")
def get_history(session: Session = Depends(get_session)):
    stmt = select(ScanJob).where(ScanJob.status == "COMPLETED").order_by(ScanJob.completed_at.desc())
    jobs = session.exec(stmt).all()
    history = []
    for job in jobs:
        if job.results:
            history.append({
                "job_id":       job.id,
                "target_model": job.target_model,
                "completed_at": job.completed_at.isoformat(),
                "results":      json.loads(job.results),
            })
    return history

@app.delete("/scans/history")
def clear_history(session: Session = Depends(get_session)):
    for job in session.exec(select(ScanJob)).all():
        session.delete(job)
    session.commit()
    return {"message": "History cleared"}
