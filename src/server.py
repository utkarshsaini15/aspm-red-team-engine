import json
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from sqlmodel import Session, select
from pydantic import BaseModel

from src.database import get_session, create_db_and_tables, engine
from src.models import ScanJob
from src.scanners import run_security_scan_generator
from src.report import generate_pdf_report
from src.config import llm_config, CONFIG_FILE_PATH
from src.llm_client import llm_client
from src.live_chart import websocket_manager, get_chart_data, get_all_metrics

# ── Lifespan ─────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(title="ASPM Red Team API v3", version="3.0.0", lifespan=lifespan)

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


class ScanRequest(BaseModel):
    target_model: str
    system_prompt: str = ""
    temperature: float = 0.5
    api_key: str = ""   # Provider key — leave empty for simulation mode


class HardeningRequest(BaseModel):
    system_prompt: str = ""
    temperature: float = 0.5
    api_key: str = ""   # forwarded to the background scan


class APIKeyRequest(BaseModel):
    provider: str  # openai, anthropic, google
    api_key: str


class ConfigUpdateRequest(BaseModel):
    providers: dict
    api_key: str = ""


async def process_scan_background(
    job_id: str, target_model: str, system_prompt: str,
    temperature: float, api_key: str = ""
):
    """
    Background task with its own Session scope — avoids DetachedInstanceError
    that would occur if we passed the request-scoped session here.
    """
    with Session(engine) as session:
        try:
            job = session.get(ScanJob, job_id)
            if not job:
                return
            job.status = "IN_PROGRESS"
            session.add(job)
            session.commit()

            async for log_line, is_final, results_json in run_security_scan_generator(
                target_model, system_prompt, temperature, api_key
            ):
                job = session.get(ScanJob, job_id)
                if not job:
                    return  # job was deleted mid-scan
                if log_line:
                    job.logs += log_line + "\n"
                if is_final:
                    job.status       = "COMPLETED"
                    job.results      = results_json
                    job.completed_at = datetime.now(timezone.utc)
                session.add(job)
                session.commit()

            print(f"[Server] Job {job_id} completed.")

        except Exception as e:
            import traceback
            traceback.print_exc()
            job = session.get(ScanJob, job_id)
            if job:
                job.status   = "FAILED"
                job.logs    += f"\n[CRITICAL ERROR] {str(e)}\n"
                job.results  = json.dumps({"error": str(e)})
                job.completed_at = datetime.now(timezone.utc)
                session.add(job)
                session.commit()


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "3.0.0", "engine": "ASPM Red Team Engine v3.0"}


@app.post("/scan/start")
def start_scan(req: ScanRequest, bg: BackgroundTasks):
    with Session(engine) as session:
        job = ScanJob(target_model=req.target_model, status="PENDING")
        session.add(job)
        session.commit()
        session.refresh(job)
        job_id = job.id
    bg.add_task(
        process_scan_background,
        job_id, req.target_model, req.system_prompt, req.temperature, req.api_key
    )
    return {"message": "Scan started", "job_id": job_id}


@app.post("/scan/harden-and-verify/{job_id}")
def harden_and_verify(job_id: str, req: HardeningRequest, bg: BackgroundTasks):
    """
    Autonomous Hardening Loop:
    Takes results of job_id, uses the auto-generated hardened_prompt,
    and starts a new verification scan automatically.
    """
    with Session(engine) as session:
        original = session.get(ScanJob, job_id)
        if not original or not original.results:
            raise HTTPException(404, "Original scan not found or incomplete")

        original_results = json.loads(original.results)
        hardened_prompt  = original_results.get("hardened_prompt", "")
        temperature      = original_results.get("temperature", 0.5)
        # Strip display suffix so raw model name is sent to LiteLLM
        target_model     = original.target_model.replace(" [HARDENED]", "").strip()
        safer_temp       = min(temperature, 0.5)

        new_job = ScanJob(target_model=f"{target_model} [HARDENED]", status="PENDING")
        session.add(new_job)
        session.commit()
        session.refresh(new_job)
        new_job_id = new_job.id

    bg.add_task(
        process_scan_background,
        new_job_id, target_model,   # ← clean model name, not the display label
        hardened_prompt, safer_temp, req.api_key
    )
    return {
        "message":         "Hardened verification scan started",
        "job_id":          new_job_id,
        "hardened_prompt": hardened_prompt,
        "temperature":     safer_temp,
    }


@app.get("/scan/stream/{job_id}")
async def stream_scan_logs(job_id: str):
    """
    Server-Sent Events (SSE) endpoint — streams log lines in real-time.
    Frontend subscribes with EventSource; no polling needed.
    Sends [DONE] when scan completes, [FAIL] on failure.
    """
    async def event_generator():
        last_pos = 0
        while True:
            with Session(engine) as session:
                job = session.get(ScanJob, job_id)
                if not job:
                    yield "data: [ERROR] Job not found\n\n"
                    return

                current_logs = job.logs or ""

                # Stream any new log lines since last check
                if len(current_logs) > last_pos:
                    new_content = current_logs[last_pos:]
                    for line in new_content.split("\n"):
                        stripped = line.rstrip()
                        if stripped:
                            yield f"data: {stripped}\n\n"
                    last_pos = len(current_logs)

                if job.status == "COMPLETED":
                    # Drain any remaining logs before signalling done
                    yield "data: [DONE]\n\n"
                    return
                elif job.status == "FAILED":
                    yield "data: [FAIL]\n\n"
                    return

            await asyncio.sleep(0.4)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "Connection":       "keep-alive",
            "X-Accel-Buffering": "no",   # disable nginx buffering when behind proxy
        },
    )


@app.get("/scan/status/{job_id}")
def get_scan_status(job_id: str):
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        return {
            "job_id":       job.id,
            "target_model": job.target_model,
            "status":       job.status,
            "logs":         job.logs,
            "results":      json.loads(job.results) if job.results else None,
            "created_at":   job.created_at.isoformat() if job.created_at   else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        }


@app.get("/scan/report/{job_id}")
def download_report(job_id: str):
    """Generate and serve a professional PDF security report."""
    with Session(engine) as session:
        job = session.get(ScanJob, job_id)
        if not job or not job.results:
            raise HTTPException(404, "Scan report not available — scan incomplete or not found")
        results = json.loads(job.results)

    try:
        from src.report import generate_pdf_report
        pdf_bytes = generate_pdf_report(results, job_id)
    except ImportError:
        raise HTTPException(500, "PDF generation unavailable — install fpdf2: pip install fpdf2")
    except Exception as e:
        raise HTTPException(500, f"PDF generation failed: {str(e)}")

    filename = f"aspm-report-{job_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/scans/history")
def get_scan_history():
    """Return all completed scans (latest first)."""
    with Session(engine) as session:
        stmt = select(ScanJob).where(ScanJob.status == "COMPLETED").order_by(ScanJob.completed_at.desc())
        jobs = session.exec(stmt).all()
        return [{"job_id":        job.id,
                 "target_model":  job.target_model,
                 "status":        job.status,
                 "completed_at":  job.completed_at.isoformat() if job.completed_at else None,
                 "results":       json.loads(job.results) if job.results else None}
                for job in jobs]

# ── API Key Management ───────────────────────────────────────────────────────
@app.get("/config/models")
def get_available_models():
    """Get list of available LLM models and their configuration status."""
    return {
        "available_models": llm_config.get_available_models(),
        "default_model": llm_config.default_provider,
        "providers": {
            model: {
                "configured": True,
                "rate_limit_rpm": config.rate_limit_rpm,
                "cost_per_1k_tokens": config.cost_per_1k_tokens
            }
            for model, config in llm_config.providers.items()
        }
    }

@app.post("/config/api-key")
def set_api_key(request: APIKeyRequest):
    """Set API key for a provider (runtime only, not persisted)."""
    try:
        # Map provider name to models
        provider_models = {
            "openai": ["gpt-4o", "gpt-4o-mini"],
            "anthropic": ["anthropic/claude-3-sonnet", "anthropic/claude-3-haiku"],
            "google": ["gemini/gemini-1.5-pro", "gemini/gemini-1.5-flash", "gemini/gemini-2.0-flash"]
        }
        
        models = provider_models.get(request.provider.lower())
        if not models:
            raise HTTPException(status_code=400, detail="Invalid provider")
        
        # Update configuration in memory
        for model in models:
            if model in llm_config.providers:
                llm_config.providers[model].api_key = request.api_key
        
        return {"message": f"API key set for {request.provider}", "models_updated": models}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/usage/stats")
def get_usage_stats():
    """Get current usage statistics and costs."""
    return llm_client.get_usage_stats()

@app.post("/config/save")
def save_configuration():
    """Save current configuration to file."""
    try:
        llm_config.save_to_file(CONFIG_FILE_PATH)
        return {"message": "Configuration saved successfully", "path": str(CONFIG_FILE_PATH)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/config/load")
def load_configuration():
    """Load configuration from file."""
    try:
        global llm_config
        llm_config = llm_config.__class__.load_from_file(CONFIG_FILE_PATH)
        return {"message": "Configuration loaded successfully", "path": str(CONFIG_FILE_PATH)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/scans/history")
def clear_history():
    with Session(engine) as session:
        for job in session.exec(select(ScanJob)).all():
            session.delete(job)
        session.commit()
    return {"message": "History cleared"}

# ---- Live Chart Endpoints ----

@app.websocket("/ws/live-chart")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live chart updates"""
    await websocket_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Echo back or process any client messages if needed
            await websocket_manager.send_personal_message(f"Received: {data}", websocket)
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

@app.get("/chart/data")
async def get_chart_data_endpoint(metric: str = "vulnerability_score", points: int = 20):
    """Get historical chart data for a specific metric"""
    return await get_chart_data(metric, points)

@app.get("/chart/metrics")
async def get_all_metrics_endpoint():
    """Get all current metrics"""
    return await get_all_metrics()

@app.get("/chart/status")
async def get_chart_status():
    """Get live chart connection status"""
    return {
        "active_connections": len(websocket_manager.active_connections),
        "is_broadcasting": websocket_manager.is_running,
        "current_phase": websocket_manager.simulator.scan_phase if websocket_manager.simulator else "idle"
    }
