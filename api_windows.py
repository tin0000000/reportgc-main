"""
ReportGC - FastAPI REST API (Windows-compatible version)
This version skips PDF generation which requires system libraries on Windows
"""

import asyncio
import json
import logging
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

import ijson
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from engine import SecurityExplainPlan, Finding, RiskLevel
from pptx_generator import PPTXGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5MB threshold
TEMP_FILE_LIFETIME = 30  # Seconds

# ==========================================
# Pydantic Models
# ==========================================

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    service: str = "ReportGC API"


class ValidationResponse(BaseModel):
    valid: bool
    format_detected: Optional[str] = None
    error: Optional[str] = None


class ReportResponse(BaseModel):
    report_id: str
    grade: str
    total_findings: int
    critical_count: int  
    high_count: int
    medium_count: int
    low_count: int
    total_effort_hours: int
    cisa_kev_count: int
    generated_at: str
    pptx_url: Optional[str] = None
    message: str = "Use /docs for interactive API documentation"


# ==========================================
# Dependency Injection
# ==========================================

_pipeline_instance = None

def get_pipeline():
    """Get or create pipeline instance."""
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = SimplePipeline()
    return _pipeline_instance


# ==========================================
# Simplified Pipeline (Engine + PPTX only)
# ==========================================

class SimplePipeline:
    """Simplified pipeline without PDF generation."""
    
    def __init__(self):
        self.pptx_gen = PPTXGenerator()
        self.output_dir = Path(tempfile.gettempdir()) / "reportgc"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def validate_scan_data(self, scan_data: Dict[str, Any]) -> bool:
        """Validate scanner output format."""
        if not isinstance(scan_data, dict):
            return False
        return "Results" in scan_data or "runs" in scan_data
    
    def process_scan(
        self, 
        scan_data: Dict[str, Any],
        report_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Process scan through engine and generate PPTX."""
        # Run through engine
        engine = SecurityExplainPlan(scan_data)
        data = engine.to_dict()
        
        if report_id:
            data['report_id'] = report_id
        
        report_id = data['report_id']
        
        # Generate PPTX
        pptx_path = self.output_dir / f"ReportGC-{report_id}.pptx"
        self.pptx_gen.generate_pptx(data, str(pptx_path))
        
        return {
            'pptx': pptx_path,
            'report_id': report_id,
            'data': data
        }


# ==========================================
# Background Tasks
# ==========================================

async def _cleanup_files(*paths: Path, delay_seconds: int = TEMP_FILE_LIFETIME):
    """Background task to clean up files after delay."""
    await asyncio.sleep(delay_seconds)
    for path in paths:
        try:
            if Path(path).exists():
                Path(path).unlink()
                logger.info(f"Cleaned up: {path}")
        except Exception as e:
            logger.error(f"Failed to cleanup {path}: {e}")


# ==========================================
# FastAPI App Lifespan
# ==========================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    logger.info("🚀 ReportGC API starting...")
    pipeline = get_pipeline()
    
    # Verify pipeline on startup
    try:
        test_data = {"Results": [{"Vulnerabilities": []}]}
        await asyncio.to_thread(pipeline.validate_scan_data, test_data)
        logger.info("✅ Pipeline verified and ready")
    except Exception as e:
        logger.error(f"❌ Pipeline initialization failed: {e}")
        raise
    
    yield
    
    # Shutdown cleanup
    logger.info("🛑 ReportGC API shutting down...")


# ==========================================
# FastAPI Application
# ==========================================

app = FastAPI(
    title="ReportGC API",
    description="🔒 Security reporting pipeline - transforms vulnerability scans into executive intelligence",
    version="1.0.0-windows",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["localhost", "127.0.0.1"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# Request Size Limit Middleware
# ==========================================

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Block requests larger than MAX_FILE_SIZE."""
    body = await request.body()
    if len(body) > MAX_FILE_SIZE:
        return JSONResponse(
            status_code=413,
            content={"detail": f"Request body too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)"}
        )
    return await call_next(request)


# ==========================================
# API Endpoints
# ==========================================

@app.get("/", tags=["System"])
async def root():
    """Welcome message."""
    return {
        "message": "ReportGC - Security Reporting Pipeline API",
        "version": "1.0.0",
        "docs": "Visit /docs for interactive documentation",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check for monitoring."""
    return HealthResponse(status="healthy", version="1.0.0-windows")


@app.post("/api/validate", response_model=ValidationResponse, tags=["Validation"])
async def validate_scan(
    scan_data: Dict[str, Any],
    pipeline = Depends(get_pipeline)
):
    """
    Validate scan data format without processing.
    
    Accepts:
    - Trivy format: Has 'Results' key
    - SARIF format: Has 'runs' key
    """
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    
    if not is_valid:
        return ValidationResponse(
            valid=False,
            error="Invalid format. Expected Trivy (Results key) or SARIF (runs key) format."
        )
    
    format_type = "sarif" if "runs" in scan_data else "trivy"
    return ValidationResponse(valid=True, format_detected=format_type)


@app.post("/api/report", tags=["Reports"])
async def generate_report(
    background_tasks: BackgroundTasks,
    scan_data: Dict[str, Any],
    report_id: Optional[str] = Query(None),
    pipeline = Depends(get_pipeline)
):
    """
    Generate security report and return PPTX presentation.
    
    **Request Body:**
    - Trivy format scan data with 'Results' key
    - SARIF format scan data with 'runs' key
    
    **Response:**
    - PowerPoint presentation (.pptx file) with executive summary
    - Includes grade, risk breakdown, effort estimates
    """
    # Validate scan data
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
        # Generate in thread pool
        result = await asyncio.to_thread(
            pipeline.process_scan,
            scan_data,
            report_id
        )
        
        pptx_path = result['pptx']
        report_id = result['report_id']
        
        # Schedule cleanup
        background_tasks.add_task(
            _cleanup_files,
            pptx_path,
            delay_seconds=TEMP_FILE_LIFETIME
        )
        
        return FileResponse(
            path=str(pptx_path),
            media_type='application/vnd.openxmlformats-officedocument.presentationml.presentation',
            filename=f"ReportGC-{report_id}.pptx"
        )
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/report/metadata", response_model=ReportResponse, tags=["Reports"])
async def generate_report_metadata(
    scan_data: Dict[str, Any],
    report_id: Optional[str] = Query(None),
    pipeline = Depends(get_pipeline)
):
    """
    Generate security report and return metadata only.
    
    Returns JSON with:
    - Grade and risk classification
    - Finding counts by severity
    - Total remediation effort in hours
    - Report ID and timestamp
    
    Does NOT return file, use /api/report for PPTX generation.
    """
    # Validate
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
        # Generate in thread pool
        result = await asyncio.to_thread(
            pipeline.process_scan,
            scan_data,
            report_id
        )
        
        data = result['data']
        
        return ReportResponse(
            report_id=result['report_id'],
            grade=data['grade'],
            total_findings=data['summary']['total_findings'],
            critical_count=data['summary']['critical'],
            high_count=data['summary']['high'],
            medium_count=data['summary']['medium'],
            low_count=data['summary']['low'],
            total_effort_hours=data.get('total_effort_hours', 0),
            cisa_kev_count=data['summary']['cisa_kev_count'],
            generated_at=data['generated_at']
        )
        
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload", tags=["Upload"])
async def upload_scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    report_id: Optional[str] = Query(None),
    pipeline = Depends(get_pipeline)
):
    """
    Upload Trivy/SARIF JSON file and generate report.
    
    **Supports:**
    - Large files up to 50MB
    - Streaming uploads for memory efficiency
    
    **Response:**
    - PowerPoint presentation with executive summary
    """
    if not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Only .json files accepted")
    
    tmp_path: Optional[Path] = None
    
    try:
        # Stream to temp file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.json') as tmp:
            total_size = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            
            while chunk := await file.read(chunk_size):
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=413, detail="File too large (max 50MB)")
                tmp.write(chunk)
            
            tmp_path = Path(tmp.name)
        
        logger.info(f"Received upload: {file.filename} ({total_size} bytes)")
        
        # Parse JSON
        with open(tmp_path, 'r') as f:
            scan_data = json.load(f)
        
        # Validate
        is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Invalid scan file format")
        
        # Generate
        result = await asyncio.to_thread(
            pipeline.process_scan,
            scan_data,
            report_id
        )
        
        # Schedule cleanup
        if tmp_path:
            background_tasks.add_task(_cleanup_files, tmp_path, delay_seconds=5)
        background_tasks.add_task(
            _cleanup_files,
            result['pptx'],
            delay_seconds=TEMP_FILE_LIFETIME
        )
        
        return FileResponse(
            path=str(result['pptx']),
            media_type='application/vnd.openxmlformats-officedocument.presentationml.presentation',
            filename=f"ReportGC-{result['report_id']}.pptx"
        )
        
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        logger.error(f"Upload processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup temp file
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except:
                pass


# ==========================================
# Main Entry Point
# ==========================================

if __name__ == "__main__":
    import uvicorn
    
    logger.info("=" * 70)
    logger.info("Starting ReportGC API Server")
    logger.info("=" * 70)
    logger.info("📡 Server: http://127.0.0.1:8000")
    logger.info("📚 Docs:   http://127.0.0.1:8000/docs")
    logger.info("=" * 70)
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
