"""
ReportGC API - Simplified Launcher for Local Testing
This version removes ijson dependency for easier setup
"""

import asyncio
import json
import logging
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from engine import SecurityExplainPlan
from pptx_generator import PPTXGenerator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
MAX_FILE_SIZE = 50 * 1024 * 1024
TEMP_FILE_LIFETIME = 30

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


# ==========================================
# Simplified Pipeline
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
# Dependency Injection
# ==========================================

_pipeline_instance = None

def get_pipeline():
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = SimplePipeline()
    return _pipeline_instance


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
    
    try:
        test_data = {"Results": [{"Vulnerabilities": []}]}
        await asyncio.to_thread(pipeline.validate_scan_data, test_data)
        logger.info("✅ Pipeline verified and ready")
    except Exception as e:
        logger.error(f"❌ Pipeline initialization failed: {e}")
        raise
    
    yield
    
    logger.info("🛑 ReportGC API shutting down...")


# ==========================================
# FastAPI Application
# ==========================================

app = FastAPI(
    title="ReportGC API",
    description="🔒 Security reporting pipeline - transforms vulnerability scans into executive intelligence",
    version="1.0.1-local",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# API Endpoints
# ==========================================

@app.get("/", tags=["System"])
async def root():
    """Welcome message with links to API docs."""
    return {
        "message": "🔒 ReportGC - Security Reporting Pipeline API",
        "version": "1.0.1-local",
        "docs": "Visit http://127.0.0.1:8000/docs for interactive documentation",
        "health": "http://127.0.0.1:8000/health",
        "examples": {
            "validate": "POST /api/validate",
            "report": "POST /api/report",
            "metadata": "POST /api/report/metadata"
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check for monitoring."""
    return HealthResponse(status="healthy", version="1.0.1-local")


@app.post("/api/validate", response_model=ValidationResponse, tags=["Validation"])
async def validate_scan(
    scan_data: Dict[str, Any],
    pipeline = Depends(get_pipeline)
):
    """
    Validate scan data format without processing.
    
    **Accepts:**
    - Trivy format: Has 'Results' key
    - SARIF format: Has 'runs' key
    
    **Example Request:**
    ```json
    {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "Title": "Test Vulnerability",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                        "Severity": "CRITICAL"
                    }
                ]
            }
        ]
    }
    ```
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
    Generate security report PowerPoint presentation.
    
    Returns a .pptx file with:
    - Executive summary slide
    - Risk matrix visualization
    - Critical findings detail
    - Remediation roadmap
    - Grade assessment (A-F)
    
    **Response:** PowerPoint file (.pptx)
    """
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
        result = await asyncio.to_thread(
            pipeline.process_scan,
            scan_data,
            report_id
        )
        
        pptx_path = result['pptx']
        
        # Schedule cleanup
        background_tasks.add_task(
            _cleanup_files,
            pptx_path,
            delay_seconds=TEMP_FILE_LIFETIME
        )
        
        return FileResponse(
            path=str(pptx_path),
            media_type='application/vnd.openxmlformats-officedocument.presentationml.presentation',
            filename=f"ReportGC-{result['report_id']}.pptx"
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
    Generate report and return metadata as JSON (no file download).
    
    **Response:** JSON object with:
    - Grade (A-F)
    - Finding counts by severity
    - Total remediation effort in hours
    - CISA KEV count
    - Report ID and timestamp
    
    Use this for integrations or to preview results before downloading PPTX.
    """
    is_valid = await asyncio.to_thread(pipeline.validate_scan_data, scan_data)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid scan data format")
    
    try:
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


# ==========================================
# Main Entry Point
# ==========================================

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*80)
    print("🚀 ReportGC API Server - Local Testing")
    print("="*80)
    print("\n📡 Server Starting...")
    print("   URL:  http://127.0.0.1:8000")
    print("   Docs: http://127.0.0.1:8000/docs")
    print("   ReDoc: http://127.0.0.1:8000/redoc")
    print("\n📝 Available Endpoints:")
    print("   GET  /              - Welcome message")
    print("   GET  /health        - Health check")
    print("   POST /api/validate  - Validate scan format")
    print("   POST /api/report    - Generate PPTX report")
    print("   POST /api/report/metadata - Get JSON metadata")
    print("\n" + "="*80 + "\n")
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info"
    )
