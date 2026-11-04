"""System & Health Router for VantaVisionAI Funding Prototype"""
from fastapi import APIRouter, Depends
from datetime import datetime
import platform
import os

from backend.app.database import get_connection
from backend.app.routers.brain import get_tenant_id
from backend.app.core_brain import ALLOWLISTED_COMMANDS

router = APIRouter(tags=["system"])

START_TIME = datetime.utcnow()

@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "app": "VantaVisionAI Funding Prototype",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@router.get("/ready")
async def readiness_check():
    db_ok = False
    try:
        conn = get_connection()
        conn.cursor().execute("SELECT 1")
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "ready": db_ok,
        "database": "connected" if db_ok else "unavailable",
        "provider": "SIMULATED",
        "real_camera_configured": False,
        "browser_scanner": "TensorFlow.js COCO-SSD MobileNet V2",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@router.get("/api/v1/system")
async def get_system_info(tenant_id: str = Depends(get_tenant_id)):
    uptime_seconds = int((datetime.utcnow() - START_TIME).total_seconds())
    return {
        "app_name": "VantaVisionAI Funding Prototype",
        "version": "1.0.0",
        "tenant_id": tenant_id,
        "uptime_seconds": uptime_seconds,
        "environment": os.environ.get("ENVIRONMENT", "prototype"),
        "platform": {
            "system": platform.system(),
            "python": platform.python_version()
        },
        "camera_subsystem": {
            "provider": "SIMULATED",
            "real_camera_configured": False,
            "browser_detector": "TensorFlow.js COCO-SSD MobileNet V2",
            "cctv_streams_active": 0,
            "simulated_streams": ["CAM-01-ENTRANCE", "CAM-02-LOBBY"]
        },
        "brain_subsystem": {
            "mode": "CONTROLLED_COMMAND_INTERFACE",
            "status": "OPERATIONAL",
            "allowlist_count": len(ALLOWLISTED_COMMANDS)
        }
    }

@router.get("/api/v1/summary")
async def get_summary(tenant_id: str = Depends(get_tenant_id)):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) as cnt FROM events WHERE tenant_id = ?", (tenant_id,))
        total_events = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ?", (tenant_id,))
        total_incidents = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
        open_incidents = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM policies WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
        active_policies = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM audit_logs WHERE tenant_id = ?", (tenant_id,))
        total_audits = cursor.fetchone()["cnt"]

        return {
            "tenant_id": tenant_id,
            "total_events": total_events,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "active_policies": active_policies,
            "total_audit_logs": total_audits,
            "provider": "SIMULATED",
            "real_camera_configured": False,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    finally:
        conn.close()
