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

CAMERA_STREAMS = [
    {
        "id": "CAM-01-ENTRANCE",
        "name": "Main Entrance Gate",
        "zone": "Perimeter Sector Alpha",
        "protocol": "RTSP (Simulated)",
        "status": "ONLINE",
        "latency_ms": 14,
        "last_ping": datetime.utcnow().isoformat() + "Z",
        "resolution": "1080p",
        "fps": 15,
        "simulated": True
    },
    {
        "id": "CAM-02-LOBBY",
        "name": "Executive Lobby West",
        "zone": "Interior Reception",
        "protocol": "RTSP (Simulated)",
        "status": "ONLINE",
        "latency_ms": 18,
        "last_ping": datetime.utcnow().isoformat() + "Z",
        "resolution": "1080p",
        "fps": 15,
        "simulated": True
    },
    {
        "id": "CAM-03-BACKDOOR",
        "name": "Back Door / Fire Exit",
        "zone": "Emergency Egress South",
        "protocol": "RTSP (Simulated)",
        "status": "ONLINE",
        "latency_ms": 22,
        "last_ping": datetime.utcnow().isoformat() + "Z",
        "resolution": "1080p",
        "fps": 15,
        "simulated": True
    },
    {
        "id": "CAM-04-DOCK",
        "name": "Loading Dock Perimeter",
        "zone": "Cargo Bay North",
        "protocol": "RTSP (Simulated)",
        "status": "ONLINE",
        "latency_ms": 16,
        "last_ping": datetime.utcnow().isoformat() + "Z",
        "resolution": "1080p",
        "fps": 15,
        "simulated": True
    },
    {
        "id": "BROWSER-LOCAL-SCANNER",
        "name": "Local Browser Scanner",
        "zone": "Operator Workstation",
        "protocol": "MediaDevices / WebRTC",
        "status": "ONLINE",
        "latency_ms": 4,
        "last_ping": datetime.utcnow().isoformat() + "Z",
        "resolution": "Dynamic",
        "fps": 12,
        "simulated": False
    }
]

@router.get("/api/v1/system")
async def get_system_info(tenant_id: str = Depends(get_tenant_id)):
    uptime_seconds = int((datetime.utcnow() - START_TIME).total_seconds())
    online_count = sum(1 for s in CAMERA_STREAMS if s["status"] == "ONLINE")
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
            "cctv_streams_active": sum(1 for s in CAMERA_STREAMS if s["status"] == "ONLINE" and s["simulated"]),
            "simulated_streams": ["CAM-01-ENTRANCE", "CAM-02-LOBBY"],
            "streams_total": len(CAMERA_STREAMS),
            "streams_online": online_count,
            "health_percentage": int((online_count / len(CAMERA_STREAMS)) * 100)
        },
        "brain_subsystem": {
            "mode": "CONTROLLED_COMMAND_INTERFACE",
            "status": "OPERATIONAL",
            "allowlist_count": len(ALLOWLISTED_COMMANDS)
        }
    }

@router.get("/api/v1/system/cameras")
async def get_camera_streams(tenant_id: str = Depends(get_tenant_id)):
    online_count = sum(1 for s in CAMERA_STREAMS if s["status"] == "ONLINE")
    disconnected_count = len(CAMERA_STREAMS) - online_count
    health_percentage = int((online_count / len(CAMERA_STREAMS)) * 100)
    return {
        "total_streams": len(CAMERA_STREAMS),
        "online_streams": online_count,
        "disconnected_streams": disconnected_count,
        "health_percentage": health_percentage,
        "status": "HEALTHY" if disconnected_count == 0 else "DEGRADED",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "streams": CAMERA_STREAMS
    }

@router.post("/api/v1/system/cameras/{stream_id}/ping")
async def ping_camera_stream(stream_id: str, tenant_id: str = Depends(get_tenant_id)):
    stream = next((s for s in CAMERA_STREAMS if s["id"] == stream_id), None)
    if not stream:
        return {"error": "STREAM_NOT_FOUND", "message": f"Stream source '{stream_id}' not found."}
    stream["last_ping"] = datetime.utcnow().isoformat() + "Z"
    return {
        "stream_id": stream["id"],
        "name": stream["name"],
        "status": stream["status"],
        "latency_ms": stream["latency_ms"] if stream["status"] == "ONLINE" else None,
        "ping_success": stream["status"] == "ONLINE",
        "last_ping": stream["last_ping"]
    }

@router.post("/api/v1/system/cameras/{stream_id}/toggle")
async def toggle_camera_stream(stream_id: str, tenant_id: str = Depends(get_tenant_id)):
    stream = next((s for s in CAMERA_STREAMS if s["id"] == stream_id), None)
    if not stream:
        return {"error": "STREAM_NOT_FOUND", "message": f"Stream source '{stream_id}' not found."}
    old_status = stream["status"]
    stream["status"] = "DISCONNECTED" if old_status == "ONLINE" else "ONLINE"
    stream["last_ping"] = datetime.utcnow().isoformat() + "Z"
    stream["latency_ms"] = 16 if stream["status"] == "ONLINE" else None
    return {
        "stream_id": stream["id"],
        "name": stream["name"],
        "previous_status": old_status,
        "new_status": stream["status"],
        "latency_ms": stream["latency_ms"],
        "timestamp": stream["last_ping"]
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
