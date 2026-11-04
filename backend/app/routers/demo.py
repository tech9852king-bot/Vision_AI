"""Demo Runner Router for VantaVisionAI Funding Prototype"""
from fastapi import APIRouter, Depends
import uuid
from datetime import datetime

from backend.app.schemas import DemoRunRequest
from backend.app.database import get_connection, log_audit
from backend.app.routers.brain import get_tenant_id

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])

@router.post("/run")
async def run_demo(
    body: DemoRunRequest,
    tenant_id: str = Depends(get_tenant_id)
):
    timestamp = datetime.utcnow().isoformat() + "Z"
    cam_id = body.camera_id or "DEMO-CAM-01"

    # Simulate a realistic intrusion scenario:
    # 1. Person detected near perimeter
    # 2. Suspicious backpack dropped
    conn = get_connection()
    cursor = conn.cursor()
    try:
        ev1_id = f"ev_demo_{uuid.uuid4().hex[:6]}"
        cursor.execute(
            "INSERT INTO events (id, tenant_id, timestamp, camera_id, class_name, confidence, bbox, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ev1_id, tenant_id, timestamp, cam_id, "person", 0.94, "[120, 180, 450, 320]", "{\"simulated\": true, \"scenario\": \"intrusion\"}")
        )

        ev2_id = f"ev_demo_{uuid.uuid4().hex[:6]}"
        cursor.execute(
            "INSERT INTO events (id, tenant_id, timestamp, camera_id, class_name, confidence, bbox, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ev2_id, tenant_id, timestamp, cam_id, "backpack", 0.88, "[380, 260, 440, 310]", "{\"simulated\": true, \"scenario\": \"unattended_item\"}")
        )

        # Trigger automatic incident creation based on pol_person_after_hours and pol_unattended_bag
        inc_id = f"inc_demo_{uuid.uuid4().hex[:6]}"
        cursor.execute(
            "INSERT INTO incidents (id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                inc_id,
                tenant_id,
                timestamp,
                "Demo Security Alert: After-Hours Intrusion with Unattended Baggage",
                "HIGH",
                "OPEN",
                "pol_person_after_hours",
                cam_id,
                f"Demonstration triggered on {cam_id}: Detected person (94%) and unattended backpack (88%). Automated incident created."
            )
        )

        conn.commit()

        log_audit(tenant_id, "DEMO_SIMULATION_RUN", "demo_operator", "SUCCESS", f"Generated events {ev1_id}, {ev2_id} and incident {inc_id}")

        return {
            "status": "SUCCESS",
            "scenario": body.scenario,
            "generated_events": [ev1_id, ev2_id],
            "generated_incident": inc_id,
            "camera_id": cam_id,
            "timestamp": timestamp,
            "note": "Demo scenario populated events and triggered policy incident for verification."
        }
    finally:
        conn.close()
