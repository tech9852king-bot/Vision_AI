"""Incidents Router for VantaVisionAI Funding Prototype"""
from fastapi import APIRouter, HTTPException, Depends, Header
from typing import List, Optional
from datetime import datetime

from backend.app.schemas import IncidentResponse
from backend.app.database import get_connection, log_audit
from backend.app.routers.brain import get_tenant_id

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    status: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, details FROM incidents WHERE tenant_id = ?"
        params = [tenant_id]
        if status:
            query += " AND status = ?"
            params.append(status.upper())
        query += " ORDER BY timestamp DESC"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [
            IncidentResponse(
                id=r["id"],
                tenant_id=r["tenant_id"],
                timestamp=r["timestamp"],
                title=r["title"],
                severity=r["severity"],
                status=r["status"],
                policy_id=r["policy_id"],
                camera_id=r["camera_id"],
                details=r["details"]
            )
            for r in rows
        ]
    finally:
        conn.close()

@router.post("/{incident_id}/resolve")
async def resolve_incident(
    incident_id: str,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, status FROM incidents WHERE id = ? AND tenant_id = ?", (incident_id, tenant_id))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found or unauthorized")

        cursor.execute(
            "UPDATE incidents SET status = 'RESOLVED' WHERE id = ? AND tenant_id = ?",
            (incident_id, tenant_id)
        )
        conn.commit()

        actor = "authenticated_user" if authorization else "security_operator"
        log_audit(tenant_id, "INCIDENT_RESOLVED", actor, "SUCCESS", f"Incident {incident_id} marked as RESOLVED")

        return {"status": "SUCCESS", "incident_id": incident_id, "new_status": "RESOLVED"}
    finally:
        conn.close()
