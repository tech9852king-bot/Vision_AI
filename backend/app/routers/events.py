"""Events Router for VantaVisionAI Funding Prototype"""
from fastapi import APIRouter, HTTPException, Depends, Header
from typing import List, Optional
import uuid
import json
from datetime import datetime

from backend.app.schemas import EventCreate, EventResponse
from backend.app.database import get_connection, log_audit
from backend.app.routers.brain import get_tenant_id

router = APIRouter(prefix="/api/v1/events", tags=["events"])

@router.get("", response_model=List[EventResponse])
async def list_events(
    limit: int = 50,
    camera_id: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT id, tenant_id, timestamp, camera_id, class_name, confidence, bbox FROM events WHERE tenant_id = ?"
        params = [tenant_id]
        if camera_id:
            query += " AND camera_id = ?"
            params.append(camera_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        result = []
        for r in rows:
            bbox = None
            if r["bbox"]:
                try:
                    bbox = json.loads(r["bbox"])
                except Exception:
                    bbox = None
            result.append(EventResponse(
                id=r["id"],
                tenant_id=r["tenant_id"],
                timestamp=r["timestamp"],
                camera_id=r["camera_id"],
                class_name=r["class_name"],
                confidence=r["confidence"],
                bbox=bbox
            ))
        return result
    finally:
        conn.close()

@router.post("", response_model=EventResponse)
async def create_event(
    event: EventCreate,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    event_id = f"ev_{uuid.uuid4().hex[:10]}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    bbox_json = json.dumps(event.bbox) if event.bbox else None
    meta_json = json.dumps(event.metadata) if event.metadata else None

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO events (id, tenant_id, timestamp, camera_id, class_name, confidence, bbox, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, tenant_id, timestamp, event.camera_id, event.class_name, event.confidence, bbox_json, meta_json)
        )

        # Policy matching engine
        cursor.execute(
            "SELECT * FROM policies WHERE tenant_id = ? AND enabled = 1 AND target_class = ?",
            (tenant_id, event.class_name)
        )
        matching_policies = cursor.fetchall()
        meta = event.metadata or {}
        parts = []
        if meta.get("track_id"):
            parts.append(f"Track: {meta['track_id']}")
        if meta.get("dwell_time_sec"):
            parts.append(f"Dwell: {meta['dwell_time_sec']}s")
        if meta.get("motion_state"):
            parts.append(f"Motion: {meta['motion_state']}")
        if meta.get("threat_score"):
            parts.append(f"Threat: {meta['threat_score']}")
        meta_suffix = f" [{', '.join(parts)}]" if parts else ""

        for pol in matching_policies:
            inc_id = f"inc_{uuid.uuid4().hex[:8]}"
            cursor.execute(
                "INSERT INTO incidents (id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    inc_id,
                    tenant_id,
                    timestamp,
                    f"Policy Triggered: {pol['name']}",
                    pol["severity"],
                    "OPEN",
                    pol["id"],
                    event.camera_id,
                    f"Detected '{event.class_name}' with confidence {round(event.confidence * 100, 1)}% violating '{pol['condition']}'{meta_suffix}"
                )
            )
            log_audit(tenant_id, "INCIDENT_AUTO_CREATED", "policy_engine", "TRIGGERED", f"Created incident {inc_id} from policy {pol['id']}")

        conn.commit()

        actor = "authenticated_user" if authorization else "scanner"
        log_audit(tenant_id, "EVENT_RECORDED", actor, "SUCCESS", f"Event {event_id} ({event.class_name}) on {event.camera_id}")

        return EventResponse(
            id=event_id,
            tenant_id=tenant_id,
            timestamp=timestamp,
            camera_id=event.camera_id,
            class_name=event.class_name,
            confidence=event.confidence,
            bbox=event.bbox
        )
    finally:
        conn.close()

@router.delete("/{event_id}")
async def delete_event(
    event_id: str,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM events WHERE id = ? AND tenant_id = ?", (event_id, tenant_id))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Event not found or unauthorized")

        cursor.execute("DELETE FROM events WHERE id = ? AND tenant_id = ?", (event_id, tenant_id))
        conn.commit()

        actor = "authenticated_user" if authorization else "anonymous"
        log_audit(tenant_id, "EVENT_DELETED", actor, "SUCCESS", f"Event {event_id} removed")

        return {"status": "SUCCESS", "deleted_event_id": event_id, "tenant_id": tenant_id}
    finally:
        conn.close()
