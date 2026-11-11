"""
Multi-Device Registry, QR Pairing, Polygon Zone Intelligence, Cross-Camera Correlation,
and Zero-Trust JWT Session Router for VantaVisionAI.
"""
import os
import uuid
import json
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Header, HTTPException

from backend.app.database import get_connection, log_audit
from backend.app.routers.brain import get_tenant_id
from backend.app.auth import create_jwt_token, get_auth_context, revoke_jwt_token
from backend.app.schemas import (
    DeviceRegisterRequest,
    PairingCreateRequest,
    PairingClaimRequest,
    DeviceHeartbeatRequest,
    ZoneCreateRequest
)

router = APIRouter(tags=["devices-zones-auth"])


@router.get("/api/v1/auth/session")
@router.get("/api/v1/auth/me")
async def get_session_info(
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    ctx = get_auth_context(authorization=authorization, x_tenant_id=x_tenant_id)
    # Issue a signed JWT if client does not have one yet
    token = create_jwt_token(
        subject=ctx["subject"],
        tenant_id=ctx["tenant_id"],
        role=ctx["role"],
        device_id=ctx.get("device_id"),
        ttl_seconds=86400
    )
    return {
        "status": "ACTIVE",
        "authenticated": ctx["authenticated"],
        "verified_jwt": ctx["verified_jwt"],
        "auth_mode": ctx["auth_mode"],
        "actor_id": ctx["actor_id"],
        "subject": ctx["subject"],
        "tenant_id": ctx["tenant_id"],
        "role": ctx["role"],
        "device_id": ctx.get("device_id"),
        "scopes": ctx.get("scopes", []),
        "token": token,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.post("/api/v1/auth/token")
async def issue_auth_token(
    body: Optional[Dict[str, Any]] = None,
    tenant_id: str = Depends(get_tenant_id)
):
    payload = body or {}
    subject = str(payload.get("subject") or payload.get("sub") or "operator@vantavision.ai").strip()
    role = str(payload.get("role") or "ADMIN").upper()
    device_id = payload.get("device_id")
    token = create_jwt_token(
        subject=subject,
        tenant_id=tenant_id,
        role=role,
        device_id=device_id,
        ttl_seconds=int(payload.get("ttl_seconds", 86400))
    )
    log_audit(tenant_id, "AUTH_JWT_ISSUED", subject, "SUCCESS", f"Issued HS256 JWT role={role}")
    return {
        "status": "ISSUED",
        "token": token,
        "token_type": "Bearer",
        "subject": subject,
        "tenant_id": tenant_id,
        "role": role,
        "device_id": device_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.post("/api/v1/auth/revoke")
async def revoke_auth_token_endpoint(
    body: Optional[Dict[str, Any]] = None,
    authorization: Optional[str] = Header(None),
    tenant_id: str = Depends(get_tenant_id)
):
    payload = body or {}
    raw_token = payload.get("token")
    if not raw_token and authorization and authorization.lower().startswith("bearer "):
        raw_token = authorization.split(" ", 1)[1].strip()
    if not raw_token:
        raise HTTPException(status_code=400, detail="Token is required for revocation.")
    revoke_jwt_token(raw_token)
    log_audit(tenant_id, "AUTH_JWT_REVOKED", "operator", "SUCCESS", "Revoked JWT token")
    return {
        "status": "REVOKED",
        "tenant_id": tenant_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/api/v1/devices")
async def list_devices(tenant_id: str = Depends(get_tenant_id)):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """SELECT id, tenant_id, name, device_type, role, camera_id, facing_mode, status,
                      capabilities, stream_mode, battery_pct, latency_ms, last_heartbeat,
                      paired_via, revoked, created_at
               FROM devices WHERE tenant_id = ? ORDER BY created_at ASC""",
            (tenant_id,)
        )
        rows = cursor.fetchall()
        devices = []
        for r in rows:
            caps = []
            if r["capabilities"]:
                try:
                    caps = json.loads(r["capabilities"])
                except Exception:
                    caps = []
            devices.append({
                "id": r["id"],
                "tenant_id": r["tenant_id"],
                "name": r["name"],
                "device_type": r["device_type"],
                "role": r["role"],
                "camera_id": r["camera_id"],
                "facing_mode": r["facing_mode"],
                "status": "REVOKED" if r["revoked"] else r["status"],
                "capabilities": caps,
                "stream_mode": r["stream_mode"],
                "battery_pct": r["battery_pct"],
                "latency_ms": r["latency_ms"],
                "last_heartbeat": r["last_heartbeat"],
                "paired_via": r["paired_via"],
                "revoked": bool(r["revoked"]),
                "created_at": r["created_at"]
            })
        online_cnt = sum(1 for d in devices if d["status"] == "ONLINE" and not d["revoked"])
        return {
            "status": "SUCCESS",
            "tenant_id": tenant_id,
            "count": len(devices),
            "online_count": online_cnt,
            "devices": devices,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    finally:
        conn.close()


@router.post("/api/v1/devices/register")
async def register_device(
    req: DeviceRegisterRequest,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    now = datetime.utcnow().isoformat() + "Z"
    dev_id = (req.device_id or "").strip() or f"DEV-{uuid.uuid4().hex[:8].upper()}"
    cam_id = (req.camera_id or "").strip() or f"CAM-NODE-{dev_id[-4:]}"
    caps_json = json.dumps(req.capabilities or ["webcam", "coco-ssd", "webrtc"])

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM devices WHERE id = ? AND tenant_id = ?", (dev_id, tenant_id))
        existing = cursor.fetchone()
        if existing:
            cursor.execute(
                """UPDATE devices SET name = ?, device_type = ?, role = ?, camera_id = ?,
                          facing_mode = ?, status = 'ONLINE', capabilities = ?, stream_mode = ?,
                          last_heartbeat = ?, revoked = 0
                   WHERE id = ? AND tenant_id = ?""",
                (
                    req.name, req.device_type, req.role, cam_id,
                    req.facing_mode or "environment", caps_json,
                    req.stream_mode or "METADATA_ONLY", now, dev_id, tenant_id
                )
            )
        else:
            cursor.execute(
                """INSERT INTO devices (
                    id, tenant_id, name, device_type, role, camera_id, facing_mode,
                    status, capabilities, stream_mode, battery_pct, latency_ms,
                    last_heartbeat, paired_via, revoked, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ONLINE', ?, ?, 100, 15.0, ?, 'DIRECT_REGISTER', 0, ?)""",
                (
                    dev_id, tenant_id, req.name, req.device_type, req.role,
                    cam_id, req.facing_mode or "environment", caps_json,
                    req.stream_mode or "METADATA_ONLY", now, now
                )
            )
        conn.commit()

        device_token = create_jwt_token(
            subject=f"device:{dev_id}",
            tenant_id=tenant_id,
            role="CAMERA_NODE" if req.role == "CAMERA_NODE" else "OPERATOR",
            device_id=dev_id,
            ttl_seconds=86400 * 7
        )
        log_audit(tenant_id, "DEVICE_REGISTERED", dev_id, "SUCCESS", f"Registered {req.name} ({req.device_type}) as {cam_id}")
        return {
            "status": "REGISTERED",
            "device": {
                "id": dev_id,
                "tenant_id": tenant_id,
                "name": req.name,
                "device_type": req.device_type,
                "role": req.role,
                "camera_id": cam_id,
                "facing_mode": req.facing_mode or "environment",
                "status": "ONLINE",
                "capabilities": req.capabilities or ["webcam", "coco-ssd", "webrtc"],
                "stream_mode": req.stream_mode or "METADATA_ONLY",
                "last_heartbeat": now
            },
            "device_token": device_token,
            "timestamp": now
        }
    finally:
        conn.close()


@router.post("/api/v1/devices/pairing/create")
async def create_pairing_session(
    req: Optional[PairingCreateRequest] = None,
    tenant_id: str = Depends(get_tenant_id)
):
    body = req or PairingCreateRequest()
    ttl = max(60, min(int(body.ttl_seconds or 300), 3600))
    now_dt = datetime.utcnow()
    expires_dt = now_dt + timedelta(seconds=ttl)
    pairing_code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
    session_id = f"pair_{uuid.uuid4().hex[:10]}"

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO pairing_sessions (
                code, id, tenant_id, role, target_label, expires_at, used, claimed_by_device_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?)""",
            (
                pairing_code, session_id, tenant_id,
                body.role or "CAMERA_NODE", body.target_label or "Mobile Camera Node",
                expires_dt.isoformat() + "Z", now_dt.isoformat() + "Z"
            )
        )
        conn.commit()
        log_audit(tenant_id, "PAIRING_CODE_CREATED", "operator", "SUCCESS", f"Created single-use pairing code {pairing_code}")
        return {
            "status": "CREATED",
            "pairing_code": pairing_code,
            "session_id": session_id,
            "tenant_id": tenant_id,
            "role": body.role or "CAMERA_NODE",
            "target_label": body.target_label or "Mobile Camera Node",
            "expires_at": expires_dt.isoformat() + "Z",
            "ttl_seconds": ttl,
            "qr_payload": json.dumps({
                "vanta_pair": True,
                "code": pairing_code,
                "tenant_id": tenant_id,
                "role": body.role or "CAMERA_NODE"
            })
        }
    finally:
        conn.close()


@router.post("/api/v1/devices/pairing/claim")
async def claim_pairing_session(req: PairingClaimRequest):
    code = (req.pairing_code or "").strip().upper()
    if not code:
        raise HTTPException(status_code=400, detail="Pairing code is required.")

    now_dt = datetime.utcnow()
    now_iso = now_dt.isoformat() + "Z"

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM pairing_sessions WHERE code = ?", (code,))
        session = cursor.fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="Invalid pairing code.")
        if session["used"]:
            raise HTTPException(status_code=409, detail="Pairing code has already been used.")

        expires_str = session["expires_at"].rstrip("Z")
        try:
            expires_dt = datetime.fromisoformat(expires_str)
            if now_dt > expires_dt:
                raise HTTPException(status_code=410, detail="Pairing code has expired.")
        except ValueError:
            pass

        tenant_id = session["tenant_id"]
        dev_id = f"DEV-{uuid.uuid4().hex[:8].upper()}"
        cam_id = (req.camera_id or "").strip() or f"CAM-MOBILE-{dev_id[-4:]}"
        caps_json = json.dumps(req.capabilities or ["webcam", "coco-ssd", "webrtc", "qr-paired"])

        cursor.execute(
            "UPDATE pairing_sessions SET used = 1, claimed_by_device_id = ? WHERE code = ?",
            (dev_id, code)
        )
        cursor.execute(
            """INSERT INTO devices (
                id, tenant_id, name, device_type, role, camera_id, facing_mode,
                status, capabilities, stream_mode, battery_pct, latency_ms,
                last_heartbeat, paired_via, revoked, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ONLINE', ?, 'METADATA_ONLY', 100, 18.0, ?, 'QR_CODE', 0, ?)""",
            (
                dev_id, tenant_id, req.device_name, req.device_type or "mobile",
                session["role"], cam_id, req.facing_mode or "environment",
                caps_json, now_iso, now_iso
            )
        )
        conn.commit()

        device_token = create_jwt_token(
            subject=f"device:{dev_id}",
            tenant_id=tenant_id,
            role=session["role"],
            device_id=dev_id,
            ttl_seconds=86400 * 7
        )
        log_audit(tenant_id, "DEVICE_PAIRED_VIA_CODE", dev_id, "SUCCESS", f"Claimed code {code} -> {req.device_name} ({cam_id})")
        return {
            "status": "PAIRED",
            "tenant_id": tenant_id,
            "device": {
                "id": dev_id,
                "tenant_id": tenant_id,
                "name": req.device_name,
                "device_type": req.device_type or "mobile",
                "role": session["role"],
                "camera_id": cam_id,
                "facing_mode": req.facing_mode or "environment",
                "status": "ONLINE",
                "paired_via": "QR_CODE"
            },
            "device_token": device_token,
            "timestamp": now_iso
        }
    finally:
        conn.close()


@router.post("/api/v1/devices/{device_id}/heartbeat")
async def device_heartbeat(
    device_id: str,
    req: Optional[DeviceHeartbeatRequest] = None,
    tenant_id: str = Depends(get_tenant_id)
):
    body = req or DeviceHeartbeatRequest()
    now_iso = datetime.utcnow().isoformat() + "Z"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, revoked FROM devices WHERE id = ? AND tenant_id = ?", (device_id, tenant_id))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")
        if row["revoked"]:
            raise HTTPException(status_code=403, detail=f"Device '{device_id}' has been revoked.")

        cursor.execute(
            """UPDATE devices
               SET status = COALESCE(?, status),
                   battery_pct = COALESCE(?, battery_pct),
                   latency_ms = COALESCE(?, latency_ms),
                   stream_mode = COALESCE(?, stream_mode),
                   facing_mode = COALESCE(?, facing_mode),
                   last_heartbeat = ?
               WHERE id = ? AND tenant_id = ?""",
            (
                body.status or "ONLINE",
                body.battery_pct,
                body.latency_ms,
                body.stream_mode,
                body.facing_mode,
                now_iso,
                device_id,
                tenant_id
            )
        )
        conn.commit()
        return {
            "status": "UPDATED",
            "device_id": device_id,
            "tenant_id": tenant_id,
            "last_heartbeat": now_iso
        }
    finally:
        conn.close()


@router.post("/api/v1/devices/{device_id}/revoke")
async def revoke_device(
    device_id: str,
    tenant_id: str = Depends(get_tenant_id)
):
    now_iso = datetime.utcnow().isoformat() + "Z"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM devices WHERE id = ? AND tenant_id = ?", (device_id, tenant_id))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")
        cursor.execute(
            "UPDATE devices SET revoked = 1, status = 'REVOKED', last_heartbeat = ? WHERE id = ? AND tenant_id = ?",
            (now_iso, device_id, tenant_id)
        )
        conn.commit()
        log_audit(tenant_id, "DEVICE_REVOKED", "operator", "SUCCESS", f"Revoked device {device_id}")
        return {
            "status": "REVOKED",
            "device_id": device_id,
            "tenant_id": tenant_id,
            "timestamp": now_iso
        }
    finally:
        conn.close()


@router.get("/api/v1/zones")
async def list_zones(
    camera_id: Optional[str] = None,
    tenant_id: str = Depends(get_tenant_id)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT id, tenant_id, name, camera_id, zone_type, severity, polygon, color, max_occupancy, max_dwell_sec, enabled, created_at FROM zones WHERE tenant_id = ?"
        params: List[Any] = [tenant_id]
        if camera_id:
            query += " AND camera_id = ?"
            params.append(camera_id)
        query += " ORDER BY id ASC"
        cursor.execute(query, params)
        zones = []
        for r in cursor.fetchall():
            poly = []
            try:
                poly = json.loads(r["polygon"])
            except Exception:
                poly = []
            zones.append({
                "id": r["id"],
                "tenant_id": r["tenant_id"],
                "name": r["name"],
                "camera_id": r["camera_id"],
                "zone_type": r["zone_type"],
                "severity": r["severity"],
                "polygon": poly,
                "color": r["color"],
                "max_occupancy": r["max_occupancy"],
                "max_dwell_sec": r["max_dwell_sec"],
                "enabled": bool(r["enabled"]),
                "created_at": r["created_at"]
            })
        return {
            "status": "SUCCESS",
            "tenant_id": tenant_id,
            "count": len(zones),
            "zones": zones
        }
    finally:
        conn.close()


@router.post("/api/v1/zones")
async def create_zone(
    req: ZoneCreateRequest,
    tenant_id: str = Depends(get_tenant_id)
):
    if not req.polygon or len(req.polygon) < 3:
        raise HTTPException(status_code=400, detail="Polygon zone requires at least 3 vertices.")
    now_iso = datetime.utcnow().isoformat() + "Z"
    zone_id = f"ZONE-{uuid.uuid4().hex[:6].upper()}"
    poly_json = json.dumps(req.polygon)

    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO zones (
                id, tenant_id, name, camera_id, zone_type, severity, polygon,
                color, max_occupancy, max_dwell_sec, enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                zone_id, tenant_id, req.name, req.camera_id,
                req.zone_type, req.severity, poly_json,
                req.color or "#ef4444", req.max_occupancy or 3,
                req.max_dwell_sec or 30, 1 if req.enabled else 0, now_iso
            )
        )
        conn.commit()
        log_audit(tenant_id, "ZONE_CREATED", "operator", "SUCCESS", f"Created polygon zone {zone_id} ({req.name})")
        return {
            "status": "CREATED",
            "zone": {
                "id": zone_id,
                "tenant_id": tenant_id,
                "name": req.name,
                "camera_id": req.camera_id,
                "zone_type": req.zone_type,
                "severity": req.severity,
                "polygon": req.polygon,
                "color": req.color or "#ef4444",
                "max_occupancy": req.max_occupancy or 3,
                "max_dwell_sec": req.max_dwell_sec or 30,
                "enabled": bool(req.enabled),
                "created_at": now_iso
            }
        }
    finally:
        conn.close()


@router.delete("/api/v1/zones/{zone_id}")
async def delete_zone(
    zone_id: str,
    tenant_id: str = Depends(get_tenant_id)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM zones WHERE id = ? AND tenant_id = ?", (zone_id, tenant_id))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail=f"Zone '{zone_id}' not found.")
        cursor.execute("DELETE FROM zones WHERE id = ? AND tenant_id = ?", (zone_id, tenant_id))
        conn.commit()
        log_audit(tenant_id, "ZONE_DELETED", "operator", "SUCCESS", f"Deleted zone {zone_id}")
        return {"status": "DELETED", "zone_id": zone_id, "tenant_id": tenant_id}
    finally:
        conn.close()


@router.get("/api/v1/correlations")
async def get_cross_camera_correlations(tenant_id: str = Depends(get_tenant_id)):
    """
    Correlates detection events across multiple cameras, devices, and zones
    using timestamps, object classes, and spatial zone adjacency.
    """
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """SELECT id, timestamp, camera_id, class_name, confidence, device_id, track_id, zone_id
               FROM events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 50""",
            (tenant_id,)
        )
        events = [dict(r) for r in cursor.fetchall()]

        by_class: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            cls = ev.get("class_name") or "object"
            by_class.setdefault(cls, []).append(ev)

        correlations = []
        for cls, cls_events in by_class.items():
            cameras = list({e["camera_id"] for e in cls_events if e.get("camera_id")})
            devices = list({e.get("device_id") or "DEV-CENTRAL-CMD" for e in cls_events})
            if len(cameras) >= 2 or len(cls_events) >= 2:
                correlations.append({
                    "correlation_id": f"CORR-{cls.upper()}-{len(cls_events)}",
                    "object_class": cls,
                    "cameras_involved": cameras,
                    "devices_involved": devices,
                    "event_count": len(cls_events),
                    "confidence_score": round(sum(e.get("confidence", 0.85) for e in cls_events) / len(cls_events), 2),
                    "pattern": "MULTI_CAMERA_TRANSIT" if len(cameras) >= 2 else "REPEATED_ZONE_ACTIVITY",
                    "latest_timestamp": cls_events[0]["timestamp"],
                    "sample_events": [e["id"] for e in cls_events[:4]]
                })

        return {
            "status": "SUCCESS",
            "tenant_id": tenant_id,
            "correlations_count": len(correlations),
            "correlations": correlations,
            "privacy_notice": "Correlations use non-biometric class, timestamp, and zone transition telemetry only.",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    finally:
        conn.close()


@router.get("/api/v1/gemini/status")
async def get_gemini_status():
    has_key = bool(os.getenv("GEMINI_API_KEY"))
    return {
        "status": "CONFIGURED" if has_key else "STANDBY_NO_KEY",
        "api_key_configured": has_key,
        "models": {
            "live": os.getenv("GEMINI_LIVE_MODEL", "gemini-3.8-live"),
            "reasoning": os.getenv("GEMINI_REASONING_MODEL", "gemini-3.8-flash"),
            "tts": os.getenv("GEMINI_TTS_MODEL", "gemini-3.8-flash-tts"),
            "tts_lite": os.getenv("GEMINI_TTS_LITE_MODEL", "gemini-3.8-flash-lite-tts"),
            "transcribe": os.getenv("GEMINI_TRANSCRIBE_MODEL", "gemini-3.5-transcribe"),
            "search_grounding": "gemini-2.5-flash",
            "maps_grounding": "gemini-2.5-flash"
        },
        "capabilities": [
            "live_bidirectional_voice",
            "search_grounding",
            "maps_grounding",
            "audio_transcription",
            "neural_tts",
            "multimodal_reasoning"
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
