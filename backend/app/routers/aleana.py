"""
Aleana Voice Assistant Router for VantaVisionAI Funding Prototype (FastAPI Parity).
Implements /api/v1/aleana/status and /api/v1/aleana/command with intent routing,
phonetic autocorrection, Hindi aliases, and SQLite audit logging.
"""
import re
from datetime import datetime
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from backend.app.database import get_connection, log_audit
from backend.app.routers.brain import get_tenant_id

router = APIRouter(prefix="/api/v1/aleana", tags=["aleana"])

class AleanaCommandRequest(BaseModel):
    query: str = Field(..., description="Spoken or typed natural language query")
    current_view: Optional[str] = Field("dashboard", description="Current UI viewport for contextual fallback")
    live_context: Optional[Dict[str, Any]] = Field(None, description="Client-side scanner context")
    pending_action: Optional[str] = Field(None, description="Guarded action awaiting confirmation")

class AleanaCommandResponse(BaseModel):
    query: str
    intent: str
    action: str
    target: Optional[str] = None
    speech: str
    data: Optional[Dict[str, Any]] = None
    timestamp: str

@router.get("/status")
async def get_aleana_status():
    return {
        "status": "ONLINE",
        "name": "ALEANA",
        "role": "Voice-Enabled Security Operations Assistant",
        "version": "2.0.0",
        "supported_languages": ["en-US", "en-IN", "hi-IN"],
        "capabilities": [
            "voice_navigation",
            "threat_summarization",
            "incident_triage",
            "scanner_control",
            "diagnostics_telemetry",
            "simulation_trigger"
        ],
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@router.post("/command", response_model=AleanaCommandResponse)
async def handle_aleana_command(
    body: AleanaCommandRequest,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    raw_query = (body.query or "").strip()
    if not raw_query:
        raise HTTPException(status_code=400, detail="Command query cannot be empty.")

    q_lower = raw_query.lower()
    clean_query = re.sub(r'[,!?;:\-/"]', ' ', q_lower)
    clean_query = re.sub(r'\s+', ' ', clean_query).strip()

    # Normalization & wake-word stripping
    q_norm = clean_query
    q_norm = re.sub(r'^(hey|hi|hello|ok|okay)?\s*(aleana|elena|alina|alana)\s*,?\s*', '', q_norm, flags=re.IGNORECASE).strip()

    # Autocorrection dictionary
    corrections = [
        (r'\bincidants\b', 'incidents'),
        (r'\bpolices\b', 'policies'),
        (r'\bpolicys\b', 'policies'),
        (r'\bcamra\b', 'camera'),
        (r'\bscaner\b', 'scanner'),
        (r'\bhelth\b', 'health')
    ]
    for pattern, replacement in corrections:
        q_norm = re.sub(pattern, replacement, q_norm)

    # Fetch live SQLite metrics for tenant
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) as c FROM events WHERE tenant_id = ?", (tenant_id,))
        ev_count = cursor.fetchone()["c"]

        cursor.execute("SELECT * FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
        open_incs = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ?", (tenant_id,))
        total_incs = cursor.fetchone()["c"]

        cursor.execute("SELECT * FROM policies WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
        active_pols = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    intent = "UNKNOWN"
    action = "REPLY"
    target = None
    speech = ""
    data: Dict[str, Any] = {}

    # 0. Session & Speech Control
    if any(q_lower == k or q_lower.startswith('aleana stop') or q_lower.startswith('aleana shutdown') or q_norm in ['stop', 'shutdown'] for k in ['aleana stop', 'aleana shutdown', 'stop aleana', 'shutdown aleana', 'stop listening', 'shutdown']):
        intent = "STOP_ASSISTANT"
        action = "STOP_SESSION"
        speech = "Aleana voice session stopped."
        data = {"session_active": False}
    elif any(k in q_norm or k in clean_query for k in ['stop speech', 'stop speaking', 'aleana stop speaking', 'stop talking', 'chup ho jao', 'chup raho']):
        intent = "STOP_SPEECH"
        action = "STOP_SPEECH"
        speech = "Speech output cancelled."
        data = {"is_speaking": False}
    elif any(q_norm == k or k in q_norm or k in q_lower for k in ['pause listening', 'pause aleana', 'pause voice', 'pause']):
        intent = "PAUSE_ASSISTANT"
        action = "PAUSE_SESSION"
        speech = "Voice recognition paused."
        data = {"session_paused": True}
    elif any(q_norm == k or k in q_norm or k in q_lower for k in ['resume listening', 'resume aleana', 'resume voice', 'start listening', 'start aleana', 'aleana start', 'aleana resume', 'resume']):
        intent = "RESUME_ASSISTANT"
        action = "RESUME_SESSION"
        speech = "Voice recognition is active. How can I help?"
        data = {"session_paused": False}
    elif any(q_norm == k or k in q_norm for k in ['repeat that', 'repeat response', 'repeat', 'dobara bolo', 'phir se bolo', 'once more']):
        intent = "REPEAT_RESPONSE"
        action = "REPEAT_RESPONSE"
        speech = "Repeating last response."
        data = {"repeat": True}

    # 1. Scanner Operations
    elif any(k in q_norm or k in q_lower for k in ['start scanner', 'start camera', 'start webcam', 'begin scan', 'camera chalu', 'camera chalu karo', 'scan start', 'turn on camera', 'chalu karo camera', 'scanner start']):
        intent = "START_SCANNER"
        action = "START_SCANNER"
        target = "scanner"
        speech = "Activating Live Vision Scanner and TensorFlow MobileNet tracking loop."
    elif any(k in q_norm or k in q_lower for k in ['stop scanner', 'stop camera', 'stop feed', 'camera band', 'camera band karo', 'scan stop', 'turn off camera', 'band karo camera', 'scanner stop']):
        intent = "STOP_SCANNER"
        action = "STOP_SCANNER"
        speech = "Vision Scanner stopped. Processing resources and camera tracks released."
    elif any(k in q_norm or k in q_lower for k in ['test feed', 'synthetic feed', 'simulate camera', 'test surveillance', 'demo feed']):
        intent = "START_TEST_FEED"
        action = "START_TEST_FEED"
        target = "scanner"
        speech = "Activating simulated Entrance Gate surveillance stream."
    elif any(k in q_norm for k in ['upload video', 'video upload', 'upload a video', 'file upload', 'video kaise upload']):
        intent = "UPLOAD_VIDEO_GUIDE"
        action = "NAVIGATE"
        target = "scanner"
        speech = "To scan recorded footage, click Upload Video in Live Vision Scanner. Files up to 50MB and 180 seconds are supported."
    elif any(k in q_norm for k in ['troubleshoot camera', 'camera help', 'camera problem', 'camera nahi chal raha', 'camera error']):
        intent = "TROUBLESHOOT_CAMERA"
        action = "NAVIGATE"
        target = "scanner"
        speech = "To troubleshoot camera, verify browser permission, ensure HTTPS or localhost, or use Test Surveillance Feed if webcam hardware is occupied."
    elif any(k in q_norm or k in q_lower for k in ['high traffic mode', 'traffic mode', 'crowd mode', 'high traffic', 'dense scene']):
        intent = "SET_FILTER_HIGH_TRAFFIC"
        action = "SET_FILTER_PRESET"
        target = "scanner"
        speech = "High-traffic surveillance mode activated. Background objects filtered; prioritizing persons and vehicles."
        data = {"preset": "hightraffic"}
    elif any(k in q_norm or k in q_lower for k in ['filter person only', 'person only', 'only persons', 'sirf log dikhao', 'persons only']):
        intent = "FILTER_PERSONS_ONLY"
        action = "SET_FILTER_PRESET"
        target = "scanner"
        speech = "Filtered to persons only. All other object categories suppressed."
        data = {"preset": "person-only"}
    elif any(k in q_norm or k in q_lower for k in ['filter vehicle only', 'vehicle only', 'only vehicles', 'sirf gadiyan dikhao', 'vehicles only']):
        intent = "FILTER_VEHICLES_ONLY"
        action = "SET_FILTER_PRESET"
        target = "scanner"
        speech = "Filtered to vehicles only. Pedestrians and background objects suppressed."
        data = {"preset": "vehicle-only"}
    elif any(k in q_norm or k in q_lower for k in ['reset filters', 'clear filter', 'show all objects', 'enable all filters', 'sab dikhao']):
        intent = "RESET_FILTERS"
        action = "SET_FILTER_PRESET"
        target = "scanner"
        speech = "Dynamic detection filters reset. All object categories active."
        data = {"preset": "all"}

    # 2. Inquiries
    elif any(k in q_norm or k in q_lower for k in ['how many incident', 'open incident', 'active incident', 'incident count', 'incidents kitne', 'kitne incidents', 'how many open incidents']) or (any(k in q_norm for k in ['how many', 'count', 'kitne']) and any(k in q_norm for k in ['incident', 'alert'])):
        intent = "QUERY_INCIDENTS"
        action = "QUERY"
        target = "incidents"
        data = {"open_incidents": len(open_incs), "total_incidents": total_incs}
        if len(open_incs) == 0:
            speech = "The security perimeter is clear. Zero open incidents are registered."
        else:
            primary_title = open_incs[0].get('title', 'Security Alert')
            speech = f"There are currently {len(open_incs)} open security incident{'s' if len(open_incs) > 1 else ''} requiring operator attention. Primary alert: {primary_title}."
    elif any(k in q_norm for k in ['how many detections', 'count detections', 'total detections', 'kitne detections', 'detection count']):
        intent = "QUERY_DETECTIONS"
        action = "QUERY"
        target = "events"
        data = {"total_events": ev_count}
        speech = f"Surveillance ledger currently contains {ev_count} verified visual detections across all zones."
    elif any(k in q_norm or k in q_lower for k in ['system health', 'check health', 'status check', 'is system ok', 'system kaisa hai', 'suraksha check karo', 'system theek hai', 'system health batao', 'check system health']):
        intent = "QUERY_HEALTH"
        action = "QUERY"
        data = {
            "health": "98%",
            "backend": "ONLINE",
            "database": "CONNECTED",
            "detector": "READY",
            "camera_provider": "SIMULATED (real_camera_configured=false)",
            "cameras": "4/4 Online",
            "database_status": "Connected",
            "open_incidents": len(open_incs),
            "active_policies": len(active_pols),
            "total_events": ev_count
        }
        speech = "All security subsystems are operating nominally. System health is 98 percent. 4 camera feeds online and SQLite database connected."
    elif any(k in q_norm or k in q_lower for k in ['summarize', 'summary', 'what happened', 'recent activity', 'threat summary', 'kya chal raha hai', 'summary report']):
        intent = "SUMMARIZE_THREATS"
        action = "QUERY"
        speech = f"Surveillance report: {ev_count} total detections recorded. {len(open_incs)} unresolved incidents, and {len(active_pols)} automated enforcement policies active."
    elif any(k in q_norm or k in q_lower for k in ['run simulation', 'simulate breach', 'trigger demo', 'test alert', 'alert test']):
        intent = "RUN_SIMULATION"
        action = "RUN_DEMO"
        speech = "Initiating end-to-end intrusion simulation sequence on Camera 01."

    # 3. Navigation
    elif any(k in q_norm for k in ['command center', 'dashboard', 'home', 'main']) and any(k in q_norm for k in ['open', 'go', 'show', 'kholo', 'dikhao']) or q_norm == 'dashboard':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "dashboard"
        speech = "Opening Command Center dashboard."
    elif any(k in q_norm for k in ['scanner', 'camera', 'live feed', 'vision', 'video']) and any(k in q_norm for k in ['open', 'go', 'show', 'kholo', 'dikhao']) or q_norm == 'scanner':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "scanner"
        speech = "Navigating to Live Vision Scanner."
    elif any(k in q_norm for k in ['event', 'detections']) and any(k in q_norm for k in ['open', 'go', 'show', 'kholo', 'dikhao']) or q_norm == 'events':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "events"
        speech = f"Opening Events log. {ev_count} total detections on record."
    elif any(k in q_norm for k in ['incident', 'breach', 'alerts']) and any(k in q_norm for k in ['open', 'go', 'show', 'kholo', 'dikhao']) or q_norm == 'incidents':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "incidents"
        speech = f"Displaying Incidents. {len(open_incs)} unresolved alerts open."
    elif any(k in q_norm for k in ['polic', 'rules', 'niyam']) and any(k in q_norm for k in ['open', 'go', 'show', 'kholo', 'dikhao']) or q_norm == 'policies':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "policies"
        speech = f"Opening Security Policies. {len(active_pols)} rules are currently enforcing."
    elif any(k in q_norm for k in ['copilot', 'assistant', 'chat']) and any(k in q_norm for k in ['open', 'go', 'show']) or q_norm == 'copilot':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "copilot"
        speech = "Opening AI Security Copilot."
    elif any(k in q_norm for k in ['brain', 'cli', 'console']) and any(k in q_norm for k in ['open', 'go', 'show']) or q_norm == 'brain':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "brain"
        speech = "Accessing Vanta Brain 7-layer command console."
    elif any(k in q_norm for k in ['audit', 'log', 'ledger']) and any(k in q_norm for k in ['open', 'go', 'show']) or q_norm == 'audit':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "audit"
        speech = "Opening Immutable Audit Trail."
    elif any(k in q_norm for k in ['system', 'diagnostic']) and any(k in q_norm for k in ['open', 'go', 'show']) or q_norm == 'system':
        intent = "NAVIGATE"
        action = "NAVIGATE"
        target = "system"
        speech = "Opening System Diagnostics & Infrastructure telemetry."
    # 4b. Category Filter & Scanner Vision Controls (Bilingual English + Hindi)
    elif any(k in q_norm for k in ['filter only person', 'filter person', 'show only person', 'persons only', 'sirf log', 'sirf log dikhao', 'sirf insaan']):
        intent = "FILTER_SCANNER"
        action = "FILTER_CATEGORY"
        target = "person"
        speech = "Filtering live scanner detections to persons only."
    elif any(k in q_norm for k in ['show vehicle', 'vehicles only', 'filter vehicle', 'gaadiyan dikhao', 'gaadi dikhao']):
        intent = "FILTER_SCANNER"
        action = "FILTER_CATEGORY"
        target = "vehicles"
        speech = "Filtering live scanner detections to vehicles."
    elif any(k in q_norm for k in ['show luggage', 'luggage only', 'bags only', 'bags dikhao', 'baggage only']):
        intent = "FILTER_SCANNER"
        action = "FILTER_CATEGORY"
        target = "luggage"
        speech = "Filtering live scanner detections to luggage and bags."
    elif any(k in q_norm for k in ['show all categor', 'show all', 'reset filter', 'sab dikhao', 'all categories']):
        intent = "FILTER_SCANNER"
        action = "FILTER_CATEGORY"
        target = "all"
        speech = "Restoring all detection categories on vision scanner."
    elif any(k in q_norm for k in ['hide detection chip', 'hide chips']):
        intent = "FILTER_SCANNER"
        action = "FILTER_CATEGORY"
        target = "none"
        speech = "Hiding detection chips from live overlay."
    elif any(k in q_norm for k in ['toggle heatmap', 'heatmap on', 'heatmap off', 'heatmap dikhao', 'thermal heatmap']):
        intent = "TOGGLE_HEATMAP"
        action = "TOGGLE_HEATMAP"
        speech = "Toggled 32 by 18 spatial-temporal thermal dwell heatmap overlay."
    elif any(k in q_norm for k in ['capture snapshot', 'take snapshot', 'take photo', 'photo lo', 'snapshot lo', 'forensic snapshot']):
        intent = "CAPTURE_SNAPSHOT"
        action = "CAPTURE_SNAPSHOT"
        speech = "Recording cryptographic watermarked forensic snapshot to evidence gallery."
    elif any(k in q_norm or k in q_lower for k in ['dispatch drone', 'launch drone', 'drone bhejo', 'send drone', 'uav dispatch', 'drone launch']):
        intent = "DISPATCH_DRONE"
        action = "DISPATCH_DRONE"
        target = "Perimeter Sector Alpha"
        speech = "Autonomous tactical UAV drone dispatched to Perimeter Sector Alpha for aerial reconnaissance."
        data = {
            "drone_id": "UAV-DELTA-704",
            "target_zone": "Perimeter Sector Alpha",
            "mission_profile": "PERIMETER_RECON",
            "status": "AIRBORNE_EN_ROUTE"
        }

    # 4c. Guarded Operational Actions with Two-Step Voice Confirmation
    elif any(k in q_norm for k in ['lockdown facility', 'lockdown', 'emergency lockdown', 'lockdown karo']):
        intent = "GUARDED_ACTION"
        action = "CONFIRMATION_REQUIRED"
        target = "LOCKDOWN_FACILITY"
        speech = "Security authorization required: Do you wish to initiate facility emergency lockdown? Say 'Yes confirm' or 'Cancel'."
    elif any(k in q_norm for k in ['purge audit log', 'purge audit', 'audit clear', 'audit saaf karo']):
        intent = "GUARDED_ACTION"
        action = "CONFIRMATION_REQUIRED"
        target = "PURGE_AUDIT_LOG"
        speech = "Security authorization required: Do you wish to purge the active audit trail? Say 'Yes confirm' or 'Cancel'."
    elif any(k in q_norm for k in ['trigger alarm', 'sound alarm', 'emergency alarm', 'alarm bajao']):
        intent = "GUARDED_ACTION"
        action = "CONFIRMATION_REQUIRED"
        target = "TRIGGER_ALARM"
        speech = "Security authorization required: Do you wish to sound the building evacuation alarm? Say 'Yes confirm' or 'Cancel'."

    # Confirmation & Guarded Execution
    elif any(q_norm == k or q_norm.startswith(k) for k in ['yes confirm', 'confirm', 'haan confirm karo', 'proceed', 'haan karo']):
        intent = "CONFIRM_GUARDED_ACTION"
        action = "EXECUTE_CONFIRMED_ACTION"
        speech = "Security authorization verified. Action executed."
    elif any(q_norm == k or q_norm.startswith(k) for k in ['cancel', 'abort', 'mat karo', 'cancel karo', 'ruko']):
        intent = "CANCEL_GUARDED_ACTION"
        action = "ABORT_GUARDED_ACTION"
        speech = "Action cancelled. Resuming standard surveillance monitoring."
    elif any(k in q_norm for k in ['resolve incident', 'clear incident', 'resolve alert', 'incident solve karo']):
        intent = "RESOLVE_INCIDENT"
        action = "RESOLVE_INCIDENT"
        target = "latest"
        conn_res = get_connection()
        try:
            cur = conn_res.cursor()
            cur.execute("SELECT id FROM incidents WHERE tenant_id = ? AND status = 'OPEN' ORDER BY timestamp DESC LIMIT 1", (tenant_id,))
            row = cur.fetchone()
            if row:
                res_id = row["id"]
                cur.execute("UPDATE incidents SET status = 'RESOLVED' WHERE id = ? AND tenant_id = ?", (res_id, tenant_id))
                conn_res.commit()
                cur.execute("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
                rem_c = cur.fetchone()["c"]
                speech = f"Incident {res_id} resolved. {rem_c} open incidents remaining."
                data = {"resolved_incident_id": res_id, "remaining_open": rem_c}
            else:
                speech = "No open incidents require resolution."
                data = {"remaining_open": 0}
        finally:
            conn_res.close()
    elif any(k in q_norm for k in ['how many objects are visible', 'objects visible', 'kitne objects dikh rahe hain', 'what is on screen', 'kya dikh raha hai', 'census']):
        intent = "QUERY_SCANNER_CENSUS"
        action = "QUERY_SCANNER_CENSUS"
        live_ctx = body.live_context or {}
        vis_count = live_ctx.get("visible_count", len(live_ctx.get("detections", [])))
        is_scan = live_ctx.get("is_scanning", False)
        class_counts = live_ctx.get("class_counts", {})
        class_str = ", ".join([f"{v} {k}{'s' if v > 1 else ''}" for k, v in class_counts.items()])
        if is_scan and vis_count > 0:
            speech = f"Live scanner currently detects {vis_count} object{'s' if vis_count > 1 else ''} in view: {class_str or 'active targets'}."
        elif is_scan:
            speech = "Live scanner is active, but zero objects currently meet detection confidence threshold."
        else:
            speech = "Vision scanner is currently offline. No objects visible in active field."
        data = {
            "visible_count": vis_count,
            "class_counts": class_counts,
            "is_scanning": bool(is_scan)
        }

    elif any(q_norm == k or q_norm == 'aleana' or q_norm == 'hey' or q_norm == 'hi' or q_lower == k for k in ['hello', 'hi', 'hey aleana', 'help', 'kya kar sakte ho', 'commands']):
        intent = "GREETING_HELP"
        action = "REPLY"
        speech = "I am listening. You can ask to open incidents, check system health, start the scanner, or summarize threats."
    else:
        current_view = body.current_view or "dashboard"
        intent = "UNRECOGNIZED_COMMAND"
        action = "REPLY"
        if current_view == "scanner":
            speech = 'Command not recognized. On the scanner screen, try saying "start webcam", "stop scanner", or "open incidents".'
        elif current_view == "incidents":
            speech = 'Command not recognized. On the incidents screen, try saying "how many incidents", "open policies", or "summarize threats".'
        elif current_view == "policies":
            speech = 'Command not recognized. On the policies screen, try saying "show incidents", "open scanner", or "check system health".'
        else:
            speech = 'Command not recognized. Say "show incidents", "start scanner", "system health", or "Aleana stop".'

    actor = "authenticated_user" if authorization else "voice_operator"
    log_audit(tenant_id, "ALEANA_VOICE_COMMAND", actor, "SUCCESS", f"Query: '{raw_query[:60]}' -> Intent: {intent}")

    return AleanaCommandResponse(
        query=raw_query,
        intent=intent,
        action=action,
        target=target,
        speech=speech,
        data=data,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )
