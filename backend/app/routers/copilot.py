"""
Security Copilot Router for VantaVisionAI Funding Prototype.
Grounded in authorized SQLite telemetry and platform records.
Delivers structured findings, evidence, interpretations, recommended steps, and explicit limitations.
"""
import os
import asyncio
import json
import urllib.request
from fastapi import APIRouter, Depends, Header, HTTPException
from datetime import datetime
from typing import Optional, List, Dict, Any

from backend.app.schemas import CopilotQueryRequest
from backend.app.database import get_connection, log_audit
from backend.app.routers.brain import get_tenant_id

router = APIRouter(prefix="/api/v1/copilot", tags=["copilot"])

@router.post("")
async def query_copilot(
    body: CopilotQueryRequest,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    query_raw = (body.query or "").strip()
    if not query_raw:
        raise HTTPException(status_code=400, detail="Query cannot be empty.")

    query_lower = query_raw.lower()
    timestamp = datetime.utcnow().isoformat() + "Z"
    actor = "authenticated_user" if authorization else "security_operator"

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Fetch verified facts for the tenant
        cursor.execute("SELECT COUNT(*) as c FROM events WHERE tenant_id = ?", (tenant_id,))
        total_events = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ?", (tenant_id,))
        total_incidents = cursor.fetchone()["c"]

        cursor.execute("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
        open_incidents = cursor.fetchone()["c"]

        cursor.execute("SELECT * FROM policies WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
        active_policies = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM incidents WHERE tenant_id = ? AND status = 'OPEN' ORDER BY timestamp DESC LIMIT 5", (tenant_id,))
        open_incident_records = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 5", (tenant_id,))
        recent_event_records = [dict(r) for r in cursor.fetchall()]

        # Structured response sections
        finding: str = ""
        evidence: List[str] = []
        interpretation: str = ""
        recommended_steps: List[str] = []
        limitations: List[str] = [
            "Hardware CCTV provider is reported as SIMULATED (real_camera_configured=false).",
            "Client-side video stream frames remain strictly in browser memory and are not sent to server."
        ]

        # Intent Recognition
        live_ctx = body.live_context or {}
        is_live_query = any(k in query_lower for k in [
            "how many objects", "visible right now", "currently visible", "visible objects",
            "people and vehicles", "people detected", "vehicles detected", "how many people",
            "track id", "track ids", "active tracks", "current tracks",
            "what changed", "tracking delta", "recent movement", "last few seconds",
            "is the scanner running", "scanner running", "scanner active", "scanner status"
        ])

        if any(k in query_lower for k in ["how many objects", "visible right now", "currently visible", "visible objects", "what is visible"]):
            if live_ctx.get("is_scanning"):
                v_count = live_ctx.get("visible_count", 0)
                track_ids = [f"#{tid}" for tid in live_ctx.get("active_track_ids", [])]
                class_counts = live_ctx.get("class_counts", {})
                classes_str = ", ".join(f"{cnt} {cls}" for cls, cnt in class_counts.items()) or "no classified objects"
                track_str = f" ({', '.join(track_ids)})" if track_ids else ""
                finding = f"Live Scanner has {v_count} object(s) currently visible in active field of view{track_str}."
                evidence = [
                    f"Track #{d.get('trackId', '?')} [{d.get('class', 'object').upper()}]: {d.get('score', 0)}% confidence"
                    for d in live_ctx.get("detections", [])
                ] or ["Real-time frame buffer contains 0 detected objects meeting confidence threshold."]
                interpretation = f"Current visual feed from {live_ctx.get('active_source', 'scanner')} displays {classes_str}. Track continuity is maintained locally by ObjectTracker."
                recommended_steps = [
                    f"Monitor active tracks {', '.join(track_ids)} for zone perimeter compliance." if track_ids else "Adjust camera angle or sensitivity if targets are expected.",
                    "Use category filter dropdown to isolate specific security classes."
                ]
            else:
                finding = "Live Scanner is currently INACTIVE / STOPPED. 0 objects currently visible."
                evidence = [
                    f"Scanner State: is_scanning = {live_ctx.get('is_scanning', False)}",
                    f"Active Source: {live_ctx.get('active_source', 'None')}"
                ]
                interpretation = "Camera sensor stream is paused or disconnected. No frame detections are occurring."
                recommended_steps = [
                    "Click 'Start Webcam' or 'Test Surveillance Feed' to begin real-time detection.",
                    "Upload a recorded surveillance video to analyze recorded footage."
                ]

        elif any(k in query_lower for k in ["people and vehicles", "how many people", "vehicles detected", "people detected"]):
            if live_ctx.get("is_scanning"):
                counts = live_ctx.get("class_counts", {})
                p_count = counts.get("person", counts.get("people", 0))
                v_keys = ["car", "truck", "motorcycle", "bus", "bicycle", "vehicle", "vehicles"]
                v_count = sum(cnt for cls, cnt in counts.items() if cls.lower() in v_keys)
                finding = f"Real-time census: {p_count} person(s) and {v_count} vehicle(s) currently detected in active feed."
                evidence = [
                    f"Persons visible: {p_count}",
                    f"Vehicles visible: {v_count}",
                    f"Total visible objects: {live_ctx.get('visible_count', 0)}",
                    f"Source: {live_ctx.get('active_source', 'Active Feed')}"
                ]
                interpretation = f"Perimeter classification confirms {p_count} pedestrian target(s) and {v_count} vehicular target(s)."
                recommended_steps = [
                    "Cross-check person coordinates against restricted perimeter zones." if p_count > 0 else "Pedestrian perimeter clear.",
                    "Log vehicle dwell times if stationary in loading docks." if v_count > 0 else "Vehicle perimeter clear."
                ]
            else:
                finding = "Scanner is currently INACTIVE. 0 people and 0 vehicles detected."
                evidence = ["Scanner is offline. Ingested events ledger contains historical records."]
                interpretation = "Start the Live Vision Scanner to begin real-time object classification."
                recommended_steps = ["Click 'Start Webcam' to activate live classification."]

        elif any(k in query_lower for k in ["track id", "track ids", "active tracks", "current tracks"]):
            if live_ctx.get("is_scanning"):
                tids = live_ctx.get("active_track_ids", [])
                finding = f"Active Track IDs currently tracked: [{', '.join(f'#{i}' for i in tids)}]." if tids else "No active object tracks are currently in field of view."
                evidence = [
                    f"Track #{d.get('trackId', '?')}: {d.get('class', 'object')} (Confidence: {d.get('score', 0)}%)"
                    for d in live_ctx.get("detections", [])
                ] or ["ObjectTracker activeTrackIds buffer is currently empty."]
                interpretation = "Continuous multi-object tracking assigns persistent IDs using centroid distance and bounding-box IoU."
                recommended_steps = [
                    "Verify trajectory stability across frame occlusions.",
                    "Use category filter to isolate individual track classes."
                ]
            else:
                finding = "Scanner is INACTIVE. No active track IDs present."
                evidence = ["ObjectTracker is reset while scanner is halted."]
                interpretation = "Track continuity resumes upon starting the camera feed."
                recommended_steps = ["Activate scanner to track moving targets."]

        elif any(k in query_lower for k in ["what changed", "tracking delta", "recent movement", "last few seconds"]):
            if live_ctx:
                hist = live_ctx.get("recent_history", [])
                finding = f"Tracking Delta: {len(hist)} distinct target(s) logged in recent rolling history." if hist else "No recent tracking changes or target movements logged."
                evidence = [
                    f"Track #{h.get('trackId', '?')} [{h.get('class', 'object').upper()}]: first seen {h.get('firstSeen', 'N/A')}, last seen {h.get('lastSeen', 'N/A')}"
                    for h in hist[:6]
                ] or ["No movement events detected in current session window."]
                interpretation = "Rolling tracking ledger maintains temporal awareness of entry, dwell, and exit transitions."
                recommended_steps = [
                    "Compare rolling delta against unauthorized access time windows.",
                    "Review event ledger for persisted threshold violations."
                ]
            else:
                finding = "No tracking delta available while scanner is idle."
                evidence = ["No live telemetry supplied."]
                interpretation = "Tracking delta requires an active scanner session."
                recommended_steps = ["Start video scanner to observe real-time delta."]

        elif any(k in query_lower for k in ["is the scanner running", "scanner running", "scanner active", "scanner status"]):
            running = bool(live_ctx.get("is_scanning", False))
            finding = f"Live Vision Scanner is RUNNING on source: {live_ctx.get('active_source', 'Active Stream')}." if running else "Live Vision Scanner is STOPPED / IDLE."
            evidence = [
                f"Scanner Running: {running}",
                f"Source: {live_ctx.get('active_source', 'None')}",
                f"Current Visible Objects: {live_ctx.get('visible_count', 0)}",
                f"Active Track IDs: [{', '.join(f'#{i}' for i in live_ctx.get('active_track_ids', []))}]"
            ]
            interpretation = "TensorFlow.js COCO-SSD MobileNet V2 inference loop is actively scanning video frames." if running else "Camera tracks and inference loop are halted. Resources are released."
            recommended_steps = ["Monitor detection feed and real-time canvas overlays.", "Click 'Stop Camera' when finished."] if running else ["Click 'Start Webcam' or 'Test Surveillance Feed' to start scanning."]

        elif any(k in query_lower for k in ["summarize recent detections", "recent detections", "summarize detections", "summary of detections"]):
            class_counts = {}
            for e in recent_event_records:
                cls = e.get("class_name", "object")
                class_counts[cls] = class_counts.get(cls, 0) + 1
            top_classes = ", ".join(f"{cnt} {cls}(s)" for cls, cnt in class_counts.items()) or "none"
            finding = f"Detection Summary: {total_events} total visual events recorded for tenant '{tenant_id}' ({top_classes})."
            evidence = [
                f"Event [{e['id']}]: {e['class_name'].upper()} on {e['camera_id']} ({int((e.get('confidence') or 0.85)*100)}% conf, {e['timestamp']})"
                for e in recent_event_records
            ] or ["Zero detection records stored in local database."]
            interpretation = f"Visual surveillance has captured {total_events} classified targets across active zones with class distribution: {top_classes}."
            recommended_steps = [
                "Review recent detection event logs in the Events tab.",
                "Adjust confidence threshold if false positives occur."
            ]

        elif any(k in query_lower for k in ["what is happening", "happening in", "selected camera feed", "camera feed", "selected feed"]):
            active_src = live_ctx.get("active_source", "Simulated Camera (CAM-01-ENTRANCE)")
            v_count = live_ctx.get("visible_count", 0)
            running = bool(live_ctx.get("is_scanning", False))
            finding = f"Feed Activity [{active_src}]: {v_count} object(s) actively tracked in real time." if running else f"Feed Activity [{active_src}]: Camera stream is currently STOPPED/IDLE. 0 live targets."
            evidence = [
                f"Stream Source: {active_src}",
                f"Inference State: {'ACTIVE' if running else 'IDLE'}",
                f"Active Objects: {v_count}",
                f"Track IDs: [{', '.join(f'#{i}' for i in live_ctx.get('active_track_ids', []))}]"
            ]
            interpretation = f"Live frame processing on {active_src} is actively matching targets against configured security zones." if running else "Feed is offline. Click 'Start Webcam' or 'Test Surveillance Feed' to monitor visual activity."
            recommended_steps = [
                "Monitor perimeter boundaries on the live video canvas." if running else "Activate camera stream to track live movement.",
                "Switch camera source dropdown to inspect alternate security angles."
            ]

        elif any(k in query_lower for k in ["explain this detection", "explain detection", "how does detection work", "detection model"]):
            finding = "Detection Pipeline: Local client-side neural inference via MobileNet V2 COCO-SSD with Per-Class NMS and Centroid Tracking."
            evidence = [
                "Model Architecture: MobileNet V2 feature extractor with Single Shot MultiBox Detector (SSD)",
                "Inference Runtime: TensorFlow.js WebGL/WASM acceleration in browser memory",
                "Duplicate Suppression: Per-Class Non-Maximum Suppression (IoU threshold: 0.50)",
                "Track Association: Euclidean centroid distance gating with multi-frame velocity extrapolation"
            ]
            interpretation = "Detections are computed entirely on the client without sending video frames over the network. Bounding boxes are filtered by confidence and tracked across frames to maintain unique track IDs."
            recommended_steps = [
                "Observe bounding box corner brackets and track IDs on the Live Scanner canvas.",
                "Use the Confidence slider to fine-tune sensitivity between 30% and 95%."
            ]

        elif any(k in query_lower for k in ["why an alert", "why alert", "why was an alert", "alert generated", "why did an alert trigger"]):
            finding = "Alert Generation Pipeline: 3-phase automated policy evaluation triggered by visual target classifications."
            evidence = [
                "Phase 1: Object detection crosses confidence threshold (e.g. person, backpack, car)",
                "Phase 2: Policy engine matches detected class against enabled security rules",
                "Phase 3: Automated incident escalation creates open incident and writes immutable audit log"
            ]
            interpretation = "Alerts are generated deterministically when visual objects meet criteria defined in Security Policies (e.g., After-Hours Perimeter Breach or Unattended Baggage)."
            recommended_steps = [
                "Inspect the active rules in the Policies tab to view trigger conditions.",
                "Acknowledge and resolve verified alerts in the Incidents view."
            ]

        elif any(k in query_lower for k in ["involving cars", "involving vehicles", "involving person", "involving people", "involving luggage", "find recent events involving"]):
            target_class = "car"
            if "person" in query_lower or "people" in query_lower:
                target_class = "person"
            elif "vehicle" in query_lower or "car" in query_lower:
                target_class = "car"
            elif "backpack" in query_lower or "luggage" in query_lower:
                target_class = "backpack"

            cursor.execute("SELECT * FROM events WHERE tenant_id = ? AND (class_name = ? OR (class_name IN ('car', 'truck', 'motorcycle', 'bus') AND ? = 'car')) ORDER BY timestamp DESC LIMIT 6", (tenant_id, target_class, target_class))
            matched_events = [dict(r) for r in cursor.fetchall()]
            finding = f"Found {len(matched_events)} event(s) involving '{target_class}' in the surveillance database."
            evidence = [
                f"Event [{e['id']}]: {e['class_name'].upper()} on {e['camera_id']} ({int((e.get('confidence') or 0.88)*100)}% conf, {e['timestamp']})"
                for e in matched_events
            ] or [f"No historical events stored matching class '{target_class}'."]
            interpretation = f"Query filtered the immutable detection log for target class '{target_class}'."
            recommended_steps = [
                f"Navigate to Events tab to inspect all {len(matched_events)} records.",
                "Correlate timestamps with authorized facility access schedules."
            ]

        elif any(term in query_lower for term in ["incident", "breach", "alert", "threat", "alarm", "open", "unresolved"]):
            finding = f"There are {open_incidents} active open incident(s) registered under tenant '{tenant_id}'."
            if open_incident_records:
                evidence = [
                    f"Incident [{inc['id']}] ({inc['severity']}): '{inc['title']}' on {inc['camera_id']} ({inc['timestamp']})"
                    for inc in open_incident_records
                ]
                interpretation = "Active incidents represent automated policy triggers resulting from detections. Operator review is required."
                recommended_steps = [
                    f"Acknowledge and inspect incident {open_incident_records[0]['id']}.",
                    "Correlate detection timestamp with local camera recordings.",
                    "Click 'Resolve' in the Incidents view once verified."
                ]
            else:
                evidence = ["No open incident records found in database."]
                interpretation = "The monitored perimeter is secure with zero unmitigated alerts."
                recommended_steps = ["Continue scheduled surveillance."]

        elif any(term in query_lower for term in ["policy", "rule", "threshold", "condition"]):
            finding = f"There are {len(active_policies)} active automated detection policies enabled for tenant '{tenant_id}'."
            evidence = [
                f"Policy [{p['id']}]: '{p['name']}' targets '{p['target_class']}' ({p['condition']}) -> Severity {p['severity']}"
                for p in active_policies
            ]
            interpretation = "Incoming visual events matching these object classes and conditions automatically trigger incident records."
            recommended_steps = [
                "Review policy conditions before scheduled operational hours.",
                "Use the Policies tab to toggle rules when operating in high-traffic periods."
            ]

        elif any(term in query_lower for term in ["camera", "feed", "stream", "video", "webcam", "scanner"]):
            finding = "The vision scanner operates locally in the client browser using TensorFlow.js COCO-SSD MobileNet V2."
            evidence = [
                "Browser Input: Supports MediaDevices getUserMedia (webcam) and HTML5 video uploads.",
                "Backend Provider: SIMULATED (real_camera_configured=false).",
                "Stream Count: 1 local client detector, 2 simulated CCTV feeds (CAM-01-ENTRANCE, CAM-02-LOBBY)."
            ]
            interpretation = "Video processing is decentralized. Frames are analyzed inside browser WebGL/CPU without cloud frame streaming, preserving user privacy."
            recommended_steps = [
                "Ensure browser camera permission is allowed and site is served over HTTPS or localhost.",
                "Use the 'Upload Video' option if physical webcam hardware is unavailable."
            ]
            limitations.append("Physical CCTV NVR/RTSP ingestion is not bound in prototype.")

        elif any(term in query_lower for term in ["status", "health", "system", "summary", "overview"]):
            finding = f"VantaVisionAI Funding Prototype is OPERATIONAL with {total_events} events, {open_incidents} open incidents, and {len(active_policies)} active policies."
            evidence = [
                f"Total Detection Events: {total_events}",
                f"Total Incidents: {total_incidents} (Open: {open_incidents})",
                f"Active Policies: {len(active_policies)}",
                "Database Engine: SQLite (Connected)"
            ]
            interpretation = "All core platform services (FastAPI, SQLite, and browser detector) are functioning normally."
            recommended_steps = [
                "Execute Brain command 'status' or 'summary' for structured telemetry.",
                "Run the Demo Simulation under Pipeline tab to test event propagation."
            ]

        elif any(term in query_lower for term in ["device", "paired", "mobile", "node", "qr"]):
            cursor.execute("SELECT id, name, device_type, role, camera_id, status FROM devices WHERE tenant_id = ? AND revoked = 0", (tenant_id,))
            devs = [dict(r) for r in cursor.fetchall()]
            online_devs = [d for d in devs if d["status"] == "ONLINE"]
            finding = f"Multi-Device Registry has {len(devs)} registered node(s) ({len(online_devs)} ONLINE) for tenant '{tenant_id}'."
            evidence = [
                f"Device [{d['id']}]: {d['name']} ({d['device_type']}/{d['role']}) -> Camera {d['camera_id']} [{d['status']}]"
                for d in devs
            ] or ["No registered devices found."]
            interpretation = "Connected devices perform local edge inference and transmit structured metadata or on-demand WebRTC streams to Central Command."
            recommended_steps = [
                "Open the Devices view to generate a single-use QR pairing code for mobile camera nodes.",
                "Monitor device heartbeats and latency in Central Command."
            ]

        elif any(term in query_lower for term in ["zone", "polygon", "perimeter", "loitering", "occupancy"]):
            cursor.execute("SELECT id, name, camera_id, zone_type, severity, max_occupancy, max_dwell_sec FROM zones WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
            zones = [dict(r) for r in cursor.fetchall()]
            finding = f"Polygon Zone Intelligence has {len(zones)} active spatial security zone(s) enforcing perimeter rules."
            evidence = [
                f"Zone [{z['id']}]: '{z['name']}' on {z['camera_id']} ({z['zone_type']}, Max Occ: {z['max_occupancy']}, Max Dwell: {z['max_dwell_sec']}s)"
                for z in zones
            ]
            interpretation = "Ray-casting point-in-polygon geometry evaluates object centroids against restricted and loitering zones in real time."
            recommended_steps = [
                "Use the Zone Intelligence tab to draw or modify polygon vertices.",
                "Inspect zone-linked incidents for dwell or occupancy violations."
            ]

        elif any(term in query_lower for term in ["correlat", "cross-camera", "across camera", "compare camera"]):
            cursor.execute("SELECT camera_id, COUNT(*) as cnt FROM events WHERE tenant_id = ? GROUP BY camera_id", (tenant_id,))
            cam_rows = [dict(r) for r in cursor.fetchall()]
            finding = f"Cross-Camera Correlation analyzed activity across {len(cam_rows)} distinct camera source(s)."
            evidence = [
                f"Camera [{r['camera_id']}]: {r['cnt']} recorded detection event(s)"
                for r in cam_rows
            ] or ["Zero multi-camera events recorded yet."]
            interpretation = "Non-biometric spatiotemporal correlation tracks object class transitions and timestamps across adjacent camera zones."
            recommended_steps = [
                "Review the Live Camera Grid to compare simultaneous feeds.",
                "Run Brain command 'correlations' for full transit vectors."
            ]

        elif any(term in query_lower for term in ["troubleshoot", "error", "fail", "broken", "black screen", "not working"]):
            finding = "Standard diagnostic sequence for camera and scanner issues."
            evidence = [
                "Check 1: Browser permission state (Prompt vs Denied).",
                "Check 2: Secure context requirements (HTTPS or localhost).",
                "Check 3: Video readiness (videoWidth > 0, readyState >= 2).",
                "Check 4: TensorFlow.js COCO-SSD CDN status."
            ]
            interpretation = "Camera issues are commonly caused by browser permission blocks or background video play rejections."
            recommended_steps = [
                "Inspect the Camera Diagnostics bar in the Scanner view.",
                "Reload the page and click 'Start Webcam' to trigger a clean permission prompt.",
                "Test local inference using 'Upload Video' with any .mp4 or .webm clip."
            ]

        else:
            # General query grounded in current telemetry
            finding = f"Security Telemetry Overview for Tenant '{tenant_id}': {total_events} events recorded, {open_incidents} open incidents."
            evidence = [
                f"Active Rules: {', '.join([p['name'] for p in active_policies[:3]])}",
                f"Recent Detections: {len(recent_event_records)} events in recent buffer"
            ]
            interpretation = "Platform is continuously monitoring visual inputs against operational security policies."
            recommended_steps = [
                "Ask specific questions regarding 'incidents', 'policies', 'devices', 'zones', 'camera status', or 'troubleshooting'.",
                "Use Brain CLI commands for direct system diagnostics."
            ]

        suggested_actions = []
        if open_incidents > 0:
            suggested_actions.append({"label": "Inspect Open Incidents", "action": "NAVIGATE", "target": "incidents"})
            suggested_actions.append({"label": "Triage Priority Incident", "action": "COPILOT_QUERY", "target": "What is the most important open incident to investigate first?"})
        if live_ctx and live_ctx.get("is_scanning"):
            suggested_actions.append({"label": "Scanner Object Breakdown", "action": "COPILOT_QUERY", "target": "Give me a census breakdown of all visible objects."})
            suggested_actions.append({"label": "Toggle Heatmap", "action": "ALEANA_CMD", "target": "toggle heatmap"})
        else:
            suggested_actions.append({"label": "Start Vision Scanner", "action": "NAVIGATE", "target": "scanner"})
            suggested_actions.append({"label": "Check System Diagnostics", "action": "BRAIN_CMD", "target": "diagnostics"})

        # Optional Hybrid Gemini API Synthesis (1500ms timeout with deterministic fallback)
        gemini_key = os.getenv("GEMINI_API_KEY")
        reasoning_model = os.getenv("GEMINI_REASONING_MODEL", "gemini-2.5-flash")
        if gemini_key:
            try:
                def call_gemini():
                    model_Target = "gemini-2.5-flash" if "3.8" in reasoning_model else reasoning_model
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_Target}:generateContent?key={gemini_key}"
                    prompt = f"""You are VantaVisionAI SOC Copilot. Refine the interpretation and recommended steps based on verified platform findings:
Query: "{query_raw}"
Finding: "{finding}"
Evidence: {json.dumps(evidence)}
Current Interpretation: "{interpretation}"
Return ONLY valid JSON in format: {{"interpretation": "refined concise analysis", "recommended_steps": ["step1", "step2"]}}"""
                    body_bytes = json.dumps({"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"responseMimeType": "application/json"}}).encode("utf-8")
                    req = urllib.request.Request(url, data=body_bytes, headers={"Content-Type": "application/json", "User-Agent": "aistudio-build"})
                    with urllib.request.urlopen(req, timeout=1.5) as resp:
                        res_data = json.loads(resp.read().decode("utf-8"))
                        text_val = res_data["candidates"][0]["content"]["parts"][0]["text"]
                        return json.loads(text_val)

                refined = await asyncio.to_thread(call_gemini)
                if refined.get("interpretation"):
                    interpretation = refined["interpretation"]
                if refined.get("recommended_steps"):
                    recommended_steps = refined["recommended_steps"]
            except Exception:
                pass

        # Log audit entry
        log_audit(
            tenant_id=tenant_id,
            action="COPILOT_QUERY_ANSWERED",
            actor=actor,
            status="SUCCESS",
            details=f"Query: {query_raw[:80]}"
        )

        return {
            "query": query_raw,
            "finding": finding,
            "evidence": evidence,
            "interpretation": interpretation,
            "recommended_steps": recommended_steps,
            "suggested_actions": suggested_actions,
            "limitations": limitations,
            "verified_facts": finding,
            "ai_interpretation": interpretation,
            "recommendation": recommended_steps,
            "unavailable_information": limitations,
            "tenant_id": tenant_id,
            "timestamp": timestamp,
            "provider_mode": "DETERMINISTIC_GROUNDED",
            "provider": "SIMULATED",
            "real_camera_configured": False
        }

    finally:
        conn.close()
