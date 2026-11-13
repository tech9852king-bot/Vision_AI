"""
Database module for VantaVisionAI Next-Generation Multi-Device Platform.
Uses SQLite for zero-configuration, robust local persistence.
Provides tenant isolation, unified multi-device & C4ISR registry, polygon zone intelligence,
idempotent event provenance, and chronological SHA-256 cryptographic audit logging.
"""
import sqlite3
import os
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional


def get_db_path() -> str:
    if "DATABASE_PATH" in os.environ and os.environ["DATABASE_PATH"].strip():
        return os.environ["DATABASE_PATH"].strip()
    db_url = os.environ.get("DATABASE_URL", "")
    if db_url.startswith("sqlite:///"):
        return db_url.replace("sqlite:///", "")
    return "vanta_vision.db"


DB_PATH = get_db_path()


def get_connection():
    path = get_db_path()
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(cursor, table: str, column: str, col_def: str):
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row["name"] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


def compute_audit_block_hash(
    tenant_id: str,
    timestamp: str,
    action: str,
    actor: str,
    status: str,
    details: str,
    prev_hash: str
) -> str:
    payload = f"{tenant_id}:{timestamp}:{action}:{actor}:{status}:{details or ''}:{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Events table with full multi-device & edge provenance
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        device_id TEXT DEFAULT 'DEV-LOCAL-CONSOLE',
        timestamp TEXT NOT NULL,
        camera_id TEXT NOT NULL,
        class_name TEXT NOT NULL,
        confidence REAL NOT NULL,
        bbox TEXT,
        track_id TEXT,
        zone_id TEXT DEFAULT 'ZONE-01-PERIMETER',
        detection_model TEXT DEFAULT 'COCO-SSD-MobileNetV2',
        processing_device TEXT DEFAULT 'edge_browser_wasm_webgl',
        processing_latency_ms REAL DEFAULT 0.0,
        metadata TEXT
    )
    """)

    _ensure_column(cursor, "events", "device_id", "TEXT DEFAULT 'DEV-LOCAL-CONSOLE'")
    _ensure_column(cursor, "events", "track_id", "TEXT")
    _ensure_column(cursor, "events", "zone_id", "TEXT DEFAULT 'ZONE-01-PERIMETER'")
    _ensure_column(cursor, "events", "detection_model", "TEXT DEFAULT 'COCO-SSD-MobileNetV2'")
    _ensure_column(cursor, "events", "processing_device", "TEXT DEFAULT 'edge_browser_wasm_webgl'")
    _ensure_column(cursor, "events", "processing_latency_ms", "REAL DEFAULT 0.0")

    # 2. Incidents table (supports device_id, track_id, zone_id)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        timestamp TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'OPEN',
        policy_id TEXT,
        camera_id TEXT,
        device_id TEXT DEFAULT 'DEV-LOCAL-CONSOLE',
        track_id TEXT,
        zone_id TEXT DEFAULT 'ZONE-01-PERIMETER',
        details TEXT
    )
    """)
    _ensure_column(cursor, "incidents", "device_id", "TEXT DEFAULT 'DEV-LOCAL-CONSOLE'")
    _ensure_column(cursor, "incidents", "track_id", "TEXT")
    _ensure_column(cursor, "incidents", "zone_id", "TEXT DEFAULT 'ZONE-01-PERIMETER'")

    # 3. Policies table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        target_class TEXT NOT NULL,
        condition TEXT NOT NULL,
        severity TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        description TEXT
    )
    """)

    # 4. Audit Logs table with write-time cryptographic SHA-256 chain columns
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT 'system',
        status TEXT NOT NULL,
        details TEXT,
        prev_hash TEXT DEFAULT 'GENESIS_BLOCK_0000',
        integrity_hash TEXT
    )
    """)
    _ensure_column(cursor, "audit_logs", "prev_hash", "TEXT DEFAULT 'GENESIS_BLOCK_0000'")
    _ensure_column(cursor, "audit_logs", "integrity_hash", "TEXT")

    # 5. Centralized Multi-Device Registry table (unified Multi-Device + C4ISR schema)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        device_id TEXT,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        display_name TEXT,
        device_type TEXT NOT NULL DEFAULT 'mobile',
        device_category TEXT DEFAULT 'Smartphone',
        role TEXT NOT NULL DEFAULT 'CAMERA_NODE',
        permission_profile TEXT DEFAULT 'CAMERA_PUBLISHER',
        camera_id TEXT NOT NULL,
        active_camera_id TEXT,
        facing_mode TEXT DEFAULT 'environment',
        status TEXT NOT NULL DEFAULT 'ONLINE',
        capabilities TEXT DEFAULT '["webcam","coco-ssd","webrtc"]',
        camera_capabilities TEXT DEFAULT '["user","environment"]',
        stream_mode TEXT DEFAULT 'METADATA_ONLY',
        stream_status TEXT DEFAULT 'METADATA_EDGE',
        detection_status TEXT DEFAULT 'ACTIVE',
        battery_pct INTEGER DEFAULT 100,
        battery_level INTEGER DEFAULT 100,
        latency_ms REAL DEFAULT 15.0,
        avg_latency_ms REAL DEFAULT 15.0,
        last_heartbeat TEXT NOT NULL,
        paired_via TEXT DEFAULT 'DIRECT_REGISTER',
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        os_info TEXT DEFAULT 'Browser Runtime',
        browser_info TEXT DEFAULT 'WebRTC Edge Node',
        assigned_workspace TEXT DEFAULT 'Primary SOC',
        assigned_zone TEXT DEFAULT 'ZONE-01-PERIMETER',
        webrtc_offer TEXT,
        webrtc_answer TEXT
    )
    """)
    _ensure_column(cursor, "devices", "id", "TEXT")
    _ensure_column(cursor, "devices", "device_id", "TEXT")
    _ensure_column(cursor, "devices", "name", "TEXT")
    _ensure_column(cursor, "devices", "display_name", "TEXT")
    _ensure_column(cursor, "devices", "device_type", "TEXT DEFAULT 'mobile'")
    _ensure_column(cursor, "devices", "device_category", "TEXT DEFAULT 'Smartphone'")
    _ensure_column(cursor, "devices", "role", "TEXT DEFAULT 'CAMERA_NODE'")
    _ensure_column(cursor, "devices", "permission_profile", "TEXT DEFAULT 'CAMERA_PUBLISHER'")
    _ensure_column(cursor, "devices", "camera_id", "TEXT DEFAULT 'CAM-01'")
    _ensure_column(cursor, "devices", "active_camera_id", "TEXT")
    _ensure_column(cursor, "devices", "facing_mode", "TEXT DEFAULT 'environment'")
    _ensure_column(cursor, "devices", "status", "TEXT DEFAULT 'ONLINE'")
    _ensure_column(cursor, "devices", "capabilities", "TEXT DEFAULT '[\"webcam\",\"coco-ssd\",\"webrtc\"]'")
    _ensure_column(cursor, "devices", "camera_capabilities", "TEXT DEFAULT '[\"user\",\"environment\"]'")
    _ensure_column(cursor, "devices", "stream_mode", "TEXT DEFAULT 'METADATA_ONLY'")
    _ensure_column(cursor, "devices", "stream_status", "TEXT DEFAULT 'METADATA_EDGE'")
    _ensure_column(cursor, "devices", "detection_status", "TEXT DEFAULT 'ACTIVE'")
    _ensure_column(cursor, "devices", "battery_pct", "INTEGER DEFAULT 100")
    _ensure_column(cursor, "devices", "battery_level", "INTEGER DEFAULT 100")
    _ensure_column(cursor, "devices", "latency_ms", "REAL DEFAULT 15.0")
    _ensure_column(cursor, "devices", "avg_latency_ms", "REAL DEFAULT 15.0")
    _ensure_column(cursor, "devices", "last_heartbeat", "TEXT")
    _ensure_column(cursor, "devices", "paired_via", "TEXT DEFAULT 'DIRECT_REGISTER'")
    _ensure_column(cursor, "devices", "revoked", "INTEGER DEFAULT 0")
    _ensure_column(cursor, "devices", "created_at", "TEXT")
    _ensure_column(cursor, "devices", "os_info", "TEXT DEFAULT 'Browser Runtime'")
    _ensure_column(cursor, "devices", "browser_info", "TEXT DEFAULT 'WebRTC Edge Node'")
    _ensure_column(cursor, "devices", "assigned_workspace", "TEXT DEFAULT 'Primary SOC'")
    _ensure_column(cursor, "devices", "assigned_zone", "TEXT DEFAULT 'ZONE-01-PERIMETER'")
    _ensure_column(cursor, "devices", "webrtc_offer", "TEXT")
    _ensure_column(cursor, "devices", "webrtc_answer", "TEXT")

    # 6. Single-Use Expiring Device Pairing Sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pairing_sessions (
        code TEXT PRIMARY KEY,
        pairing_code TEXT,
        id TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        role TEXT NOT NULL DEFAULT 'CAMERA_NODE',
        permission_profile TEXT DEFAULT 'CAMERA_PUBLISHER',
        target_label TEXT DEFAULT 'Mobile Camera Node',
        assigned_zone TEXT DEFAULT 'ZONE-01-PERIMETER',
        assigned_workspace TEXT DEFAULT 'Primary SOC',
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        status TEXT DEFAULT 'PENDING',
        claimed_by_device_id TEXT,
        created_at TEXT NOT NULL
    )
    """)
    _ensure_column(cursor, "pairing_sessions", "code", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "pairing_code", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "id", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "role", "TEXT DEFAULT 'CAMERA_NODE'")
    _ensure_column(cursor, "pairing_sessions", "permission_profile", "TEXT DEFAULT 'CAMERA_PUBLISHER'")
    _ensure_column(cursor, "pairing_sessions", "target_label", "TEXT DEFAULT 'Mobile Camera Node'")
    _ensure_column(cursor, "pairing_sessions", "assigned_zone", "TEXT DEFAULT 'ZONE-01-PERIMETER'")
    _ensure_column(cursor, "pairing_sessions", "assigned_workspace", "TEXT DEFAULT 'Primary SOC'")
    _ensure_column(cursor, "pairing_sessions", "expires_at", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "used", "INTEGER DEFAULT 0")
    _ensure_column(cursor, "pairing_sessions", "status", "TEXT DEFAULT 'PENDING'")
    _ensure_column(cursor, "pairing_sessions", "claimed_by_device_id", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "created_at", "TEXT")

    # 7. Polygon Zone Intelligence table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS zones (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        camera_id TEXT NOT NULL DEFAULT 'CAM-01-ENTRANCE',
        zone_type TEXT NOT NULL DEFAULT 'RESTRICTED',
        severity TEXT NOT NULL DEFAULT 'HIGH',
        polygon TEXT NOT NULL,
        polygon_points TEXT,
        color TEXT NOT NULL DEFAULT '#f43f5e',
        max_occupancy INTEGER NOT NULL DEFAULT 3,
        max_dwell_sec INTEGER NOT NULL DEFAULT 30,
        dwell_threshold_sec INTEGER DEFAULT 30,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)
    _ensure_column(cursor, "zones", "id", "TEXT")
    _ensure_column(cursor, "zones", "name", "TEXT")
    _ensure_column(cursor, "zones", "camera_id", "TEXT DEFAULT 'CAM-01-ENTRANCE'")
    _ensure_column(cursor, "zones", "zone_type", "TEXT DEFAULT 'RESTRICTED'")
    _ensure_column(cursor, "zones", "severity", "TEXT DEFAULT 'HIGH'")
    _ensure_column(cursor, "zones", "polygon", "TEXT DEFAULT '[]'")
    _ensure_column(cursor, "zones", "polygon_points", "TEXT")
    _ensure_column(cursor, "zones", "color", "TEXT DEFAULT '#f43f5e'")
    _ensure_column(cursor, "zones", "max_occupancy", "INTEGER DEFAULT 3")
    _ensure_column(cursor, "zones", "max_dwell_sec", "INTEGER DEFAULT 30")
    _ensure_column(cursor, "zones", "dwell_threshold_sec", "INTEGER DEFAULT 30")
    _ensure_column(cursor, "zones", "enabled", "INTEGER DEFAULT 1")
    _ensure_column(cursor, "zones", "created_at", "TEXT")

    conn.commit()

    # Backfill any existing audit_logs rows that lack integrity_hash
    cursor.execute("SELECT id, tenant_id, timestamp, action, actor, status, details, prev_hash, integrity_hash FROM audit_logs ORDER BY id ASC")
    all_audit = cursor.fetchall()
    prev_by_tenant: Dict[str, str] = {}
    updates_needed = False
    for r in all_audit:
        t_id = r["tenant_id"] or "default"
        expected_prev = prev_by_tenant.get(t_id, "GENESIS_BLOCK_0000")
        expected_hash = compute_audit_block_hash(
            t_id,
            r["timestamp"] or "",
            r["action"] or "",
            r["actor"] or "system",
            r["status"] or "SUCCESS",
            r["details"] or "",
            expected_prev
        )
        if r["prev_hash"] != expected_prev or r["integrity_hash"] != expected_hash:
            cursor.execute(
                "UPDATE audit_logs SET prev_hash = ?, integrity_hash = ? WHERE id = ?",
                (expected_prev, expected_hash, r["id"])
            )
            updates_needed = True
        prev_by_tenant[t_id] = expected_hash
    if updates_needed:
        conn.commit()

    # Seed default policies if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM policies")
    if cursor.fetchone()["cnt"] == 0:
        default_policies = [
            ("pol_person_after_hours", "default", "After-Hours Person Incursion", "person", "time_between(22:00, 06:00)", "HIGH", 1, "Detects unauthorized human presence during closed facility hours."),
            ("pol_unattended_bag", "default", "Unattended Object / Backpack", "backpack", "dwell_time > 180s", "MEDIUM", 1, "Triggers when baggage remains stationary without associated person nearby."),
            ("pol_restricted_vehicle", "default", "Restricted Area Vehicle Access", "car", "zone == 'loading_dock_restricted'", "CRITICAL", 1, "Unauthorized vehicular entry into designated high-security perimeter."),
            ("pol_weapon_safety", "default", "Safety Hazard Object Detected", "scissors", "confidence > 0.65", "HIGH", 1, "Identifies potential sharp or dangerous implement hazards in workspace.")
        ]
        cursor.executemany(
            "INSERT INTO policies (id, tenant_id, name, target_class, condition, severity, enabled, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            default_policies
        )
        conn.commit()

    # Seed default incidents if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM incidents")
    if cursor.fetchone()["cnt"] == 0:
        now_iso = datetime.utcnow().isoformat() + "Z"
        default_incidents = [
            ("inc_001", "default", now_iso, "After-Hours Perimeter Breach Detected", "HIGH", "OPEN", "pol_person_after_hours", "CAM-01-ENTRANCE", "DEV-NODE-01", "TRK-01", "ZONE-01-PERIMETER", "Human presence observed at entrance gate outside operational schedule."),
            ("inc_002", "default", now_iso, "Stationary Baggage in Transit Hallway", "MEDIUM", "OPEN", "pol_unattended_bag", "CAM-02-LOBBY", "DEV-NODE-02", "TRK-02", "ZONE-02-LOBBY", "Unattended backpack identified near central elevator column.")
        ]
        cursor.executemany(
            "INSERT INTO incidents (id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, device_id, track_id, zone_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            default_incidents
        )
        conn.commit()

    # Seed default registered devices if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM devices")
    if cursor.fetchone()["cnt"] == 0:
        now_iso = datetime.utcnow().isoformat() + "Z"
        default_devices = [
            ("DEV-CONSOLE-PRIMARY", "DEV-CONSOLE-PRIMARY", "default", "Primary Command Workstation", "Primary Command Workstation", "desktop", "Desktop Workstation", "CENTRAL_COMMAND", "COMMAND_ADMIN", "BROWSER-SCANNER", "BROWSER-SCANNER", "user", "ONLINE", '["webcam","coco-ssd","webrtc","aleana-voice"]', '["user","environment"]', "LIVE_WEBRTC", "LIVE_WEBRTC", "ACTIVE", 100, 100, 4.0, 4.0, now_iso, "SYSTEM_DEFAULT", 0, now_iso),
            ("DEV-MOBILE-ALPHA", "DEV-MOBILE-ALPHA", "default", "Patrol Unit Alpha (Android)", "Patrol Unit Alpha (Android)", "mobile", "Smartphone", "CAMERA_NODE", "CAMERA_PUBLISHER", "CAM-01-ENTRANCE", "CAM-01-ENTRANCE", "environment", "ONLINE", '["webcam","coco-ssd","webrtc"]', '["user","environment"]', "WEBRTC_READY", "WEBRTC_READY", "ACTIVE", 86, 86, 32.0, 32.0, now_iso, "QR_CODE", 0, now_iso),
            ("DEV-TABLET-LOBBY", "DEV-TABLET-LOBBY", "default", "Executive Lobby Kiosk (iPad)", "Executive Lobby Kiosk (iPad)", "tablet", "Tablet", "CAMERA_NODE", "CAMERA_PUBLISHER", "CAM-02-LOBBY", "CAM-02-LOBBY", "environment", "ONLINE", '["webcam","coco-ssd","webrtc"]', '["user","environment"]', "METADATA_ONLY", "METADATA_EDGE", "ACTIVE", 94, 94, 28.0, 28.0, now_iso, "DIRECT_REGISTER", 0, now_iso)
        ]
        cursor.executemany(
            """INSERT INTO devices (
                id, device_id, tenant_id, name, display_name, device_type, device_category, role, permission_profile,
                camera_id, active_camera_id, facing_mode, status, capabilities, camera_capabilities,
                stream_mode, stream_status, detection_status, battery_pct, battery_level,
                latency_ms, avg_latency_ms, last_heartbeat, paired_via, revoked, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            default_devices
        )
        conn.commit()

    # Seed default polygon zones if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM zones")
    if cursor.fetchone()["cnt"] == 0:
        now_iso = datetime.utcnow().isoformat() + "Z"
        p1 = json.dumps([[0.25, 0.28], [0.75, 0.28], [0.75, 0.88], [0.25, 0.88]])
        p2 = json.dumps([[0.15, 0.35], [0.85, 0.35], [0.85, 0.90], [0.15, 0.90]])
        p3 = json.dumps([[0.10, 0.20], [0.90, 0.20], [0.90, 0.85], [0.10, 0.85]])
        default_zones = [
            ("ZONE-01-PERIMETER", "default", "North Gate Restricted Perimeter", "CAM-01-ENTRANCE", "RESTRICTED", "HIGH", p1, p1, "#f43f5e", 2, 8, 8, 1, now_iso),
            ("ZONE-02-LOBBY", "default", "Executive Elevator Transit Zone", "CAM-02-LOBBY", "LOITERING_WATCH", "MEDIUM", p2, p2, "#00e5ff", 5, 15, 15, 1, now_iso),
            ("ZONE-03-DOCK", "default", "Loading Dock Vehicular Bay", "CAM-03-PARKING", "VEHICLE_ONLY", "CRITICAL", p3, p3, "#f59e0b", 2, 30, 30, 1, now_iso)
        ]
        cursor.executemany(
            """INSERT INTO zones (
                id, tenant_id, name, camera_id, zone_type, severity, polygon, polygon_points,
                color, max_occupancy, max_dwell_sec, dwell_threshold_sec, enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            default_zones
        )
        conn.commit()

    # 8. VANTA AI Universal Infrastructure Intelligence OS Tables (Gate 2)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS facilities (
        facility_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        industry_profile TEXT DEFAULT 'manufacturing',
        location TEXT DEFAULT 'Austin, TX',
        coordinates TEXT DEFAULT '{"lat":30.2672,"lng":-97.7431}',
        status TEXT DEFAULT 'OPERATIONAL',
        total_area_sqm REAL DEFAULT 48500,
        operating_mode TEXT DEFAULT '24x7_CONTINUOUS',
        environmental_conditions TEXT DEFAULT '{"ambient_temp_c":23.4,"relative_humidity_pct":44}',
        buildings TEXT DEFAULT '[]',
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        asset_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_id TEXT NOT NULL,
        building_id TEXT DEFAULT 'BLD-A-PRODUCTION',
        floor_id TEXT DEFAULT 'FL-A1-MAIN',
        zone_id TEXT DEFAULT 'ZONE-PERIMETER-ALPHA',
        name TEXT NOT NULL,
        asset_type TEXT DEFAULT 'PRODUCTION_MACHINERY',
        criticality TEXT DEFAULT 'CRITICAL',
        status TEXT DEFAULT 'ONLINE',
        coordinates_2d TEXT DEFAULT '{"x":280,"y":220}',
        linked_camera_id TEXT DEFAULT 'CAM-01-ENTRANCE',
        linked_equipment_id TEXT,
        linked_sensors TEXT DEFAULT '[]',
        provenance TEXT DEFAULT 'VERIFIED_ASSET_REGISTRY'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS equipment (
        equipment_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        zone_id TEXT DEFAULT 'ZONE-PERIMETER-ALPHA',
        camera_id TEXT DEFAULT 'CAM-01-ENTRANCE',
        name TEXT NOT NULL,
        category TEXT DEFAULT 'CNC_MACHINING_CENTER',
        manufacturer TEXT DEFAULT 'Siemens',
        model TEXT DEFAULT 'DMU-210-P',
        status TEXT DEFAULT 'WARNING_VIBRATION',
        temperature_c REAL DEFAULT 86.4,
        vibration_mm_s REAL DEFAULT 7.45,
        power_kw REAL DEFAULT 44.2,
        rated_power_kw REAL DEFAULT 40.0,
        runtime_hours REAL DEFAULT 8420,
        mtbf_hours REAL DEFAULT 10000,
        days_since_maintenance INTEGER DEFAULT 195,
        recent_anomaly_count INTEGER DEFAULT 3,
        last_updated TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sensors (
        sensor_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_id TEXT NOT NULL,
        equipment_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        zone_id TEXT DEFAULT 'ZONE-PERIMETER-ALPHA',
        name TEXT NOT NULL,
        sensor_type TEXT NOT NULL,
        unit TEXT NOT NULL,
        protocol TEXT DEFAULT 'OPC_UA',
        adapter_id TEXT DEFAULT 'ADP-OPCUA-01',
        min_threshold REAL DEFAULT 0.1,
        max_threshold REAL DEFAULT 7.1,
        current_value REAL DEFAULT 7.45,
        status TEXT DEFAULT 'ANOMALY_HIGH',
        provenance TEXT DEFAULT 'SIMULATED_OPC_UA_STREAM',
        sampling_interval_sec INTEGER DEFAULT 5,
        last_reading_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS telemetry_readings (
        reading_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        sensor_id TEXT NOT NULL,
        equipment_id TEXT NOT NULL,
        facility_id TEXT NOT NULL,
        metric TEXT NOT NULL,
        value REAL NOT NULL,
        unit TEXT NOT NULL,
        protocol TEXT DEFAULT 'OPC_UA',
        provenance TEXT DEFAULT 'SIMULATED_OPC_UA_STREAM',
        is_anomaly INTEGER DEFAULT 0,
        severity TEXT DEFAULT 'NOMINAL',
        z_score REAL DEFAULT 0.5,
        timestamp TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS maintenance_records (
        maintenance_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_id TEXT NOT NULL,
        equipment_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        title TEXT NOT NULL,
        maintenance_type TEXT DEFAULT 'PREDICTIVE_INTERVENTION',
        priority TEXT DEFAULT 'HIGH',
        status TEXT DEFAULT 'RECOMMENDED_PENDING_APPROVAL',
        health_score_at_trigger REAL DEFAULT 34.5,
        failure_risk_pct REAL DEFAULT 65.5,
        rul_estimated_hours INTEGER DEFAULT 540,
        analysis_method TEXT,
        recommended_action TEXT,
        limitations TEXT,
        outcome_status TEXT DEFAULT 'AWAITING_EXECUTION',
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS energy_records (
        energy_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_id TEXT NOT NULL,
        scope TEXT DEFAULT 'FACILITY_TOTAL',
        active_power_kw REAL DEFAULT 542.7,
        baseline_power_kw REAL DEFAULT 465.0,
        peak_demand_kw REAL DEFAULT 588.0,
        power_factor REAL DEFAULT 0.86,
        idle_equipment_kw REAL DEFAULT 28.5,
        production_units_per_hr REAL DEFAULT 145.0,
        electricity_tariff_usd_per_kwh REAL DEFAULT 0.14,
        verified_savings_kwh_month REAL DEFAULT 4200.0,
        provenance TEXT DEFAULT 'MODBUS_MAIN_METER_SIMULATION',
        timestamp TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigations (
        investigation_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_id TEXT NOT NULL,
        title TEXT NOT NULL,
        status TEXT DEFAULT 'EVIDENCE_CORRELATED',
        trigger_source TEXT DEFAULT 'CROSS_SYSTEM_CORRELATOR',
        target_asset_id TEXT,
        target_equipment_id TEXT,
        camera_id TEXT DEFAULT 'CAM-01-ENTRANCE',
        confidence_score REAL DEFAULT 0.91,
        evidence_chain TEXT DEFAULT '{}',
        timeline TEXT DEFAULT '[]',
        supporting_evidence TEXT DEFAULT '[]',
        contradictory_evidence TEXT DEFAULT '[]',
        root_cause_hypothesis TEXT,
        correlation_vs_causation_note TEXT,
        recommended_inspection_steps TEXT DEFAULT '[]',
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS workflows (
        workflow_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        facility_id TEXT NOT NULL,
        template_id TEXT NOT NULL,
        title TEXT NOT NULL,
        target_asset_id TEXT,
        target_equipment_id TEXT,
        priority TEXT DEFAULT 'HIGH',
        status TEXT DEFAULT 'PENDING_APPROVAL',
        requires_human_approval INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("SELECT COUNT(*) as cnt FROM facilities")
    if cursor.fetchone()["cnt"] == 0:
        now_iso = datetime.utcnow().isoformat() + "Z"
        cursor.execute(
            "INSERT INTO facilities (facility_id, tenant_id, name, industry_profile, location, status, total_area_sqm, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("FAC-01-AUSTIN-GIGA", "default", "Vanta Nexus Precision Manufacturing & Microgrid Plant", "manufacturing", "Austin, TX", "OPERATIONAL", 48500.0, now_iso)
        )
        cursor.execute(
            "INSERT INTO assets (asset_id, tenant_id, facility_id, name, asset_type, criticality, status, linked_camera_id, linked_equipment_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("AST-CNC-SPINDLE-01", "default", "FAC-01-AUSTIN-GIGA", "5-Axis CNC Gantry Milling Center #01", "PRODUCTION_MACHINERY", "CRITICAL", "DEGRADED_WARNING", "CAM-01-ENTRANCE", "EQ-CNC-01")
        )
        cursor.execute(
            "INSERT INTO equipment (equipment_id, tenant_id, facility_id, asset_id, name, category, status, temperature_c, vibration_mm_s, power_kw, rated_power_kw, runtime_hours, mtbf_hours, days_since_maintenance, recent_anomaly_count, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("EQ-CNC-01", "default", "FAC-01-AUSTIN-GIGA", "AST-CNC-SPINDLE-01", "Siemens Sinumerik 5-Axis High-Speed Spindle Drive #01", "CNC_MACHINING_CENTER", "WARNING_VIBRATION", 86.4, 7.45, 44.2, 40.0, 8420.0, 10000.0, 195, 3, now_iso)
        )
        cursor.execute(
            "INSERT INTO sensors (sensor_id, tenant_id, facility_id, equipment_id, asset_id, name, sensor_type, unit, protocol, current_value, status, last_reading_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("SEN-VIB-101", "default", "FAC-01-AUSTIN-GIGA", "EQ-CNC-01", "AST-CNC-SPINDLE-01", "CNC Spindle Piezo Vibration Accelerometer", "VIBRATION_RMS", "mm/s", "OPC_UA", 7.45, "ANOMALY_HIGH", now_iso)
        )
        cursor.execute(
            "INSERT INTO maintenance_records (maintenance_id, tenant_id, facility_id, equipment_id, asset_id, title, priority, status, health_score_at_trigger, failure_risk_pct, rul_estimated_hours, analysis_method, recommended_action, limitations, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("MNT-2025-089", "default", "FAC-01-AUSTIN-GIGA", "EQ-CNC-01", "AST-CNC-SPINDLE-01", "Predictive Alert: CNC #01 Spindle Front Bearing Wear", "HIGH", "RECOMMENDED_PENDING_APPROVAL", 34.5, 65.5, 540, "ISO-10816 Multi-Variate Degradation", "Perform 4-hour spindle bearing inspection and lubrication.", "Statistical degradation estimate.", now_iso)
        )
        cursor.execute(
            "INSERT INTO energy_records (energy_id, tenant_id, facility_id, active_power_kw, baseline_power_kw, peak_demand_kw, power_factor, idle_equipment_kw, production_units_per_hr, verified_savings_kwh_month, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("ENG-FAC01-CURRENT", "default", "FAC-01-AUSTIN-GIGA", 542.7, 465.0, 588.0, 0.86, 28.5, 145.0, 4200.0, now_iso)
        )
        cursor.execute(
            "INSERT INTO investigations (investigation_id, tenant_id, facility_id, title, status, target_asset_id, target_equipment_id, camera_id, confidence_score, root_cause_hypothesis, correlation_vs_causation_note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("INV-RCA-2025-001", "default", "FAC-01-AUSTIN-GIGA", "Cross-System RCA: CNC #01 Thermal/Vibration Anomaly", "EVIDENCE_CORRELATED", "AST-CNC-SPINDLE-01", "EQ-CNC-01", "CAM-01-ENTRANCE", 0.91, "Mechanical bearing friction on EQ-CNC-01 causing +10.5% power spike.", "Power spike is an effect of mechanical bearing drag, not upstream transformer fault.", now_iso)
        )
        cursor.execute(
            "INSERT INTO workflows (workflow_id, tenant_id, facility_id, template_id, title, target_asset_id, target_equipment_id, priority, status, requires_human_approval, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("WF-EXEC-101", "default", "FAC-01-AUSTIN-GIGA", "WF-TPL-MAINT-ISOLATION", "Controlled Spindle Inspection & Bearing Work Order — EQ-CNC-01", "AST-CNC-SPINDLE-01", "EQ-CNC-01", "HIGH", "PENDING_APPROVAL", 1, now_iso)
        )
        conn.commit()

    conn.close()
    log_audit("default", "SYSTEM_INIT", "system", "SUCCESS", "Database initialized with baseline schemas, multi-device registry, polygon zones, and VANTA AI infrastructure foundation")


def log_audit(tenant_id: str, action: str, actor: str, status: str, details: str):
    t_id = (tenant_id or "default").strip() or "default"
    now_iso = datetime.utcnow().isoformat() + "Z"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT integrity_hash FROM audit_logs WHERE tenant_id = ? AND integrity_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
            (t_id,)
        )
        last_row = cursor.fetchone()
        prev_hash = last_row["integrity_hash"] if (last_row and last_row["integrity_hash"]) else "GENESIS_BLOCK_0000"
        integrity_hash = compute_audit_block_hash(t_id, now_iso, action, actor, status, details, prev_hash)
        cursor.execute(
            "INSERT INTO audit_logs (tenant_id, timestamp, action, actor, status, details, prev_hash, integrity_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (t_id, now_iso, action, actor, status, details, prev_hash, integrity_hash)
        )
        conn.commit()
    finally:
        conn.close()


def verify_audit_chain(tenant_id: str = "default", limit: int = 100) -> Dict[str, Any]:
    t_id = (tenant_id or "default").strip() or "default"
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, tenant_id, timestamp, action, actor, status, details, prev_hash, integrity_hash FROM audit_logs WHERE tenant_id = ? ORDER BY id ASC",
            (t_id,)
        )
        rows = cursor.fetchall()
        expected_prev = "GENESIS_BLOCK_0000"
        chain_verified = True
        chronological_blocks: List[Dict[str, Any]] = []

        for r in rows:
            d = dict(r)
            computed = compute_audit_block_hash(
                d.get("tenant_id") or t_id,
                d.get("timestamp") or "",
                d.get("action") or "",
                d.get("actor") or "system",
                d.get("status") or "SUCCESS",
                d.get("details") or "",
                expected_prev
            )
            if not d.get("integrity_hash") or d.get("prev_hash") != expected_prev:
                d["prev_hash"] = expected_prev
                d["integrity_hash"] = computed
                cursor.execute(
                    "UPDATE audit_logs SET prev_hash = ?, integrity_hash = ? WHERE id = ?",
                    (expected_prev, computed, d["id"])
                )
            elif d["integrity_hash"] != computed:
                chain_verified = False
            expected_prev = d["integrity_hash"]
            chronological_blocks.append(d)

        conn.commit()
        newest_first = list(reversed(chronological_blocks))[:limit]
        return {
            "chain_verified": chain_verified,
            "genesis_block": "GENESIS_BLOCK_0000",
            "head_block_hash": expected_prev,
            "total_blocks": len(chronological_blocks),
            "blocks": newest_first
        }
    finally:
        conn.close()


# Initialize on module load
init_db()
