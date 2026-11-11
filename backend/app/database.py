"""
Database module for VantaVisionAI Next-Generation Multi-Device Platform.
Uses SQLite for zero-configuration, robust local persistence.
Provides tenant isolation, multi-device registry, polygon zone intelligence,
idempotent event provenance, and cryptographic audit logging.
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

    # Ensure backward-compatible migration if events table already existed
    _ensure_column(cursor, "events", "device_id", "TEXT DEFAULT 'DEV-LOCAL-CONSOLE'")
    _ensure_column(cursor, "events", "track_id", "TEXT")
    _ensure_column(cursor, "events", "zone_id", "TEXT DEFAULT 'ZONE-01-PERIMETER'")
    _ensure_column(cursor, "events", "detection_model", "TEXT DEFAULT 'COCO-SSD-MobileNetV2'")
    _ensure_column(cursor, "events", "processing_device", "TEXT DEFAULT 'edge_browser_wasm_webgl'")
    _ensure_column(cursor, "events", "processing_latency_ms", "REAL DEFAULT 0.0")

    # 2. Incidents table
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
        zone_id TEXT DEFAULT 'ZONE-01-PERIMETER',
        details TEXT
    )
    """)
    _ensure_column(cursor, "incidents", "device_id", "TEXT DEFAULT 'DEV-LOCAL-CONSOLE'")
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

    # 4. Audit Logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT 'system',
        status TEXT NOT NULL,
        details TEXT
    )
    """)

    # 5. Centralized Multi-Device Registry table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        name TEXT NOT NULL,
        device_type TEXT NOT NULL DEFAULT 'mobile',
        role TEXT NOT NULL DEFAULT 'CAMERA_NODE',
        camera_id TEXT NOT NULL,
        facing_mode TEXT DEFAULT 'environment',
        status TEXT NOT NULL DEFAULT 'ONLINE',
        capabilities TEXT DEFAULT '["webcam","coco-ssd","webrtc"]',
        stream_mode TEXT DEFAULT 'METADATA_ONLY',
        battery_pct INTEGER DEFAULT 100,
        latency_ms REAL DEFAULT 15.0,
        last_heartbeat TEXT NOT NULL,
        paired_via TEXT DEFAULT 'DIRECT_REGISTER',
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )
    """)
    _ensure_column(cursor, "devices", "id", "TEXT")
    _ensure_column(cursor, "devices", "name", "TEXT")
    _ensure_column(cursor, "devices", "device_type", "TEXT DEFAULT 'mobile'")
    _ensure_column(cursor, "devices", "role", "TEXT DEFAULT 'CAMERA_NODE'")
    _ensure_column(cursor, "devices", "camera_id", "TEXT DEFAULT 'CAM-01'")
    _ensure_column(cursor, "devices", "facing_mode", "TEXT DEFAULT 'environment'")
    _ensure_column(cursor, "devices", "status", "TEXT DEFAULT 'ONLINE'")
    _ensure_column(cursor, "devices", "capabilities", "TEXT DEFAULT '[\"webcam\",\"coco-ssd\",\"webrtc\"]'")
    _ensure_column(cursor, "devices", "stream_mode", "TEXT DEFAULT 'METADATA_ONLY'")
    _ensure_column(cursor, "devices", "battery_pct", "INTEGER DEFAULT 100")
    _ensure_column(cursor, "devices", "latency_ms", "REAL DEFAULT 15.0")
    _ensure_column(cursor, "devices", "last_heartbeat", "TEXT")
    _ensure_column(cursor, "devices", "paired_via", "TEXT DEFAULT 'DIRECT_REGISTER'")
    _ensure_column(cursor, "devices", "revoked", "INTEGER DEFAULT 0")
    _ensure_column(cursor, "devices", "created_at", "TEXT")

    # 6. Single-Use Expiring Device Pairing Sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pairing_sessions (
        code TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        role TEXT NOT NULL DEFAULT 'CAMERA_NODE',
        target_label TEXT DEFAULT 'Mobile Camera Node',
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        claimed_by_device_id TEXT,
        created_at TEXT NOT NULL
    )
    """)
    _ensure_column(cursor, "pairing_sessions", "code", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "id", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "role", "TEXT DEFAULT 'CAMERA_NODE'")
    _ensure_column(cursor, "pairing_sessions", "target_label", "TEXT DEFAULT 'Mobile Camera Node'")
    _ensure_column(cursor, "pairing_sessions", "expires_at", "TEXT")
    _ensure_column(cursor, "pairing_sessions", "used", "INTEGER DEFAULT 0")
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
        color TEXT NOT NULL DEFAULT '#f43f5e',
        max_occupancy INTEGER NOT NULL DEFAULT 3,
        max_dwell_sec INTEGER NOT NULL DEFAULT 30,
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
    _ensure_column(cursor, "zones", "color", "TEXT DEFAULT '#f43f5e'")
    _ensure_column(cursor, "zones", "max_occupancy", "INTEGER DEFAULT 3")
    _ensure_column(cursor, "zones", "max_dwell_sec", "INTEGER DEFAULT 30")
    _ensure_column(cursor, "zones", "enabled", "INTEGER DEFAULT 1")
    _ensure_column(cursor, "zones", "created_at", "TEXT")

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
            ("inc_001", "default", now_iso, "After-Hours Perimeter Breach Detected", "HIGH", "OPEN", "pol_person_after_hours", "CAM-01-ENTRANCE", "DEV-NODE-01", "ZONE-01-PERIMETER", "Human presence observed at entrance gate outside operational schedule."),
            ("inc_002", "default", now_iso, "Stationary Baggage in Transit Hallway", "MEDIUM", "OPEN", "pol_unattended_bag", "CAM-02-LOBBY", "DEV-NODE-02", "ZONE-02-LOBBY", "Unattended backpack identified near central elevator column.")
        ]
        cursor.executemany(
            "INSERT INTO incidents (id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, device_id, zone_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            default_incidents
        )
        conn.commit()

    # Seed default registered devices if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM devices")
    if cursor.fetchone()["cnt"] == 0:
        now_iso = datetime.utcnow().isoformat() + "Z"
        default_devices = [
            ("DEV-CONSOLE-PRIMARY", "default", "Primary Command Workstation", "desktop", "CENTRAL_COMMAND", "BROWSER-SCANNER", "user", "ONLINE", '["webcam","coco-ssd","webrtc","aleana-voice"]', "LIVE_WEBRTC", 100, 4.0, now_iso, "SYSTEM_DEFAULT", 0, now_iso),
            ("DEV-MOBILE-ALPHA", "default", "Patrol Unit Alpha (Android)", "mobile", "CAMERA_NODE", "CAM-01-ENTRANCE", "environment", "ONLINE", '["webcam","coco-ssd","webrtc"]', "WEBRTC_READY", 86, 32.0, now_iso, "QR_CODE", 0, now_iso),
            ("DEV-TABLET-LOBBY", "default", "Executive Lobby Kiosk (iPad)", "tablet", "CAMERA_NODE", "CAM-02-LOBBY", "environment", "ONLINE", '["webcam","coco-ssd","webrtc"]', "METADATA_ONLY", 94, 28.0, now_iso, "DIRECT_REGISTER", 0, now_iso)
        ]
        cursor.executemany(
            """INSERT INTO devices (
                id, tenant_id, name, device_type, role, camera_id, facing_mode,
                status, capabilities, stream_mode, battery_pct, latency_ms,
                last_heartbeat, paired_via, revoked, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            default_devices
        )
        conn.commit()

    # Seed default polygon zones if empty
    cursor.execute("SELECT COUNT(*) as cnt FROM zones")
    if cursor.fetchone()["cnt"] == 0:
        now_iso = datetime.utcnow().isoformat() + "Z"
        default_zones = [
            ("ZONE-01-PERIMETER", "default", "North Gate Restricted Perimeter", "CAM-01-ENTRANCE", "RESTRICTED", "HIGH", json.dumps([[0.25, 0.28], [0.75, 0.28], [0.75, 0.88], [0.25, 0.88]]), "#f43f5e", 2, 8, 1, now_iso),
            ("ZONE-02-LOBBY", "default", "Executive Elevator Transit Zone", "CAM-02-LOBBY", "LOITERING_WATCH", "MEDIUM", json.dumps([[0.15, 0.35], [0.85, 0.35], [0.85, 0.90], [0.15, 0.90]]), "#00e5ff", 5, 15, 1, now_iso),
            ("ZONE-03-DOCK", "default", "Loading Dock Vehicular Bay", "CAM-03-PARKING", "VEHICLE_ONLY", "CRITICAL", json.dumps([[0.10, 0.20], [0.90, 0.20], [0.90, 0.85], [0.10, 0.85]]), "#f59e0b", 2, 30, 1, now_iso)
        ]
        cursor.executemany(
            """INSERT INTO zones (
                id, tenant_id, name, camera_id, zone_type, severity, polygon,
                color, max_occupancy, max_dwell_sec, enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            default_zones
        )
        conn.commit()

    # Log system init audit
    log_audit("default", "SYSTEM_INIT", "system", "SUCCESS", "Database initialized with baseline schemas, multi-device registry, and polygon zones")
    conn.close()


def log_audit(tenant_id: str, action: str, actor: str, status: str, details: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (tenant_id, timestamp, action, actor, status, details) VALUES (?, ?, ?, ?, ?, ?)",
        (tenant_id, datetime.utcnow().isoformat() + "Z", action, actor, status, details)
    )
    conn.commit()
    conn.close()


# Initialize on module load
init_db()
