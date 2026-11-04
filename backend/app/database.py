"""
Database module for VantaVisionAI Funding Prototype.
Uses SQLite for zero-configuration, robust local persistence.
Provides tenant isolation and audit logging.
"""
import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

def get_db_path() -> str:
    if "DATABASE_PATH" in os.environ:
        return os.environ["DATABASE_PATH"]
    db_url = os.environ.get("DATABASE_URL", "")
    if db_url.startswith("sqlite:///"):
        return db_url.replace("sqlite:///", "")
    return "vanta_vision.db"

DB_PATH = get_db_path()

def get_connection():
    conn = sqlite3.connect(get_db_path(), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Events table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL DEFAULT 'default',
        timestamp TEXT NOT NULL,
        camera_id TEXT NOT NULL,
        class_name TEXT NOT NULL,
        confidence REAL NOT NULL,
        bbox TEXT,
        metadata TEXT
    )
    """)

    # Incidents table
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
        details TEXT
    )
    """)

    # Policies table
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

    # Audit Logs table
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
        default_incidents = [
            ("inc_001", "default", datetime.utcnow().isoformat() + "Z", "After-Hours Perimeter Breach Detected", "HIGH", "OPEN", "pol_person_after_hours", "CAM-01-ENTRANCE", "Human presence observed at entrance gate outside operational schedule."),
            ("inc_002", "default", datetime.utcnow().isoformat() + "Z", "Stationary Baggage in Transit Hallway", "MEDIUM", "OPEN", "pol_unattended_bag", "CAM-02-LOBBY", "Unattended backpack identified near central elevator column.")
        ]
        cursor.executemany(
            "INSERT INTO incidents (id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            default_incidents
        )
        conn.commit()

    # Log system init audit
    log_audit("default", "SYSTEM_INIT", "system", "SUCCESS", "Database initialized with baseline schemas and policies")
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
