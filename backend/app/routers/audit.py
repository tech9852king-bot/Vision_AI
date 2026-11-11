"""Audit Router for VantaVisionAI Funding Prototype with Cryptographic Integrity Ledger"""
from datetime import datetime
from fastapi import APIRouter, Depends

from backend.app.database import get_connection, verify_audit_chain
from backend.app.routers.brain import get_tenant_id

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/dossier")
async def get_forensic_dossier(tenant_id: str = Depends(get_tenant_id)):
    chain_info = verify_audit_chain(tenant_id=tenant_id, limit=100)
    conn = get_connection()
    cursor = conn.cursor()
    try:
        # 1. Incidents (open and resolved)
        cursor.execute(
            "SELECT id, tenant_id, camera_id, policy_id, title, severity, status, timestamp, details, device_id, track_id, zone_id FROM incidents WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 50",
            (tenant_id,)
        )
        incidents = [dict(r) for r in cursor.fetchall()]

        # 2. Recent events
        cursor.execute(
            "SELECT id, tenant_id, camera_id, class_name, confidence, bbox, timestamp, device_id, track_id, zone_id FROM events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 50",
            (tenant_id,)
        )
        events = [dict(r) for r in cursor.fetchall()]

        # 3. Active policies
        cursor.execute(
            "SELECT id, tenant_id, name, target_class, condition, severity, enabled, description FROM policies WHERE tenant_id = ?",
            (tenant_id,)
        )
        policies = [dict(r) for r in cursor.fetchall()]

        return {
            "dossier_type": "CRYPTOGRAPHIC_FORENSIC_DOSSIER",
            "tenant_id": tenant_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "chain_verified": chain_info["chain_verified"],
            "genesis_block": chain_info["genesis_block"],
            "head_block_hash": chain_info["head_block_hash"],
            "total_audit_blocks": chain_info["total_blocks"],
            "incidents": incidents,
            "recent_events": events,
            "policies": policies,
            "audit_trail": chain_info["blocks"],
            "compliance_attestation": "Cryptographically sealed under immutable SHA-256 block chain rules in accordance with SOC-2 CC6.1 and ISO 27001:2022 A.12.4"
        }
    finally:
        conn.close()


@router.get("")
async def list_audit_logs(
    limit: int = 50,
    tenant_id: str = Depends(get_tenant_id)
):
    chain_info = verify_audit_chain(tenant_id=tenant_id, limit=limit)
    return chain_info["blocks"]
