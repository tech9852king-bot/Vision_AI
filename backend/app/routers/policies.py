"""Policies Router for VantaVisionAI Funding Prototype"""
from fastapi import APIRouter, HTTPException, Depends, Header
from typing import List, Optional
import uuid

from backend.app.schemas import PolicyResponse, PolicyToggleRequest, PolicyCreate
from backend.app.database import get_connection, log_audit
from backend.app.routers.brain import get_tenant_id

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])

@router.get("", response_model=List[PolicyResponse])
async def list_policies(tenant_id: str = Depends(get_tenant_id)):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT id, tenant_id, name, target_class, condition, severity, enabled, description FROM policies WHERE tenant_id = ? ORDER BY id ASC",
            (tenant_id,)
        )
        rows = cursor.fetchall()
        return [
            PolicyResponse(
                id=r["id"],
                tenant_id=r["tenant_id"],
                name=r["name"],
                target_class=r["target_class"],
                condition=r["condition"],
                severity=r["severity"],
                enabled=bool(r["enabled"]),
                description=r["description"]
            )
            for r in rows
        ]
    finally:
        conn.close()

@router.post("", response_model=PolicyResponse, status_code=201)
async def create_policy(
    body: PolicyCreate,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    pol_id = f"pol_{uuid.uuid4().hex[:8]}"
    severity = (body.severity or "MEDIUM").upper()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO policies (id, tenant_id, name, target_class, condition, severity, enabled, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (pol_id, tenant_id, body.name, body.target_class, body.condition, severity, 1 if body.enabled else 0, body.description)
        )
        conn.commit()

        actor = "authenticated_user" if authorization else "security_admin"
        log_audit(tenant_id, "POLICY_CREATED", actor, "SUCCESS", f"Created policy {pol_id} ('{body.name}')")

        return PolicyResponse(
            id=pol_id,
            tenant_id=tenant_id,
            name=body.name,
            target_class=body.target_class,
            condition=body.condition,
            severity=severity,
            enabled=body.enabled,
            description=body.description
        )
    finally:
        conn.close()

@router.put("/{policy_id}/toggle")
async def toggle_policy(
    policy_id: str,
    body: PolicyToggleRequest,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, name FROM policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Policy not found")

        cursor.execute(
            "UPDATE policies SET enabled = ? WHERE id = ? AND tenant_id = ?",
            (1 if body.enabled else 0, policy_id, tenant_id)
        )
        conn.commit()

        actor = "authenticated_user" if authorization else "security_admin"
        action = "POLICY_ENABLED" if body.enabled else "POLICY_DISABLED"
        log_audit(tenant_id, action, actor, "SUCCESS", f"Policy {policy_id} ('{row['name']}') state changed to {body.enabled}")

        return {"status": "SUCCESS", "policy_id": policy_id, "enabled": body.enabled}
    finally:
        conn.close()

@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: str,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, name FROM policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Policy not found")

        cursor.execute("DELETE FROM policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id))
        conn.commit()

        actor = "authenticated_user" if authorization else "security_admin"
        log_audit(tenant_id, "POLICY_DELETED", actor, "SUCCESS", f"Deleted policy {policy_id} ('{row['name']}')")

        return {"status": "SUCCESS", "deleted_policy_id": policy_id, "tenant_id": tenant_id}
    finally:
        conn.close()
