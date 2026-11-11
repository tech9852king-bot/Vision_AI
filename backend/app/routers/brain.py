"""
Controlled Brain Command Interface & Approved Tool Registry Router
Enforces strict allowlisting, parameter validation, role checking, and audit logging.
No shell execution, no arbitrary SQL, no raw credential exposure.
"""
from fastapi import APIRouter, Header, HTTPException, Request, Depends
from datetime import datetime
from typing import Optional, Dict, Any, List

from backend.app.schemas import (
    BrainCommandRequest,
    BrainCommandResponse,
    BrainToolListResponse,
    BrainToolItem,
    BrainToolExecuteRequest,
    BrainToolExecuteResponse
)
from backend.app.core_brain import ALLOWLISTED_COMMANDS
from backend.app.brain_service import BrainService
from backend.app.brain_tools import GLOBAL_TOOL_REGISTRY
from backend.app.auth import get_auth_context

router = APIRouter(prefix="/api/v1/brain", tags=["brain"])

def get_tenant_id(
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
) -> str:
    ctx = get_auth_context(authorization=authorization, x_tenant_id=x_tenant_id)
    return getattr(ctx, "tenant_id", None) or (ctx["tenant_id"] if "tenant_id" in ctx else "default")


@router.post("", response_model=BrainCommandResponse)
async def execute_brain_command(
    request: BrainCommandRequest,
    req: Request,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    actor = "authenticated_user" if authorization else "operator"
    success, result_data = BrainService.process_command(
        command_str=request.command,
        args=request.args,
        tenant_id=tenant_id,
        actor=actor,
        tool_name=request.tool
    )

    timestamp = datetime.utcnow().isoformat() + "Z"

    if not success:
        raise HTTPException(
            status_code=400,
            detail=result_data
        )

    execution_time_ms = result_data.get("execution_time_ms") if isinstance(result_data, dict) else None

    return BrainCommandResponse(
        command=request.command.strip().lower() if request.command else (f"tool:{request.tool}" if request.tool else ""),
        status="SUCCESS",
        result=result_data,
        timestamp=timestamp,
        tenant_id=tenant_id,
        execution_time_ms=execution_time_ms,
        provider="SIMULATED",
        real_camera_configured=False
    )

@router.get("/tools", response_model=BrainToolListResponse)
async def list_brain_tools(tenant_id: str = Depends(get_tenant_id)):
    """
    Returns the introspection schema of all approved tools in the VantaVisionAI Brain.
    """
    tools = GLOBAL_TOOL_REGISTRY.list_tools()
    return BrainToolListResponse(
        tools=[BrainToolItem(**t) for t in tools],
        count=len(tools),
        timestamp=datetime.utcnow().isoformat() + "Z"
    )

@router.get("/tools/{tool_name}", response_model=BrainToolItem)
async def get_brain_tool_detail(tool_name: str, tenant_id: str = Depends(get_tenant_id)):
    """
    Retrieves the parameter specification and permission requirements for a specific tool.
    """
    tool = GLOBAL_TOOL_REGISTRY.get(tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found in approved registry.")
    return BrainToolItem(**tool.to_dict())

@router.post("/tools/{tool_name}", response_model=BrainToolExecuteResponse)
async def execute_brain_tool(
    tool_name: str,
    request: BrainToolExecuteRequest,
    tenant_id: str = Depends(get_tenant_id),
    authorization: Optional[str] = Header(None)
):
    """
    Directly executes an approved tool with argument validation and audit recording.
    """
    actor = "authenticated_user" if authorization else "operator"
    tool_res = GLOBAL_TOOL_REGISTRY.execute_tool(
        name=tool_name,
        args=request.args,
        tenant_id=tenant_id,
        actor=actor
    )

    timestamp = datetime.utcnow().isoformat() + "Z"

    if tool_res["status"] != "SUCCESS":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "TOOL_EXECUTION_FAILED",
                "tool": tool_name,
                "message": tool_res.get("error"),
                "timestamp": timestamp
            }
        )

    return BrainToolExecuteResponse(
        status="SUCCESS",
        tool=tool_name,
        category=tool_res.get("category"),
        data=tool_res.get("data"),
        execution_time_ms=tool_res.get("execution_time_ms", 0.0),
        error=None,
        timestamp=timestamp
    )
