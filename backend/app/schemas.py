"""Pydantic schemas for VantaVisionAI Funding Prototype"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class BrainCommandRequest(BaseModel):
    command: str = Field(..., description="Allowlisted Brain command name: help, status, capabilities, summary, incidents, policies, cameras, events, diagnostics, audit, troubleshoot, tools")
    args: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional command arguments")
    tool: Optional[str] = Field(default=None, description="Optional direct tool name to execute")

class BrainCommandResponse(BaseModel):
    command: str
    status: str
    result: Any
    timestamp: str
    tenant_id: str
    execution_time_ms: Optional[float] = None
    provider: str = "SIMULATED"
    real_camera_configured: bool = False

class BrainToolItem(BaseModel):
    name: str
    description: str
    category: str
    permission: str
    parameters: Dict[str, Any]
    is_destructive: bool
    timeout_seconds: float

class BrainToolListResponse(BaseModel):
    tools: List[BrainToolItem]
    count: int
    timestamp: str

class BrainToolExecuteRequest(BaseModel):
    args: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Tool execution arguments")

class BrainToolExecuteResponse(BaseModel):
    status: str
    tool: str
    category: Optional[str] = None
    data: Any = None
    execution_time_ms: float
    error: Optional[str] = None
    timestamp: str

class EventCreate(BaseModel):
    camera_id: str = "BROWSER-SCANNER"
    class_name: str
    confidence: float
    bbox: Optional[List[float]] = None
    metadata: Optional[Dict[str, Any]] = None

class EventResponse(BaseModel):
    id: str
    tenant_id: str
    timestamp: str
    camera_id: str
    class_name: str
    confidence: float
    bbox: Optional[List[float]] = None

class IncidentResponse(BaseModel):
    id: str
    tenant_id: str
    timestamp: str
    title: str
    severity: str
    status: str
    policy_id: Optional[str] = None
    camera_id: Optional[str] = None
    details: Optional[str] = None

class PolicyResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    target_class: str
    condition: str
    severity: str
    enabled: bool
    description: Optional[str] = None

class PolicyToggleRequest(BaseModel):
    enabled: bool

class PolicyCreate(BaseModel):
    name: str = Field(..., description="Policy rule name")
    target_class: str = Field(default="person", description="Target object class")
    condition: str = Field(default="confidence > 0.70", description="Trigger condition")
    severity: str = Field(default="MEDIUM", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    enabled: bool = Field(default=True, description="Enforcement state")
    description: Optional[str] = Field(default="", description="Rule description")

class CopilotQueryRequest(BaseModel):
    query: str
    context: Optional[str] = None
    live_context: Optional[Dict[str, Any]] = None
    conversation_history: Optional[List[Dict[str, str]]] = None

class DemoRunRequest(BaseModel):
    scenario: Optional[str] = "intrusion"
    camera_id: Optional[str] = "DEMO-CAM-01"
