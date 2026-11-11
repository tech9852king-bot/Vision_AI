"""Pydantic schemas for VantaVisionAI Next-Generation Multi-Device Platform"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class BrainCommandRequest(BaseModel):
    command: str = Field(..., description="Allowlisted Brain command name: help, status, capabilities, summary, incidents, policies, cameras, devices, zones, events, diagnostics, audit, troubleshoot, tools")
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
    event_id: Optional[str] = None
    device_id: Optional[str] = "DEV-LOCAL-CONSOLE"
    camera_id: str = "BROWSER-SCANNER"
    class_name: str
    confidence: float
    bbox: Optional[List[float]] = None
    track_id: Optional[str] = None
    zone_id: Optional[str] = "ZONE-01-PERIMETER"
    detection_model: Optional[str] = "COCO-SSD-MobileNetV2"
    processing_device: Optional[str] = "edge_browser_wasm_webgl"
    processing_latency_ms: Optional[float] = 0.0
    metadata: Optional[Dict[str, Any]] = None


class EventResponse(BaseModel):
    id: str
    tenant_id: str
    device_id: Optional[str] = "DEV-LOCAL-CONSOLE"
    timestamp: str
    camera_id: str
    class_name: str
    confidence: float
    bbox: Optional[List[float]] = None
    track_id: Optional[str] = None
    zone_id: Optional[str] = "ZONE-01-PERIMETER"
    detection_model: Optional[str] = "COCO-SSD-MobileNetV2"
    processing_device: Optional[str] = "edge_browser_wasm_webgl"
    processing_latency_ms: Optional[float] = 0.0


class IncidentResponse(BaseModel):
    id: str
    tenant_id: str
    timestamp: str
    title: str
    severity: str
    status: str
    policy_id: Optional[str] = None
    camera_id: Optional[str] = None
    device_id: Optional[str] = None
    zone_id: Optional[str] = None
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


class DeviceRegisterRequest(BaseModel):
    device_id: Optional[str] = None
    display_name: str = Field(default="Mobile Camera Node")
    device_category: str = Field(default="Smartphone")
    os_info: Optional[str] = Field(default="Mobile OS")
    browser_info: Optional[str] = Field(default="Mobile Browser")
    camera_capabilities: Optional[List[str]] = Field(default_factory=lambda: ["user", "environment"])
    active_camera_id: Optional[str] = Field(default="CAM-MOBILE-01")
    assigned_workspace: Optional[str] = Field(default="Primary SOC")
    assigned_zone: Optional[str] = Field(default="ZONE-01-PERIMETER")
    permission_profile: Optional[str] = Field(default="CAMERA_PUBLISHER")


class PairingCreateRequest(BaseModel):
    assigned_zone: Optional[str] = "ZONE-01-PERIMETER"
    assigned_workspace: Optional[str] = "Primary SOC"
    permission_profile: Optional[str] = "CAMERA_PUBLISHER"
    ttl_seconds: Optional[int] = 300


class PairingClaimRequest(BaseModel):
    pairing_code: str
    display_name: Optional[str] = "Paired Camera Client"
    device_category: Optional[str] = "Smartphone"
    os_info: Optional[str] = "Mobile OS"
    browser_info: Optional[str] = "PWA Client"
    camera_capabilities: Optional[List[str]] = Field(default_factory=lambda: ["user", "environment"])
    active_camera_id: Optional[str] = "CAM-PAIRED-01"


class DeviceHeartbeatRequest(BaseModel):
    stream_status: Optional[str] = "METADATA_EDGE"
    detection_status: Optional[str] = "ACTIVE"
    active_camera_id: Optional[str] = None
    battery_level: Optional[int] = 100
    avg_latency_ms: Optional[float] = 32.0


class ZoneCreateRequest(BaseModel):
    name: str
    zone_type: Optional[str] = "RESTRICTED"
    camera_id: Optional[str] = "CAM-01-ENTRANCE"
    polygon_points: List[List[float]] = Field(default_factory=lambda: [[0.2, 0.2], [0.8, 0.2], [0.8, 0.8], [0.2, 0.8]])
    dwell_threshold_sec: Optional[int] = 10
    max_occupancy: Optional[int] = 3
    severity: Optional[str] = "HIGH"
    color: Optional[str] = "#f43f5e"
    enabled: Optional[bool] = True
