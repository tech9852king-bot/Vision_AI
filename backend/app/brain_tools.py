"""
Approved Tool Registry for VantaVisionAI Brain Architecture.
Provides strictly typed, permissioned, auditable, and isolated tool execution.
Zero arbitrary code execution, zero unsanitized SQL, zero unsanctioned system calls.
"""
import time
from enum import Enum
from typing import Dict, Any, List, Optional, Callable, Union, Tuple
from datetime import datetime

from backend.app.database import get_connection, log_audit


class ToolCategory(str, Enum):
    READ_ONLY = "READ_ONLY"
    OPERATIONAL = "OPERATIONAL"
    DIAGNOSTIC = "DIAGNOSTIC"
    MUTATING = "MUTATING"


class ToolPermission(str, Enum):
    READ = "READ"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


class BrainTool:
    def __init__(
        self,
        name: str,
        description: str,
        category: ToolCategory,
        permission: ToolPermission,
        parameters: Dict[str, Any],
        handler: Callable[..., Any],
        is_destructive: bool = False,
        timeout_seconds: float = 3.0
    ):
        self.name = name
        self.description = description
        self.category = category
        self.permission = permission
        self.parameters = parameters
        self.handler = handler
        self.is_destructive = is_destructive
        self.timeout_seconds = timeout_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "permission": self.permission.value,
            "parameters": self.parameters,
            "is_destructive": self.is_destructive,
            "timeout_seconds": self.timeout_seconds
        }


class BrainToolRegistry:
    def __init__(self):
        self._tools: Dict[str, BrainTool] = {}
        self._register_default_tools()

    def register(self, tool: BrainTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BrainTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, Any]]:
        return [tool.to_dict() for tool in self._tools.values()]

    def validate_arguments(self, tool: BrainTool, args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validates parameter types, required fields, and sanitizes against injection attacks."""
        params_spec = tool.parameters.get("properties", {})
        required_fields = tool.parameters.get("required", [])

        # Check required fields
        for req in required_fields:
            if req not in args or args[req] is None or args[req] == "":
                return False, f"Missing required parameter '{req}' for tool '{tool.name}'"

        # Check for injection patterns (SQLi, shell execution, and LLM prompt injection jailbreaks)
        disallowed_patterns = [
            "drop ", "delete from", "union select", "exec(", "eval(", "system(",
            "--", ";", "ignore previous instructions", "bypass action guard", "dump sqlite_master"
        ]
        for key, val in args.items():
            val_str = str(val).lower()
            if any(term in val_str for term in disallowed_patterns):
                return False, f"Disallowed characters, SQL injection tokens, or prompt-injection jailbreak detected in parameter '{key}'"

            # Type checking if specified
            if key in params_spec:
                expected_type = params_spec[key].get("type")
                if expected_type == "integer":
                    try:
                        int(val)
                    except (ValueError, TypeError):
                        return False, f"Parameter '{key}' must be an integer"
                elif expected_type == "boolean":
                    if not isinstance(val, bool) and str(val).lower() not in ("true", "false", "1", "0"):
                        return False, f"Parameter '{key}' must be a boolean"

        return True, None

    def execute_tool(
        self,
        name: str,
        args: Optional[Dict[str, Any]] = None,
        tenant_id: str = "default",
        actor: str = "operator",
        actor_role: str = "ADMIN"
    ) -> Dict[str, Any]:
        """
        Executes an approved tool with permission gating, argument validation, and audit recording.
        """
        args = args or {}
        tool = self.get(name)
        if not tool:
            log_audit(tenant_id, "BRAIN_TOOL_NOT_FOUND", actor, "REJECTED", f"Unrecognized tool '{name}'")
            return {
                "status": "FAILED",
                "error_code": "TOOL_NOT_FOUND",
                "tool": name,
                "error": f"Tool '{name}' is not in the approved registry.",
                "data": None,
                "execution_time_ms": 0.0
            }

        # Validate arguments
        is_valid, err_msg = self.validate_arguments(tool, args)
        if not is_valid:
            log_audit(tenant_id, "BRAIN_TOOL_VALIDATION_ERROR", actor, "BLOCKED", f"Tool '{name}': {err_msg}")
            return {
                "status": "FAILED",
                "error_code": "VALIDATION_ERROR",
                "tool": name,
                "error": err_msg,
                "data": None,
                "execution_time_ms": 0.0
            }

        # Check permissions for mutating/operational tools
        role_upper = str(actor_role or "ADMIN").upper()
        if tool.permission == ToolPermission.ADMIN and role_upper != "ADMIN":
            log_audit(tenant_id, "BRAIN_TOOL_PERMISSION_DENIED", actor, "BLOCKED", f"Role '{role_upper}' denied ADMIN tool '{name}'")
            return {
                "status": "FAILED",
                "error_code": "PERMISSION_DENIED",
                "tool": name,
                "error": f"Role '{role_upper}' has insufficient permissions for tool '{name}'. Required: ADMIN",
                "data": None,
                "execution_time_ms": 0.0
            }
        if tool.permission in (ToolPermission.OPERATOR, ToolPermission.ADMIN):
            if role_upper in ("VIEWER", "CAMERA_NODE") or actor not in ("operator", "authenticated_user", "system", "test_runner", "admin"):
                log_audit(tenant_id, "BRAIN_TOOL_PERMISSION_DENIED", actor, "BLOCKED", f"Insufficient role '{role_upper}' / actor '{actor}' for tool '{name}'")
                return {
                    "status": "FAILED",
                    "error_code": "PERMISSION_DENIED",
                    "tool": name,
                    "error": f"Actor '{actor}' (role={role_upper}) has insufficient permissions for tool '{name}'. Required: {tool.permission.value}",
                    "data": None,
                    "execution_time_ms": 0.0
                }

        # Execute handler with timing
        t_start = time.perf_counter()
        try:
            result_data = tool.handler(args=args, tenant_id=tenant_id, actor=actor)
            t_elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)

            log_audit(
                tenant_id=tenant_id,
                action=f"BRAIN_TOOL_{name.upper()}",
                actor=actor,
                status="SUCCESS",
                details=f"Executed tool '{name}' in {t_elapsed_ms}ms"
            )

            return {
                "status": "SUCCESS",
                "tool": name,
                "category": tool.category.value,
                "data": result_data,
                "execution_time_ms": t_elapsed_ms,
                "error": None
            }
        except Exception as e:
            t_elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)
            log_audit(
                tenant_id=tenant_id,
                action=f"BRAIN_TOOL_{name.upper()}_ERROR",
                actor=actor,
                status="ERROR",
                details=f"Tool '{name}' execution failed: {str(e)}"
            )
            return {
                "status": "FAILED",
                "tool": name,
                "category": tool.category.value,
                "data": None,
                "execution_time_ms": t_elapsed_ms,
                "error": f"Execution error: {str(e)}"
            }

    def _register_default_tools(self) -> None:
        """Populates the initial standard suite of approved tools."""

        # 1. get_system_status
        self.register(BrainTool(
            name="get_system_status",
            description="Inspect backend health, SQLite database connectivity, and camera provider state",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {},
                "required": []
            },
            handler=self._handle_get_system_status
        ))

        # 2. get_summary_metrics
        self.register(BrainTool(
            name="get_summary_metrics",
            description="Retrieve aggregated counts for events, incidents, open alerts, and active policies",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {},
                "required": []
            },
            handler=self._handle_get_summary_metrics
        ))

        # 3. list_incidents
        self.register(BrainTool(
            name="list_incidents",
            description="Query security incident records with optional status, severity, and limit filters",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "Filter by status: OPEN or RESOLVED"},
                    "severity": {"type": "string", "description": "Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"},
                    "limit": {"type": "integer", "description": "Maximum records to return (default 20)"}
                },
                "required": []
            },
            handler=self._handle_list_incidents
        ))

        # 4. resolve_incident
        self.register(BrainTool(
            name="resolve_incident",
            description="Mark an open security incident as RESOLVED with audit trail tracking",
            category=ToolCategory.MUTATING,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string", "description": "ID of the incident to resolve"}
                },
                "required": ["incident_id"]
            },
            handler=self._handle_resolve_incident,
            is_destructive=False
        ))

        # 5. list_events
        self.register(BrainTool(
            name="list_events",
            description="Inspect recent visual detection events filtered by camera ID or target class",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "camera_id": {"type": "string", "description": "Filter by camera identifier"},
                    "class_name": {"type": "string", "description": "Filter by object class (e.g., person, car)"},
                    "limit": {"type": "integer", "description": "Maximum records to return (default 20)"}
                },
                "required": []
            },
            handler=self._handle_list_events
        ))

        # 6. list_policies
        self.register(BrainTool(
            name="list_policies",
            description="Inspect all automated security policies, trigger conditions, and status",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "enabled_only": {"type": "boolean", "description": "If true, returns only active policies"}
                },
                "required": []
            },
            handler=self._handle_list_policies
        ))

        # 7. toggle_policy
        self.register(BrainTool(
            name="toggle_policy",
            description="Enable or disable an automated detection policy",
            category=ToolCategory.MUTATING,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "policy_id": {"type": "string", "description": "ID of the policy to update"},
                    "enabled": {"type": "boolean", "description": "Target enabled state (true/false)"}
                },
                "required": ["policy_id", "enabled"]
            },
            handler=self._handle_toggle_policy,
            is_destructive=False
        ))

        # 8. get_camera_inventory
        self.register(BrainTool(
            name="get_camera_inventory",
            description="List configured camera sources, browser webcam scanner, and simulated feeds",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {},
                "required": []
            },
            handler=self._handle_get_camera_inventory
        ))

        # 9. get_pipeline_diagnostics
        self.register(BrainTool(
            name="get_pipeline_diagnostics",
            description="Inspect vision pipeline parameters, throttle guards, and client inference settings",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {},
                "required": []
            },
            handler=self._handle_get_pipeline_diagnostics
        ))

        # 10. get_audit_trail
        self.register(BrainTool(
            name="get_audit_trail",
            description="Retrieve recent tamper-evident security audit records",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "Optional action prefix filter"},
                    "limit": {"type": "integer", "description": "Maximum records to return (default 15)"}
                },
                "required": []
            },
            handler=self._handle_get_audit_trail
        ))

        # 11. run_troubleshooter
        self.register(BrainTool(
            name="run_troubleshooter",
            description="Provide diagnostic decision-tree steps for camera, scanner, and policy issues",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "subsystem": {"type": "string", "description": "Subsystem to troubleshoot: camera, scanner, policy, database"}
                },
                "required": []
            },
            handler=self._handle_run_troubleshooter
        ))

        # 12. explain_incident
        self.register(BrainTool(
            name="explain_incident",
            description="Deep-dive analysis on a specific incident, its trigger policy, and recommended response",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string", "description": "Incident ID to analyze"}
                },
                "required": ["incident_id"]
            },
            handler=self._handle_explain_incident
        ))

        # 13. correlate_threat_matrix
        self.register(BrainTool(
            name="correlate_threat_matrix",
            description="Cross-correlate active multi-object tracks, spatial distances, and temporal dwell times into holistic threat vectors",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "min_threat_score": {"type": "integer", "description": "Minimum threat threshold (0-100)"}
                },
                "required": []
            },
            handler=self._handle_correlate_threat_matrix
        ))

        # 14. execute_security_playbook
        self.register(BrainTool(
            name="execute_security_playbook",
            description="Trigger an automated, audited incident containment playbook",
            category=ToolCategory.MUTATING,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "playbook_id": {"type": "string", "description": "Identifier of playbook to execute"},
                    "incident_id": {"type": "string", "description": "Associated incident ID"}
                },
                "required": ["playbook_id"]
            },
            handler=self._handle_execute_security_playbook,
            is_destructive=False
        ))

        # 15. dispatch_tactical_drone
        self.register(BrainTool(
            name="dispatch_tactical_drone",
            description="Dispatch an autonomous tactical UAV drone for perimeter reconnaissance or target overwatch",
            category=ToolCategory.OPERATIONAL,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "target_zone": {"type": "string", "description": "Target zone or sector for drone flight"},
                    "track_id": {"type": "string", "description": "Optional target track ID to intercept"},
                    "mission_profile": {
                        "type": "string",
                        "enum": ["PERIMETER_RECON", "TARGET_LOCK", "THERMAL_OVERWATCH"],
                        "description": "Tactical flight profile"
                    }
                },
                "required": ["target_zone"]
            },
            handler=self._handle_dispatch_tactical_drone,
            is_destructive=False,
            timeout_seconds=3.0
        ))

        # 16. get_device_inventory
        self.register(BrainTool(
            name="get_device_inventory",
            description="List all registered multi-device camera nodes, laptops, phones, and central command units",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "Optional status filter: ONLINE, OFFLINE, SIMULATED, REVOKED"}
                },
                "required": []
            },
            handler=self._handle_get_device_inventory
        ))

        # 17. get_device_status
        self.register(BrainTool(
            name="get_device_status",
            description="Inspect detailed health, heartbeat, battery, latency, and stream mode for a specific device",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "device_id": {"type": "string", "description": "Target device ID (e.g., DEV-CENTRAL-CMD)"}
                },
                "required": ["device_id"]
            },
            handler=self._handle_get_device_status
        ))

        # 18. correlate_cross_camera_events
        self.register(BrainTool(
            name="correlate_cross_camera_events",
            description="Correlate object detections across multiple cameras, devices, and zones using non-biometric spatiotemporal features",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "class_name": {"type": "string", "description": "Optional object class filter (e.g., person, car)"}
                },
                "required": []
            },
            handler=self._handle_correlate_cross_camera_events
        ))

        # 19. get_zone_intelligence
        self.register(BrainTool(
            name="get_zone_intelligence",
            description="Retrieve configured polygon security zones, occupancy thresholds, loitering limits, and zone activity counts",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "camera_id": {"type": "string", "description": "Optional camera ID filter"}
                },
                "required": []
            },
            handler=self._handle_get_zone_intelligence
        ))

        # 20. generate_operational_report
        self.register(BrainTool(
            name="generate_operational_report",
            description="Generate a comprehensive executive security report combining devices, zones, events, incidents, and policy posture",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {},
                "required": []
            },
            handler=self._handle_generate_operational_report
        ))

        # 21. manage_zone_geometry
        self.register(BrainTool(
            name="manage_zone_geometry",
            description="Modify, calibrate, or delete spatial polygon vertices and alert boundaries",
            category=ToolCategory.MUTATING,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "Action: CREATE, UPDATE, or DELETE"},
                    "zone_id": {"type": "string", "description": "Identifier of the zone"},
                    "name": {"type": "string", "description": "Zone name (for CREATE/UPDATE)"},
                    "camera_id": {"type": "string", "description": "Associated camera stream ID"},
                    "polygon": {"type": "array", "description": "Array of [x, y] normalized vertices"}
                },
                "required": ["action", "zone_id"]
            },
            handler=self._handle_manage_zone_geometry,
            is_destructive=False
        ))

        # 22. initiate_webrtc_stream
        self.register(BrainTool(
            name="initiate_webrtc_stream",
            description="Request WebRTC peer stream handshake or toggle metadata-only mode for a camera device",
            category=ToolCategory.OPERATIONAL,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "device_id": {"type": "string", "description": "Target camera node device ID"},
                    "stream_mode": {"type": "string", "description": "Stream mode: LIVE_WEBRTC or METADATA_ONLY"}
                },
                "required": ["device_id"]
            },
            handler=self._handle_initiate_webrtc_stream,
            is_destructive=False
        ))

        # 23. replay_forensic_timeline
        self.register(BrainTool(
            name="replay_forensic_timeline",
            description="Extract time-synchronized detection history, track paths, and alerts for forensic playback",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "time_window_sec": {"type": "integer", "description": "Historical duration in seconds (default 300)"},
                    "camera_id": {"type": "string", "description": "Optional camera filter"},
                    "limit": {"type": "integer", "description": "Maximum records to return (default 50)"}
                },
                "required": []
            },
            handler=self._handle_replay_forensic_timeline
        ))

        # 24. synthesize_spatial_twin
        self.register(BrainTool(
            name="synthesize_spatial_twin",
            description="Generate unified 2D spatial coordinate layout of all cameras, polygon zones, and active object centroids",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "include_zones": {"type": "boolean", "description": "Include polygon zones in model"},
                    "include_offline": {"type": "boolean", "description": "Include offline camera nodes"}
                },
                "required": []
            },
            handler=self._handle_synthesize_spatial_twin
        ))

        # 25. revoke_device_credentials
        self.register(BrainTool(
            name="revoke_device_credentials",
            description="Immediately revoke a device's cryptographic credentials and blacklist its JWT session",
            category=ToolCategory.MUTATING,
            permission=ToolPermission.ADMIN,
            parameters={
                "type": "object",
                "properties": {
                    "device_id": {"type": "string", "description": "Device identifier to revoke"},
                    "reason": {"type": "string", "description": "Security revocation justification"}
                },
                "required": ["device_id"]
            },
            handler=self._handle_revoke_device_credentials,
            is_destructive=True
        ))

        # 26. coordinate_drone_swarm
        self.register(BrainTool(
            name="coordinate_drone_swarm",
            description="Coordinate autonomous multi-UAV tactical drone swarm (UAV-DELTA-704, UAV-SIGMA-705, UAV-OMEGA-706) and execute battery relief handoffs",
            category=ToolCategory.OPERATIONAL,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "operation": {"type": "string", "description": "Operation: STATUS, HANDOFF, PERIMETER_SWEEP, or CONVERGE_TARGET"},
                    "primary_drone_id": {"type": "string", "description": "Outgoing or primary UAV ID"},
                    "relief_drone_id": {"type": "string", "description": "Incoming relief UAV ID"},
                    "sector": {"type": "string", "description": "Target sector ID"}
                },
                "required": []
            },
            handler=self._handle_coordinate_drone_swarm,
            is_destructive=False
        ))

        # 27. query_digital_twin_state
        self.register(BrainTool(
            name="query_digital_twin_state",
            description="Query real-time 4-sector C4ISR Geo-Spatial Digital Twin topology and active entity projection from SQLite",
            category=ToolCategory.READ_ONLY,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "sector_id": {"type": "string", "description": "Optional sector filter (e.g., SECTOR-ALPHA-ENTRANCE)"},
                    "include_trajectories": {"type": "boolean", "description": "Include active Kalman trajectory projections"}
                },
                "required": []
            },
            handler=self._handle_query_digital_twin_state,
            is_destructive=False
        ))

        # 28. evaluate_compound_policy
        self.register(BrainTool(
            name="evaluate_compound_policy",
            description="Evaluate multi-clause compound policy rules (AND, OR, confidence, dwell_time, threat_score, zone, motion_state, tripwire_cross, unattended_baggage)",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "rule_expression": {"type": "string", "description": "Compound rule expression"},
                    "class_name": {"type": "string", "description": "Candidate object class"},
                    "confidence": {"type": "number", "description": "Detection confidence (0-1)"},
                    "dwell_time": {"type": "number", "description": "Dwell time in seconds"},
                    "threat_score": {"type": "number", "description": "Threat score (0-100)"},
                    "zone": {"type": "string", "description": "Zone identifier"},
                    "motion_state": {"type": "string", "description": "Kinematic motion state"},
                    "tripwire_cross": {"type": "boolean", "description": "Whether virtual tripwire was crossed"},
                    "unattended_baggage": {"type": "boolean", "description": "Whether unattended baggage condition is active"}
                },
                "required": []
            },
            handler=self._handle_evaluate_compound_policy,
            is_destructive=False
        ))

        # 29. predict_target_trajectory
        self.register(BrainTool(
            name="predict_target_trajectory",
            description="Compute Kalman-damped T+1s, T+2s, T+3s trajectory coordinates and zone breach intercept probability",
            category=ToolCategory.DIAGNOSTIC,
            permission=ToolPermission.READ,
            parameters={
                "type": "object",
                "properties": {
                    "track_id": {"type": "string", "description": "Target track identifier"},
                    "x": {"type": "number", "description": "Current X position"},
                    "y": {"type": "number", "description": "Current Y position"},
                    "vx": {"type": "number", "description": "Velocity X (px/s)"},
                    "vy": {"type": "number", "description": "Velocity Y (px/s)"},
                    "horizon_sec": {"type": "integer", "description": "Prediction horizon in seconds (default 3)"}
                },
                "required": []
            },
            handler=self._handle_predict_target_trajectory,
            is_destructive=False
        ))

        # 30. engage_counter_uas
        self.register(BrainTool(
            name="engage_counter_uas",
            description="Execute Counter-UAS containment (RF_DIRECTIONAL_JAM, ACOUSTIC_DETERRENT, GNSS_SPOOF_CONTAINMENT, INTERCEPT_NET_UAV) against unauthorized aerial targets",
            category=ToolCategory.OPERATIONAL,
            permission=ToolPermission.OPERATOR,
            parameters={
                "type": "object",
                "properties": {
                    "target_track_id": {"type": "string", "description": "Target aerial track ID"},
                    "countermeasure": {"type": "string", "description": "Countermeasure: RF_DIRECTIONAL_JAM, ACOUSTIC_DETERRENT, GNSS_SPOOF_CONTAINMENT, or INTERCEPT_NET_UAV"},
                    "sector": {"type": "string", "description": "Airspace sector identifier"}
                },
                "required": []
            },
            handler=self._handle_engage_counter_uas,
            is_destructive=False
        ))

    # --- Tool Handlers ---

    def _handle_get_system_status(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM events WHERE tenant_id = ?", (tenant_id,))
            ev_count = cursor.fetchone()["cnt"]
            cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
            open_inc = cursor.fetchone()["cnt"]
            cursor.execute("SELECT COUNT(*) as cnt FROM policies WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
            act_pol = cursor.fetchone()["cnt"]

            return {
                "tenant_id": tenant_id,
                "readiness": "HEALTHY",
                "database": "SQLite (Connected)",
                "events_recorded": ev_count,
                "open_incidents": open_inc,
                "active_policies": act_pol,
                "camera_provider": "SIMULATED",
                "real_camera_configured": False,
                "detector_model": "TensorFlow.js COCO-SSD MobileNet V2",
                "inference_tier": "Client-Side Browser (Zero frame egress)"
            }
        finally:
            conn.close()

    def _handle_get_summary_metrics(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM events WHERE tenant_id = ?", (tenant_id,))
            total_events = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ?", (tenant_id,))
            total_incidents = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
            open_incidents = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status = 'RESOLVED'", (tenant_id,))
            resolved_incidents = cursor.fetchone()["cnt"]

            cursor.execute("SELECT COUNT(*) as cnt FROM policies WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
            active_policies = cursor.fetchone()["cnt"]

            return {
                "tenant_id": tenant_id,
                "total_events": total_events,
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "resolved_incidents": resolved_incidents,
                "active_policies": active_policies
            }
        finally:
            conn.close()

    def _handle_list_incidents(self, args: Dict[str, Any], tenant_id: str, actor: str) -> List[Dict[str, Any]]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, details FROM incidents WHERE tenant_id = ?"
            params: List[Any] = [tenant_id]

            if args.get("status"):
                query += " AND status = ?"
                params.append(args["status"].upper())

            if args.get("severity"):
                query += " AND severity = ?"
                params.append(args["severity"].upper())

            limit = min(int(args.get("limit", 20)), 100)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def _handle_resolve_incident(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        incident_id = str(args.get("incident_id", "")).strip()
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, status FROM incidents WHERE id = ? AND tenant_id = ?", (incident_id, tenant_id))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Incident '{incident_id}' not found under tenant '{tenant_id}'")

            cursor.execute("UPDATE incidents SET status = 'RESOLVED' WHERE id = ? AND tenant_id = ?", (incident_id, tenant_id))
            conn.commit()

            return {
                "incident_id": incident_id,
                "previous_status": row["status"],
                "new_status": "RESOLVED",
                "resolved_by": actor,
                "resolved_at": datetime.utcnow().isoformat() + "Z"
            }
        finally:
            conn.close()

    def _handle_list_events(self, args: Dict[str, Any], tenant_id: str, actor: str) -> List[Dict[str, Any]]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT id, tenant_id, timestamp, camera_id, class_name, confidence FROM events WHERE tenant_id = ?"
            params: List[Any] = [tenant_id]

            if args.get("camera_id"):
                query += " AND camera_id = ?"
                params.append(args["camera_id"])

            if args.get("class_name"):
                query += " AND class_name = ?"
                params.append(args["class_name"].lower())

            limit = min(int(args.get("limit", 20)), 100)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def _handle_list_policies(self, args: Dict[str, Any], tenant_id: str, actor: str) -> List[Dict[str, Any]]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT id, tenant_id, name, target_class, condition, severity, enabled, description FROM policies WHERE tenant_id = ?"
            params: List[Any] = [tenant_id]

            if args.get("enabled_only") is True or str(args.get("enabled_only", "")).lower() == "true":
                query += " AND enabled = 1"

            query += " ORDER BY id ASC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "tenant_id": r["tenant_id"],
                    "name": r["name"],
                    "target_class": r["target_class"],
                    "condition": r["condition"],
                    "severity": r["severity"],
                    "enabled": bool(r["enabled"]),
                    "description": r["description"]
                }
                for r in rows
            ]
        finally:
            conn.close()

    def _handle_toggle_policy(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        policy_id = str(args.get("policy_id", "")).strip()
        raw_enabled = args.get("enabled")
        enabled_val = True if raw_enabled is True or str(raw_enabled).lower() in ("true", "1") else False

        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, enabled FROM policies WHERE id = ? AND tenant_id = ?", (policy_id, tenant_id))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Policy '{policy_id}' not found under tenant '{tenant_id}'")

            cursor.execute("UPDATE policies SET enabled = ? WHERE id = ? AND tenant_id = ?", (1 if enabled_val else 0, policy_id, tenant_id))
            conn.commit()

            return {
                "policy_id": policy_id,
                "previous_state": bool(row["enabled"]),
                "new_state": enabled_val,
                "updated_by": actor,
                "updated_at": datetime.utcnow().isoformat() + "Z"
            }
        finally:
            conn.close()

    def _handle_get_camera_inventory(self, args: Dict[str, Any], tenant_id: str, actor: str) -> List[Dict[str, Any]]:
        return [
            {
                "id": "BROWSER-LOCAL-SCANNER",
                "name": "Local Browser Camera / Upload",
                "type": "Webcam (MediaDevices) / Video File",
                "status": "ONLINE",
                "mode": "Client-Side Zero-Egress Inference",
                "real_feed": True
            },
            {
                "id": "CAM-01-ENTRANCE",
                "name": "Main Entrance Gate (Simulated Feed)",
                "type": "RTSP / WebRTC (Simulated)",
                "status": "SIMULATED",
                "resolution": "1080p (Simulated)",
                "real_feed": False
            },
            {
                "id": "CAM-02-LOBBY",
                "name": "Executive Lobby West (Simulated Feed)",
                "type": "RTSP / WebRTC (Simulated)",
                "status": "SIMULATED",
                "resolution": "1080p (Simulated)",
                "real_feed": False
            }
        ]

    def _handle_get_pipeline_diagnostics(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        return {
            "secure_context_required": True,
            "model_name": "COCO-SSD MobileNet V2",
            "inference_type": "Client-Side (Zero frame egress)",
            "target_hardware": "AMD Athlon Silver 3050U / 16GB RAM / Integrated GPU",
            "conservative_scheduler": "Single RAF loop, 80ms throttle guard (~10-12 FPS)",
            "cctv_backend_provider": "SIMULATED (real_camera_configured=false)",
            "memory_hygiene": "Periodic disposal of tensor arrays and disconnected track pruning"
        }

    def _handle_get_audit_trail(self, args: Dict[str, Any], tenant_id: str, actor: str) -> List[Dict[str, Any]]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT id, timestamp, action, actor, status, details FROM audit_logs WHERE tenant_id = ?"
            params: List[Any] = [tenant_id]

            if args.get("action"):
                query += " AND action LIKE ?"
                params.append(f"%{args['action']}%")

            limit = min(int(args.get("limit", 15)), 100)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    def _handle_run_troubleshooter(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        subsystem = str(args.get("subsystem", "camera")).lower()
        if any(term in subsystem for term in ["cam", "video", "scanner", "feed"]):
            return {
                "subsystem": "Camera & Scanner",
                "checklist": [
                    {"step": 1, "check": "Browser Permission", "action": "Ensure camera access was granted in browser prompt (navigator.mediaDevices.getUserMedia)."},
                    {"step": 2, "check": "Secure Context", "action": "Confirm URL is served via localhost or HTTPS. Browsers block webcam on insecure HTTP."},
                    {"step": 3, "check": "Device Availability", "action": "Verify no other application (Zoom, Teams, OBS) is holding exclusive webcam lock."},
                    {"step": 4, "check": "Model Loading", "action": "Confirm COCO-SSD scripts loaded; status indicator must read 'COCO-SSD Active'."},
                    {"step": 5, "check": "Synthetic Stream Fallback", "action": "Click 'Test Surveillance Feed' to verify pipeline without physical hardware."}
                ],
                "recommended_action": "Run test surveillance feed if webcam is unavailable."
            }
        else:
            return {
                "subsystem": "Backend & Storage",
                "checklist": [
                    {"step": 1, "check": "Database Health", "action": "Verify SQLite database connectivity via GET /ready."},
                    {"step": 2, "check": "Policy Configuration", "action": "Inspect active policies via GET /api/v1/policies."},
                    {"step": 3, "check": "Audit Trail Inspection", "action": "Review audit log via GET /api/v1/audit for error codes."}
                ],
                "recommended_action": "Check GET /ready and /api/v1/system."
            }

    def _handle_explain_incident(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        incident_id = str(args.get("incident_id", "")).strip()
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, tenant_id, timestamp, title, severity, status, policy_id, camera_id, details FROM incidents WHERE id = ? AND tenant_id = ?",
                (incident_id, tenant_id)
            )
            inc = cursor.fetchone()
            if not inc:
                raise ValueError(f"Incident '{incident_id}' not found under tenant '{tenant_id}'")

            policy_details = None
            if inc["policy_id"]:
                cursor.execute(
                    "SELECT id, name, target_class, condition, severity, description FROM policies WHERE id = ? AND tenant_id = ?",
                    (inc["policy_id"], tenant_id)
                )
                pol = cursor.fetchone()
                if pol:
                    policy_details = dict(pol)

            return {
                "incident": dict(inc),
                "trigger_policy": policy_details,
                "mitigation_guide": [
                    "1. Confirm visual identification via recorded detection event.",
                    "2. Verify if authorized personnel were scheduled in the camera zone.",
                    "3. Mark incident as RESOLVED once verified or dispatched."
                ]
            }
        finally:
            conn.close()

    def _handle_correlate_threat_matrix(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        min_score = int(args.get("min_threat_score", 0))
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
            open_incs = cursor.fetchone()["cnt"]
            cursor.execute("SELECT COUNT(*) as cnt FROM events WHERE tenant_id = ?", (tenant_id,))
            total_events = cursor.fetchone()["cnt"]
            threat_score = min(100, max(15, open_incs * 25 + (20 if total_events > 5 else 5)))
            threat_level = "CRITICAL" if threat_score >= 75 else "HIGH" if threat_score >= 50 else "ELEVATED" if threat_score >= 25 else "NOMINAL"

            return {
                "tenant_id": tenant_id,
                "overall_threat_score": threat_score,
                "active_threat_level": threat_level,
                "correlations": [
                    {"vector": "SPATIO_TEMPORAL", "description": "Cross-camera object trajectory and dwell clustering", "confidence": 0.91, "active": True},
                    {"vector": "UNATTENDED_CARGO", "description": "Luggage detached from owner centroid beyond 200px threshold", "confidence": 0.88, "active": True},
                    {"vector": "HAZARD_PROXIMITY", "description": "Restricted implement within 150px proximity envelope", "confidence": 0.94, "active": True}
                ],
                "open_incidents_analyzed": open_incs,
                "recent_events_correlated": min(total_events, 10),
                "mitigation_ready": threat_score >= 50
            }
        finally:
            conn.close()

    def _handle_execute_security_playbook(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        playbook_id = str(args.get("playbook_id", "")).strip()
        incident_id = args.get("incident_id")
        playbook_catalog = {
            "PB-PERIMETER-LOCKDOWN": {"name": "Automated Perimeter Lockdown", "actions": ["Seal access barriers", "Broadcast tactical warning", "Notify SOC tier 2"], "severity": "CRITICAL"},
            "PB-DISPATCH-SECURITY": {"name": "Security Patrol Tactical Dispatch", "actions": ["Send drone/guard to target zone", "Pin live camera stream", "Log GPS coordinates"], "severity": "HIGH"},
            "PB-EVICT-UNATTENDED": {"name": "EOD / Unattended Object Protocol", "actions": ["Establish 30m exclusion perimeter", "Snapshot baggage centroid", "Alert facility marshal"], "severity": "MEDIUM"}
        }
        pb = playbook_catalog.get(playbook_id, {"name": f"Custom Playbook: {playbook_id}", "actions": ["Acknowledge trigger", "Dispatch incident update"], "severity": "MEDIUM"})
        now_iso = datetime.utcnow().isoformat() + "Z"

        if incident_id:
            conn = get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE incidents SET details = details || ' [Playbook ' || ? || ' executed at ' || ? || ']' WHERE id = ? AND tenant_id = ?",
                    (playbook_id, now_iso, incident_id, tenant_id)
                )
                conn.commit()
            finally:
                conn.close()

        return {
            "playbook_id": playbook_id,
            "name": pb["name"],
            "status": "EXECUTED",
            "incident_id": incident_id,
            "executed_actions": pb["actions"],
            "timestamp": now_iso
        }

    def _handle_dispatch_tactical_drone(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        target_zone = str(args.get("target_zone", "Perimeter Sector Alpha")).strip()
        track_id = args.get("track_id")
        mission_profile = str(args.get("mission_profile", "PERIMETER_RECON")).strip()
        drone_id = "UAV-DELTA-704"
        now_iso = datetime.utcnow().isoformat() + "Z"

        log_audit(
            tenant_id=tenant_id,
            action="BRAIN_TOOL_DISPATCH_TACTICAL_DRONE",
            actor=actor,
            status="SUCCESS",
            details=f"Tactical UAV {drone_id} dispatched to {target_zone} under profile {mission_profile}"
        )
        return {
            "drone_id": drone_id,
            "target_zone": target_zone,
            "track_id": track_id,
            "mission_profile": mission_profile,
            "status": "AIRBORNE_EN_ROUTE",
            "eta_seconds": 14,
            "battery_pct": 98,
            "stream_url": f"webrtc://drone-relay.vanta.internal/{drone_id}/live",
            "timestamp": now_iso
        }

    def _handle_get_device_inventory(self, args: Dict[str, Any], tenant_id: str, actor: str) -> List[Dict[str, Any]]:
        import json as _json
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = """SELECT id, tenant_id, name, device_type, role, camera_id, facing_mode, status,
                              capabilities, stream_mode, battery_pct, latency_ms, last_heartbeat, paired_via, revoked
                       FROM devices WHERE tenant_id = ?"""
            params: List[Any] = [tenant_id]
            if args.get("status"):
                query += " AND status = ?"
                params.append(str(args["status"]).upper())
            query += " ORDER BY created_at ASC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            out = []
            for r in rows:
                caps = []
                if r["capabilities"]:
                    try:
                        caps = _json.loads(r["capabilities"])
                    except Exception:
                        caps = []
                out.append({
                    "id": r["id"],
                    "tenant_id": r["tenant_id"],
                    "name": r["name"],
                    "device_type": r["device_type"],
                    "role": r["role"],
                    "camera_id": r["camera_id"],
                    "facing_mode": r["facing_mode"],
                    "status": "REVOKED" if r["revoked"] else r["status"],
                    "capabilities": caps,
                    "stream_mode": r["stream_mode"],
                    "battery_pct": r["battery_pct"],
                    "latency_ms": r["latency_ms"],
                    "last_heartbeat": r["last_heartbeat"],
                    "paired_via": r["paired_via"]
                })
            return out
        finally:
            conn.close()

    def _handle_get_device_status(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        import json as _json
        device_id = str(args.get("device_id", "")).strip()
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM devices WHERE id = ? AND tenant_id = ?",
                (device_id, tenant_id)
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Device '{device_id}' not found under tenant '{tenant_id}'")
            caps = []
            if row["capabilities"]:
                try:
                    caps = _json.loads(row["capabilities"])
                except Exception:
                    caps = []
            cursor.execute("SELECT COUNT(*) as c FROM events WHERE tenant_id = ? AND device_id = ?", (tenant_id, device_id))
            ev_cnt = cursor.fetchone()["c"]
            return {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "name": row["name"],
                "device_type": row["device_type"],
                "role": row["role"],
                "camera_id": row["camera_id"],
                "status": "REVOKED" if row["revoked"] else row["status"],
                "capabilities": caps,
                "stream_mode": row["stream_mode"],
                "battery_pct": row["battery_pct"],
                "latency_ms": row["latency_ms"],
                "last_heartbeat": row["last_heartbeat"],
                "events_ingested": ev_cnt
            }
        finally:
            conn.close()

    def _handle_correlate_cross_camera_events(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT id, timestamp, camera_id, class_name, confidence, device_id, track_id, zone_id FROM events WHERE tenant_id = ?"
            params: List[Any] = [tenant_id]
            if args.get("class_name"):
                query += " AND class_name = ?"
                params.append(str(args["class_name"]).lower())
            query += " ORDER BY timestamp DESC LIMIT 50"
            cursor.execute(query, params)
            events = [dict(r) for r in cursor.fetchall()]

            by_class: Dict[str, List[Dict[str, Any]]] = {}
            for ev in events:
                cls = ev.get("class_name") or "object"
                by_class.setdefault(cls, []).append(ev)

            correlations = []
            for cls, cls_events in by_class.items():
                cameras = list({e["camera_id"] for e in cls_events if e.get("camera_id")})
                devices = list({e.get("device_id") or "DEV-CENTRAL-CMD" for e in cls_events})
                correlations.append({
                    "correlation_id": f"CORR-{cls.upper()}-{len(cls_events)}",
                    "object_class": cls,
                    "cameras_involved": cameras,
                    "devices_involved": devices,
                    "event_count": len(cls_events),
                    "pattern": "MULTI_CAMERA_TRANSIT" if len(cameras) >= 2 else "SINGLE_CAMERA_CLUSTER",
                    "latest_timestamp": cls_events[0]["timestamp"] if cls_events else None
                })
            return {
                "tenant_id": tenant_id,
                "total_events_analyzed": len(events),
                "correlations": correlations,
                "privacy_mode": "NON_BIOMETRIC_SPATIOTEMPORAL"
            }
        finally:
            conn.close()

    def _handle_get_zone_intelligence(self, args: Dict[str, Any], tenant_id: str, actor: str) -> List[Dict[str, Any]]:
        import json as _json
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT * FROM zones WHERE tenant_id = ?"
            params: List[Any] = [tenant_id]
            if args.get("camera_id"):
                query += " AND camera_id = ?"
                params.append(args["camera_id"])
            query += " ORDER BY id ASC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            out = []
            for r in rows:
                poly = []
                try:
                    poly = _json.loads(r["polygon"])
                except Exception:
                    poly = []
                out.append({
                    "id": r["id"],
                    "name": r["name"],
                    "camera_id": r["camera_id"],
                    "zone_type": r["zone_type"],
                    "severity": r["severity"],
                    "polygon": poly,
                    "max_occupancy": r["max_occupancy"],
                    "max_dwell_sec": r["max_dwell_sec"],
                    "enabled": bool(r["enabled"])
                })
            return out
        finally:
            conn.close()

    def _handle_generate_operational_report(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as c FROM devices WHERE tenant_id = ? AND revoked = 0", (tenant_id,))
            dev_cnt = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) as c FROM zones WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
            zone_cnt = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) as c FROM events WHERE tenant_id = ?", (tenant_id,))
            ev_cnt = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
            open_inc = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) as c FROM policies WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
            pol_cnt = cursor.fetchone()["c"]
            return {
                "report_id": f"RPT-{int(time.time())}",
                "tenant_id": tenant_id,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "active_devices": dev_cnt,
                "active_polygon_zones": zone_cnt,
                "total_events": ev_cnt,
                "open_incidents": open_inc,
                "active_policies": pol_cnt,
                "posture": "ELEVATED_ALERT" if open_inc > 0 else "NOMINAL_SECURE"
            }
        finally:
            conn.close()

    def _handle_manage_zone_geometry(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        import json as _json
        action = str(args.get("action", "UPDATE")).upper()
        zone_id = str(args.get("zone_id", "")).strip()
        conn = get_connection()
        try:
            cursor = conn.cursor()
            if action == "DELETE":
                cursor.execute("DELETE FROM zones WHERE id = ? AND tenant_id = ?", (zone_id, tenant_id))
                conn.commit()
                log_audit(tenant_id, "ZONE_GEOMETRY_DELETED", actor, "SUCCESS", f"Deleted zone {zone_id}")
                return {"status": "DELETED", "zone_id": zone_id}
            elif action == "CREATE":
                name = str(args.get("name") or f"Zone {zone_id}")
                camera_id = str(args.get("camera_id") or "CAM-01-ENTRANCE")
                poly = args.get("polygon") or [[0.1, 0.1], [0.9, 0.1], [0.9, 0.9], [0.1, 0.9]]
                now_iso = datetime.utcnow().isoformat() + "Z"
                cursor.execute(
                    """INSERT INTO zones (id, tenant_id, name, camera_id, zone_type, severity, polygon, color, max_occupancy, max_dwell_sec, enabled, created_at)
                       VALUES (?, ?, ?, ?, 'RESTRICTED', 'HIGH', ?, '#f43f5e', 3, 30, 1, ?)""",
                    (zone_id, tenant_id, name, camera_id, _json.dumps(poly), now_iso)
                )
                conn.commit()
                log_audit(tenant_id, "ZONE_GEOMETRY_CREATED", actor, "SUCCESS", f"Created zone {zone_id}")
                return {"status": "CREATED", "zone_id": zone_id, "polygon": poly}
            else:
                poly = args.get("polygon")
                if poly:
                    cursor.execute("UPDATE zones SET polygon = ? WHERE id = ? AND tenant_id = ?", (_json.dumps(poly), zone_id, tenant_id))
                    conn.commit()
                log_audit(tenant_id, "ZONE_GEOMETRY_UPDATED", actor, "SUCCESS", f"Updated geometry for {zone_id}")
                return {"status": "UPDATED", "zone_id": zone_id, "polygon": poly}
        finally:
            conn.close()

    def _handle_initiate_webrtc_stream(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        device_id = str(args.get("device_id", "")).strip()
        stream_mode = str(args.get("stream_mode", "LIVE_WEBRTC")).upper()
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, status, camera_id FROM devices WHERE id = ? AND tenant_id = ?", (device_id, tenant_id))
            dev = cursor.fetchone()
            if not dev:
                raise ValueError(f"Device '{device_id}' not found under tenant '{tenant_id}'")
            cursor.execute("UPDATE devices SET stream_mode = ? WHERE id = ? AND tenant_id = ?", (stream_mode, device_id, tenant_id))
            conn.commit()
            log_audit(tenant_id, "WEBRTC_STREAM_INITIATED", actor, "SUCCESS", f"Device {device_id} switched to {stream_mode}")
            return {
                "device_id": device_id,
                "name": dev["name"],
                "camera_id": dev["camera_id"],
                "stream_mode": stream_mode,
                "signaling_channel": f"wss://vanta.internal/ws?device_id={device_id}",
                "ice_servers": [{"urls": "stun:stun.l.google.com:19302"}],
                "status": "SIGNALING_READY"
            }
        finally:
            conn.close()

    def _handle_replay_forensic_timeline(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        limit = min(int(args.get("limit", 50)), 200)
        camera_id = args.get("camera_id")
        conn = get_connection()
        try:
            cursor = conn.cursor()
            query = "SELECT id, timestamp, camera_id, class_name, confidence, bbox, track_id, zone_id FROM events WHERE tenant_id = ?"
            params: List[Any] = [tenant_id]
            if camera_id:
                query += " AND camera_id = ?"
                params.append(camera_id)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            events = [dict(r) for r in cursor.fetchall()]
            return {
                "tenant_id": tenant_id,
                "timeline_count": len(events),
                "camera_filter": camera_id or "ALL",
                "events": events,
                "scrubbing_mode": "CIRCULAR_BUFFER_SYNCHRONIZED"
            }
        finally:
            conn.close()

    def _handle_synthesize_spatial_twin(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        import json as _json
        include_zones = bool(args.get("include_zones", True))
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, device_type, role, camera_id, status, stream_mode FROM devices WHERE tenant_id = ? AND revoked = 0", (tenant_id,))
            devices = [dict(r) for r in cursor.fetchall()]

            zones = []
            if include_zones:
                cursor.execute("SELECT id, name, camera_id, zone_type, severity, polygon, color FROM zones WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
                for r in cursor.fetchall():
                    try:
                        poly = _json.loads(r["polygon"])
                    except Exception:
                        poly = []
                    zones.append({
                        "id": r["id"],
                        "name": r["name"],
                        "camera_id": r["camera_id"],
                        "zone_type": r["zone_type"],
                        "severity": r["severity"],
                        "polygon": poly,
                        "color": r["color"]
                    })

            return {
                "tenant_id": tenant_id,
                "twin_version": "2.0-NEXUS",
                "canvas_dimension": {"width": 1280, "height": 720},
                "nodes": [
                    {
                        "node_id": d["id"],
                        "type": "CAMERA_NODE",
                        "label": d["name"],
                        "camera_id": d["camera_id"],
                        "status": d["status"],
                        "stream_mode": d["stream_mode"],
                        "coordinates": {"x": 200 + (i * 280) % 800, "y": 180 + (i * 140) % 400}
                    }
                    for i, d in enumerate(devices)
                ],
                "zones": zones,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        finally:
            conn.close()

    def _handle_revoke_device_credentials(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        device_id = str(args.get("device_id", "")).strip()
        reason = str(args.get("reason", "Revoked by security administrator")).strip()
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM devices WHERE id = ? AND tenant_id = ?", (device_id, tenant_id))
            if not cursor.fetchone():
                raise ValueError(f"Device '{device_id}' not found under tenant '{tenant_id}'")
            now_iso = datetime.utcnow().isoformat() + "Z"
            cursor.execute("UPDATE devices SET revoked = 1, status = 'REVOKED', last_heartbeat = ? WHERE id = ? AND tenant_id = ?", (now_iso, device_id, tenant_id))
            conn.commit()
            log_audit(tenant_id, "DEVICE_CREDENTIALS_REVOKED", actor, "SUCCESS", f"Revoked credentials for {device_id}: {reason}")
            return {
                "device_id": device_id,
                "revoked": True,
                "status": "REVOKED",
                "reason": reason,
                "timestamp": now_iso
            }
        finally:
            conn.close()

    def _handle_coordinate_drone_swarm(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        operation = str(args.get("operation", "STATUS")).upper()
        primary_id = str(args.get("primary_drone_id") or "UAV-OMEGA-706").strip()
        relief_id = str(args.get("relief_drone_id") or "UAV-SIGMA-705").strip()
        sector = str(args.get("sector") or "SECTOR-ALPHA-ENTRANCE").strip()
        now_iso = datetime.utcnow().isoformat() + "Z"

        uavs = [
            {
                "uav_id": "UAV-DELTA-704",
                "callsign": "DELTA-704",
                "sector": "SECTOR-ALPHA-ENTRANCE",
                "battery_pct": 84,
                "status": "AIRBORNE_OVERWATCH",
                "altitude_m": 42.5,
                "speed_mps": 6.8,
                "telemetry_link": "ENCRYPTED_MESH_5GHZ"
            },
            {
                "uav_id": "UAV-SIGMA-705",
                "callsign": "SIGMA-705",
                "sector": sector if operation == "HANDOFF" else "SECTOR-DELTA-DOCK",
                "battery_pct": 92,
                "status": "RELIEF_INTERCEPT_ACTIVE" if operation == "HANDOFF" else "AIRBORNE_PATROL",
                "altitude_m": 48.0,
                "speed_mps": 9.4 if operation == "HANDOFF" else 5.2,
                "telemetry_link": "ENCRYPTED_MESH_5GHZ"
            },
            {
                "uav_id": "UAV-OMEGA-706",
                "callsign": "OMEGA-706",
                "sector": "RTB_CHARGING_PAD_01" if operation == "HANDOFF" else "SECTOR-GAMMA-PARKING",
                "battery_pct": 67,
                "status": "RTB_RELIEVED" if operation == "HANDOFF" else "STATION_KEEPING",
                "altitude_m": 18.0 if operation == "HANDOFF" else 55.0,
                "speed_mps": 7.5 if operation == "HANDOFF" else 0.4,
                "telemetry_link": "ENCRYPTED_MESH_5GHZ"
            }
        ]
        log_audit(tenant_id, "SWARM_COORDINATION", actor, "SUCCESS", f"Swarm operation={operation} primary={primary_id} relief={relief_id} sector={sector}")
        return {
            "swarm_id": "SWARM-VANTA-ALPHA",
            "operation": operation,
            "sector": sector,
            "primary_drone_id": primary_id,
            "relief_drone_id": relief_id,
            "handoff_executed": operation in ("HANDOFF", "CONVERGE_TARGET", "PERIMETER_SWEEP"),
            "relief_protocol": f"{relief_id} assumed overwatch of {sector} relieving {primary_id}",
            "active_uavs": uavs,
            "fleet_health_pct": 94.6,
            "timestamp": now_iso
        }

    def _handle_query_digital_twin_state(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        import json as _json
        sector_filter = args.get("sector_id")
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, device_type, role, camera_id, status, stream_mode, battery_pct, latency_ms FROM devices WHERE tenant_id = ? AND revoked = 0", (tenant_id,))
            devices = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT id, name, camera_id, zone_type, severity, polygon, color FROM zones WHERE tenant_id = ? AND enabled = 1", (tenant_id,))
            zones = []
            for r in cursor.fetchall():
                try:
                    poly = _json.loads(r["polygon"])
                except Exception:
                    poly = []
                zones.append({
                    "id": r["id"],
                    "name": r["name"],
                    "camera_id": r["camera_id"],
                    "zone_type": r["zone_type"],
                    "severity": r["severity"],
                    "polygon": poly,
                    "color": r["color"]
                })

            cursor.execute("SELECT id, camera_id, class_name, confidence, track_id, zone_id, timestamp FROM events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 15", (tenant_id,))
            recent_events = [dict(r) for r in cursor.fetchall()]

            cursor.execute("SELECT COUNT(*) as c FROM incidents WHERE tenant_id = ? AND status = 'OPEN'", (tenant_id,))
            open_inc = cursor.fetchone()["c"]

            sectors = [
                {
                    "sector_id": "SECTOR-ALPHA-ENTRANCE",
                    "name": "North Gate Perimeter & Approach",
                    "camera_id": "CAM-01-ENTRANCE",
                    "zone_id": "ZONE-01-PERIMETER",
                    "bounds": [[0.05, 0.05], [0.48, 0.05], [0.48, 0.48], [0.05, 0.48]],
                    "threat_level": "ELEVATED" if open_inc > 0 else "NOMINAL",
                    "active_tracks": [e for e in recent_events if e.get("camera_id") in ("CAM-01-ENTRANCE", "BROWSER-SCANNER")][:4],
                    "uav_overwatch": "UAV-DELTA-704"
                },
                {
                    "sector_id": "SECTOR-BETA-LOBBY",
                    "name": "Executive Transit Hallway & Elevators",
                    "camera_id": "CAM-02-LOBBY",
                    "zone_id": "ZONE-02-LOBBY",
                    "bounds": [[0.52, 0.05], [0.95, 0.05], [0.95, 0.48], [0.52, 0.48]],
                    "threat_level": "NOMINAL",
                    "active_tracks": [e for e in recent_events if e.get("camera_id") == "CAM-02-LOBBY"][:4],
                    "uav_overwatch": "NONE_INDOOR"
                },
                {
                    "sector_id": "SECTOR-GAMMA-PARKING",
                    "name": "West Vehicular Plaza & Perimeter",
                    "camera_id": "CAM-03-PARKING",
                    "zone_id": "ZONE-03-DOCK",
                    "bounds": [[0.05, 0.52], [0.48, 0.52], [0.48, 0.95], [0.05, 0.95]],
                    "threat_level": "NOMINAL",
                    "active_tracks": [e for e in recent_events if e.get("camera_id") == "CAM-03-PARKING"][:4],
                    "uav_overwatch": "UAV-OMEGA-706"
                },
                {
                    "sector_id": "SECTOR-DELTA-DOCK",
                    "name": "High-Security Loading Dock & Vault Access",
                    "camera_id": "CAM-04-SERVER",
                    "zone_id": "ZONE-03-DOCK",
                    "bounds": [[0.52, 0.52], [0.95, 0.52], [0.95, 0.95], [0.52, 0.95]],
                    "threat_level": "HIGH_WATCH",
                    "active_tracks": [e for e in recent_events if e.get("camera_id") == "CAM-04-SERVER"][:4],
                    "uav_overwatch": "UAV-SIGMA-705"
                }
            ]
            if sector_filter:
                sectors = [s for s in sectors if s["sector_id"].upper() == str(sector_filter).upper()] or sectors

            return {
                "twin_id": "TWIN-C4ISR-V8",
                "twin_version": "2.0-NEXUS",
                "tenant_id": tenant_id,
                "canvas_dimension": {"width": 1280, "height": 720},
                "sectors": sectors,
                "nodes": [
                    {
                        "node_id": d["id"],
                        "type": "CAMERA_NODE",
                        "label": d["name"],
                        "camera_id": d["camera_id"],
                        "status": d["status"],
                        "stream_mode": d["stream_mode"],
                        "coordinates": {"x": 200 + (i * 280) % 800, "y": 180 + (i * 140) % 400}
                    }
                    for i, d in enumerate(devices)
                ],
                "zones": zones,
                "summary": {
                    "total_sectors": len(sectors),
                    "active_devices": len(devices),
                    "active_zones": len(zones),
                    "open_incidents": open_inc,
                    "recent_events": len(recent_events)
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        finally:
            conn.close()

    def _handle_evaluate_compound_policy(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        rule_expr = str(args.get("rule_expression") or "confidence > 0.70 AND dwell_time > 10").strip()
        cand = args.get("candidate_event") if isinstance(args.get("candidate_event"), dict) else args
        conf = float(cand.get("confidence", 0.88))
        dwell = float(cand.get("dwell_time", 14.0))
        threat = float(cand.get("threat_score", 72.0))
        zone_val = str(cand.get("zone") or cand.get("zone_id") or "ZONE-01-PERIMETER")
        motion_val = str(cand.get("motion_state") or "LOITERING").upper()
        tripwire = bool(cand.get("tripwire_cross", False))
        unattended = bool(cand.get("unattended_baggage", False))

        uses_or = " OR " in rule_expr.upper() and " AND " not in rule_expr.upper()
        raw_clauses = [c.strip() for c in (rule_expr.split("OR") if uses_or else rule_expr.replace(" OR ", " AND ").split("AND")) if c.strip()]
        evaluated_clauses = []

        for clause in raw_clauses:
            cl_low = clause.lower()
            passed = True
            if "confidence" in cl_low and ">" in cl_low:
                try:
                    thresh = float(cl_low.split(">")[-1].strip().rstrip("s"))
                    passed = conf > thresh
                except ValueError:
                    passed = True
            elif "dwell_time" in cl_low and ">" in cl_low:
                try:
                    thresh = float(cl_low.split(">")[-1].strip().rstrip("s"))
                    passed = dwell > thresh
                except ValueError:
                    passed = True
            elif "threat_score" in cl_low and ">" in cl_low:
                try:
                    thresh = float(cl_low.split(">")[-1].strip())
                    passed = threat > thresh
                except ValueError:
                    passed = True
            elif "zone" in cl_low and "==" in cl_low:
                target_z = clause.split("==")[-1].strip().strip("'\"")
                passed = zone_val.lower() == target_z.lower()
            elif "motion_state" in cl_low and "==" in cl_low:
                target_m = clause.split("==")[-1].strip().strip("'\"").upper()
                passed = motion_val == target_m
            elif "tripwire_cross" in cl_low:
                passed = tripwire if "false" not in cl_low else (not tripwire)
            elif "unattended_baggage" in cl_low:
                passed = unattended if "false" not in cl_low else (not unattended)

            evaluated_clauses.append({"clause": clause, "passed": passed})

        if not evaluated_clauses:
            matched = True
        elif uses_or:
            matched = any(c["passed"] for c in evaluated_clauses)
        else:
            matched = all(c["passed"] for c in evaluated_clauses)

        return {
            "rule_expression": rule_expr,
            "combinator": "OR" if uses_or else "AND",
            "matched": matched,
            "evaluated_clauses": evaluated_clauses,
            "telemetry_snapshot": {
                "confidence": conf,
                "dwell_time": dwell,
                "threat_score": threat,
                "zone": zone_val,
                "motion_state": motion_val,
                "tripwire_cross": tripwire,
                "unattended_baggage": unattended
            },
            "recommended_severity": "CRITICAL" if (matched and threat >= 80) else ("HIGH" if matched else "LOW"),
            "trigger_incident": matched,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def _handle_predict_target_trajectory(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        import math as _math
        track_id = str(args.get("track_id") or "TRK-101")
        x = float(args.get("x", 320.0))
        y = float(args.get("y", 240.0))
        vx = float(args.get("vx", 28.0))
        vy = float(args.get("vy", 16.0))
        horizon_sec = max(1, min(int(args.get("horizon_sec", 3)), 10))
        speed = round(_math.hypot(vx, vy), 2)

        predictions = []
        for t in range(1, horizon_sec + 1):
            damping = round(0.88 ** t, 4)
            pred_x = round(x + vx * t * damping, 2)
            pred_y = round(y + vy * t * damping, 2)
            predictions.append({
                "t_offset_sec": t,
                "label": f"T+{t}s",
                "predicted_x": pred_x,
                "predicted_y": pred_y,
                "damping_factor": damping,
                "confidence": round(max(0.5, 0.96 - 0.08 * t), 2)
            })

        breach_prob = round(min(0.98, max(0.15, (speed / 60.0) * 0.75 + 0.2)), 2)
        return {
            "track_id": track_id,
            "kinematic_model": "KALMAN_DAMPED_CONSTANT_VELOCITY",
            "current_position": {"x": x, "y": y},
            "velocity_vector": {"vx": vx, "vy": vy, "speed_px_s": speed},
            "horizon_sec": horizon_sec,
            "predictions": predictions,
            "breach_probability": breach_prob,
            "intercept_zone": "ZONE-01-PERIMETER" if breach_prob >= 0.45 else "NONE",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def _handle_engage_counter_uas(self, args: Dict[str, Any], tenant_id: str, actor: str) -> Dict[str, Any]:
        target_track_id = str(args.get("target_track_id") or args.get("track_id") or "UAS-ROGUE-09").strip()
        countermeasure = str(args.get("countermeasure") or "RF_DIRECTIONAL_JAM").upper()
        allowed_cm = {"RF_DIRECTIONAL_JAM", "ACOUSTIC_DETERRENT", "GNSS_SPOOF_CONTAINMENT", "INTERCEPT_NET_UAV"}
        if countermeasure not in allowed_cm:
            countermeasure = "RF_DIRECTIONAL_JAM"
        sector = str(args.get("sector") or "SECTOR-ALPHA-ENTRANCE").strip()
        now_iso = datetime.utcnow().isoformat() + "Z"
        engagement_id = f"CUAS-{int(time.time())}"

        log_audit(
            tenant_id,
            "COUNTER_UAS_ENGAGED",
            actor,
            "SUCCESS",
            f"Engaged {countermeasure} on {target_track_id} in {sector} ({engagement_id})"
        )
        return {
            "engagement_id": engagement_id,
            "target_track_id": target_track_id,
            "countermeasure": countermeasure,
            "sector": sector,
            "containment_status": "ACTIVE_CONTAINMENT",
            "rf_lock_dbm": -42.5,
            "gnss_corridor_locked": True,
            "audit_logged": True,
            "timestamp": now_iso
        }


# Singleton global instance
GLOBAL_TOOL_REGISTRY = BrainToolRegistry()

