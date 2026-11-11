"""
Core Brain Command Specifications, Validation, and Layer Definitions.
Pure Python module with zero external framework dependencies.
"""
from typing import Dict, Any, Tuple, Optional, List

# Primary allowlisted commands and structured operational intents (20 allowlisted commands)
ALLOWLISTED_COMMANDS: Dict[str, str] = {
    "help": "List all available allowlisted commands and syntax guide",
    "status": "Check backend health, camera provider mode, and system parameters",
    "capabilities": "View verified operational capabilities and active AI modules",
    "summary": "Retrieve aggregated detection counts, active incidents, and policy stats",
    "incidents": "Query open security incidents, severity levels, and trigger policies",
    "policies": "Review automated detection rules, thresholds, and operational status",
    "cameras": "Inspect registered video inputs and physical vs simulated stream status",
    "events": "Inspect recent detection events filtered by tenant and camera",
    "diagnostics": "View camera pipeline diagnostics and runtime telemetry",
    "audit": "Inspect latest security actions and audit trails",
    "troubleshoot": "Step-by-step diagnostic guidance for camera, scanner, and policy issues",
    "tools": "List approved Brain tools and execution schemas",
    "devices": "Inspect registered multi-device camera nodes, pairing status, and health",
    "zones": "Inspect polygon security zones, occupancy limits, and loitering rules",
    "correlations": "Run cross-camera spatiotemporal object correlation across active nodes",
    "swarm": "Coordinate autonomous multi-UAV tactical drone fleet and battery relief handoffs",
    "twin": "Query 4-sector C4ISR Geo-Spatial Digital Twin topology and active track projections",
    "evaluate": "Evaluate multi-clause compound policy rules against live or candidate telemetry",
    "predict": "Compute Kalman-damped T+1s..T+3s target trajectory and zone breach probability",
    "cuas": "Engage Counter-UAS containment protocols against unauthorized aerial targets"
}

# Mapping of commands to underlying approved tools
COMMAND_TOOL_MAPPING: Dict[str, str] = {
    "status": "get_system_status",
    "summary": "get_summary_metrics",
    "incidents": "list_incidents",
    "policies": "list_policies",
    "cameras": "get_camera_inventory",
    "events": "list_events",
    "diagnostics": "get_pipeline_diagnostics",
    "audit": "get_audit_trail",
    "troubleshoot": "run_troubleshooter",
    "devices": "get_device_inventory",
    "zones": "get_zone_intelligence",
    "correlations": "correlate_cross_camera_events",
    "swarm": "coordinate_drone_swarm",
    "twin": "query_digital_twin_state",
    "evaluate": "evaluate_compound_policy",
    "predict": "predict_target_trajectory",
    "cuas": "engage_counter_uas"
}


def validate_brain_command(cmd_raw: str) -> Tuple[bool, str]:
    """
    Validates command against strict allowlist.
    Returns (is_valid, normalized_command).
    """
    if not cmd_raw:
        return False, ""
    normalized = cmd_raw.strip().lower()
    if normalized in ALLOWLISTED_COMMANDS:
        return True, normalized
    return False, normalized
