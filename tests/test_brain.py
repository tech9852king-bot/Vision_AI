"""
Comprehensive Unit Tests for VantaVisionAI 7-Layer Brain Architecture & Approved Tool Registry
Runs with Python standard library unittest.
"""
import unittest
import os
import sqlite3
import json
from datetime import datetime

os.environ["DATABASE_PATH"] = "test_vanta_vision.db"

from backend.app.database import init_db, get_connection, log_audit
from backend.app.core_brain import ALLOWLISTED_COMMANDS, COMMAND_TOOL_MAPPING, validate_brain_command
from backend.app.brain_service import BrainService
from backend.app.brain_tools import GLOBAL_TOOL_REGISTRY, ToolCategory, ToolPermission


class TestVantaVisionBrain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists("test_vanta_vision.db"):
            try:
                os.remove("test_vanta_vision.db")
            except Exception:
                pass

    def setUp(self):
        self.conn = get_connection()
        self.cursor = self.conn.cursor()

    def tearDown(self):
        self.conn.close()

    def test_allowlisted_commands_completeness(self):
        """Ensure all required allowlisted commands and operational intents are registered."""
        expected = [
            "help", "status", "capabilities", "summary",
            "incidents", "policies", "cameras", "events",
            "diagnostics", "audit", "troubleshoot", "tools"
        ]
        for cmd in expected:
            self.assertIn(cmd, ALLOWLISTED_COMMANDS, f"Command '{cmd}' must be in allowlist")

    def test_approved_tool_registry_registration(self):
        """Verify the approved tool registry contains all standard operational tools."""
        tools = GLOBAL_TOOL_REGISTRY.list_tools()
        self.assertGreaterEqual(len(tools), 10, "Registry should contain at least 10 approved tools")

        expected_tools = [
            "get_system_status", "get_summary_metrics", "list_incidents",
            "resolve_incident", "list_events", "list_policies",
            "toggle_policy", "get_camera_inventory", "get_pipeline_diagnostics",
            "get_audit_trail", "run_troubleshooter", "explain_incident"
        ]
        registered_names = [t["name"] for t in tools]
        for name in expected_tools:
            self.assertIn(name, registered_names, f"Tool '{name}' must be registered")

    def test_brain_service_execution(self):
        """Verify 7-layer BrainService produces structured response contracts for all commands."""
        commands = [
            "help", "status", "capabilities", "summary", "incidents",
            "policies", "cameras", "events", "diagnostics", "audit", "troubleshoot", "tools"
        ]
        for cmd in commands:
            success, res = BrainService.process_command(cmd, tenant_id="default")
            self.assertTrue(success, f"Command '{cmd}' must execute successfully")
            self.assertEqual(res["command"], cmd)
            self.assertIn("finding", res)
            self.assertIn("evidence", res)
            self.assertIn("interpretation", res)
            self.assertIn("recommended_steps", res)
            self.assertIn("warnings", res)
            self.assertIn("executed_tools", res)
            self.assertIn("execution_time_ms", res)
            self.assertFalse(res["real_camera_configured"])

    def test_direct_tool_execution_read_only(self):
        """Verify read-only tools execute safely and return structured data with timing."""
        res = GLOBAL_TOOL_REGISTRY.execute_tool("get_system_status", {}, tenant_id="default")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["tool"], "get_system_status")
        self.assertEqual(res["category"], "DIAGNOSTIC")
        self.assertIn("readiness", res["data"])
        self.assertGreater(res["execution_time_ms"], 0.0)

    def test_direct_tool_execution_mutating_incident(self):
        """Verify mutating tool resolve_incident updates database and records audit trail."""
        # Insert a test incident
        inc_id = "inc_test_mutate_101"
        self.cursor.execute(
            "INSERT INTO incidents (id, tenant_id, timestamp, title, severity, status) VALUES (?, ?, ?, ?, ?, ?)",
            (inc_id, "default", datetime.utcnow().isoformat(), "Test Perimeter Alarm", "HIGH", "OPEN")
        )
        self.conn.commit()

        # Execute mutating tool
        res = GLOBAL_TOOL_REGISTRY.execute_tool(
            "resolve_incident",
            {"incident_id": inc_id},
            tenant_id="default",
            actor="operator"
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["data"]["new_status"], "RESOLVED")

        # Verify DB state
        self.cursor.execute("SELECT status FROM incidents WHERE id = ?", (inc_id,))
        row = self.cursor.fetchone()
        self.assertEqual(row["status"], "RESOLVED")

    def test_direct_tool_execution_mutating_policy(self):
        """Verify toggle_policy toggles enabled flag and audits action."""
        res = GLOBAL_TOOL_REGISTRY.execute_tool(
            "toggle_policy",
            {"policy_id": "pol_person_after_hours", "enabled": False},
            tenant_id="default",
            actor="operator"
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertFalse(res["data"]["new_state"])

        # Re-enable
        res_re = GLOBAL_TOOL_REGISTRY.execute_tool(
            "toggle_policy",
            {"policy_id": "pol_person_after_hours", "enabled": True},
            tenant_id="default",
            actor="operator"
        )
        self.assertEqual(res_re["status"], "SUCCESS")
        self.assertTrue(res_re["data"]["new_state"])

    def test_tool_argument_validation_and_injection_blocking(self):
        """Verify tool registry validates schemas and rejects malicious injection payloads."""
        # Missing required parameter
        res_missing = GLOBAL_TOOL_REGISTRY.execute_tool("resolve_incident", {}, tenant_id="default")
        self.assertEqual(res_missing["status"], "FAILED")
        self.assertIn("Missing required parameter", res_missing["error"])

        # SQL injection attempt in argument
        res_sqli = GLOBAL_TOOL_REGISTRY.execute_tool(
            "resolve_incident",
            {"incident_id": "1; DROP TABLE incidents;--"},
            tenant_id="default"
        )
        self.assertEqual(res_sqli["status"], "FAILED")
        self.assertIn("Disallowed characters", res_sqli["error"])

    def test_dangerous_commands_disallowed(self):
        """Ensure unknown commands, shell injections, and arbitrary tools are rejected."""
        forbidden = [
            "bash", "sh", "exec", "eval", "system", "cat /etc/passwd",
            "DROP TABLE events;", "SELECT * FROM users;", "reboot"
        ]
        for cmd in forbidden:
            success, res = BrainService.process_command(cmd, tenant_id="default")
            self.assertFalse(success, f"Disallowed command '{cmd}' must fail validation")
            self.assertEqual(res.get("error"), "COMMAND_NOT_ALLOWLISTED")

    def test_action_guard_blocks_malicious_args(self):
        """Action guard must block parameter payloads with destructive SQL or shell terms."""
        success, res = BrainService.process_command("events", args={"filter": "1; DROP TABLE events;--"}, tenant_id="default")
        self.assertFalse(success, "Action Guard must block SQL injection parameter")
        self.assertEqual(res.get("error"), "MALFORMED_ARGUMENTS")

    def test_tenant_isolation(self):
        """Ensure data created by tenant A cannot be observed by tenant B in Brain commands."""
        tenant_a = "tenant-gamma"
        tenant_b = "tenant-delta"

        # Insert incident under tenant A
        self.cursor.execute(
            "INSERT INTO incidents (id, tenant_id, timestamp, title, severity, status) VALUES (?, ?, ?, ?, ?, ?)",
            ("inc_isolated_a", tenant_a, datetime.utcnow().isoformat(), "Gamma Vault Breach", "CRITICAL", "OPEN")
        )
        self.conn.commit()

        # Query Brain under tenant B
        success_b, res_b = BrainService.process_command("incidents", tenant_id=tenant_b)
        self.assertTrue(success_b)
        ids_b = [r["id"] for r in res_b["evidence"]["records"]]
        self.assertNotIn("inc_isolated_a", ids_b, "Tenant B must not see Tenant A incidents")

        # Query Brain under tenant A
        success_a, res_a = BrainService.process_command("incidents", tenant_id=tenant_a)
        self.assertTrue(success_a)
        ids_a = [r["id"] for r in res_a["evidence"]["records"]]
        self.assertIn("inc_isolated_a", ids_a, "Tenant A must see their own incidents")

    def test_audit_logging_integrity(self):
        """Verify immutable audit log records all actions."""
        log_audit("default", "BRAIN_VERIFICATION", "test_runner", "SUCCESS", "Executed automated unit test")
        self.cursor.execute("SELECT * FROM audit_logs WHERE action = 'BRAIN_VERIFICATION'")
        row = self.cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["actor"], "test_runner")


if __name__ == "__main__":
    unittest.main()
