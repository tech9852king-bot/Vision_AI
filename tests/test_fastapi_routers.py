"""
Unit tests for FastAPI Aleana router and Policy CRUD endpoints.
"""
import unittest
import os
import json
from datetime import datetime

os.environ["DATABASE_PATH"] = "test_vanta_vision.db"

try:
    import fastapi
    from backend.app.routers.aleana import handle_aleana_command, get_aleana_status, AleanaCommandRequest
    from backend.app.routers.policies import create_policy, delete_policy, list_policies, PolicyCreate
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

class TestFastAPIRouters(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        if not HAS_FASTAPI:
            raise unittest.SkipTest("FastAPI not installed in host Python environment (available in Docker/venv)")
        init_db()

    async def test_aleana_status_parity(self):
        status = await get_aleana_status()
        self.assertEqual(status["status"], "ONLINE")
        self.assertEqual(status["name"], "ALEANA")
        self.assertIn("voice_navigation", status["capabilities"])

    async def test_aleana_command_incidents_intent(self):
        req = AleanaCommandRequest(query="how many open incidents do we have?", current_view="dashboard")
        resp = await handle_aleana_command(req, tenant_id="default")
        self.assertEqual(resp.intent, "QUERY_INCIDENTS")
        self.assertEqual(resp.action, "QUERY")
        self.assertEqual(resp.target, "incidents")

    async def test_aleana_command_hindi_alias(self):
        req = AleanaCommandRequest(query="camera chalu karo", current_view="dashboard")
        resp = await handle_aleana_command(req, tenant_id="default")
        self.assertEqual(resp.intent, "START_SCANNER")
        self.assertEqual(resp.action, "START_SCANNER")

    async def test_policy_crud_lifecycle(self):
        # Create a test policy
        policy_data = PolicyCreate(
            name="Loading Dock Alert",
            target_class="truck",
            condition="confidence > 0.80",
            severity="HIGH",
            enabled=True,
            description="High priority truck detection"
        )
        created = await create_policy(policy_data, tenant_id="default")
        self.assertTrue(created.id.startswith("pol_"))
        self.assertEqual(created.name, "Loading Dock Alert")

        # Verify listed
        policies = await list_policies(tenant_id="default")
        self.assertTrue(any(p.id == created.id for p in policies))

        # Delete policy
        del_resp = await delete_policy(created.id, tenant_id="default")
        self.assertEqual(del_resp["status"], "SUCCESS")

        # Verify deletion
        policies_after = await list_policies(tenant_id="default")
        self.assertFalse(any(p.id == created.id for p in policies_after))

if __name__ == "__main__":
    unittest.main()
