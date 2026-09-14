import pathlib
import tempfile
import unittest
from unittest import mock

from workflow_engine import WorkflowEngine
from workspace_store import WorkspaceStore


class WorkflowEngineTests(unittest.TestCase):
    def make_store(self, directory):
        store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
        project = store.create_project({"name": "Authorised lab"})
        return store, project

    def test_workflow_rejects_cycles(self):
        with tempfile.TemporaryDirectory() as directory:
            store, project = self.make_store(directory)
            with self.assertRaisesRegex(ValueError, "cycle"):
                store.create_workflow({"project_id": project["id"], "name": "Cycle", "steps": [
                    {"id": "one", "capability": "system.info", "depends_on": ["two"]},
                    {"id": "two", "capability": "system.info", "depends_on": ["one"]},
                ]})

    def test_workflow_and_run_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            store, project = self.make_store(directory)
            workflow = store.create_workflow({
                "project_id": project["id"], "name": "Inventory",
                "steps": [{"id": "info", "capability": "system.info"}],
            })
            run = store.create_workflow_run(workflow["id"])
            restored = WorkspaceStore(store.path).snapshot()
            self.assertEqual(restored["workflows"][0]["id"], workflow["id"])
            self.assertEqual(restored["workflow_runs"][0]["id"], run["id"])

    def test_workflow_edit_and_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            store, project = self.make_store(directory)
            workflow = store.create_workflow({
                "project_id": project["id"], "name": "Inventory",
                "steps": [{"id": "info", "capability": "system.info"}],
            })
            updated = store.update_workflow(workflow["id"], {
                "name": "Inventory v2", "description": "Renamed",
                "steps": [{"id": "info", "capability": "system.info"},
                          {"id": "conn", "capability": "net.connectivity.check", "depends_on": ["info"]}],
            })
            self.assertEqual(updated["name"], "Inventory v2")
            self.assertEqual(len(updated["steps"]), 2)
            self.assertGreater(updated["updated_at_ms"], workflow["updated_at_ms"] - 1)
            actions = [event["action"] for event in store.snapshot()["audit_events"]]
            self.assertIn("workflow.updated", actions)
            store.delete_workflow(workflow["id"])
            self.assertEqual(store.snapshot()["workflows"], [])
            self.assertIn("workflow.deleted", [event["action"] for event in store.snapshot()["audit_events"]])
            with self.assertRaises(KeyError):
                store.delete_workflow(workflow["id"])

    def test_workflow_edit_and_delete_are_blocked_while_a_run_is_active(self):
        with tempfile.TemporaryDirectory() as directory:
            store, project = self.make_store(directory)
            workflow = store.create_workflow({
                "project_id": project["id"], "name": "Inventory",
                "steps": [{"id": "info", "capability": "system.info"}],
            })
            store.create_workflow_run(workflow["id"])
            with self.assertRaisesRegex(ValueError, "active run"):
                store.update_workflow(workflow["id"], {"name": "New name"})
            with self.assertRaisesRegex(ValueError, "active run"):
                store.delete_workflow(workflow["id"])
            # Once the run is no longer active (queued/running), editing/deleting is fine again.
            run = store.snapshot()["workflow_runs"][0]
            store.update_workflow_run(run["id"], {"status": "complete", "steps": run["steps"]})
            store.update_workflow(workflow["id"], {"name": "New name"})
            store.delete_workflow(workflow["id"])

    def test_scheduler_obeys_dependencies_and_capabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            store, project = self.make_store(directory)
            workflow = store.create_workflow({
                "project_id": project["id"], "name": "Inventory",
                "steps": [
                    {"id": "info", "capability": "system.info"},
                    {"id": "connectivity", "capability": "net.connectivity.check",
                     "depends_on": ["info"]},
                ],
            })
            run = store.create_workflow_run(workflow["id"])
            coordinator = mock.MagicMock()
            coordinator.state.return_value = {"nodes": [
                {"device_id": "desktop", "status": "ready", "capabilities": ["system.info"]},
                {"device_id": "p4", "status": "ready",
                 "capabilities": ["system.info", "net.connectivity.check"]},
            ]}
            coordinator.invoke.side_effect = [
                {"payload": {"status": "ok", "result": {"firmware": "1"}}},
                {"payload": {"status": "ok", "result": {"internet_possible": True}}},
            ]
            engine = WorkflowEngine(coordinator, store)
            self.assertTrue(engine.advance_once())
            first = next(item for item in store.snapshot()["workflow_runs"] if item["id"] == run["id"])
            self.assertEqual([item["status"] for item in first["steps"]], ["complete", "pending"])
            self.assertTrue(engine.advance_once())
            completed = next(item for item in store.snapshot()["workflow_runs"] if item["id"] == run["id"])
            self.assertEqual(completed["status"], "complete")
            self.assertEqual(coordinator.invoke.call_args_list[1].args[0], "p4")

    def test_failed_step_retries_then_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            store, project = self.make_store(directory)
            workflow = store.create_workflow({
                "project_id": project["id"], "name": "Retry",
                "steps": [{"id": "info", "capability": "system.info", "retries": 1}],
            })
            run = store.create_workflow_run(workflow["id"])
            coordinator = mock.MagicMock()
            coordinator.state.return_value = {"nodes": [
                {"device_id": "desktop", "status": "ready", "capabilities": ["system.info"]},
            ]}
            coordinator.invoke.side_effect = RuntimeError("temporary failure")
            engine = WorkflowEngine(coordinator, store)
            engine.advance_once()
            retrying = next(item for item in store.snapshot()["workflow_runs"] if item["id"] == run["id"])
            self.assertEqual(retrying["steps"][0]["status"], "pending")
            engine.advance_once()
            failed = next(item for item in store.snapshot()["workflow_runs"] if item["id"] == run["id"])
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["steps"][0]["attempts"], 2)

    def test_cancel_marks_pending_steps_without_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            store, project = self.make_store(directory)
            workflow = store.create_workflow({
                "project_id": project["id"], "name": "Cancel",
                "steps": [{"id": "info", "capability": "system.info"}],
            })
            run = store.create_workflow_run(workflow["id"])
            coordinator = mock.MagicMock()
            engine = WorkflowEngine(coordinator, store)
            cancelled = engine.cancel(run["id"])
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertEqual(cancelled["steps"][0]["status"], "cancelled")
            coordinator.invoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
