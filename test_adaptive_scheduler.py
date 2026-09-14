import pathlib
import tempfile
import unittest
from unittest import mock

from adaptive_scheduler import DistributedScanEngine, select_node, shard_ranges
from engagement_policy import EngagementPolicy
from workspace_store import WorkspaceStore


def node(device_id, capabilities=("net.discovery.scan",), address="192.168.8.5",
        status="ready", network_mbps=100):
    return {"device_id": device_id, "capabilities": list(capabilities), "address": address,
            "status": status, "resources": {"network_mbps": network_mbps}}


class SelectNodeTests(unittest.TestCase):
    def test_filters_by_capability(self):
        nodes = [node("a", capabilities=["system.info"]), node("b")]
        self.assertEqual(select_node(nodes, "net.discovery.scan")["device_id"], "b")

    def test_returns_none_when_nothing_capable(self):
        self.assertIsNone(select_node([node("a", capabilities=["system.info"])], "net.discovery.scan"))

    def test_prefers_the_node_whose_subnet_actually_contains_the_target(self):
        nodes = [node("far", address="10.0.0.5"), node("near", address="192.168.8.9")]
        chosen = select_node(nodes, "net.discovery.scan", network="192.168.8.0/24")
        self.assertEqual(chosen["device_id"], "near")

    def test_falls_back_to_all_capable_nodes_when_no_topology_match(self):
        nodes = [node("only", address="10.0.0.5")]
        chosen = select_node(nodes, "net.discovery.scan", network="192.168.8.0/24")
        self.assertEqual(chosen["device_id"], "only")

    def test_excludes_already_tried_nodes(self):
        nodes = [node("a"), node("b")]
        chosen = select_node(nodes, "net.discovery.scan", exclude={"a"})
        self.assertEqual(chosen["device_id"], "b")

    def test_prefers_less_loaded_node(self):
        nodes = [node("busy"), node("idle")]
        chosen = select_node(nodes, "net.discovery.scan", active_leases={"busy": 3, "idle": 0})
        self.assertEqual(chosen["device_id"], "idle")

    def test_prefers_higher_bandwidth_when_load_is_equal(self):
        nodes = [node("slow", network_mbps=10), node("fast", network_mbps=1000)]
        chosen = select_node(nodes, "net.discovery.scan")
        self.assertEqual(chosen["device_id"], "fast")

    def test_prefers_ready_status(self):
        nodes = [node("degraded", status="degraded"), node("ready", status="ready")]
        chosen = select_node(nodes, "net.discovery.scan")
        self.assertEqual(chosen["device_id"], "ready")


class ShardRangesTests(unittest.TestCase):
    def test_shards_a_24_into_28_sized_chunks(self):
        chunks = shard_ranges("192.168.8.0/24", 16)
        self.assertEqual(chunks[0], ("192.168.8.1", "192.168.8.16"))
        self.assertEqual(chunks[1], ("192.168.8.17", "192.168.8.32"))
        self.assertEqual(chunks[-1], ("192.168.8.241", "192.168.8.254"))
        self.assertEqual(sum((int(end.split(".")[-1]) - int(start.split(".")[-1]) + 1)
                             for start, end in chunks), 254)

    def test_chunk_size_larger_than_network_yields_one_chunk(self):
        chunks = shard_ranges("192.168.8.0/28", 999)
        self.assertEqual(chunks, [("192.168.8.1", "192.168.8.14")])

    def test_single_host_network_yields_one_single_address_chunk(self):
        # Python's ipaddress.hosts() treats a /32 as its own one usable host (RFC 3021-
        # style), so this is the smallest real case -- not an error.
        self.assertEqual(shard_ranges("192.168.8.9/32", 16), [("192.168.8.9", "192.168.8.9")])


class DistributedScanEngineTests(unittest.TestCase):
    def make_engine(self, directory, with_policy=False):
        store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
        project = store.create_project({"name": "Authorised lab"})
        policy = None
        if with_policy:
            policy = EngagementPolicy(store, pathlib.Path(directory) / "scope.key",
                                      delegation_key=b"k" * 32)
        coordinator = mock.MagicMock()
        engine = DistributedScanEngine(coordinator, store, policy)
        return engine, store, project, coordinator, policy

    # -- create() -----------------------------------------------------------

    def test_create_parallel_shards_the_network_into_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            scan = engine.create({"project_id": project["id"], "mode": "parallel",
                                  "network": "192.168.8.0/24", "chunk_size": 64})
            self.assertEqual(scan["status"], "running")
            self.assertEqual(len(scan["chunks"]), 4)
            self.assertTrue(all(chunk["status"] == "pending" for chunk in scan["chunks"]))
            self.assertTrue(all(not chunk["fixed_node"] for chunk in scan["chunks"]))

    def test_create_rejects_unknown_project_or_bad_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            with self.assertRaises(ValueError):
                engine.create({"project_id": "missing", "mode": "parallel", "network": "10.0.0.0/24"})
            with self.assertRaisesRegex(ValueError, "mode"):
                engine.create({"project_id": project["id"], "mode": "chaotic", "network": "10.0.0.0/24"})

    def test_create_consensus_makes_one_chunk_per_node_per_target(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4"), node("adv")]}
            scan = engine.create({"project_id": project["id"], "mode": "consensus",
                                  "network": "192.168.8.0/24", "targets": ["192.168.8.9", "192.168.8.10"]})
            self.assertEqual(len(scan["chunks"]), 4)
            self.assertTrue(all(chunk["fixed_node"] for chunk in scan["chunks"]))
            assigned = {(chunk["start_ip"], chunk["assigned_node"]) for chunk in scan["chunks"]}
            self.assertEqual(assigned, {("192.168.8.9", "p4"), ("192.168.8.9", "adv"),
                                        ("192.168.8.10", "p4"), ("192.168.8.10", "adv")})

    def test_create_consensus_requires_a_live_capable_node(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": []}
            with self.assertRaisesRegex(ValueError, "no live node"):
                engine.create({"project_id": project["id"], "mode": "consensus",
                              "network": "192.168.8.0/24", "targets": ["192.168.8.9"]})

    def test_create_consensus_rejects_target_outside_network(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4")]}
            with self.assertRaisesRegex(ValueError, "outside"):
                engine.create({"project_id": project["id"], "mode": "consensus",
                              "network": "192.168.8.0/24", "targets": ["10.0.0.9"]})

    # -- advance(): parallel dispatch, concurrency ceiling -------------------

    def test_advance_dispatches_up_to_the_concurrency_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4")]}
            scan = engine.create({"project_id": project["id"], "mode": "parallel",
                                  "network": "192.168.8.0/24", "chunk_size": 16,
                                  "max_concurrent_chunks": 2})
            coordinator.invoke.return_value = {"payload": {"status": "ok",
                                               "result": {"job_status": "running", "job_id": "job-1"}}}
            engine.advance(scan["id"])
            updated = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            running = [chunk for chunk in updated["chunks"] if chunk["status"] == "running"]
            pending = [chunk for chunk in updated["chunks"] if chunk["status"] == "pending"]
            self.assertEqual(len(running), 2)
            self.assertEqual(len(pending), len(updated["chunks"]) - 2)

    def test_advance_polls_running_chunks_to_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4")]}
            scan = engine.create({"project_id": project["id"], "mode": "parallel",
                                  "network": "192.168.8.0/28", "chunk_size": 16})
            coordinator.invoke.return_value = {"payload": {"status": "ok",
                                               "result": {"job_status": "running", "job_id": "job-1"}}}
            engine.advance(scan["id"])
            coordinator.invoke.return_value = {"payload": {"result": {"job_status": "complete", "hosts": []}}}
            engine.advance(scan["id"])
            final = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            self.assertEqual(final["status"], "complete")
            self.assertEqual(final["chunks"][0]["status"], "complete")

    def test_advance_backs_off_when_no_node_is_eligible(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            # Create with a node present, then remove all nodes before advancing --
            # dispatch has nothing to select and must leave the chunk pending, not fail it.
            coordinator.state.return_value = {"nodes": [node("p4")]}
            scan = engine.create({"project_id": project["id"], "mode": "parallel",
                                  "network": "192.168.8.0/28", "chunk_size": 16})
            coordinator.state.return_value = {"nodes": []}
            changed = engine.advance(scan["id"])
            self.assertFalse(changed)
            unchanged = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            self.assertTrue(all(chunk["status"] == "pending" for chunk in unchanged["chunks"]))
            coordinator.invoke.assert_not_called()

    def test_advance_respects_scope_concurrency_as_backpressure(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, policy = self.make_engine(directory, with_policy=True)
            scope = policy.create_scope({
                "project_id": project["id"], "included_networks": ["192.168.8.0/24"],
                "capability_classes": ["discovery"], "max_concurrency": 1, "max_requests_per_minute": 60,
                "expires_at_ms": __import__("time").time() * 1000 + 60000,
            })
            coordinator.state.return_value = {"nodes": [node("p4"), node("adv")]}
            scan = engine.create({"project_id": project["id"], "scope_id": scope["id"], "mode": "parallel",
                                  "network": "192.168.8.0/24", "chunk_size": 64,
                                  "max_concurrent_chunks": 4})
            coordinator.invoke.return_value = {"payload": {"status": "ok",
                                               "result": {"job_status": "running", "job_id": "job-1"}}}
            engine.advance(scan["id"])
            updated = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            # The scope only allows one concurrent dispatch, so only one chunk (of four)
            # should have actually gone out even though max_concurrent_chunks allows four.
            self.assertEqual(sum(1 for chunk in updated["chunks"] if chunk["status"] == "running"), 1)
            self.assertEqual(sum(1 for chunk in updated["chunks"] if chunk["status"] == "pending"), 3)

    # -- failover -------------------------------------------------------------

    def test_a_running_chunks_disappearing_node_is_requeued_to_a_different_node(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4")]}
            scan = engine.create({"project_id": project["id"], "mode": "parallel",
                                  "network": "192.168.8.0/28", "chunk_size": 16})
            coordinator.invoke.return_value = {"payload": {"status": "ok",
                                               "result": {"job_status": "running", "job_id": "job-1"}}}
            engine.advance(scan["id"])
            # p4 disappears from the live roster mid-job; adv comes online instead.
            coordinator.state.return_value = {"nodes": [node("adv")]}
            engine.advance(scan["id"])
            after_failover = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            chunk = after_failover["chunks"][0]
            self.assertIn("p4", chunk["tried_nodes"])
            self.assertIn(chunk["status"], ("pending", "running"))
            if chunk["status"] == "running":
                self.assertEqual(chunk["assigned_node"], "adv")

    def test_chunk_fails_permanently_after_exceeding_the_attempt_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4")]}
            scan = engine.create({"project_id": project["id"], "mode": "parallel",
                                  "network": "192.168.8.0/28", "chunk_size": 16})
            coordinator.invoke.side_effect = RuntimeError("node unreachable")
            for _ in range(3):
                engine.advance(scan["id"])
            final = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            self.assertEqual(final["chunks"][0]["status"], "failed")
            self.assertEqual(final["status"], "failed")

    # -- consensus reconciliation ----------------------------------------------

    def test_consensus_reconciliation_flags_low_concord_on_disagreement(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4"), node("adv")]}
            scan = engine.create({"project_id": project["id"], "mode": "consensus",
                                  "network": "192.168.8.0/24", "targets": ["192.168.8.9"]})

            def invoke(device_id, capability, arguments, trace_id=""):
                if capability == "net.discovery.scan":
                    return {"payload": {"status": "ok", "result": {"job_status": "complete",
                                        "hosts": ["192.168.8.9"] if device_id == "p4" else []}}}
                raise AssertionError("unexpected capability")
            coordinator.invoke.side_effect = invoke
            engine.advance(scan["id"])
            final = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            self.assertEqual(final["status"], "complete")
            target = final["consensus"]["targets"]["192.168.8.9"]
            self.assertEqual(target["concord"], "low")
            self.assertEqual(target["detected_count"], 1)
            self.assertEqual(target["total_observations"], 2)
            # A consensus scan's reconciliation is also recorded as evidence.
            evidence = store.snapshot()["evidence"]
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]["kind"], "consensus-scan")

    def test_consensus_reconciliation_high_concord_on_unanimous_agreement(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4"), node("adv")]}
            scan = engine.create({"project_id": project["id"], "mode": "consensus",
                                  "network": "192.168.8.0/24", "targets": ["192.168.8.9"]})
            coordinator.invoke.return_value = {"payload": {"status": "ok",
                                               "result": {"job_status": "complete", "hosts": ["192.168.8.9"]}}}
            engine.advance(scan["id"])
            final = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            self.assertEqual(final["consensus"]["targets"]["192.168.8.9"]["concord"], "high")

    def test_consensus_target_is_unobserved_when_every_check_fails_to_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4")]}
            scan = engine.create({"project_id": project["id"], "mode": "consensus",
                                  "network": "192.168.8.0/24", "targets": ["192.168.8.9"]})
            coordinator.invoke.side_effect = RuntimeError("node unreachable")
            for _ in range(3):
                engine.advance(scan["id"])
            final = next(item for item in store.snapshot()["distributed_scans"] if item["id"] == scan["id"])
            self.assertEqual(final["consensus"]["targets"]["192.168.8.9"]["concord"], "unobserved")

    # -- cancel -----------------------------------------------------------------

    def test_cancel_stops_running_chunks_and_marks_pending_ones_cancelled(self):
        with tempfile.TemporaryDirectory() as directory:
            engine, store, project, coordinator, _ = self.make_engine(directory)
            coordinator.state.return_value = {"nodes": [node("p4")]}
            scan = engine.create({"project_id": project["id"], "mode": "parallel",
                                  "network": "192.168.8.0/24", "chunk_size": 16,
                                  "max_concurrent_chunks": 1})
            coordinator.invoke.return_value = {"payload": {"status": "ok",
                                               "result": {"job_status": "running", "job_id": "job-1"}}}
            engine.advance(scan["id"])
            coordinator.invoke.reset_mock()
            coordinator.invoke.return_value = {"payload": {"status": "ok"}}
            cancelled = engine.cancel(scan["id"])
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertTrue(all(chunk["status"] == "cancelled" for chunk in cancelled["chunks"]))
            coordinator.invoke.assert_called_once_with("p4", "coordination.job.cancel", {"job_id": "job-1"})


if __name__ == "__main__":
    unittest.main()
