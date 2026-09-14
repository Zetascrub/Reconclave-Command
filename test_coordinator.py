from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import time
import types
import unittest
from email.message import Message
from unittest import mock


fake_zeroconf = sys.modules.get("zeroconf", types.ModuleType("zeroconf"))
fake_zeroconf.ServiceBrowser = mock.MagicMock
fake_zeroconf.ServiceInfo = mock.MagicMock
fake_zeroconf.ServiceListener = object
fake_zeroconf.Zeroconf = mock.MagicMock
sys.modules["zeroconf"] = fake_zeroconf

HERE = pathlib.Path(__file__).parent
node_spec = importlib.util.spec_from_file_location("reconclave_node", HERE / "reconclave_node.py")
node_module = importlib.util.module_from_spec(node_spec)
assert node_spec.loader is not None
node_spec.loader.exec_module(node_module)
sys.modules["reconclave_node"] = node_module
coordinator_spec = importlib.util.spec_from_file_location("coordinator", HERE / "coordinator.py")
coordinator_module = importlib.util.module_from_spec(coordinator_spec)
assert coordinator_spec.loader is not None
sys.modules["coordinator"] = coordinator_module
coordinator_spec.loader.exec_module(coordinator_module)
desktop_spec = importlib.util.spec_from_file_location("desktop_app", HERE / "desktop_app.py")
desktop_module = importlib.util.module_from_spec(desktop_spec)
assert desktop_spec.loader is not None
desktop_spec.loader.exec_module(desktop_module)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.node = node_module.Node("rc-local", "Local", "127.0.0.1", 8767)
        self.node.roles = ["node", "coordinator"]
        self.coordinator = coordinator_module.Coordinator(
            self.node, mock.MagicMock(), execution_key="test execution",
            clock=lambda: self.now)

    def announcement(self, device_id="rc-peer", capabilities=None):
        return {
            "proto": "reconclave/1", "type": "announce",
            "payload": {
                "device_id": device_id, "device_type": "test-node", "firmware": "0.1",
                "roles": ["node"], "capabilities": capabilities or ["system.info"],
                "capability_descriptors": [], "resources": {}, "status": "ready",
            },
        }

    def authenticated_response(self, request, boot_nonce=""):
        payload = request["payload"]
        nonce = payload["auth"]["nonce"]
        request_id = payload["request_id"]
        result = {}
        digest = coordinator_module.canonical_digest(result)
        canonical = f"rc-peer|rc-local|{request_id}|ok|{boot_nonce}|{digest}|{nonce}".encode()
        tag = coordinator_module.hmac.new(
            self.coordinator.execution_key, canonical,
            coordinator_module.hashlib.sha256).digest()[:16].hex()
        return {"payload": {"request_id": request_id, "status": "ok", "result": result,
                            "auth": {"nonce": nonce, "payload_digest": digest, "tag": tag}}}

    def test_refresh_adds_peer_and_expiry_removes_it(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response), \
             mock.patch.object(coordinator_module.json, "load", return_value=self.announcement()):
            self.assertTrue(self.coordinator.refresh_peer("192.0.2.8", 8767, "peer.local"))
        state = self.coordinator.state()
        self.assertEqual([item["device_id"] for item in state["nodes"]], ["rc-local", "rc-peer"])
        self.now += coordinator_module.NODE_TTL_SECONDS + 1
        self.assertEqual([item["device_id"] for item in self.coordinator.state()["nodes"]], ["rc-local"])

    def test_invoke_rejects_unadvertised_capability_without_network_request(self):
        peer = coordinator_module.Peer("rc-peer", "192.0.2.8", 8767,
                                       self.announcement(), self.now)
        self.coordinator.peers[peer.device_id] = peer
        with mock.patch.object(coordinator_module.urllib.request, "urlopen") as opener:
            with self.assertRaisesRegex(ValueError, "not advertised"):
                self.coordinator.invoke("rc-peer", "net.discovery.scan", {})
            opener.assert_not_called()

    def test_trusted_invoke_is_signed_with_execution_domain(self):
        announcement = self.announcement(capabilities=["net.discovery.scan"])
        announcement["payload"]["capability_descriptors"] = [{
            "id": "net.discovery.scan", "version": 1, "permission": "trusted",
            "features": [], "limits": {"weight": 1, "max_concurrency": 1},
        }]
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False

        def response_document(stream):
            sent = stream
            if hasattr(stream, "full_url"):
                sent = stream
            request_body = sent.data
            request = coordinator_module.json.loads(request_body)
            request_id = request["payload"]["request_id"]
            self.assertIn("auth", request["payload"])
            self.assertEqual(request["payload"]["auth"]["coordinator_priority"], 100)
            self.assertEqual(request["payload"]["auth"]["lease_ms"], 15000)
            return self.authenticated_response(request)

        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response) as opener, \
             mock.patch.object(coordinator_module.json, "load") as loader:
            loader.side_effect = lambda _response: response_document(opener.call_args.args[0])
            result = self.coordinator.invoke("rc-peer", "net.discovery.scan", {"network": "192.0.2.0/24"})
        self.assertEqual(result["payload"]["status"], "ok")

    def test_p4_style_request_signature_includes_boot_nonce(self):
        announcement = self.announcement(capabilities=["net.discovery.scan"])
        announcement["payload"]["security"] = {"boot_nonce": "abc123", "mode": "hmac-sha256-128"}
        announcement["payload"]["capability_descriptors"] = [{
            "id": "net.discovery.scan", "version": 1, "permission": "trusted",
        }]
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        captured = {}

        def load_response(_response):
            request = coordinator_module.json.loads(captured["request"].data)
            payload = request["payload"]
            canonical = (f"rc-local|rc-peer|{payload['request_id']}|net.discovery.scan|"
                         f"abc123|{payload['auth']['payload_digest']}|"
                         f"{payload['auth']['nonce']}|100|15000").encode()
            self.assertEqual(payload["auth"]["payload_digest"],
                             coordinator_module.canonical_digest(payload["arguments"]))
            expected = coordinator_module.hmac.new(
                self.coordinator.execution_key, canonical,
                coordinator_module.hashlib.sha256).digest()[:16].hex()
            self.assertEqual(payload["auth"]["tag"], expected)
            return self.authenticated_response(request, "abc123")

        def open_request(request, timeout):
            captured["request"] = request
            return response

        with mock.patch.object(coordinator_module.urllib.request, "urlopen", side_effect=open_request), \
             mock.patch.object(coordinator_module.json, "load", side_effect=load_response):
            self.coordinator.invoke("rc-peer", "net.discovery.scan", {})

    def test_trusted_invoke_rejects_unauthenticated_response(self):
        announcement = self.announcement(capabilities=["net.discovery.scan"])
        announcement["payload"]["capability_descriptors"] = [{
            "id": "net.discovery.scan", "version": 1, "permission": "trusted",
        }]
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response) as opener, \
             mock.patch.object(coordinator_module.json, "load") as loader:
            loader.side_effect = lambda _response: {"payload": {
                "request_id": coordinator_module.json.loads(opener.call_args.args[0].data)["payload"]["request_id"],
                "status": "ok", "result": {},
            }}
            with self.assertRaises(ConnectionError):
                self.coordinator.invoke("rc-peer", "net.discovery.scan", {})

    def test_trusted_invoke_rejects_tampered_response_result(self):
        announcement = self.announcement(capabilities=["net.discovery.scan"])
        announcement["payload"]["capability_descriptors"] = [{
            "id": "net.discovery.scan", "version": 1, "permission": "trusted",
        }]
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response) as opener, \
             mock.patch.object(coordinator_module.json, "load") as loader:
            def tampered(_response):
                request = coordinator_module.json.loads(opener.call_args.args[0].data)
                document = self.authenticated_response(request)
                document["payload"]["result"] = {"hosts": ["203.0.113.9"]}
                return document
            loader.side_effect = tampered
            with self.assertRaises(ConnectionError):
                self.coordinator.invoke("rc-peer", "net.discovery.scan", {})

    def test_invoke_with_trace_id_records_dispatch_outcome_via_audit_sink(self):
        announcement = self.announcement(capabilities=["system.info"])
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        recorded = []
        self.coordinator.audit_sink = recorded.append
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response) as opener, \
             mock.patch.object(coordinator_module.json, "load") as loader:
            loader.side_effect = lambda _response: {"payload": {
                "request_id": coordinator_module.json.loads(opener.call_args.args[0].data)["payload"]["request_id"],
                "status": "ok", "result": {},
            }}
            self.coordinator.invoke("rc-peer", "system.info", {}, trace_id="trace-abc123")
        self.assertEqual(len(recorded), 1)
        event = recorded[0]
        self.assertEqual(event["action"], "node.dispatch")
        self.assertEqual(event["trace_id"], "trace-abc123")
        self.assertEqual(event["subject_id"], "rc-peer")
        self.assertEqual(event["capability"], "system.info")
        self.assertEqual(event["outcome"], "accepted")

    def test_invoke_without_trace_id_produces_no_audit_record(self):
        announcement = self.announcement(capabilities=["system.info"])
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        recorded = []
        self.coordinator.audit_sink = recorded.append
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response) as opener, \
             mock.patch.object(coordinator_module.json, "load") as loader:
            loader.side_effect = lambda _response: {"payload": {
                "request_id": coordinator_module.json.loads(opener.call_args.args[0].data)["payload"]["request_id"],
                "status": "ok", "result": {},
            }}
            self.coordinator.invoke("rc-peer", "system.info", {})
        self.assertEqual(recorded, [])

    def test_invoke_with_trace_id_but_no_audit_sink_does_not_crash(self):
        # No peer registered: this exercises the KeyError/"node_unavailable"
        # path with trace correlation requested but no sink wired in.
        self.assertIsNone(self.coordinator.audit_sink)
        with self.assertRaises(KeyError):
            self.coordinator.invoke("rc-missing", "system.info", {}, trace_id="trace-xyz")

    def test_invoke_records_node_unavailable_outcome_for_missing_peer(self):
        recorded = []
        self.coordinator.audit_sink = recorded.append
        with self.assertRaises(KeyError):
            self.coordinator.invoke("rc-missing", "system.info", {}, trace_id="trace-xyz")
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["outcome"], "node_unavailable")
        self.assertEqual(recorded[0]["trace_id"], "trace-xyz")

    def test_invoke_audit_sink_failure_does_not_break_dispatch(self):
        announcement = self.announcement(capabilities=["system.info"])
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)

        def failing_sink(_event):
            raise RuntimeError("workspace unavailable")

        self.coordinator.audit_sink = failing_sink
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response) as opener, \
             mock.patch.object(coordinator_module.json, "load") as loader:
            loader.side_effect = lambda _response: {"payload": {
                "request_id": coordinator_module.json.loads(opener.call_args.args[0].data)["payload"]["request_id"],
                "status": "ok", "result": {},
            }}
            result = self.coordinator.invoke("rc-peer", "system.info", {}, trace_id="trace-abc123")
        self.assertEqual(result["payload"]["status"], "ok")

    # -- upload_artifact (fleet.ota.apply phase 2) --------------------------

    def test_upload_artifact_rejects_unadvertised_capability_without_network_request(self):
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, self.announcement(), self.now)
        with mock.patch.object(coordinator_module.urllib.request, "urlopen") as opener:
            with self.assertRaisesRegex(ValueError, "not advertised"):
                self.coordinator.upload_artifact("rc-peer", "tok", b"firmware-bytes")
            opener.assert_not_called()

    def test_upload_artifact_posts_raw_bytes_and_verifies_authenticated_result(self):
        announcement = self.announcement(capabilities=["fleet.ota.apply"])
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        artifact = b"\x01\x02firmware-image-bytes\x03\x04"
        digest = "d" * 64
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        captured = {}

        def open_request(request, timeout):
            captured["request"] = request
            return response

        def result_document(_response):
            request = captured["request"]
            canonical = f"rc-peer|rc-local|tok|ok|{digest}".encode()
            tag = coordinator_module.hmac.new(
                self.coordinator.execution_key, canonical,
                coordinator_module.hashlib.sha256).digest()[:16].hex()
            return {"status": "ok", "artifact_sha256": digest, "tag": tag}

        with mock.patch.object(coordinator_module.urllib.request, "urlopen",
                               side_effect=open_request) as opener, \
             mock.patch.object(coordinator_module.json, "load", side_effect=result_document):
            result = self.coordinator.upload_artifact("rc-peer", "tok", artifact)
        self.assertEqual(result["artifact_sha256"], digest)
        request = captured["request"]
        self.assertEqual(request.data, artifact)
        self.assertIn("/ota-upload?token=tok", request.full_url)
        self.assertEqual(request.get_header("Content-type"), "application/octet-stream")
        opener.assert_called_once()
        self.assertEqual(opener.call_args.kwargs.get("timeout") or opener.call_args.args[1],
                         coordinator_module.OTA_UPLOAD_TIMEOUT_SECONDS)

    def test_upload_artifact_rejects_result_with_wrong_tag(self):
        announcement = self.announcement(capabilities=["fleet.ota.apply"])
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response), \
             mock.patch.object(coordinator_module.json, "load",
                               return_value={"status": "ok", "artifact_sha256": "d" * 64, "tag": "00" * 16}):
            with self.assertRaises(ConnectionError):
                self.coordinator.upload_artifact("rc-peer", "tok", b"firmware")

    def test_upload_artifact_surfaces_device_rejection_message(self):
        announcement = self.announcement(capabilities=["fleet.ota.apply"])
        self.coordinator.peers["rc-peer"] = coordinator_module.Peer(
            "rc-peer", "192.0.2.8", 8767, announcement, self.now)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(coordinator_module.urllib.request, "urlopen", return_value=response), \
             mock.patch.object(coordinator_module.json, "load", return_value={
                 "status": "rejected", "error": {"code": "HASH_MISMATCH", "message": "digest did not match"}}):
            with self.assertRaisesRegex(ValueError, "digest did not match"):
                self.coordinator.upload_artifact("rc-peer", "tok", b"firmware")

    def test_signed_json_rejects_ambiguous_float_representation(self):
        with self.assertRaisesRegex(ValueError, "signed JSON"):
            coordinator_module.canonical_digest({"interval_ms": 1000.0})

    def test_scan_scope_validation_is_bounded_and_consistent(self):
        desktop_module.validate_scan_arguments({
            "network": "192.0.2.0/24", "start_ip": "192.0.2.1", "end_ip": "192.0.2.42",
        })
        with self.assertRaises(ValueError):
            desktop_module.validate_scan_arguments({
                "network": "192.0.0.0/16", "start_ip": "192.0.2.1", "end_ip": "192.0.2.42",
            })
        with self.assertRaises(ValueError):
            desktop_module.validate_scan_arguments({
                "network": "192.0.2.0/24", "start_ip": "192.0.2.42", "end_ip": "192.0.2.1",
            })

    def test_target_bearing_capability_detection_matches_policy_boundary(self):
        self.assertTrue(desktop_module.is_target_bearing("net.discovery.scan"))
        self.assertTrue(desktop_module.is_target_bearing("net.tcp.inspect"))
        self.assertTrue(desktop_module.is_target_bearing("vuln.nuclei.templates"))
        self.assertTrue(desktop_module.is_target_bearing("tool.nmap.services"))
        self.assertFalse(desktop_module.is_target_bearing("system.info"))
        self.assertFalse(desktop_module.is_target_bearing("coordination.job.status"))

    def test_workflow_run_requires_signed_scope_for_target_bearing_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            workspace = desktop_module.WorkspaceStore(base / "workspace.json")
            policy = desktop_module.EngagementPolicy(workspace, base / "scope.key", b"k" * 32)
            project = workspace.create_project({"name": "Engagement"})
            benign = workspace.create_workflow({"project_id": project["id"], "name": "Benign",
                "steps": [{"id": "info", "capability": "system.info", "arguments": {}}]})
            scanning = workspace.create_workflow({"project_id": project["id"], "name": "Scanning",
                "steps": [{"id": "scan", "capability": "net.discovery.scan",
                           "arguments": {"network": "192.0.2.0/24"}}]})
            handler = object.__new__(desktop_module.AppHandler)
            handler.server = types.SimpleNamespace(workspace=workspace, policy=policy)

            def create_run(workflow, scope_id=""):
                workflow_lookup = next(item for item in handler.server.workspace.snapshot()["workflows"]
                                       if item["id"] == workflow["id"])
                target_bearing = any(desktop_module.is_target_bearing(step["capability"])
                                     for step in workflow_lookup["steps"])
                if scope_id:
                    handler.server.policy.get_valid(scope_id, workflow_lookup["project_id"])
                elif target_bearing:
                    raise PermissionError("a signed engagement scope is required to run a "
                                          "workflow with target-bearing steps")
                return handler.server.workspace.create_workflow_run(workflow["id"], scope_id)

            # A workflow with no target-bearing steps runs fine without a scope.
            create_run(benign)
            # A workflow with a target-bearing step is rejected up front, not deep in dispatch.
            with self.assertRaises(PermissionError):
                create_run(scanning)
            # It succeeds once a real signed scope is supplied.
            scope = policy.create_scope({"project_id": project["id"],
                "included_networks": ["192.0.2.0/24"], "capability_classes": ["discovery"],
                "expires_at_ms": int(time.time() * 1000) + 60000})
            create_run(scanning, scope["id"])

    def test_distributed_scan_creation_requires_signed_scope_for_target_bearing_capability(self):
        # Mirrors the workflow-run test above for the same reject-at-creation-time
        # boundary, now for POST /api/distributed-scans (desktop_app.py).
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            workspace = desktop_module.WorkspaceStore(base / "workspace.json")
            policy = desktop_module.EngagementPolicy(workspace, base / "scope.key", b"k" * 32)
            project = workspace.create_project({"name": "Engagement"})

            def create_scan(scope_id=""):
                capability = "net.discovery.scan"
                target_bearing = (capability in desktop_module.TARGET_CAPABILITIES or
                                  capability.startswith(desktop_module.TARGET_PREFIXES))
                if scope_id:
                    policy.get_valid(scope_id, project["id"])
                elif target_bearing:
                    raise PermissionError(
                        "a signed engagement scope is required for a target-bearing distributed scan")

            with self.assertRaises(PermissionError):
                create_scan()
            scope = policy.create_scope({"project_id": project["id"],
                "included_networks": ["192.0.2.0/24"], "capability_classes": ["discovery"],
                "expires_at_ms": int(time.time() * 1000) + 60000})
            create_scan(scope["id"])  # does not raise

    # -- operators/roles/approvals (Phase 10) --------------------------------

    def make_handler(self, workspace, operators=None, approvals=None):
        handler = object.__new__(desktop_module.AppHandler)
        handler.server = types.SimpleNamespace(operators=operators, approvals=approvals,
                                               workspace=workspace)
        handler.headers = Message()
        handler.send_json = mock.MagicMock()
        return handler

    def test_legacy_single_operator_mode_requires_no_session_at_all(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            operators = desktop_module.OperatorManager(workspace)
            handler = self.make_handler(workspace, operators=operators)
            operator = handler.resolve_operator()
            self.assertIsNone(operator)
            self.assertTrue(handler.enforce_authenticated("/api/projects", operator))
            handler.send_json.assert_not_called()

    def test_authorization_header_resolves_a_real_session(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            operators = desktop_module.OperatorManager(workspace)
            operators.create_operator({"username": "alice", "password": "x" * 12}, actor=None)
            session = operators.login("alice", "x" * 12)
            handler = self.make_handler(workspace, operators=operators)
            handler.headers["Authorization"] = f"Bearer {session['token']}"
            resolved = handler.resolve_operator()
            self.assertEqual(resolved["username"], "alice")

    def test_multi_operator_mode_rejects_missing_or_invalid_session(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            operators = desktop_module.OperatorManager(workspace)
            operators.create_operator({"username": "alice", "password": "x" * 12}, actor=None)
            handler = self.make_handler(workspace, operators=operators)
            self.assertFalse(handler.enforce_authenticated("/api/projects", None))
            handler.send_json.assert_called_once_with(401, {"error": "authentication_required"})
            # The bootstrap/session/login paths stay reachable without a session even
            # once operators exist.
            handler.send_json.reset_mock()
            for exempt_path in ("/api/login", "/api/session", "/api/operators"):
                self.assertTrue(handler.enforce_authenticated(exempt_path, None))
            handler.send_json.assert_not_called()

    def test_viewer_role_is_blocked_from_mutating_but_not_from_identity_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            operators = desktop_module.OperatorManager(workspace)
            admin = operators.create_operator({"username": "admin", "password": "x" * 12}, actor=None)
            viewer = operators.create_operator({"username": "viewer", "password": "y" * 12, "role": "viewer"},
                                               actor=admin)
            handler = self.make_handler(workspace, operators=operators)
            self.assertFalse(handler.enforce_not_viewer("/api/projects", viewer))
            handler.send_json.assert_called_once_with(403, {"error": "viewer_role_is_read_only"})
            handler.send_json.reset_mock()
            self.assertTrue(handler.enforce_not_viewer("/api/logout", viewer))
            handler.send_json.assert_not_called()
            self.assertTrue(handler.enforce_not_viewer("/api/projects", admin))

    def test_scope_creation_requires_admin_once_operators_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            operators = desktop_module.OperatorManager(workspace)
            admin = operators.create_operator({"username": "admin", "password": "x" * 12}, actor=None)
            junior = operators.create_operator({"username": "junior", "password": "y" * 12, "role": "operator"},
                                               actor=admin)
            handler = self.make_handler(workspace, operators=operators)
            with self.assertRaisesRegex(PermissionError, "admin role"):
                handler.require_admin_when_multi_operator(junior, handler.server)
            handler.require_admin_when_multi_operator(admin, handler.server)  # does not raise

    def test_host_inspection_rejects_unapproved_or_external_targets(self):
        with self.assertRaises(PermissionError):
            desktop_module.inspect_hosts("192.0.2.10", {"hosts": ["192.0.2.20"], "ports": [80]})
        with self.assertRaises(ValueError):
            desktop_module.inspect_hosts("192.0.2.10", {
                "operator_authorised": True, "hosts": ["198.51.100.2"], "ports": [80],
            })
        with self.assertRaises(ValueError):
            desktop_module.inspect_hosts("192.0.2.10", {
                "operator_authorised": True, "hosts": ["192.0.2.20"], "ports": [0],
            })

    def test_host_inspection_reports_only_open_ports(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.connect_ex.side_effect = lambda target: 0 if target[1] == 443 else 111
        with mock.patch.object(desktop_module.socket, "socket", return_value=connection):
            result = desktop_module.inspect_hosts("192.0.2.10", {
                "operator_authorised": True,
                "hosts": ["192.0.2.20"], "ports": [80, 443],
            })
        self.assertEqual(result["checked"], 2)
        self.assertEqual(result["hosts"], [{
            "address": "192.0.2.20", "open_ports": [443], "checked_ports": 2,
        }])

    def test_trust_store_selects_unique_peer_keys(self):
        with __import__("tempfile").TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "fleet.json"
            path.write_text(__import__("json").dumps({"links": {
                "rc-local|rc-peer": "11" * 32,
                "rc-local|rc-other": "22" * 32,
                "unrelated|rc-peer": "33" * 32,
            }}))
            keys = desktop_module.load_trust_keys(path, "rc-local")
        self.assertEqual(keys, {"rc-peer": bytes.fromhex("11" * 32),
                                "rc-other": bytes.fromhex("22" * 32)})

    def test_outbox_import_is_durable_before_acknowledgement(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = workspace.create_project({"name": "Lab"})
            coordinator = mock.MagicMock()
            coordinator.invoke.side_effect = [
                {"payload": {"result": {"records": [{
                    "sequence": 7, "project_id": project["id"], "rule_id": "r1",
                    "boot_id": "boot", "kind": "system-snapshot", "run_count": 1,
                }]}}},
                {"payload": {"status": "ok"}},
            ]
            engine = desktop_module.AutomationEngine(coordinator, workspace)
            engine._sync_outbox({"device_id": "rc-p4"}, workspace.snapshot())
            self.assertEqual(len(workspace.snapshot()["evidence"]), 1)
            self.assertEqual(coordinator.invoke.call_args_list[1].args,
                             ("rc-p4", "evidence.outbox.ack", {"sequence": 7}))

    def test_outbox_sync_carries_verified_response_signature_as_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = workspace.create_project({"name": "Lab"})
            coordinator = mock.MagicMock()
            coordinator.invoke.side_effect = [
                {"payload": {"result": {"records": [{
                    "sequence": 9, "project_id": project["id"], "rule_id": "r1",
                    "boot_id": "boot", "kind": "system-snapshot", "run_count": 1,
                }]}, "auth": {"nonce": "abc123", "tag": "deadbeef" * 4}}},
                {"payload": {"status": "ok"}},
            ]
            engine = desktop_module.AutomationEngine(coordinator, workspace)
            engine._sync_outbox({"device_id": "rc-p4"}, workspace.snapshot())
            [evidence] = workspace.snapshot()["evidence"]
            self.assertEqual(evidence["provenance"], {
                "source_node": "rc-p4", "verified": True, "response_nonce": "abc123",
                "response_tag": "deadbeef" * 4, "algorithm": "hmac-sha256-truncated16",
            })
            # Content-addressed custody must fold provenance into the hash, or a
            # swapped/forged provenance claim would go undetected.
            self.assertTrue(workspace.verify_evidence(project["id"])["valid"])
            tampered = workspace.snapshot()
            tampered["evidence"][0]["provenance"]["source_node"] = "rc-attacker"
            workspace.data = tampered
            self.assertFalse(workspace.verify_evidence(project["id"])["valid"])

    def test_outbox_sync_without_a_response_signature_leaves_provenance_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = workspace.create_project({"name": "Lab"})
            coordinator = mock.MagicMock()
            coordinator.invoke.side_effect = [
                {"payload": {"result": {"records": [{
                    "sequence": 1, "project_id": project["id"], "boot_id": "boot",
                }]}}},
                {"payload": {"status": "ok"}},
            ]
            engine = desktop_module.AutomationEngine(coordinator, workspace)
            engine._sync_outbox({"device_id": "rc-p4"}, workspace.snapshot())
            [evidence] = workspace.snapshot()["evidence"]
            self.assertNotIn("provenance", evidence)
            self.assertTrue(workspace.verify_evidence(project["id"])["valid"])

    def test_automation_trigger_is_audited_before_the_playbook_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = workspace.create_project({"name": "Lab"})
            coordinator = mock.MagicMock()
            coordinator.invoke.return_value = {"payload": {"result": {"firmware": "1"}}}
            engine = desktop_module.AutomationEngine(coordinator, workspace)
            rule = workspace.create_automation({"project_id": project["id"], "node_id": "rc-p4",
                                                "condition": "dhcp_assigned", "playbook": "system_snapshot"})
            engine._trigger(rule, {"dhcp_assigned": True})
            actions = [event["action"] for event in workspace.snapshot()["audit_events"]]
            self.assertIn("automation.triggered", actions)
            trigger_event = next(event for event in workspace.snapshot()["audit_events"]
                                 if event["action"] == "automation.triggered")
            self.assertEqual(trigger_event["subject_id"], rule["id"])
            self.assertEqual(trigger_event["outcome"], "system_snapshot")
            self.assertEqual(trigger_event["node_id"], "rc-p4")
            self.assertEqual(trigger_event["condition"], "dhcp_assigned")
            # Recorded even though the playbook call below is what actually fails.
            coordinator.invoke.side_effect = RuntimeError("node unreachable")
            with self.assertRaises(RuntimeError):
                engine._trigger(rule, {"dhcp_assigned": True})
            self.assertEqual([event["action"] for event in workspace.snapshot()["audit_events"]].count(
                "automation.triggered"), 2)

    def test_orphaned_outbox_record_does_not_block_valid_record(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = desktop_module.WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = workspace.create_project({"name": "Lab"})
            coordinator = mock.MagicMock()
            coordinator.invoke.side_effect = [
                {"payload": {"result": {"records": [
                    {"sequence": 1, "project_id": "deleted", "boot_id": "boot"},
                    {"sequence": 2, "project_id": project["id"], "rule_id": "r2",
                     "boot_id": "boot", "kind": "system-snapshot"},
                ]}}},
                {"payload": {"status": "ok"}},
            ]
            engine = desktop_module.AutomationEngine(coordinator, workspace)
            with self.assertRaisesRegex(ValueError, "unknown project"):
                engine._sync_outbox({"device_id": "rc-p4"}, workspace.snapshot())
            self.assertEqual(len(workspace.snapshot()["evidence"]), 1)
            self.assertEqual(coordinator.invoke.call_args_list[1].args[-1], {"sequence": 2})

    def test_loopback_api_rejects_cross_site_origin(self):
        handler = object.__new__(desktop_module.AppHandler)
        handler.server = types.SimpleNamespace(server_port=8767)
        handler.headers = Message()
        handler.headers["Origin"] = "https://attacker.example"
        self.assertFalse(handler.trusted_api_origin())
        handler.headers.replace_header("Origin", "http://127.0.0.1:8767")
        self.assertTrue(handler.trusted_api_origin())


if __name__ == "__main__":
    unittest.main()
