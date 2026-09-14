import hashlib
import hmac
import importlib.util
import json
import pathlib
import threading
import time
import sys
import tempfile
import types
import unittest
from unittest import mock


fake_zeroconf = types.ModuleType("zeroconf")
fake_zeroconf.ServiceInfo = object
fake_zeroconf.Zeroconf = object
sys.modules.setdefault("zeroconf", fake_zeroconf)
module_path = pathlib.Path(__file__).with_name("reconclave_node.py")
spec = importlib.util.spec_from_file_location("reconclave_desktop_node", module_path)
node_module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(node_module)


class DesktopNodeTests(unittest.TestCase):
    def make_request(self, node, capability, arguments, auth=None):
        payload = {"request_id": "req-1", "capability": capability, "arguments": arguments}
        if auth is not None:
            payload["auth"] = auth
        return {
            "proto": node_module.PROTOCOL,
            "type": "request",
            "source_node": "rc-test-coordinator",
            "destination_node": node.node_id,
            "payload": payload,
        }

    def signed_auth(self, node, capability, arguments, passphrase, nonce):
        digest = node_module.canonical_digest(arguments)
        canonical = "|".join(["rc-test-coordinator", node.node_id, "req-1", capability,
                              node.boot_nonce, digest, nonce, "100", "15000"]).encode()
        key = hashlib.sha256(passphrase.encode()).digest()
        return {"nonce": nonce, "payload_digest": digest, "coordinator_priority": 100,
                "lease_ms": 15000,
                "tag": hmac.new(key, canonical, hashlib.sha256).digest()[:16].hex()}

    def test_capabilities_follow_enabled_handlers(self):
        plain = node_module.Node("plain", "plain", "127.0.0.1", 8767)
        scanning = node_module.Node("scan", "scan", "127.0.0.1", 8767, True,
                                    execution_key="test key")
        self.assertNotIn("net.discovery.scan", plain.announcement()["payload"]["capabilities"])
        self.assertIn("net.discovery.scan", scanning.announcement()["payload"]["capabilities"])
        scan_descriptor = next(item for item in scanning.announcement()["payload"]["capability_descriptors"]
                               if item["id"] == "net.discovery.scan")
        self.assertEqual(scan_descriptor["permission"], "trusted")
        self.assertEqual(scan_descriptor["limits"]["weight"], 4)
        self.assertNotIn("recurring", scan_descriptor["features"])
        with tempfile.TemporaryDirectory() as directory:
            durable = node_module.Node("durable", "durable", "127.0.0.1", 8767, True,
                                       evidence_dir=directory, execution_key="test key")
            durable_descriptor = next(item for item in durable.announcement()["payload"]["capability_descriptors"]
                                      if item["id"] == "net.discovery.scan")
            self.assertIn("durable", durable_descriptor["features"])
            self.assertIn("callback", durable_descriptor["features"])

    def test_callback_lease_verifies_expected_coordinator(self):
        node = node_module.Node("scan", "scan", "127.0.0.1", 8767)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        with mock.patch.object(node_module.urllib.request, "urlopen", return_value=response), \
             mock.patch.object(node_module.json, "load", return_value={
                 "payload": {"device_id": "rc-coordinator", "roles": ["coordinator"]}
             }):
            self.assertTrue(node._callback_coordinator_reachable({
                "callback_endpoint": "http://192.0.2.1:8766",
                "owner_coordinator": "rc-coordinator",
            }))
            self.assertFalse(node._callback_coordinator_reachable({
                "callback_endpoint": "http://192.0.2.1:8766",
                "owner_coordinator": "different-node",
            }))

    def test_network_scan_is_not_exposed_without_authentication_key(self):
        node = node_module.Node("scan", "scan", "127.0.0.1", 8767, True)
        self.assertNotIn("net.discovery.scan", node.announcement()["payload"]["capabilities"])

    def test_announcement_creates_new_evidence_directory_before_reporting_resources(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = str(pathlib.Path(parent) / "new-evidence")
            node = node_module.Node("collector", "collector", "127.0.0.1", 8767,
                                    evidence_dir=directory, evidence_key="test key")
            announcement = node.announcement()
            self.assertTrue(pathlib.Path(directory).is_dir())
            self.assertTrue(announcement["payload"]["resources"]["persistent_storage"])

    def test_non_object_request_and_arguments_are_rejected(self):
        node = node_module.Node("node", "node", "127.0.0.1", 8767)
        _, response = node.respond([])
        self.assertEqual(response["payload"]["error"]["code"], "INVALID_REQUEST")
        request = self.make_request(node, "system.info", [])
        _, response = node.respond(request)
        self.assertEqual(response["payload"]["error"]["code"], "INVALID_REQUEST")

    def test_authenticated_evidence_write_and_replay_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            passphrase = "test evidence key"
            node = node_module.Node("collector", "collector", "127.0.0.1", 8767,
                                    evidence_dir=directory, evidence_key=passphrase)
            evidence = {
                "job_id": "job-1", "source_node": "rc-test-coordinator",
                "evidence_id": "evidence-1",
                "target": "192.0.2.10", "timestamp_ms": 1,
                "observation": {"responsive": True},
            }
            nonce = "0011223344556677"
            arguments = {"evidence": evidence}
            auth = self.signed_auth(node, "storage.evidence.write", arguments, passphrase, nonce)
            request = self.make_request(node, "storage.evidence.write", arguments, auth)
            _, response = node.respond(request)
            self.assertEqual(response["payload"]["status"], "ok")
            self.assertEqual(response["payload"]["result"]["evidence_id"], "evidence-1")
            records = list(pathlib.Path(directory).glob("evidence-*.rcspool"))
            self.assertEqual(len(records), 1)
            self.assertNotIn("192.0.2.10", records[0].read_text())
            # respond() carries the just-verified request signature into the stored
            # record as provenance (platform-roadmap.md Phase 5's push-in gap) rather
            # than only trusting the envelope's unauthenticated source_node string.
            [stored] = node.encrypted_spool.read(records[0])
            self.assertEqual(stored, {**evidence, "provenance": {
                "source_node": "rc-test-coordinator", "verified": True,
                "request_nonce": nonce, "request_tag": auth["tag"],
                "algorithm": "hmac-sha256-truncated16",
            }})
            _, replay = node.respond(request)
            self.assertEqual(replay["payload"]["error"]["code"], "UNAUTHENTICATED")

            second_nonce = "0011223344556688"
            request["payload"]["auth"] = self.signed_auth(
                node, "storage.evidence.write", arguments, passphrase, second_nonce)
            _, duplicate = node.respond(request)
            self.assertTrue(duplicate["payload"]["result"]["duplicate"])
            self.assertEqual(len(records[0].read_text().splitlines()), 1)

    def test_provider_rejects_scope_delegation_bound_to_different_arguments(self):
        passphrase = "execution key"
        node = node_module.Node("runner", "runner", "127.0.0.1", 8767,
                                execution_key=passphrase)
        node.capability_handlers["tool.nmap.services"] = lambda arguments: {"accepted": arguments["hosts"]}
        original = {"hosts": ["192.168.20.4"], "ports": [443]}
        now = int(time.time() * 1000)
        token = {"scope_id": "scope-1", "project_id": "project-1",
                 "capability": "tool.nmap.services", "destination_node": node.node_id,
                 "included_networks": ["192.168.20.0/24"], "excluded_networks": [],
                 "capability_classes": ["discovery"],
                 "arguments_digest": node_module.canonical_digest(original),
                 "lease_id": "lease-1", "issued_at_ms": now,
                 "expires_at_ms": now + 60000, "nonce": "delegation-1"}
        key = hashlib.sha256(passphrase.encode()).digest()
        token["tag"] = hmac.new(key, json.dumps(token, sort_keys=True, separators=(",", ":")).encode(),
                                hashlib.sha256).hexdigest()
        delegated = {**original, "_scope_delegation": token}
        request = self.make_request(node, "tool.nmap.services", delegated,
                                    self.signed_auth(node, "tool.nmap.services", delegated,
                                                     passphrase, "outer-1"))
        _, response = node.respond(request)
        self.assertEqual(response["payload"]["status"], "ok")

        tampered = {**delegated, "hosts": ["192.168.20.5"]}
        request = self.make_request(node, "tool.nmap.services", tampered,
                                    self.signed_auth(node, "tool.nmap.services", tampered,
                                                     passphrase, "outer-2"))
        _, response = node.respond(request)
        self.assertEqual(response["payload"]["error"]["code"], "SCOPE_INVALID")

    def test_tool_capabilities_and_shared_job_control_registered_when_available(self):
        with mock.patch("tool_runner.shutil.which", return_value="/usr/bin/true"):
            node = node_module.Node("runner", "runner", "127.0.0.1", 8767,
                                    execution_key="exec key", enable_tools=True)
        capabilities = node.announcement()["payload"]["capabilities"]
        for capability in ("tool.nmap.services", "tool.dns.lookup", "tool.tcpdump.capture",
                           "tool.job.status", "tool.job.cancel"):
            self.assertIn(capability, capabilities)
        descriptors = {item["id"]: item for item in node.announcement()["payload"]["capability_descriptors"]}
        # Job status polling is public like coordination.job.status; job control
        # that changes state (cancel) and the tool adapters themselves are trusted.
        self.assertEqual(descriptors["tool.job.status"]["permission"], "public")
        self.assertEqual(descriptors["tool.job.cancel"]["permission"], "trusted")
        self.assertEqual(descriptors["tool.dns.lookup"]["permission"], "trusted")
        self.assertEqual(descriptors["tool.tcpdump.capture"]["permission"], "trusted")
        self.assertIn("isolation", descriptors["tool.dns.lookup"])

    def test_tool_capabilities_and_job_control_absent_when_no_tool_is_installed(self):
        with mock.patch("tool_runner.shutil.which", return_value=None):
            node = node_module.Node("runner", "runner", "127.0.0.1", 8767,
                                    execution_key="exec key", enable_tools=True)
        capabilities = node.announcement()["payload"]["capabilities"]
        for capability in ("tool.nmap.services", "tool.dns.lookup", "tool.tcpdump.capture",
                           "tool.job.status", "tool.job.cancel"):
            self.assertNotIn(capability, capabilities)

    def test_dns_lookup_and_tcpdump_capture_require_signed_requests(self):
        with mock.patch("tool_runner.shutil.which", return_value="/usr/bin/true"):
            node = node_module.Node("runner", "runner", "127.0.0.1", 8767,
                                    execution_key="exec key", enable_tools=True)
        for capability, arguments in (("tool.dns.lookup", {"names": ["example.com"]}),
                                      ("tool.tcpdump.capture", {"interface": "lo", "count": 1})):
            _, response = node.respond(self.make_request(node, capability, arguments))
            self.assertEqual(response["payload"]["error"]["code"], "UNAUTHENTICATED")

    def test_tool_job_dispatch_status_and_idempotent_cancel_round_trip_through_respond(self):
        passphrase = "execution key"
        with mock.patch("tool_runner.shutil.which", return_value="/usr/bin/true"):
            node = node_module.Node("runner", "runner", "127.0.0.1", 8767,
                                    execution_key=passphrase, enable_tools=True)
        release = threading.Event()
        process = mock.MagicMock()
        process.pid = 5150
        process.returncode = 0

        def _communicate(timeout=None):
            release.wait(timeout=5)
            return ('<nmaprun><host><address addr="192.168.20.4" addrtype="ipv4"/>'
                    '<ports></ports></host></nmaprun>', "")

        process.communicate.side_effect = _communicate
        original = {"hosts": ["192.168.20.4"], "ports": [443]}
        now = int(time.time() * 1000)
        token = {"scope_id": "scope-1", "project_id": "project-1",
                 "capability": "tool.nmap.services", "destination_node": node.node_id,
                 "included_networks": ["192.168.20.0/24"], "excluded_networks": [],
                 "capability_classes": ["discovery"],
                 "arguments_digest": node_module.canonical_digest(original),
                 "lease_id": "lease-1", "issued_at_ms": now,
                 "expires_at_ms": now + 60000, "nonce": "delegation-1"}
        key = hashlib.sha256(passphrase.encode()).digest()
        token["tag"] = hmac.new(key, json.dumps(token, sort_keys=True, separators=(",", ":")).encode(),
                                hashlib.sha256).hexdigest()
        delegated = {**original, "_scope_delegation": token}

        with mock.patch("tool_runner.shutil.which", return_value="/usr/bin/true"), \
             mock.patch("tool_runner.subprocess.Popen", return_value=process):
            request = self.make_request(node, "tool.nmap.services", delegated,
                                        self.signed_auth(node, "tool.nmap.services", delegated,
                                                         passphrase, "outer-1"))
            _, response = node.respond(request)
            self.assertEqual(response["payload"]["status"], "ok")
            job_id = response["payload"]["result"]["job_id"]
            self.assertEqual(response["payload"]["result"]["job_status"], "running")

            # tool.job.status is public read-only polling, like coordination.job.status:
            # no auth object is required.
            status_request = self.make_request(node, "tool.job.status", {"job_id": job_id})
            _, status_response = node.respond(status_request)
            self.assertEqual(status_response["payload"]["status"], "ok")
            self.assertEqual(status_response["payload"]["result"]["job_status"], "running")

            release.set()
            deadline = time.monotonic() + 2
            result = None
            while time.monotonic() < deadline:
                _, status_response = node.respond(status_request)
                result = status_response["payload"]["result"]
                if result["job_status"] == "complete":
                    break
                time.sleep(0.01)
            self.assertEqual(result["job_status"], "complete")
            self.assertEqual(result["result"]["hosts"][0]["address"], "192.168.20.4")

            # Cancelling a finished job is still an "ok" no-op (idempotent, like
            # coordination.job.cancel), but the request must still be signed.
            cancel_arguments = {"job_id": job_id}
            unauth_cancel = self.make_request(node, "tool.job.cancel", cancel_arguments)
            _, unauth_response = node.respond(unauth_cancel)
            self.assertEqual(unauth_response["payload"]["error"]["code"], "UNAUTHENTICATED")

            cancel_request = self.make_request(node, "tool.job.cancel", cancel_arguments,
                                               self.signed_auth(node, "tool.job.cancel", cancel_arguments,
                                                                passphrase, "cancel-1"))
            _, cancel_response = node.respond(cancel_request)
            self.assertEqual(cancel_response["payload"]["status"], "ok")
            self.assertTrue(cancel_response["payload"]["result"]["ok"])
            self.assertFalse(cancel_response["payload"]["result"]["cancelled"])


class ArmedClockTests(unittest.TestCase):
    def test_checkpoint_and_reload_preserves_elapsed_time(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = str(pathlib.Path(directory) / "standing_grant_state.json")
            clock = node_module.ArmedClock(state_path, "grant-1")
            time.sleep(0.05)
            clock.checkpoint()
            elapsed_before_reload = clock.elapsed_ms(duration_ms=60000)
            self.assertGreaterEqual(elapsed_before_reload, 50)

            reloaded = node_module.ArmedClock(state_path, "grant-1")
            elapsed_after_reload = reloaded.elapsed_ms(duration_ms=60000)
            self.assertGreaterEqual(elapsed_after_reload, elapsed_before_reload)

    def test_missing_or_mismatched_state_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_path = str(pathlib.Path(directory) / "does-not-exist.json")
            clock = node_module.ArmedClock(missing_path, "grant-1")
            self.assertEqual(clock.elapsed_ms(duration_ms=60000), 60001)

            state_path = str(pathlib.Path(directory) / "standing_grant_state.json")
            node_module.ArmedClock(state_path, "grant-1").checkpoint()
            mismatched = node_module.ArmedClock(state_path, "grant-2")
            self.assertEqual(mismatched.elapsed_ms(duration_ms=60000), 60001)

            with open(state_path, "w", encoding="utf-8") as handle:
                handle.write("not json")
            corrupt = node_module.ArmedClock(state_path, "grant-1")
            self.assertEqual(corrupt.elapsed_ms(duration_ms=60000), 60001)


if __name__ == "__main__":
    unittest.main()
