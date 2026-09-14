#!/usr/bin/env python3
"""Local Reconclave web node and coordinator."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import mimetypes
import os
import pathlib
import signal
import socket
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from zeroconf import ServiceInfo, Zeroconf

from adaptive_scheduler import DistributedScanEngine
from coordinator import Coordinator
from engagement_policy import TARGET_CAPABILITIES, TARGET_PREFIXES, EngagementPolicy
from fleet_manager import FleetManager
from operators import ApprovalManager, OperatorManager
from reconclave_node import ANNOUNCE_PATH, MESSAGE_PATH, PROTOCOL, Node, local_ip
from workspace_store import WorkspaceStore
from workflow_engine import WorkflowEngine
from vulnerability_analysis import import_document

WEB_ROOT = pathlib.Path(__file__).parent / "web" / "dist"
DEFAULT_TRUST_STORE = pathlib.Path(__file__).resolve().parents[2] / ".reconclave-provisioning" / "fleet.json"
DEFAULT_WORKSPACE_STORE = pathlib.Path(__file__).resolve().parents[2] / ".reconclave-data" / "workspace.json"
MAX_BODY_BYTES = 2 * 1024 * 1024
# /api/fleet/releases carries a whole firmware image as base64 (~1.34x inflation) plus a
# little JSON overhead; FleetManager.MAX_ARTIFACT_BYTES bounds the decoded artifact itself,
# this bounds the encoded request body reaching it. Kept as its own constant rather than
# raising MAX_BODY_BYTES globally, since every other route has no business accepting
# anything near this size.
MAX_RELEASE_BODY_BYTES = 11 * 1024 * 1024
MAX_INSPECTION_HOSTS = 16
MAX_INSPECTION_PORTS = 128


class AutomationEngine:
    """Evaluates a small, auditable allowlist of node conditions and playbooks."""
    def __init__(self, coordinator: Coordinator, workspace: WorkspaceStore) -> None:
        self.coordinator = coordinator
        self.workspace = workspace
        self.stop_event = threading.Event()
        self.condition_state: dict[str, bool] = {}
        self.thread = threading.Thread(target=self._run, name="reconclave-automations", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def _condition(self, rule: dict, nodes: dict[str, dict]) -> tuple[bool, dict]:
        node = nodes.get(rule["node_id"])
        if node is None:
            return False, {}
        if rule["condition"] == "dhcp_assigned":
            return bool(node.get("address")), {"ip": node.get("address"), "dhcp_assigned": True}
        response = self.coordinator.invoke(rule["node_id"], "net.connectivity.check", {})
        result = response.get("payload", {}).get("result", {})
        return result.get("internet_possible") is True, result

    def _trigger(self, rule: dict, condition_result: dict) -> None:
        now = int(time.time() * 1000)
        # Recorded before dispatch, not after, so the trigger itself is on the
        # audit trail even if the playbook call below fails partway - the UI's
        # notification layer treats this as "rule started"; the playbook's own
        # evidence/job audit events (below) carry how it actually finished.
        self.workspace.add_audit_event({
            "project_id": rule["project_id"], "action": "automation.triggered",
            "subject_id": rule["id"], "outcome": rule["playbook"],
            "node_id": rule["node_id"], "condition": rule["condition"],
        })
        if rule["playbook"] == "system_snapshot":
            response = self.coordinator.invoke(rule["node_id"], "system.info", {})
            result = response.get("payload", {}).get("result", {})
            self.workspace.add_evidence({
                "project_id": rule["project_id"], "kind": "automation-snapshot",
                "title": f"Triggered snapshot · {rule['node_id']}",
                "summary": f"{rule['condition']} condition activated",
                "data": {"condition": condition_result, "result": result, "rule_id": rule["id"]},
                "captured_at_ms": now,
            })
        else:
            address = ipaddress.ip_address(condition_result.get("ip") or
                                           next(item["address"] for item in self.coordinator.state()["nodes"]
                                                if item["device_id"] == rule["node_id"]))
            network = ipaddress.ip_network(f"{address}/24", strict=False)
            arguments = {"network": str(network), "start_ip": str(network.network_address + 1),
                         "end_ip": str(network.broadcast_address - 1)}
            if rule.get("interval_ms"):
                arguments["schedule"] = {"interval_ms": rule["interval_ms"],
                                         "after_completion": True}
            response = self.coordinator.invoke(rule["node_id"], "net.discovery.scan", arguments)
            result = response.get("payload", {}).get("result", {})
            self.workspace.upsert_job({
                "id": f"auto-{rule['id']}-{now}", "project_id": rule["project_id"],
                "provider_id": rule["node_id"], "capability": "net.discovery.scan",
                "status": result.get("job_status", "running"), "checked": result.get("checked", 0),
                "total": result.get("total", 0), "hosts": result.get("hosts", []),
                "scope": {**arguments, "automation_rule": rule["id"]},
            })
        self.workspace.set_automation(rule["id"], {"last_triggered_ms": now, "last_error": ""})

    def _sync_outbox(self, node: dict, snapshot: dict) -> None:
        response = self.coordinator.invoke(node["device_id"], "evidence.outbox.read", {})
        records = response.get("payload", {}).get("result", {}).get("records", [])
        # Coordinator.invoke() already verified this response's tag against the node's
        # provisioned execution key before returning it (Coordinator._dispatch raises
        # otherwise) - carry that proof of origin into the ledger instead of only
        # recording an unauthenticated "source_node" string, per platform-roadmap.md
        # Phase 5. The signature covers the whole outbox batch (P4 has no separate
        # per-record evidence key independent of the pulling coordinator's own
        # execution key), so every record ingested from one read shares the same
        # response_nonce/response_tag - that's a batch-level provenance proof, not a
        # per-record one, and is reported as such rather than implied otherwise.
        auth = response.get("payload", {}).get("auth", {})
        provenance = ({"source_node": node["device_id"], "verified": True,
                       "response_nonce": str(auth.get("nonce", "")),
                       "response_tag": str(auth.get("tag", "")),
                       "algorithm": "hmac-sha256-truncated16"}
                      if auth.get("tag") else {})
        errors = []
        for record in records:
            project_id = str(record.get("project_id", ""))
            if not any(item.get("id") == project_id for item in snapshot["projects"]):
                errors.append(f"outbox record references unknown project {project_id!r}")
                continue
            boot_id = str(record.get("boot_id", "legacy"))
            evidence_id = f"outbox-{node['device_id']}-{boot_id}-{int(record['sequence'])}"
            self.workspace.add_evidence({
                "id": evidence_id, "project_id": project_id,
                "job_id": f"rule-{record.get('rule_id', '')}",
                "kind": record.get("kind", "node-evidence"),
                "title": f"Autonomous P4 result · {node['device_id']}",
                "summary": f"Rule {record.get('rule_id')} run {record.get('run_count', 1)}",
                "data": {**record, "source_node": node["device_id"]},
                "provenance": provenance,
            })
            # Delete from the device only after the durable local write returns.
            self.coordinator.invoke(node["device_id"], "evidence.outbox.ack",
                                    {"sequence": record["sequence"]})
        if errors:
            raise ValueError("; ".join(errors))

    def _clear_sync_errors(self, node_id: str) -> None:
        for rule in self.workspace.snapshot().get("automations", []):
            if (rule.get("node_id") == node_id and rule.get("device_managed") and
                    str(rule.get("last_error", "")).startswith("Evidence sync failed:")):
                self.workspace.set_automation(rule["id"], {"last_error": ""})

    def _run(self) -> None:
        while not self.stop_event.wait(10):
            snapshot = self.workspace.snapshot()
            nodes = {item["device_id"]: item for item in self.coordinator.state()["nodes"]}
            for node in nodes.values():
                if "evidence.outbox.read" not in node.get("capabilities", []):
                    continue
                try:
                    self._sync_outbox(node, snapshot)
                    self._clear_sync_errors(node["device_id"])
                except Exception as error:
                    message = f"Evidence sync failed: {error}"[:300]
                    print(f"[{node['device_id']}] {message}")
                    for rule in snapshot.get("automations", []):
                        if (rule.get("node_id") == node["device_id"] and
                                rule.get("device_managed") and
                                rule.get("last_error") != message):
                            self.workspace.set_automation(rule["id"], {"last_error": message})
            active_ids = set()
            for rule in snapshot.get("automations", []):
                node = nodes.get(rule["node_id"])
                if (not rule.get("device_managed") and node is not None and
                        "automation.rule.put" in node.get("capabilities", [])):
                    try:
                        response = self.coordinator.invoke(rule["node_id"], "automation.rule.put",
                                                          {"rule": rule})
                        if response.get("payload", {}).get("status") == "ok":
                            self.workspace.set_automation(rule["id"], {
                                "device_managed": True, "last_error": ""})
                    except Exception as error:
                        message = f"Rule provisioning failed: {error}"[:300]
                        print(f"[{rule['node_id']}] {message}")
                        if rule.get("last_error") != message:
                            self.workspace.set_automation(rule["id"], {"last_error": message})
                    continue
                if not rule.get("enabled") or rule.get("device_managed"):
                    continue
                active_ids.add(rule["id"])
                try:
                    matched, result = self._condition(rule, nodes)
                    previous = self.condition_state.get(rule["id"], False)
                    self.condition_state[rule["id"]] = matched
                    if matched and not previous:
                        self._trigger(rule, result)
                except Exception as error:
                    message = str(error)[:300]
                    if rule.get("last_error") != message:
                        self.workspace.set_automation(rule["id"], {"last_error": message})
            self.condition_state = {key: value for key, value in self.condition_state.items()
                                    if key in active_ids}


def inspect_hosts(local_address: str, body: dict) -> dict:
    if body.get("operator_authorised") is not True:
        raise PermissionError("explicit host inspection authorization acknowledgement is required")
    local = ipaddress.ip_address(local_address)
    network = ipaddress.ip_network(f"{local}/24", strict=False)
    raw_hosts = body.get("hosts", [])
    raw_ports = body.get("ports", [])
    if not isinstance(raw_hosts, list) or not 1 <= len(raw_hosts) <= MAX_INSPECTION_HOSTS:
        raise ValueError(f"hosts must contain 1-{MAX_INSPECTION_HOSTS} addresses")
    if not isinstance(raw_ports, list) or not 1 <= len(raw_ports) <= MAX_INSPECTION_PORTS:
        raise ValueError(f"ports must contain 1-{MAX_INSPECTION_PORTS} values")
    hosts = []
    for value in dict.fromkeys(str(item) for item in raw_hosts):
        address = ipaddress.ip_address(value)
        if address.version != 4 or address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError("every target must be a usable address on the attached /24")
        hosts.append(str(address))
    ports = []
    for value in dict.fromkeys(raw_ports):
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError("ports must be between 1 and 65535")
        ports.append(port)

    def probe(pair: tuple[str, int]) -> tuple[str, int, bool]:
        host, port = pair
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.35)
            return host, port, connection.connect_ex((host, port)) == 0

    results = {host: [] for host in hosts}
    pairs = [(host, port) for host in hosts for port in ports]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(pairs))) as pool:
        for host, port, opened in pool.map(probe, pairs):
            if opened:
                results[host].append(port)
    return {"hosts": [{"address": host, "open_ports": sorted(results[host]),
                        "checked_ports": len(ports)} for host in hosts],
            "ports": sorted(ports), "checked": len(pairs)}


def is_target_bearing(capability: str) -> bool:
    """True for a capability that requires a signed, delegated engagement scope.

    Mirrors EngagementPolicy.authorize's own test (engagement_policy.py) so a
    workflow definition can be checked for target-bearing steps before a run is
    ever queued, rather than only discovering the missing scope deep inside a
    failed dispatch attempt.
    """
    return capability in TARGET_CAPABILITIES or capability.startswith(TARGET_PREFIXES)


def validate_scan_arguments(arguments: dict) -> None:
    """Reject broad or internally inconsistent assessment scopes before dispatch."""
    network = ipaddress.ip_network(str(arguments.get("network", "")), strict=True)
    if network.version != 4 or network.num_addresses > 256:
        raise ValueError("network must be an IPv4 /24 or smaller")
    first = ipaddress.ip_address(str(arguments.get("start_ip", "")))
    last = ipaddress.ip_address(str(arguments.get("end_ip", "")))
    if (first not in network or last not in network or first > last or
            first == network.network_address or last == network.broadcast_address):
        raise ValueError("scan range must contain usable addresses inside network")


def load_trust_keys(path: pathlib.Path | None, coordinator_id: str) -> dict[str, bytes]:
    if path is None or not path.is_file():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    keys = {}
    for link, value in document.get("links", {}).items():
        peers = link.split("|")
        if len(peers) != 2 or coordinator_id not in peers:
            continue
        peer_id = peers[1] if peers[0] == coordinator_id else peers[0]
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(f"invalid trust key for {peer_id}")
        keys[peer_id] = bytes.fromhex(value)
    return keys


class AppHandler(BaseHTTPRequestHandler):
    server: "AppServer"

    def local_client(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1")

    def trusted_api_origin(self) -> bool:
        """Reject browser-driven cross-origin mutations of the loopback API."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True  # Preserve non-browser CLI/API clients on loopback.
        try:
            parsed = urllib.parse.urlsplit(origin)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return False
        return parsed.scheme == "http" and host in ("127.0.0.1", "localhost", "::1") and port == self.server.server_port

    # -- operator identity (Phase 10) ---------------------------------------------
    #
    # A Bearer token, not a cookie: cookies are attached to a request automatically
    # regardless of origin, which is exactly the ambient-credential problem
    # trusted_api_origin already exists to guard against for this loopback API: a token
    # only travels if the page's own JS attaches it, so cross-origin/CSRF exposure isn't
    # widened by adding sessions at all.

    NO_SESSION_REQUIRED_PATHS = ("/api/login", "/api/session", "/api/operators")
    IDENTITY_PATHS = ("/api/login", "/api/logout", "/api/session")

    def resolve_operator(self) -> dict | None:
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        return self.server.operators.resolve_session(token) if token else None

    def enforce_authenticated(self, path: str, operator: dict | None) -> bool:
        """False means a 401 has already been sent and the caller must stop.

        With no operator accounts created yet, every request is exempt -- this is the
        "preserve a simple single-operator mode now" requirement (platform-roadmap.md
        Product decisions): multi-operator mode only turns on once an operator actually
        exists. /api/operators is exempt too since OperatorManager.create_operator
        itself enforces the equivalent bootstrap-vs-admin-only rule; letting an
        unauthenticated bootstrap attempt reach it produces a clearer PermissionError
        than a generic 401 once operators already exist.
        """
        if self.server.operators.count() == 0 or path in self.NO_SESSION_REQUIRED_PATHS:
            return True
        if operator is None:
            self.send_json(401, {"error": "authentication_required"})
            return False
        return True

    def enforce_not_viewer(self, path: str, operator: dict | None) -> bool:
        """False means a 403 has already been sent. A viewer role is read-only, so this
        only ever needs to run for mutating requests (POST/DELETE); operator is None in
        legacy single-operator mode, where nothing is gated by role at all. Login/logout
        are identity operations, not workspace mutations, so an already-logged-in
        viewer re-authenticating (or logging out) is exempt rather than 403ing.
        """
        if path in self.IDENTITY_PATHS:
            return True
        if operator is not None and operator["role"] == "viewer":
            self.send_json(403, {"error": "viewer_role_is_read_only"})
            return False
        return True

    @staticmethod
    def require_admin_when_multi_operator(operator: dict | None, server: "AppServer") -> None:
        """Raises PermissionError for the small set of actions registered in the
        approval executors (scope.create, fleet.release.create): once any operator
        exists, only admin may perform these directly -- anyone else must go through
        POST /api/approvals instead, which is what actually gives "approval" teeth
        rather than being an optional parallel path admins and non-admins can both skip.
        """
        if server.operators.count() > 0 and (operator is None or operator["role"] != "admin"):
            raise PermissionError(
                "this action requires admin role, or a decided approval request (POST /api/approvals)")

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store" if content_type == "application/json" else "public, max-age=3600")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, body: dict) -> None:
        self.send_bytes(status, json.dumps(body, separators=(",", ":")).encode(), "application/json")

    def do_GET(self) -> None:
        parsed_path = urllib.parse.urlsplit(self.path)
        path = parsed_path.path
        operator = self.resolve_operator()
        if path.startswith("/api/") and not self.enforce_authenticated(path, operator):
            return
        if path == ANNOUNCE_PATH:
            self.send_json(200, self.server.node.announcement())
        elif path == "/api/session":
            self.send_json(200, {"auth_required": self.server.operators.count() > 0, "operator": operator})
        elif path == "/api/state":
            if self.local_client():
                self.send_json(200, self.server.coordinator.state())
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path == "/api/workspace":
            if self.local_client():
                self.send_json(200, self.server.workspace.snapshot())
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path == "/api/evidence/verify":
            if self.local_client():
                project_id = urllib.parse.parse_qs(parsed_path.query).get("project_id", [""])[0]
                self.send_json(200, self.server.workspace.verify_evidence(project_id))
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path == "/api/evidence/export":
            if self.local_client():
                project_id = urllib.parse.parse_qs(parsed_path.query).get("project_id", [""])[0]
                self.send_json(200, self.server.workspace.evidence_bundle(project_id))
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path == "/api/audit":
            if self.local_client():
                query = urllib.parse.parse_qs(parsed_path.query)
                project_id = query.get("project_id", [""])[0]
                cursor = query.get("cursor", [""])[0]
                try:
                    limit = int(query.get("limit", [""])[0] or 100)
                except ValueError:
                    limit = 100
                self.send_json(200, self.server.workspace.list_audit_events(project_id, cursor, limit))
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path == "/api/audit/export":
            if self.local_client():
                project_id = urllib.parse.parse_qs(parsed_path.query).get("project_id", [""])[0]
                self.send_json(200, self.server.workspace.audit_bundle(project_id))
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path == "/api/findings/export":
            if self.local_client():
                project_id = urllib.parse.parse_qs(parsed_path.query).get("project_id", [""])[0]
                self.send_json(200, self.server.workspace.findings_bundle(project_id))
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path == "/api/events":
            if self.local_client():
                self.stream_events()
            else:
                self.send_json(403, {"error": "local_access_only"})
        elif path.startswith("/api/"):
            self.send_json(404, {"error": "not_found"})
        else:
            self.serve_web(path)

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/api/") and not self.local_client():
            self.send_json(403, {"error": "local_access_only"})
            return
        if path.startswith("/api/") and (not self.trusted_api_origin() or
                self.headers.get_content_type() != "application/json"):
            self.send_json(403, {"error": "untrusted_browser_request"})
            return
        operator = self.resolve_operator()
        if path.startswith("/api/"):
            if not self.enforce_authenticated(path, operator):
                return
            if not self.enforce_not_viewer(path, operator):
                return
        self.server.workspace.set_current_actor(operator["id"] if operator else "local-operator")
        try:
            max_length = MAX_RELEASE_BODY_BYTES if path == "/api/fleet/releases" else MAX_BODY_BYTES
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > max_length:
                raise ValueError("invalid body length")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("body must be an object")
            if path == MESSAGE_PATH:
                status, response = self.server.node.respond(body)
                self.send_json(status, response)
                return
            if path == "/api/login":
                self.send_json(200, self.server.operators.login(
                    str(body.get("username", "")), str(body.get("password", ""))))
                return
            if path == "/api/logout":
                auth = self.headers.get("Authorization", "")
                token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
                self.server.operators.logout(token)
                self.send_json(200, {"ok": True})
                return
            if path == "/api/operators":
                self.send_json(201, self.server.operators.create_operator(body, operator))
                return
            if path == "/api/approvals":
                if operator is None:
                    raise PermissionError("an operator session is required to request an approval")
                self.send_json(201, self.server.approvals.request(
                    str(body.get("action_type", "")), body.get("payload", {}), operator))
                return
            if path == "/api/projects":
                self.send_json(201, self.server.workspace.create_project(body))
                return
            if path == "/api/workflows":
                self.send_json(201, self.server.workspace.create_workflow(body))
                return
            if path == "/api/scopes":
                if body.get("operator_authorised") is not True:
                    raise PermissionError("explicit engagement scope approval is required")
                self.require_admin_when_multi_operator(operator, self.server)
                self.send_json(201, self.server.policy.create_scope(body))
                return
            if path == "/api/findings/import":
                if body.get("operator_authorised") is not True:
                    raise PermissionError("explicit vulnerability import approval is required")
                project_id = str(body.get("project_id", ""))
                content = body.get("content", "")
                if not isinstance(content, str) or not content or len(content.encode()) > MAX_BODY_BYTES - 4096:
                    raise ValueError("vulnerability document is empty or too large")
                findings = import_document(project_id, str(body.get("format", "")), content,
                                           str(body.get("plugin_id", "offline")))
                saved = self.server.workspace.upsert_findings(project_id, findings)
                self.server.workspace.add_audit_event({"project_id": project_id,
                    "action": "findings.imported", "subject_id": str(body.get("format", "")),
                    "outcome": "accepted", "count": len(saved)})
                self.send_json(201, {"findings": saved, "count": len(saved)})
                return
            if path == "/api/findings/correlate":
                # Explicit "correlate now" trigger rather than an automatic
                # per-job hook - see WorkspaceStore.correlate_findings's
                # docstring for why. No operator_authorised gate: this only
                # derives new candidate/confirmed-observed state from evidence
                # and findings the operator already approved importing, the
                # same trust level as /api/evidence/verify.
                project_id = str(body.get("project_id", ""))
                evidence_ids = body.get("evidence_ids")
                if evidence_ids is not None and not isinstance(evidence_ids, list):
                    raise ValueError("evidence_ids must be a list when provided")
                self.send_json(200, self.server.workspace.correlate_findings(
                    project_id, [str(item) for item in evidence_ids] if evidence_ids is not None else None))
                return
            if path == "/api/audit/prune":
                if body.get("operator_authorised") is not True:
                    raise PermissionError("explicit audit retention approval is required")
                max_age_ms = body.get("max_age_ms")
                max_count = body.get("max_count")
                self.send_json(200, self.server.workspace.prune_audit_events(
                    int(max_age_ms) if max_age_ms is not None else None,
                    int(max_count) if max_count is not None else None))
                return
            if path == "/api/fleet/config":
                self.send_json(200, self.server.fleet.set_config(body))
                return
            if path == "/api/fleet/releases":
                if body.get("operator_authorised") is not True:
                    raise PermissionError("explicit release signing approval is required")
                self.require_admin_when_multi_operator(operator, self.server)
                self.send_json(201, self.server.fleet.create_release(body))
                return
            if path == "/api/fleet/rollouts":
                if body.get("operator_authorised") is not True:
                    raise PermissionError("explicit OTA rollout approval is required")
                self.send_json(201, self.server.fleet.create_rollout(body))
                return
            if path == "/api/automations":
                if body.get("operator_authorised") is not True:
                    raise PermissionError("explicit automation authorization acknowledgement is required")
                rule = self.server.workspace.create_automation({**body, "device_managed": True})
                if rule["playbook"] == "network_scout":
                    self.server.policy.get_valid(rule.get("scope_id", ""), rule["project_id"])
                try:
                    response = self.server.coordinator.invoke(rule["node_id"], "automation.rule.put",
                                                              {"rule": rule})
                    accepted = response.get("payload", {}).get("status") == "ok"
                except Exception:
                    accepted = False
                if not accepted:
                    self.server.workspace.set_automation(rule["id"], {
                        "enabled": False, "last_error": "Node refused durable rule"})
                    raise ConnectionError("node refused durable rule")
                self.send_json(201, rule)
                return
            if path == "/api/jobs":
                self.send_json(200, self.server.workspace.upsert_job(body))
                return
            if path == "/api/evidence":
                self.send_json(201, self.server.workspace.add_evidence(body))
                return
            if path == "/api/inspect":
                self.server.policy.authorize(str(body.get("scope_id", "")),
                                             str(body.get("project_id", "")),
                                             "net.tcp.inspect", {"hosts": body.get("hosts", [])})
                result = inspect_hosts(self.server.node.address, body)
                project_id = str(body.get("project_id", ""))
                job_id = f"inspect-{uuid.uuid4().hex[:12]}"
                if project_id:
                    self.server.workspace.upsert_job({
                        "id": job_id, "project_id": project_id,
                        "provider_id": self.server.node.node_id,
                        "capability": "net.tcp.inspect", "status": "complete",
                        "checked": result["checked"], "total": result["checked"],
                        "hosts": [item["address"] for item in result["hosts"]],
                        "scope": {"ports": result["ports"]},
                    })
                    self.server.workspace.add_evidence({
                        "id": f"{job_id}-tcp", "project_id": project_id,
                        "job_id": job_id, "kind": "tcp-services",
                        "title": f"TCP inspection · {len(result['hosts'])} host(s)",
                        "summary": f"{sum(len(item['open_ports']) for item in result['hosts'])} open ports observed",
                        "data": result,
                    })
                result["job_id"] = job_id
                result["captured_at_ms"] = int(time.time() * 1000)
                self.send_json(200, result)
                return
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "workflows"] and parts[3] == "runs":
                workflow_id = urllib.parse.unquote(parts[2])
                workflow = next((item for item in self.server.workspace.snapshot()["workflows"]
                                 if item.get("id") == workflow_id), None)
                if workflow is None:
                    raise KeyError(workflow_id)
                scope_id = str(body.get("scope_id", ""))
                target_bearing = any(is_target_bearing(step["capability"]) for step in workflow["steps"])
                if scope_id:
                    self.server.policy.get_valid(scope_id, workflow["project_id"])
                elif target_bearing:
                    raise PermissionError(
                        "a signed engagement scope is required to run a workflow with "
                        "target-bearing steps")
                self.send_json(201, self.server.workspace.create_workflow_run(workflow_id, scope_id))
                return
            if len(parts) == 4 and parts[:2] == ["api", "workflow-runs"] and parts[3] == "cancel":
                self.send_json(200, self.server.workflows.cancel(urllib.parse.unquote(parts[2])))
                return
            if len(parts) == 4 and parts[:2] == ["api", "approvals"] and parts[3] == "decide":
                if operator is None:
                    raise PermissionError("an operator session is required to decide an approval")
                self.send_json(200, self.server.approvals.decide(
                    urllib.parse.unquote(parts[2]), str(body.get("decision", "")), operator))
                return
            if path == "/api/distributed-scans":
                capability = str(body.get("capability", "net.discovery.scan"))
                scope_id = str(body.get("scope_id", ""))
                project_id = str(body.get("project_id", ""))
                target_bearing = capability in TARGET_CAPABILITIES or capability.startswith(TARGET_PREFIXES)
                # Mirrors /api/workflows/<id>/runs: reject at creation time with no valid
                # scope rather than only discovering the gap deep inside a per-chunk
                # dispatch attempt later.
                if scope_id:
                    self.server.policy.get_valid(scope_id, project_id)
                elif target_bearing:
                    raise PermissionError(
                        "a signed engagement scope is required for a target-bearing distributed scan")
                self.send_json(201, self.server.scheduler.create(body))
                return
            if len(parts) == 4 and parts[:2] == ["api", "distributed-scans"] and parts[3] == "cancel":
                self.send_json(200, self.server.scheduler.cancel(urllib.parse.unquote(parts[2])))
                return
            if len(parts) == 4 and parts[:2] == ["api", "fleet"] and parts[3] == "advance":
                self.send_json(200, self.server.fleet.advance_rollout(urllib.parse.unquote(parts[2])))
                return
            if len(parts) == 4 and parts[:2] == ["api", "fleet"] and parts[3] == "rollback":
                if body.get("operator_authorised") is not True:
                    raise PermissionError("explicit rollback approval is required")
                self.send_json(200, self.server.fleet.rollback_rollout(urllib.parse.unquote(parts[2])))
                return
            if len(parts) == 4 and parts[:2] == ["api", "findings"] and parts[3] == "status":
                finding_id = urllib.parse.unquote(parts[2])
                self.send_json(200, self.server.workspace.set_finding_status(
                    finding_id, str(body.get("status", "")), str(body.get("note", ""))))
                return
            if len(parts) == 4 and parts[:2] == ["api", "findings"] and parts[3] == "suppress":
                finding_id = urllib.parse.unquote(parts[2])
                self.send_json(200, self.server.workspace.set_finding_suppression(
                    finding_id, body.get("suppressed") is True, str(body.get("reason", ""))))
                return
            if len(parts) == 4 and parts[:2] == ["api", "findings"] and parts[3] == "remediation":
                finding_id = urllib.parse.unquote(parts[2])
                self.send_json(200, self.server.workspace.set_finding_remediation(finding_id, body))
                return
            if len(parts) == 3 and parts[:2] == ["api", "automations"]:
                rule = self.server.workspace.set_automation(urllib.parse.unquote(parts[2]), body)
                if rule.get("device_managed"):
                    response = self.server.coordinator.invoke(rule["node_id"], "automation.rule.put",
                                                              {"rule": rule})
                    if response.get("payload", {}).get("status") != "ok":
                        raise ConnectionError("node refused durable rule update")
                self.send_json(200, rule)
                return
            if len(parts) == 3 and parts[:2] == ["api", "workflows"]:
                self.send_json(200, self.server.workspace.update_workflow(
                    urllib.parse.unquote(parts[2]), body))
                return
            if len(parts) == 4 and parts[:2] == ["api", "nodes"] and parts[3] == "invoke":
                capability = str(body.get("capability", ""))
                arguments = body.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise ValueError("arguments must be an object")
                if capability == "net.discovery.scan":
                    if body.get("operator_authorised") is not True:
                        raise PermissionError("explicit scope authorization acknowledgement is required")
                    validate_scan_arguments(arguments)
                    arguments = self.server.policy.delegate(str(body.get("scope_id", "")),
                                                            str(body.get("project_id", "")), capability,
                                                            arguments, urllib.parse.unquote(parts[2]))
                response = self.server.coordinator.invoke(
                    urllib.parse.unquote(parts[2]), capability, arguments)
                result = response.get("payload", {}).get("result", {})
                if result.get("job_status") not in ("running", "waiting"):
                    self.server.policy.release(arguments)
                self.send_json(200, response)
                return
            self.send_json(404, {"error": "not_found"})
        except PermissionError as error:
            self.send_json(403, {"error": "trust_required", "message": str(error)})
        except KeyError as error:
            self.send_json(404, {"error": "node_unavailable", "message": str(error)})
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": "invalid_request", "message": str(error)})
        except ConnectionError as error:
            self.send_json(502, {"error": "node_request_failed", "message": str(error)})
        finally:
            self.server.workspace.clear_current_actor()

    def do_DELETE(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if not self.local_client():
            self.send_json(403, {"error": "local_access_only"})
            return
        if not self.trusted_api_origin():
            self.send_json(403, {"error": "untrusted_browser_request"})
            return
        operator = self.resolve_operator()
        if not self.enforce_authenticated(path, operator):
            return
        if not self.enforce_not_viewer(path, operator):
            return
        self.server.workspace.set_current_actor(operator["id"] if operator else "local-operator")
        parts = path.strip("/").split("/")
        try:
            if len(parts) == 3 and parts[:2] == ["api", "automations"]:
                rule_id = urllib.parse.unquote(parts[2])
                rule = next((item for item in self.server.workspace.snapshot()["automations"]
                             if item.get("id") == rule_id), None)
                if rule is None:
                    raise KeyError(rule_id)
                if rule.get("device_managed"):
                    response = self.server.coordinator.invoke(rule["node_id"],
                                                              "automation.rule.delete", {"id": rule_id})
                    if response.get("payload", {}).get("status") != "ok":
                        raise ConnectionError("node refused durable rule deletion")
                self.send_json(200, self.server.workspace.delete_automation(rule_id))
            elif len(parts) == 3 and parts[:2] == ["api", "workflows"]:
                self.send_json(200, self.server.workspace.delete_workflow(urllib.parse.unquote(parts[2])))
            else:
                self.send_json(404, {"error": "not_found"})
        except KeyError as error:
            self.send_json(404, {"error": "not_found", "message": str(error)})
        except ValueError as error:
            self.send_json(400, {"error": "invalid_request", "message": str(error)})
        except ConnectionError as error:
            self.send_json(502, {"error": "node_request_failed", "message": str(error)})
        finally:
            self.server.workspace.clear_current_actor()

    def stream_events(self) -> None:
        try:
            revision = int(self.headers.get("Last-Event-ID", "0"))
        except ValueError:
            revision = 0
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                state = self.server.coordinator.wait_for_change(revision)
                revision = state["revision"]
                encoded = json.dumps(state, separators=(",", ":"))
                self.wfile.write(f"id: {revision}\nevent: state\ndata: {encoded}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

    def serve_web(self, path: str) -> None:
        relative = path.lstrip("/") or "index.html"
        candidate = (WEB_ROOT / relative).resolve()
        if WEB_ROOT.resolve() not in candidate.parents or not candidate.is_file():
            candidate = WEB_ROOT / "index.html"
        if not candidate.is_file():
            self.send_json(503, {"error": "web_ui_not_built",
                                 "message": "Run npm install && npm run build in tools/desktop-node/web"})
            return
        mime = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_bytes(200, candidate.read_bytes(), mime)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], node: Node, coordinator: Coordinator,
                 workspace: WorkspaceStore, workflows: WorkflowEngine, policy: EngagementPolicy,
                 fleet: FleetManager, scheduler: DistributedScanEngine, operators: OperatorManager,
                 approvals: ApprovalManager) -> None:
        self.node = node
        self.coordinator = coordinator
        self.workspace = workspace
        self.workflows = workflows
        self.policy = policy
        self.fleet = fleet
        self.scheduler = scheduler
        self.operators = operators
        self.approvals = approvals
        super().__init__(address, AppHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Reconclave desktop web coordinator")
    parser.add_argument("--address", default=local_ip(), help="LAN IPv4 address to advertise")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--name", default=socket.gethostname())
    parser.add_argument("--node-id", default=f"rc-desktop-{uuid.getnode():012x}")
    parser.add_argument("--mode", choices=("node", "coordinator", "both"), default="both")
    parser.add_argument("--enable-network-scan", action="store_true")
    parser.add_argument("--enable-tools", action="store_true")
    parser.add_argument("--evidence-dir", default=None)
    parser.add_argument("--execution-key", default=os.environ.get("RECONCLAVE_EXECUTION_KEY"))
    parser.add_argument("--evidence-key", default=os.environ.get("RECONCLAVE_EVIDENCE_KEY"))
    parser.add_argument("--trust-store", type=pathlib.Path, default=DEFAULT_TRUST_STORE,
                        help="ignored per-link provisioning store")
    parser.add_argument("--workspace-store", type=pathlib.Path, default=DEFAULT_WORKSPACE_STORE,
                        help="local project/job/evidence index")
    args = parser.parse_args()
    if args.enable_network_scan and not args.execution_key:
        parser.error("an execution key is required when network scan is enabled")
    if args.evidence_dir and not args.evidence_key:
        parser.error("an evidence key is required when evidence storage is enabled")

    node_enabled = args.mode in ("node", "both")
    node = Node(args.node_id, args.name, args.address, args.port,
                node_enabled and args.enable_network_scan,
                args.evidence_dir if node_enabled else None,
                args.evidence_key, args.execution_key, node_enabled and args.enable_tools)
    node.roles = ["node"] + (["coordinator"] if args.mode in ("coordinator", "both") else [])
    zeroconf = Zeroconf()
    try:
        trust_keys = load_trust_keys(args.trust_store, args.node_id)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(f"could not load trust store: {error}")
    coordinator = Coordinator(node, zeroconf, args.execution_key, args.evidence_key,
                              trust_keys=trust_keys)
    if args.mode in ("coordinator", "both"):
        coordinator.start()
    try:
        workspace = WorkspaceStore(args.workspace_store)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(f"could not load workspace store: {error}")
    # Correlate node transport dispatch attempts into the same trace as the
    # job/workflow-run audit events already recorded by the workspace store.
    coordinator.audit_sink = workspace.add_audit_event
    delegation_key = hashlib.sha256(args.execution_key.encode()).digest() if args.execution_key else None
    policy = EngagementPolicy(workspace, args.workspace_store.with_suffix(".scope-key"), delegation_key)
    workflows = WorkflowEngine(coordinator, workspace, policy)
    fleet = FleetManager(coordinator, workspace, workspace.custody_key)
    fleet.reconcile_once()
    scheduler = DistributedScanEngine(coordinator, workspace, policy)
    operators = OperatorManager(workspace)
    # The approval registry is deliberately small for this first slice: the two
    # existing operator_authorised-gated actions with the clearest two-person-control
    # case (what's authorised to be attacked, what firmware gets pushed). Extending it
    # to more action types later is just another executors entry, not a redesign.
    approvals = ApprovalManager(workspace, executors={
        "scope.create": policy.create_scope,
        "fleet.release.create": fleet.create_release,
    })
    server = AppServer(("0.0.0.0", args.port), node, coordinator, workspace, workflows, policy, fleet,
                       scheduler, operators, approvals)
    automations = AutomationEngine(coordinator, workspace)
    automations.start()
    workflows.start()
    fleet.start()
    scheduler.start()
    service = ServiceInfo(
        "_reconclave._tcp.local.", f"{args.node_id}._reconclave._tcp.local.",
        addresses=[socket.inet_aton(args.address)], port=args.port,
        properties={"proto": PROTOCOL, "roles": ",".join(node.roles),
                    "device": "desktop-web", "path": ANNOUNCE_PATH},
        server=f"{args.node_id}.local.")
    zeroconf.register_service(service)

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"Reconclave desktop {args.mode} at http://127.0.0.1:{args.port}")
    print(f"Provisioned peer identities: {len(trust_keys)}")
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        automations.close()
        workflows.close()
        fleet.close()
        coordinator.close()
        zeroconf.unregister_service(service)
        zeroconf.close()
        server.server_close()


if __name__ == "__main__":
    main()
