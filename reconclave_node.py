#!/usr/bin/env python3
"""A small, read-only Reconclave node for a desktop or laptop."""

from __future__ import annotations

import argparse
import collections
import datetime
import errno
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import threading
import time
import uuid
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from zeroconf import ServiceInfo, Zeroconf
from tool_runner import ToolRunner
from encrypted_spool import EncryptedSpool

PROTOCOL = "reconclave/1"
FIRMWARE = "0.1.0"
ANNOUNCE_PATH = "/reconclave/v1/announce"
MESSAGE_PATH = "/reconclave/v1/message"
OTA_UPLOAD_PATH = "/reconclave/v1/ota-upload"
MAX_EVIDENCE_RECORD_BYTES = 16 * 1024
EVIDENCE_REQUIRED_FIELDS = ("job_id", "source_node", "target", "timestamp_ms", "observation")
# Assessment, persistent writes, and job control all cross a trust boundary. A node
# only advertises these handlers when a key is configured and verifies every call.
AUTH_REQUIRED_CAPABILITIES = {
    "net.discovery.scan", "storage.evidence.write", "coordination.job.cancel",
    "tool.nmap.services", "tool.dns.lookup", "tool.tcpdump.capture", "tool.job.cancel",
    "tool.masscan.services", "tool.arpscan.sweep",
}
AUTH_TAG_BYTES = 16
RECENT_NONCES_PER_SOURCE = 16
# net.discovery.scan, tool.nmap.services, and tool.masscan.services all take
# explicit IP/network targets that a signed scope delegation can bind to.
# tool.dns.lookup targets hostnames (not IP networks), tool.tcpdump.capture's
# target is an optional local filter, and tool.arpscan.sweep can only ever reach
# its own attached L2 segment regardless of arguments - none of the three fit the
# current IP-subnet scope-delegation contract, or (for arp-scan) need to; they
# still require the execution-key auth above. See platform-roadmap notes for
# follow-up on dns/tcpdump.
SCOPE_REQUIRED_CAPABILITIES = {"net.discovery.scan", "tool.nmap.services", "tool.masscan.services"}
# Packaged tool adapters that use the shared async job registry in ToolRunner
# rather than a bespoke per-capability job slot like net.discovery.scan's.
TOOL_JOB_CAPABILITIES = ("tool.nmap.services", "tool.dns.lookup", "tool.tcpdump.capture",
                         "tool.masscan.services", "tool.arpscan.sweep")


def canonical_digest(value: object) -> str:
    def validate(item: object) -> None:
        if item is None or isinstance(item, (bool, str)):
            return
        if isinstance(item, int) and not isinstance(item, bool) and abs(item) <= 9007199254740991:
            return
        if isinstance(item, list):
            for child in item: validate(child)
            return
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            for child in item.values(): validate(child)
            return
        raise ValueError("signed JSON contains an unsupported value")
    validate(value)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class CapabilityError(Exception):
    """Raised by a capability handler for a request that reaches execution but must
    be refused (rejected) or that fails while running (error)."""

    def __init__(self, code: str, message: str, status: str = "rejected") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def local_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        return probe.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        probe.close()


class ArmedClock:
    """Persists a standing scope grant's elapsed "armed" time across restarts.

    A standing grant (EngagementPolicy.mint_standing_grant) carries a duration,
    not an absolute expiry, because a device may have no live coordinator - and,
    on an ESP32 target, no wall clock at all - to check back in against. This
    class tracks elapsed time itself: a monotonic clock in memory, checkpointed
    to a small JSON state file periodically and on clean shutdown so elapsed
    time survives a restart.

    Fail-closed by design: a missing, unreadable, or grant_id-mismatched state
    file is treated as fully elapsed - elapsed_ms() reports one millisecond past
    duration_ms - rather than freshly armed. A device that lost its bookkeeping
    must never silently re-arm itself; it stays disarmed until an operator
    mints and provisions a fresh grant.
    """

    CHECKPOINT_INTERVAL_SECONDS = 60.0

    def __init__(self, state_path: str, grant_id: str) -> None:
        self.state_path = state_path
        self.grant_id = grant_id
        self.lock = threading.Lock()
        self._elapsed_ms, self._known_good = self._load()
        self._checkpoint_monotonic = time.monotonic()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _load(self) -> tuple[int, bool]:
        try:
            with open(self.state_path, encoding="utf-8") as handle:
                state = json.load(handle)
            if state.get("grant_id") != self.grant_id:
                return 0, False
            return max(0, int(state["elapsed_ms_at_checkpoint"])), True
        except (OSError, ValueError, KeyError, TypeError):
            return 0, False

    def elapsed_ms(self, duration_ms: int) -> int:
        with self.lock:
            if not self._known_good:
                return int(duration_ms) + 1
            return self._elapsed_ms + int((time.monotonic() - self._checkpoint_monotonic) * 1000)

    def checkpoint(self) -> None:
        with self.lock:
            if not self._known_good:
                return
            now = time.monotonic()
            self._elapsed_ms += int((now - self._checkpoint_monotonic) * 1000)
            self._checkpoint_monotonic = now
            try:
                tmp_path = f"{self.state_path}.tmp"
                with open(tmp_path, "w", encoding="utf-8") as handle:
                    json.dump({"grant_id": self.grant_id, "elapsed_ms_at_checkpoint": self._elapsed_ms}, handle)
                os.replace(tmp_path, self.state_path)
            except OSError:
                pass  # best-effort; the in-memory value is still correct for elapsed_ms()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="reconclave-armed-clock")
        self._thread.start()

    def _run(self) -> None:
        while not self._stop_event.wait(self.CHECKPOINT_INTERVAL_SECONDS):
            self.checkpoint()

    def close(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.checkpoint()


class Node:
    def __init__(self, node_id: str, name: str, address: str, port: int,
                 enable_network_scan: bool = False, evidence_dir: str | None = None,
                 evidence_key: str | None = None, execution_key: str | None = None,
                 enable_tools: bool = False, standing_grant: dict | None = None,
                 standing_grant_state_path: str | None = None) -> None:
        self.node_id = node_id
        self.name = name
        self.address = address
        self.port = port
        self.started = time.monotonic()
        # Foundation only (platform-roadmap.md's deferred "local automation engine"
        # phase is what will actually check this): a provisioned standing grant plus
        # its persisted elapsed-time tracker, so a future capability handler running
        # with no live coordinator has EngagementPolicy.verify_standing_grant and a
        # real elapsed_ms() to check it against. Omitting both leaves every existing
        # code path unchanged.
        self.standing_grant = standing_grant
        self.armed_clock: ArmedClock | None = None
        if standing_grant is not None and standing_grant_state_path is not None:
            self.armed_clock = ArmedClock(standing_grant_state_path, str(standing_grant.get("grant_id", "")))
            self.armed_clock.start()
        self.boot_nonce = secrets.token_hex(8)
        self.sequence = 0
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()
        self.scan_cancelled = threading.Event()
        self.scan_state = {
            "job_status": "idle", "checked": 0, "total": 0, "hosts": [], "error": "",
            "recurring": False, "run_count": 0,
        }
        self.evidence_dir = evidence_dir
        self.encrypted_spool = EncryptedSpool(evidence_dir, evidence_key, node_id) if evidence_dir and evidence_key else None
        if self.evidence_dir is not None:
            os.makedirs(self.evidence_dir, exist_ok=True)
        self.evidence_lock = threading.Lock()
        self.evidence_ids: set[str] = set()
        # The passphrase itself is never stored, only its digest - mirrors how the
        # Cardputer's Grove-paired peer key is kept.
        self.evidence_key = hashlib.sha256(evidence_key.encode()).digest() if evidence_key else None
        self.execution_key = hashlib.sha256(execution_key.encode()).digest() if execution_key else None
        self.tool_runner = ToolRunner(self.execution_key)
        self.nonce_lock = threading.Lock()
        self.recent_nonces: dict[str, collections.deque] = {}
        # Announcements are generated from this dispatcher. Adding a handler
        # automatically advertises it; removing one removes the claim.
        self.capability_handlers = {
            "system.info": self.system_info,
            "desktop.resources": self.desktop_resources,
        }
        if enable_network_scan and self.execution_key is not None:
            self.capability_handlers["net.discovery.scan"] = self.start_network_scan
            self.capability_handlers["coordination.job.status"] = self.network_scan_status
            if self.execution_key is not None:
                self.capability_handlers["coordination.job.cancel"] = self.cancel_network_scan
        if evidence_dir is not None and self.evidence_key is not None:
            self.capability_handlers["storage.evidence.write"] = self.write_evidence
        if enable_network_scan and self.execution_key is not None:
            self.restore_scan_task()
        if enable_tools and self.execution_key is not None:
            availability = self.tool_runner.available()
            tool_handlers = {
                "tool.nmap.services": self.tool_runner.nmap_services,
                "tool.dns.lookup": self.tool_runner.dns_lookup,
                "tool.tcpdump.capture": self.tool_runner.tcpdump_capture,
                "tool.masscan.services": self.tool_runner.masscan_services,
                "tool.arpscan.sweep": self.tool_runner.arpscan_sweep,
            }
            for capability, handler in tool_handlers.items():
                if availability.get(capability, {}).get("available"):
                    self.capability_handlers[capability] = handler
            # Every packaged tool adapter shares one async job registry (ToolRunner.jobs),
            # so a single pair of job-control capabilities covers all of them - unlike
            # net.discovery.scan, which owns a single dedicated job slot on Node itself
            # and is queried through coordination.job.status/coordination.job.cancel.
            if any(capability in self.capability_handlers for capability in TOOL_JOB_CAPABILITIES):
                self.capability_handlers["tool.job.status"] = self.tool_runner.job_status
                self.capability_handlers["tool.job.cancel"] = self.tool_runner.job_cancel

    def capability_descriptor(self, capability: str) -> dict:
        descriptor = {
            "id": capability,
            "version": 1,
            "permission": "trusted" if capability in AUTH_REQUIRED_CAPABILITIES else "public",
            "features": [],
            "limits": {"weight": 1, "max_concurrency": 1},
        }
        if capability == "net.discovery.scan":
            descriptor["features"] = ["ipv4", "range"]
            if self.evidence_dir is not None:
                descriptor["features"] += [
                    "recurring", "after_completion", "independent", "callback", "durable"
                ]
            descriptor["limits"] = {"weight": 4, "max_concurrency": 1}
        elif capability == "storage.evidence.write":
            descriptor["features"] = ["jsonl"]
        elif capability in TOOL_JOB_CAPABILITIES:
            descriptor.update(self.tool_runner.manifest(capability))
        elif capability == "tool.job.status":
            descriptor["features"] = ["job-id-addressed"]
        elif capability == "tool.job.cancel":
            descriptor["features"] = ["job-id-addressed", "idempotent"]
        return descriptor

    def verify_auth(self, source_node: str, destination_node: str, request_id: str,
                     capability: str, arguments: dict, auth: object) -> tuple[bytes, str]:
        """Raises CapabilityError unless `auth` is a valid, fresh signature over this
        exact request. Only called for capabilities in AUTH_REQUIRED_CAPABILITIES,
        which are registered only when their corresponding trust-domain key exists."""
        if not isinstance(auth, dict):
            raise CapabilityError("UNAUTHENTICATED", "request is not signed")
        nonce = str(auth.get("nonce", ""))
        tag_hex = str(auth.get("tag", ""))
        if not nonce or not tag_hex:
            raise CapabilityError("UNAUTHENTICATED", "request is not signed")
        key = self.evidence_key if capability == "storage.evidence.write" else self.execution_key
        if key is None:
            raise CapabilityError("UNAUTHENTICATED", "trust key is not configured")
        payload_digest = canonical_digest(arguments)
        if auth.get("payload_digest") != payload_digest:
            raise CapabilityError("UNAUTHENTICATED", "signed arguments do not match request")
        priority = int(auth.get("coordinator_priority", 0))
        lease_ms = int(auth.get("lease_ms", 0))
        canonical = "|".join([source_node, destination_node, request_id, capability,
                              self.boot_nonce, payload_digest, nonce, str(priority), str(lease_ms)]).encode()
        expected = hmac.new(key, canonical, hashlib.sha256).digest()[:AUTH_TAG_BYTES]
        try:
            supplied = bytes.fromhex(tag_hex)
        except ValueError:
            raise CapabilityError("UNAUTHENTICATED", "malformed signature") from None
        if not hmac.compare_digest(expected, supplied):
            raise CapabilityError("UNAUTHENTICATED", "invalid signature")
        with self.nonce_lock:
            seen = self.recent_nonces.setdefault(
                source_node, collections.deque(maxlen=RECENT_NONCES_PER_SOURCE))
            if nonce in seen:
                raise CapabilityError("UNAUTHENTICATED", "replayed request")
            seen.append(nonce)
        return key, nonce

    def close(self) -> None:
        """Best-effort cleanup on shutdown - checkpoints the armed clock (if any)
        so elapsed standing-grant time isn't lost on a clean restart."""
        if self.armed_clock is not None:
            self.armed_clock.close()

    def system_info(self, _arguments: dict) -> dict:
        return {
            "device_type": "desktop-node",
            "firmware": FIRMWARE,
            "name": self.name,
            "platform": platform.system(),
            "platform_release": platform.release(),
            "hostname": socket.gethostname(),
            "uptime_ms": int((time.monotonic() - self.started) * 1000),
            "ip": self.address,
        }

    def verify_scope_delegation(self, capability: str, arguments: dict) -> None:
        token = arguments.get("_scope_delegation")
        if not isinstance(token, dict) or self.execution_key is None:
            raise CapabilityError("SCOPE_REQUIRED", "signed scope delegation is required")
        tag = str(token.get("tag", ""))
        unsigned = {key: value for key, value in token.items() if key != "tag"}
        expected = hmac.new(self.execution_key,
                            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(tag, expected):
            raise CapabilityError("SCOPE_INVALID", "scope delegation signature is invalid")
        original = {key: value for key, value in arguments.items() if key != "_scope_delegation"}
        if (token.get("capability") != capability or token.get("destination_node") != self.node_id or
                token.get("arguments_digest") != canonical_digest(original)):
            raise CapabilityError("SCOPE_INVALID", "scope delegation does not match this operation")
        now = int(time.time() * 1000)
        if not int(token.get("issued_at_ms", 0)) <= now < int(token.get("expires_at_ms", 0)):
            raise CapabilityError("SCOPE_EXPIRED", "scope delegation has expired")
        includes = [ipaddress.ip_network(value) for value in token.get("included_networks", [])]
        excludes = [ipaddress.ip_network(value) for value in token.get("excluded_networks", [])]
        targets = [original.get(key) for key in ("network", "target", "host") if original.get(key)]
        targets += original.get("hosts", []) if isinstance(original.get("hosts"), list) else []
        if not targets:
            raise CapabilityError("SCOPE_INVALID", "delegation contains no explicit target")
        for value in targets:
            target = ipaddress.ip_network(str(value), strict=False)
            if not any(target.subnet_of(network) for network in includes) or any(target.overlaps(network) for network in excludes):
                raise CapabilityError("SCOPE_DENIED", f"target {value} is outside delegated scope")

    def desktop_resources(self, _arguments: dict) -> dict:
        disk = shutil.disk_usage("/")
        result = {
            "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else [],
            "cpu_count": os.cpu_count() or 0,
            "disk_total_bytes": disk.total,
            "disk_free_bytes": disk.free,
        }
        if hasattr(os, "sysconf"):
            try:
                result["memory_total_bytes"] = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
                result["memory_available_bytes"] = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
            except (ValueError, OSError):
                pass
        return result

    def network_scan_status(self, _arguments: dict) -> dict:
        with self.scan_lock:
            return self.network_scan_status_unlocked()

    def cancel_network_scan(self, _arguments: dict) -> dict:
        # Idempotent: cancelling with nothing running is still a successful no-op.
        self.scan_cancelled.set()
        with self.scan_lock:
            if self.scan_state["job_status"] == "running":
                self.scan_state["recurring"] = False
            self.remove_scan_task()
            return self.network_scan_status_unlocked()

    @property
    def scan_task_path(self) -> str | None:
        return os.path.join(self.evidence_dir, "recurring-scan-task.json") if self.evidence_dir else None

    def save_scan_task(self, arguments: dict) -> None:
        path = self.scan_task_path
        if path is None:
            return
        os.makedirs(self.evidence_dir, exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"active": True, "arguments": arguments}, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    def remove_scan_task(self) -> None:
        path = self.scan_task_path
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def restore_scan_task(self) -> None:
        path = self.scan_task_path
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as handle:
                stored = json.load(handle)
            if stored.get("active") and isinstance(stored.get("arguments"), dict):
                self.start_network_scan(stored["arguments"])
        except (OSError, ValueError, TypeError):
            # Preserve the file for operator recovery; do not execute malformed state.
            return

    @staticmethod
    def _parse_schedule(arguments: dict) -> int | None:
        schedule = arguments.get("schedule")
        if not schedule:
            return None
        interval_ms = int(schedule.get("interval_ms", 0))
        if interval_ms <= 0:
            raise ValueError("schedule.interval_ms must be a positive integer")
        return interval_ms

    def start_network_scan(self, arguments: dict) -> dict:
        with self.scan_lock:
            if self.scan_state["job_status"] == "running":
                return self.network_scan_status_unlocked()
            try:
                network = ipaddress.ip_network(arguments.get("network", f"{self.address}/24"), strict=False)
                if network.version != 4 or network.num_addresses > 256:
                    raise ValueError("network must be an IPv4 /24 or smaller")
                first = ipaddress.ip_address(arguments.get("start_ip", str(network.network_address + 1)))
                last = ipaddress.ip_address(arguments.get("end_ip", str(network.broadcast_address - 1)))
                if (first not in network or last not in network or first > last or
                        first == network.network_address or last == network.broadcast_address):
                    raise ValueError("scan range must contain usable addresses inside network")
                interval_ms = self._parse_schedule(arguments)
                schedule = arguments.get("schedule", {})
                policy = str(schedule.get("policy", "independent"))
                callback_endpoint = str(schedule.get("callback_endpoint", ""))
                owner_coordinator = str(schedule.get("owner_coordinator", ""))
                if interval_ms is not None and self.evidence_dir is None:
                    raise ValueError("durable recurring scans require evidence storage")
                if policy not in ("independent", "callback"):
                    raise ValueError("unsupported recurring policy")
                if policy == "callback" and (not callback_endpoint.startswith("http://") or
                                              not owner_coordinator):
                    raise ValueError("callback policy requires coordinator identity and endpoint")
            except ValueError as error:
                self.scan_state = {
                    "job_status": "failed", "checked": 0, "total": 0, "hosts": [], "error": str(error),
                    "recurring": False, "run_count": 0,
                }
                return self.network_scan_status_unlocked()
            hosts = [str(ipaddress.ip_address(value)) for value in range(int(first), int(last) + 1)
                     if str(ipaddress.ip_address(value)) != self.address]
            self.scan_cancelled.clear()
            self.scan_state = {
                "job_status": "running", "checked": 0, "total": len(hosts), "hosts": [], "error": "",
                "recurring": interval_ms is not None, "run_count": 0,
            }
        threading.Thread(target=self._scan_network,
                         args=(hosts, interval_ms, dict(arguments.get("schedule", {}))),
                         daemon=True).start()
        if interval_ms is not None:
            self.save_scan_task(arguments)
        return self.network_scan_status({})

    def network_scan_status_unlocked(self) -> dict:
        return {
            "job_status": self.scan_state["job_status"],
            "checked": self.scan_state["checked"],
            "total": self.scan_state["total"],
            "hosts": list(self.scan_state["hosts"]),
            "error": self.scan_state["error"],
            "recurring": self.scan_state["recurring"],
            "run_count": self.scan_state["run_count"],
        }

    @staticmethod
    def _host_responds(address: str) -> bool:
        # A successful connection or an explicit refusal both prove a host is present.
        for port in (80, 443, 22, 445, 3389):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.12)
            try:
                result = sock.connect_ex((address, port))
                if result in (0, errno.ECONNREFUSED):
                    return True
            finally:
                sock.close()
        return False

    def _callback_coordinator_reachable(self, schedule: dict) -> bool:
        endpoint = str(schedule.get("callback_endpoint", "")).rstrip("/")
        owner = str(schedule.get("owner_coordinator", ""))
        if not endpoint or not owner:
            return False
        if not endpoint.endswith(ANNOUNCE_PATH):
            endpoint += ANNOUNCE_PATH
        try:
            with urllib.request.urlopen(endpoint, timeout=1.5) as response:
                document = json.load(response)
            payload = document.get("payload", {})
            return payload.get("device_id") == owner and "coordinator" in payload.get("roles", [])
        except (OSError, ValueError, urllib.error.URLError):
            return False

    def _scan_network(self, hosts: list[str], interval_ms: int | None,
                      schedule: dict) -> None:
        while True:
            try:
                with ThreadPoolExecutor(max_workers=32, thread_name_prefix="recon-scan") as pool:
                    futures = {pool.submit(self._host_responds, host): host for host in hosts}
                    for future in as_completed(futures):
                        responsive = future.result()
                        with self.scan_lock:
                            self.scan_state["checked"] += 1
                            if responsive:
                                self.scan_state["hosts"].append(futures[future])
                with self.scan_lock:
                    self.scan_state["hosts"].sort(key=ipaddress.ip_address)
                    self.scan_state["run_count"] += 1
                    still_recurring = self.scan_state["recurring"] and not self.scan_cancelled.is_set()
                    self.scan_state["job_status"] = "running" if still_recurring else "complete"
            except Exception as error:  # Preserve job visibility instead of losing the worker silently.
                with self.scan_lock:
                    self.scan_state["job_status"] = "failed"
                    self.scan_state["error"] = str(error)[:160]
                return
            if not still_recurring or interval_ms is None:
                return
            if schedule.get("policy", "independent") == "callback":
                maximum = max(1, min(10, int(schedule.get("max_failures", 3))))
                reachable = False
                for attempt in range(maximum):
                    if self._callback_coordinator_reachable(schedule):
                        reachable = True
                        break
                    if attempt + 1 < maximum and self.scan_cancelled.wait(5 * (2 ** attempt)):
                        return
                if not reachable:
                    with self.scan_lock:
                        self.scan_state["job_status"] = "stopped"
                        self.scan_state["recurring"] = False
                        self.scan_state["error"] = "coordinator callback lease expired"
                    self.remove_scan_task()
                    return
            # after_completion semantics: the interval is measured from this run's
            # end, so a slow pass never overlaps the next one.
            if self.scan_cancelled.wait(interval_ms / 1000):
                with self.scan_lock:
                    self.scan_state["job_status"] = "complete"
                    self.scan_state["recurring"] = False
                return
            with self.scan_lock:
                self.scan_state["checked"] = 0
                self.scan_state["hosts"] = []

    def write_evidence(self, arguments: dict) -> dict:
        record = arguments.get("evidence")
        if not isinstance(record, dict) or any(field not in record for field in EVIDENCE_REQUIRED_FIELDS):
            raise CapabilityError("INVALID_REQUEST", "evidence record missing a required field")
        provenance = arguments.get("_provenance")
        if isinstance(provenance, dict) and str(provenance.get("source_node", "")):
            # Note this is distinct from (and doesn't overwrite) the record's own
            # "source_node" field above, which is self-reported content describing what
            # the evidence is about, not who authenticated the request that delivered it.
            record = {**record, "provenance": {
                "source_node": str(provenance.get("source_node", ""))[:80],
                "verified": bool(provenance.get("verified", False)),
                "request_nonce": str(provenance.get("request_nonce", ""))[:64],
                "request_tag": str(provenance.get("request_tag", ""))[:64],
                "algorithm": str(provenance.get("algorithm", ""))[:40],
            }}
        encoded = json.dumps(record, separators=(",", ":"))
        if len(encoded.encode()) > MAX_EVIDENCE_RECORD_BYTES:
            raise CapabilityError("INVALID_REQUEST", "evidence record exceeds size limit")
        assert self.evidence_dir is not None  # capability is only registered when set
        evidence_id = str(record.get("evidence_id", ""))
        if not evidence_id:
            evidence_id = hashlib.sha256(encoded.encode()).hexdigest()[:32]
            record["evidence_id"] = evidence_id
            encoded = json.dumps(record, separators=(",", ":"))
        try:
            os.makedirs(self.evidence_dir, exist_ok=True)
            day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
            with self.evidence_lock:
                duplicate = evidence_id in self.evidence_ids
                if not duplicate:
                    assert self.encrypted_spool is not None
                    self.encrypted_spool.append(record, day)
                    self.evidence_ids.add(evidence_id)
        except (OSError, ValueError) as error:
            raise CapabilityError("STORAGE_UNAVAILABLE", str(error)[:160], status="error") from error
        canonical = f"{self.node_id}|{evidence_id}|stored".encode()
        assert self.evidence_key is not None
        receipt = hmac.new(self.evidence_key, canonical, hashlib.sha256).digest()[:AUTH_TAG_BYTES].hex()
        return {"stored": True, "duplicate": duplicate, "evidence_id": evidence_id,
                "receipt": {"tag": receipt}}

    def envelope(self, message_type: str, destination: str | None = None) -> dict:
        with self.lock:
            self.sequence += 1
            sequence = self.sequence
        message = {
            "proto": PROTOCOL,
            "type": message_type,
            "message_id": f"{self.node_id}-{sequence}",
            "source_node": self.node_id,
            "timestamp_ms": int(time.time() * 1000),
            "sequence": sequence,
            "payload": {},
        }
        if destination:
            message["destination_node"] = destination
        return message

    def announcement(self) -> dict:
        message = self.envelope("announce")
        message["payload"] = {
            "device_id": self.node_id,
            "device_type": "desktop-node",
            "firmware": FIRMWARE,
            "roles": getattr(self, "roles", ["node"]),
            "capabilities": sorted(self.capability_handlers),
            "capability_descriptors": [
                self.capability_descriptor(capability)
                for capability in sorted(self.capability_handlers)
            ],
            "resources": {
                "network_mbps": 1000,
                "persistent_storage": self.evidence_dir is not None,
                "storage_free_bytes": shutil.disk_usage(self.evidence_dir or "/").free,
            },
            "status": "ready",
            "security": {"boot_nonce": self.boot_nonce, "mode": "hmac-sha256-128"},
        }
        return message

    def respond(self, request: object) -> tuple[int, dict]:
        if not isinstance(request, dict):
            response = self.envelope("response", "unknown")
            response["payload"] = {
                "request_id": "invalid-request",
                "status": "rejected",
                "error": {"code": "INVALID_REQUEST", "message": "Request must be an object"},
            }
            return 200, response
        source = str(request.get("source_node", "unknown"))
        payload = request.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}
        request_id = str(payload.get("request_id", "invalid-request"))
        response = self.envelope("response", source)
        valid = (
            request.get("proto") == PROTOCOL
            and request.get("type") == "request"
            and request.get("destination_node") == self.node_id
        )
        if not valid:
            response["payload"] = {
                "request_id": request_id,
                "status": "rejected",
                "error": {"code": "INVALID_REQUEST", "message": "Malformed or misdirected request"},
            }
        elif payload.get("capability") not in self.capability_handlers:
            response["payload"] = {
                "request_id": request_id,
                "status": "rejected",
                "error": {"code": "CAPABILITY_UNAVAILABLE", "message": "Capability is not available"},
            }
        else:
            capability = str(payload["capability"])
            try:
                arguments = payload.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise CapabilityError("INVALID_REQUEST", "arguments must be an object")
                if capability in AUTH_REQUIRED_CAPABILITIES:
                    destination = str(request.get("destination_node", ""))
                    response_key, response_nonce = self.verify_auth(source, destination, request_id,
                                                                     capability, arguments, payload.get("auth"))
                    if capability == "storage.evidence.write":
                        # verify_auth just proved this exact request was signed with the
                        # evidence key -- carry that proof into the stored record instead
                        # of discarding it once the check passes, mirroring the
                        # outbox-pull path's provenance (desktop_app.py
                        # AutomationEngine._sync_outbox) for this separate push-in path
                        # into ReconclaveNode's own encrypted spool (platform-roadmap.md
                        # Phase 5). Injected as a reserved argument rather than a new
                        # write_evidence() parameter, matching _scope_delegation's
                        # existing convention elsewhere.
                        request_auth = payload.get("auth") if isinstance(payload.get("auth"), dict) else {}
                        arguments = {**arguments, "_provenance": {
                            "source_node": source, "verified": True,
                            "request_nonce": str(request_auth.get("nonce", "")),
                            "request_tag": str(request_auth.get("tag", "")),
                            "algorithm": "hmac-sha256-truncated16",
                        }}
                if capability in SCOPE_REQUIRED_CAPABILITIES:
                    self.verify_scope_delegation(capability, arguments)
                result = self.capability_handlers[capability](arguments)
                response["payload"] = {"request_id": request_id, "status": "ok", "result": result}
            except CapabilityError as error:
                response["payload"] = {
                    "request_id": request_id,
                    "status": error.status,
                    "error": {"code": error.code, "message": error.message},
                }
            if capability in AUTH_REQUIRED_CAPABILITIES and 'response_key' in locals():
                response_body = response["payload"].get("result", response["payload"].get("error", {}))
                digest = canonical_digest(response_body)
                canonical = "|".join([self.node_id, source, request_id,
                                      response["payload"]["status"], self.boot_nonce,
                                      digest, response_nonce]).encode()
                response["payload"]["auth"] = {"nonce": response_nonce, "payload_digest": digest,
                                                  "tag": hmac.new(response_key, canonical, hashlib.sha256).digest()[:AUTH_TAG_BYTES].hex()}
        return 200, response


class Handler(BaseHTTPRequestHandler):
    server: "NodeServer"

    def send_json(self, status: int, body: dict) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path == ANNOUNCE_PATH:
            self.send_json(200, self.server.node.announcement())
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != MESSAGE_PATH:
            self.send_json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 16384:
                raise ValueError("invalid body length")
            request = json.loads(self.rfile.read(length))
            status, response = self.server.node.respond(request)
            capability = request.get("payload", {}).get("capability", "unknown") if isinstance(request, dict) else "unknown"
            response_payload = response.get("payload", {})
            outcome = response_payload.get("status", "unknown")
            error_code = response_payload.get("error", {}).get("code", "")
            print(f"request capability={capability} outcome={outcome}" +
                  (f" error={error_code}" if error_code else ""), flush=True)
            self.send_json(status, response)
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "invalid_json"})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")


class NodeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], node: Node) -> None:
        self.node = node
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a read-only Reconclave desktop node")
    parser.add_argument("--address", default=local_ip(), help="LAN IPv4 address to advertise")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--name", default=socket.gethostname())
    parser.add_argument("--node-id", default=f"rc-desktop-{uuid.getnode():012x}")
    parser.add_argument("--enable-network-scan", action="store_true",
                        help="advertise and enable bounded local /24 discovery")
    parser.add_argument("--evidence-dir", default=None,
                        help="advertise storage.evidence.write and append records under this directory")
    parser.add_argument("--evidence-key", default=None,
                        help="shared passphrase for evidence writes and storage receipts")
    parser.add_argument("--execution-key", default=None,
                        help="shared passphrase for trusted scan and job-control requests")
    parser.add_argument("--enable-tools", action="store_true",
                        help="advertise installed read-only packaged assessment adapters")
    args = parser.parse_args()
    if args.enable_network_scan and not args.execution_key:
        parser.error("--execution-key is required with --enable-network-scan")
    if args.evidence_dir and not args.evidence_key:
        parser.error("--evidence-key is required with --evidence-dir")

    node = Node(args.node_id, args.name, args.address, args.port, args.enable_network_scan,
                args.evidence_dir, args.evidence_key, args.execution_key, args.enable_tools)
    server = NodeServer(("0.0.0.0", args.port), node)
    service = ServiceInfo(
        "_reconclave._tcp.local.",
        f"{args.node_id}._reconclave._tcp.local.",
        addresses=[socket.inet_aton(args.address)],
        port=args.port,
        properties={"proto": PROTOCOL, "roles": "node", "device": "desktop-node", "path": ANNOUNCE_PATH},
        server=f"{args.node_id}.local.",
    )
    zeroconf = Zeroconf()
    zeroconf.register_service(service)
    stopping = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopping.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"Reconclave desktop node {args.node_id}")
    print(f"Advertising http://{args.address}:{args.port}{ANNOUNCE_PATH}")
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        zeroconf.unregister_service(service)
        zeroconf.close()
        server.server_close()
        node.close()
        print("Node stopped")


if __name__ == "__main__":
    main()
