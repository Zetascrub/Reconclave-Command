"""Capability/resource/topology-aware node selection and distributed scanning.

Phase 7 (docs/platform-roadmap.md): adaptive node selection, scope-sharded parallel
scanning with failover and backpressure, and consensus scanning (design doc §9.2). All
three share one idea -- a scan "chunk" is a (network, start_ip, end_ip) argument tuple
for the existing net.discovery.scan capability, dispatched through the existing
EngagementPolicy/dispatch-lease machinery -- no new device-side capability is needed.
"""

from __future__ import annotations

import ipaddress
import threading
import time
import uuid


def node_subnet(node: dict) -> ipaddress.IPv4Network | None:
    """Best-effort inference of a node's own attached /24, the same heuristic
    AutomationEngine's scout playbook already uses (desktop_app.py) -- nodes don't
    currently advertise an explicit subnet, only their own address.
    """
    address = node.get("address")
    if not address:
        return None
    try:
        network = ipaddress.ip_network(f"{address}/24", strict=False)
    except ValueError:
        return None
    return network if network.version == 4 else None


def select_node(nodes: list[dict], capability: str, *, network: str | None = None,
                exclude: set[str] | None = None, active_leases: dict[str, int] | None = None) -> dict | None:
    """Picks the best candidate node for one dispatch: capability-filtered, then
    topology-preferred (a node whose own attached subnet actually contains `network`,
    when that narrows the field at all -- dispatching to a node that can't reach the
    target just wastes a round trip before that node's own scope-delegation check
    rejects it), then ranked by current load (fewer active dispatch leases first, then
    higher advertised bandwidth) as an adaptive throughput proxy grounded in signals this
    platform already tracks rather than new telemetry invented for this alone.

    Returns None when nothing is eligible right now -- callers treat that as backpressure
    (try again on the next tick), not a hard failure.
    """
    exclude = exclude or set()
    active_leases = active_leases or {}
    capable = [node for node in nodes if capability in node.get("capabilities", [])]
    if not capable:
        return None
    # `exclude` (nodes a failing chunk already tried) is a preference, not a hard filter:
    # on a single-node deployment -- the common case -- permanently blacklisting the only
    # capable node after one transient failure would strand the chunk in "pending"
    # forever instead of ever reaching the attempt ceiling and failing cleanly.
    not_excluded = [node for node in capable if node.get("device_id") not in exclude]
    if not_excluded:
        capable = not_excluded
    if network:
        try:
            target_network = ipaddress.ip_network(str(network), strict=False)
        except ValueError:
            target_network = None
        if target_network is not None:
            topology_matched = []
            for node in capable:
                subnet = node_subnet(node)
                if subnet is not None and (subnet == target_network or
                                           target_network.subnet_of(subnet) or subnet.subnet_of(target_network)):
                    topology_matched.append(node)
            if topology_matched:
                capable = topology_matched
    def rank(node: dict) -> tuple:
        device_id = str(node.get("device_id", ""))
        load = active_leases.get(device_id, 0)
        not_ready = 0 if node.get("status") == "ready" else 1
        bandwidth = -(node.get("resources", {}).get("network_mbps") or 0)
        return (not_ready, load, bandwidth, device_id)
    return sorted(capable, key=rank)[0]


def active_lease_counts(snapshot: dict) -> dict[str, int]:
    """Live dispatch-lease count per node, used as select_node's load signal. Shared
    between WorkflowEngine and DistributedScanEngine rather than each keeping its own
    copy -- it's the one existing, already-tracked load signal on this platform.
    """
    now = int(time.time() * 1000)
    counts: dict[str, int] = {}
    for lease in snapshot.get("dispatch_leases", []):
        if lease.get("active") and lease.get("expires_at_ms", 0) > now:
            device = str(lease.get("destination_node", ""))
            counts[device] = counts.get(device, 0) + 1
    return counts


def shard_ranges(network: str, chunk_size: int) -> list[tuple[str, str]]:
    """Splits a network's usable host range (excludes the network/broadcast addresses,
    matching net.discovery.scan's own start_ip/end_ip convention) into contiguous
    (start_ip, end_ip) chunks of at most `chunk_size` addresses -- design doc §9.1's
    /28 "work units" example, generalised to any chunk size rather than a fixed prefix.
    """
    parsed = ipaddress.ip_network(str(network), strict=True)
    if parsed.version != 4:
        raise ValueError("only IPv4 networks are supported")
    chunk_size = max(1, int(chunk_size))
    hosts = list(parsed.hosts())
    if not hosts:
        raise ValueError("network has no usable host addresses")
    return [(str(hosts[start]), str(hosts[min(start + chunk_size, len(hosts)) - 1]))
            for start in range(0, len(hosts), chunk_size)]


TERMINAL_OK_STATUSES = ("complete", "idle", "cancelled")
MAX_CHUNK_ATTEMPTS = 3
MAX_TARGETS_PER_CONSENSUS_SCAN = 32
MAX_CHUNK_SIZE = 256
MAX_CONCURRENT_CHUNKS = 32


class DistributedScanEngine:
    """Orchestrates parallel (scope-sharded) and consensus distributed scans.

    Mirrors WorkflowEngine's own shape (threaded tick loop, one advance_once-style method
    doing the real work, delegated-scope release on every exit path) deliberately, rather
    than inventing a different orchestration idiom for what is structurally the same kind
    of durable, poll-driven dispatch loop.
    """

    def __init__(self, coordinator, workspace, policy=None) -> None:
        self.coordinator = coordinator
        self.workspace = workspace
        self.policy = policy
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="reconclave-distributed-scan", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def _run(self) -> None:
        while not self.stop_event.wait(1):
            try:
                snapshot = self.workspace.snapshot()
                for scan in snapshot.get("distributed_scans", []):
                    if scan.get("status") == "running":
                        self.advance(scan["id"])
            except Exception as error:
                print(f"[distributed-scan] scheduler error: {error}")

    def create(self, body: dict) -> dict:
        project_id = str(body.get("project_id", "")).strip()
        scope_id = str(body.get("scope_id", "")).strip()
        mode = str(body.get("mode", "")).strip()
        capability = str(body.get("capability", "net.discovery.scan")).strip()
        network = str(body.get("network", "")).strip()
        if mode not in ("parallel", "consensus"):
            raise ValueError("mode must be 'parallel' or 'consensus'")
        if not project_id or not any(item.get("id") == project_id
                                     for item in self.workspace.snapshot()["projects"]):
            raise ValueError("project does not exist")
        parsed_network = ipaddress.ip_network(network, strict=True)
        if parsed_network.version != 4:
            raise ValueError("only IPv4 networks are supported")

        if mode == "parallel":
            chunk_size = min(max(int(body.get("chunk_size", 16)), 1), MAX_CHUNK_SIZE)
            chunks = [self._new_chunk(start, end, fixed_node="")
                     for start, end in shard_ranges(network, chunk_size)]
        else:
            targets = body.get("targets", [])
            if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS_PER_CONSENSUS_SCAN:
                raise ValueError(f"consensus mode requires 1-{MAX_TARGETS_PER_CONSENSUS_SCAN} targets")
            nodes = [node for node in self.coordinator.state().get("nodes", [])
                    if capability in node.get("capabilities", [])]
            if not nodes:
                raise ValueError("no live node currently advertises this capability")
            chunks = []
            for raw_target in targets:
                parsed_target = ipaddress.ip_address(str(raw_target))
                if parsed_target not in parsed_network:
                    raise ValueError(f"target {parsed_target} is outside {network}")
                target = str(parsed_target)
                for node in nodes:
                    chunks.append(self._new_chunk(target, target, fixed_node=node["device_id"]))

        max_concurrent = min(max(int(body.get("max_concurrent_chunks", 4)), 1), MAX_CONCURRENT_CHUNKS)
        now = int(time.time() * 1000)
        scan = {"id": f"dscan-{uuid.uuid4().hex[:12]}", "project_id": project_id, "scope_id": scope_id,
               "mode": mode, "capability": capability, "network": network,
               "max_concurrent_chunks": max_concurrent, "status": "running",
               "chunks": chunks, "consensus": None, "created_at_ms": now, "updated_at_ms": now}
        return self.workspace.add_distributed_scan(scan)

    @staticmethod
    def _new_chunk(start_ip: str, end_ip: str, *, fixed_node: str) -> dict:
        return {"id": f"chunk-{uuid.uuid4().hex[:12]}", "start_ip": start_ip, "end_ip": end_ip,
               "status": "pending", "assigned_node": fixed_node, "fixed_node": bool(fixed_node),
               "job_id": "", "attempts": 0, "tried_nodes": [], "result": {}, "error": "",
               "delegated_arguments": None}

    @staticmethod
    def _active_lease_counts(snapshot: dict) -> dict[str, int]:
        return active_lease_counts(snapshot)

    def _release(self, chunk: dict) -> None:
        if self.policy is not None and isinstance(chunk.get("delegated_arguments"), dict):
            self.policy.release(chunk["delegated_arguments"])

    def _requeue_or_fail(self, chunk: dict, error: str, tried_node: str = "") -> None:
        self._release(chunk)
        node_id = tried_node or str(chunk.get("assigned_node", ""))
        if node_id and node_id not in chunk["tried_nodes"]:
            chunk["tried_nodes"].append(node_id)
        chunk["error"] = error
        chunk["job_id"] = ""
        chunk["delegated_arguments"] = None
        if chunk["attempts"] >= MAX_CHUNK_ATTEMPTS:
            chunk["status"] = "failed"
        else:
            chunk["status"] = "pending"
            if not chunk["fixed_node"]:
                chunk["assigned_node"] = ""

    def _poll_chunk(self, chunk: dict, provider: dict) -> bool:
        """Returns True if this chunk's status changed."""
        try:
            response = self.coordinator.invoke(provider["device_id"], "coordination.job.status",
                                               {"job_id": chunk["job_id"]})
            payload = response.get("payload", {})
            result = payload.get("result", {})
            job_status = result.get("job_status", "failed")
            chunk["result"] = result
            if job_status in ("running", "waiting"):
                return False
            if job_status in TERMINAL_OK_STATUSES:
                chunk["status"] = "complete" if job_status == "complete" else "cancelled"
                self._release(chunk)
                return True
            raise RuntimeError(result.get("error") or f"job ended with status {job_status}")
        except Exception as error:
            chunk["attempts"] += 1
            self._requeue_or_fail(chunk, str(error)[:200])
            return True

    def _dispatch_chunk(self, scan: dict, chunk: dict, nodes: list[dict],
                        active_leases: dict[str, int]) -> bool:
        """Returns True if this chunk's status changed (a successful dispatch or a
        dispatch failure); returns False for backpressure (nothing eligible right now,
        or the engagement scope's own concurrency/rate ceiling is momentarily full) --
        callers must simply retry on the next tick rather than treat that as an error.
        """
        if chunk["fixed_node"]:
            provider = next((node for node in nodes if node["device_id"] == chunk["assigned_node"]
                            and scan["capability"] in node.get("capabilities", [])), None)
            if provider is None:
                chunk["attempts"] += 1
                self._requeue_or_fail(chunk, "assigned node is no longer available")
                return True
        else:
            provider = select_node(nodes, scan["capability"], network=scan["network"],
                                   exclude=set(chunk["tried_nodes"]), active_leases=active_leases)
            if provider is None:
                return False
        arguments = {"network": scan["network"], "start_ip": chunk["start_ip"], "end_ip": chunk["end_ip"]}
        try:
            if self.policy is not None and scan.get("scope_id"):
                arguments = self.policy.delegate(scan["scope_id"], scan["project_id"], scan["capability"],
                                                 arguments, provider["device_id"])
            response = self.coordinator.invoke(provider["device_id"], scan["capability"], arguments)
        except PermissionError:
            return False  # scope concurrency/rate limit, or trust key not configured -- backpressure
        except Exception as error:
            chunk["attempts"] += 1
            self._requeue_or_fail(chunk, str(error)[:200], tried_node=provider["device_id"])
            return True
        payload = response.get("payload", {})
        chunk["attempts"] += 1
        if payload.get("status") != "ok":
            error = payload.get("error", {})
            self._requeue_or_fail(chunk, error.get("message") or error.get("code") or "capability rejected",
                                  tried_node=provider["device_id"])
            return True
        result = payload.get("result", {})
        chunk["result"] = result
        chunk["assigned_node"] = provider["device_id"]
        chunk["delegated_arguments"] = arguments
        chunk["error"] = ""
        if result.get("job_status") in ("running", "waiting"):
            chunk["status"] = "running"
            chunk["job_id"] = str(result.get("job_id", ""))
        else:
            chunk["status"] = "complete"
            self._release(chunk)
        return True

    def advance(self, scan_id: str) -> bool:
        snapshot = self.workspace.snapshot()
        scan = next((item for item in snapshot["distributed_scans"] if item["id"] == scan_id), None)
        if scan is None or scan.get("status") != "running":
            return False
        nodes = self.coordinator.state().get("nodes", [])
        active_leases = self._active_lease_counts(snapshot)
        changed = False

        for chunk in scan["chunks"]:
            if chunk["status"] != "running":
                continue
            provider = next((node for node in nodes if node["device_id"] == chunk["assigned_node"]), None)
            if provider is None:
                chunk["attempts"] += 1
                self._requeue_or_fail(chunk, "assigned node is no longer available")
                changed = True
                continue
            if self._poll_chunk(chunk, provider):
                changed = True

        running_count = sum(1 for chunk in scan["chunks"] if chunk["status"] == "running")
        for chunk in scan["chunks"]:
            if running_count >= scan["max_concurrent_chunks"]:
                break
            if chunk["status"] != "pending":
                continue
            if self._dispatch_chunk(scan, chunk, nodes, active_leases):
                changed = True
            if chunk["status"] == "running":
                running_count += 1

        if not any(chunk["status"] in ("pending", "running") for chunk in scan["chunks"]):
            failed = sum(1 for chunk in scan["chunks"] if chunk["status"] == "failed")
            scan["status"] = ("failed" if failed == len(scan["chunks"])
                              else "complete" if failed == 0 else "partial")
            if scan["mode"] == "consensus" and scan.get("consensus") is None:
                scan["consensus"] = self._reconcile_consensus(scan)
                self.workspace.add_evidence({
                    "project_id": scan["project_id"], "job_id": scan["id"], "kind": "consensus-scan",
                    "title": "Consensus scan reconciliation",
                    "summary": f"{len(scan['consensus']['targets'])} target(s) checked, "
                              f"scan {scan['id']}",
                    "data": scan["consensus"],
                })
            changed = True

        if changed:
            self.workspace.update_distributed_scan(scan_id, {
                "status": scan["status"], "chunks": scan["chunks"], "consensus": scan["consensus"]})
        return changed

    @staticmethod
    def _reconcile_consensus(scan: dict) -> dict:
        """Groups this scan's per-(node,target) chunks by target and classifies
        agreement. A target only some nodes detected is "low" concord (design doc §9.2's
        worked example) and worth investigating; a target every node that actually
        completed a check agreed on (whether present or absent) is "high" concord --
        distinct from "unobserved", where no node's check ever actually completed, so
        there is no explicit negative to report, only an absence of data (§9.2's
        "distinguish not observed from an explicit negative result").
        """
        by_target: dict[str, list[dict]] = {}
        for chunk in scan["chunks"]:
            by_target.setdefault(chunk["start_ip"], []).append(chunk)
        targets = {}
        for target, chunks in by_target.items():
            observations = []
            for chunk in chunks:
                if chunk["status"] not in ("complete", "cancelled"):
                    continue
                hosts = chunk.get("result", {}).get("hosts", [])
                observations.append({"node_id": chunk.get("assigned_node", ""),
                                     "detected": target in hosts})
            detected = sum(1 for item in observations if item["detected"])
            if not observations:
                concord = "unobserved"
            elif detected in (0, len(observations)):
                concord = "high"
            else:
                concord = "low"
            targets[target] = {"observations": observations, "concord": concord,
                               "detected_count": detected, "total_observations": len(observations)}
        return {"targets": targets}

    def cancel(self, scan_id: str) -> dict:
        snapshot = self.workspace.snapshot()
        scan = next((item for item in snapshot["distributed_scans"] if item["id"] == scan_id), None)
        if scan is None:
            raise KeyError(scan_id)
        for chunk in scan["chunks"]:
            if chunk["status"] == "running" and chunk.get("assigned_node"):
                try:
                    self.coordinator.invoke(chunk["assigned_node"], "coordination.job.cancel",
                                           {"job_id": chunk.get("job_id")})
                except Exception as error:
                    chunk["error"] = f"Cancellation delivery failed: {error}"[:200]
                self._release(chunk)
            if chunk["status"] in ("pending", "running"):
                chunk["status"] = "cancelled"
        return self.workspace.update_distributed_scan(scan_id, {"status": "cancelled", "chunks": scan["chunks"]})
