"""Durable capability-workflow scheduler for the desktop coordinator."""

from __future__ import annotations

import threading
import time

from adaptive_scheduler import active_lease_counts, select_node


class WorkflowEngine:
    def __init__(self, coordinator, workspace, policy=None) -> None:
        self.coordinator = coordinator
        self.workspace = workspace
        self.policy = policy
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="reconclave-workflows", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    @staticmethod
    def _provider(step: dict, nodes: list[dict], active_leases: dict[str, int] | None = None) -> dict | None:
        """An explicit preferred_node is always honoured as-is (an operator's deliberate
        pin overrides any heuristic). Otherwise defers to adaptive_scheduler.select_node
        (Phase 7) for capability/topology/load-aware selection instead of just "the first
        ready node" -- the step's own arguments.network, when present, is the topology hint.
        """
        preferred = step.get("preferred_node")
        if preferred:
            return next((node for node in nodes if node.get("device_id") == preferred
                        and step["capability"] in node.get("capabilities", [])), None)
        network = step.get("arguments", {}).get("network") if isinstance(step.get("arguments"), dict) else None
        return select_node(nodes, step["capability"], network=network, active_leases=active_leases)

    def _poll_step(self, state: dict, provider: dict, trace_id: str = "") -> None:
        response = self.coordinator.invoke(provider["device_id"], "coordination.job.status",
                                           {"job_id": state.get("job_id")}, trace_id=trace_id)
        payload = response.get("payload", {})
        result = payload.get("result", {})
        job_status = result.get("job_status", "failed")
        state["result"] = result
        if job_status in ("running", "waiting"):
            return
        if job_status in ("complete", "idle", "cancelled"):
            state["status"] = "complete" if job_status == "complete" else "cancelled"
            if self.policy is not None and isinstance(state.get("delegated_arguments"), dict):
                self.policy.release(state["delegated_arguments"])
            return
        raise RuntimeError(result.get("error") or f"job ended with status {job_status}")

    def _start_step(self, definition: dict, state: dict, provider: dict, trace_id: str = "") -> None:
        state["attempts"] += 1
        state["node_id"] = provider["device_id"]
        state["started_at_ms"] = int(time.time() * 1000)
        state["delegated_arguments"] = definition.get("arguments", {})
        response = self.coordinator.invoke(provider["device_id"], definition["capability"],
                                           definition.get("arguments", {}), trace_id=trace_id)
        payload = response.get("payload", {})
        if payload.get("status") != "ok":
            error = payload.get("error", {})
            raise RuntimeError(error.get("message") or error.get("code") or "capability rejected")
        result = payload.get("result", {})
        state["result"] = result
        if result.get("job_status") in ("running", "waiting"):
            state["status"] = "running"
            state["job_id"] = result.get("job_id")
        else:
            state["status"] = "complete"
            if self.policy is not None:
                self.policy.release(definition.get("arguments", {}))

    def advance_once(self) -> bool:
        snapshot = self.workspace.snapshot()
        nodes = self.coordinator.state().get("nodes", [])
        active_leases = active_lease_counts(snapshot)
        workflows = {item["id"]: item for item in snapshot.get("workflows", [])}
        for run in snapshot.get("workflow_runs", []):
            if run.get("status") not in ("queued", "running"):
                continue
            workflow = workflows.get(run.get("workflow_id"))
            if workflow is None:
                self.workspace.update_workflow_run(run["id"], {"status": "failed"})
                return True
            definitions = {item["id"]: item for item in workflow["steps"]}
            states = {item["id"]: item for item in run["steps"]}
            changed = run.get("status") != "running"
            run["status"] = "running"
            for state in run["steps"]:
                if state["status"] != "running":
                    continue
                definition = definitions[state["id"]]
                if int(time.time() * 1000) - state.get("started_at_ms", 0) > definition.get("timeout_ms", 300000):
                    if self.policy is not None and isinstance(state.get("delegated_arguments"), dict):
                        self.policy.release(state["delegated_arguments"])
                    state["error"] = "workflow step timed out"
                    state["status"] = ("pending" if state["attempts"] <= definition["retries"]
                                       else "failed")
                    changed = True
                    break
                provider = next((node for node in nodes
                                 if node.get("device_id") == state.get("node_id")), None)
                if provider is None:
                    continue
                try:
                    self._poll_step(state, provider, trace_id=run.get("trace_id", ""))
                    state["error"] = ""
                except Exception as error:
                    if self.policy is not None and isinstance(state.get("delegated_arguments"), dict):
                        self.policy.release(state["delegated_arguments"])
                    state["error"] = str(error)[:300]
                    state["status"] = ("pending" if state["attempts"] <= definition["retries"]
                                       else "failed")
                changed = True
                break
            else:
                completed = {item["id"] for item in run["steps"] if item["status"] == "complete"}
                ready = [definition for definition in workflow["steps"]
                         if states[definition["id"]]["status"] == "pending" and
                         set(definition["depends_on"]) <= completed]
                if ready:
                    definition = ready[0]
                    state = states[definition["id"]]
                    provider = self._provider(definition, nodes, active_leases)
                    if provider is not None:
                        try:
                            if self.policy is not None:
                                delegated = self.policy.delegate(run.get("scope_id", ""), run["project_id"],
                                                                 definition["capability"], definition.get("arguments", {}),
                                                                 provider["device_id"])
                                definition = {**definition, "arguments": delegated}
                            self._start_step(definition, state, provider, trace_id=run.get("trace_id", ""))
                            state["error"] = ""
                        except Exception as error:
                            if self.policy is not None and isinstance(state.get("delegated_arguments"), dict):
                                self.policy.release(state["delegated_arguments"])
                            state["error"] = str(error)[:300]
                            state["status"] = ("pending" if state["attempts"] <= definition["retries"]
                                               else "failed")
                        changed = True
            statuses = {item["status"] for item in run["steps"]}
            if "failed" in statuses:
                run["status"] = "failed"
            elif statuses <= {"complete"}:
                run["status"] = "complete"
            if changed:
                self.workspace.update_workflow_run(run["id"], {
                    "status": run["status"], "steps": run["steps"],
                })
                return True
        return False

    def _run(self) -> None:
        while not self.stop_event.wait(1):
            try:
                self.advance_once()
            except Exception as error:
                print(f"[workflow] scheduler error: {error}")

    def cancel(self, run_id: str) -> dict:
        snapshot = self.workspace.snapshot()
        run = next((item for item in snapshot.get("workflow_runs", [])
                    if item.get("id") == run_id), None)
        if run is None:
            raise KeyError(run_id)
        for state in run["steps"]:
            if state.get("status") == "running" and state.get("node_id"):
                try:
                    self.coordinator.invoke(state["node_id"], "coordination.job.cancel",
                                            {"job_id": state.get("job_id")}, trace_id=run.get("trace_id", ""))
                except Exception as error:
                    state["error"] = f"Cancellation delivery failed: {error}"[:300]
                if self.policy is not None and isinstance(state.get("delegated_arguments"), dict):
                    self.policy.release(state["delegated_arguments"])
            if state.get("status") in ("pending", "running"):
                state["status"] = "cancelled"
        return self.workspace.update_workflow_run(run_id, {"status": "cancelled", "steps": run["steps"]})
