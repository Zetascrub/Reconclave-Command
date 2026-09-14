"""Durable local project, job, and evidence index for the desktop coordinator."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import pathlib
import re
import threading
import time
import uuid

from vulnerability_analysis import (
    ALLOWED_STATUS_TRANSITIONS,
    REMEDIATION_STATUSES,
    correlate_observations,
)


class WorkspaceStore:
    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        self.custody_key_path = path.with_suffix(".custody-key")
        self.custody_key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.custody_key_path.exists():
            self.custody_key = self.custody_key_path.read_bytes()
            if len(self.custody_key) != 32:
                raise ValueError("evidence custody key must contain exactly 32 bytes")
        else:
            self.custody_key = os.urandom(32)
            descriptor = os.open(self.custody_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(self.custody_key)
        # Set for the duration of one request by AppHandler (via set_current_actor) so
        # _append_audit can attribute the resulting audit events to a real operator once
        # any exist, instead of the "local-operator" default -- a thread-local rather
        # than threading every audit-producing method's signature through with an actor
        # parameter, since ThreadingHTTPServer already gives each request its own thread.
        self._actor_local = threading.local()
        # Operator password material lives in its own file, never in self.data -- unlike
        # every other collection here, self.data is handed out verbatim by snapshot()
        # (that's what GET /api/workspace returns to the browser), so a password hash
        # has no business anywhere inside it. Same reasoning as custody_key living
        # outside self.data above.
        self.credentials_path = path.with_suffix(".operator-credentials.json")
        if self.credentials_path.is_file():
            self._credentials: dict[str, dict] = json.loads(self.credentials_path.read_text(encoding="utf-8"))
        else:
            self._credentials = {}
        # Session tokens are a bearer credential -- like password hashes above, and
        # unlike every other collection here, they must never appear in snapshot()
        # (GET /api/workspace hands that to any authenticated browser, including a
        # viewer; a leaked token is an impersonation of whoever it belongs to). Kept
        # in memory only, not persisted at all: restarting the desktop app simply signs
        # every operator out, which is an acceptable, unsurprising cost for never having
        # a live token sitting on disk.
        self._sessions: dict[str, dict] = {}
        self.data = {"revision": 0, "projects": [], "jobs": [], "evidence": [],
                     "automations": [], "workflows": [], "workflow_runs": [], "scopes": [],
                     "audit_events": [], "dispatch_leases": [], "findings": [],
                     "fleet_nodes": [], "fleet_configs": [], "ota_releases": [], "ota_rollouts": [],
                     "distributed_scans": [], "operators": [], "approvals": []}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        document = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("workspace root must be an object")
        for name in ("projects", "jobs", "evidence", "automations", "workflows", "workflow_runs", "scopes", "audit_events", "dispatch_leases", "findings", "fleet_nodes", "fleet_configs", "ota_releases", "ota_rollouts", "distributed_scans", "operators", "approvals"):
            if not isinstance(document.get(name, []), list):
                raise ValueError(f"workspace {name} must be a list")
        self.data = {"revision": int(document.get("revision", 0)),
                     "projects": document.get("projects", []),
                     "jobs": document.get("jobs", []),
                     "evidence": document.get("evidence", []),
                     "automations": document.get("automations", []),
                     "workflows": document.get("workflows", []),
                     "workflow_runs": document.get("workflow_runs", []),
                     "scopes": document.get("scopes", []),
                     "audit_events": document.get("audit_events", []),
                     "dispatch_leases": document.get("dispatch_leases", []),
                     "findings": document.get("findings", []),
                     "fleet_nodes": document.get("fleet_nodes", []),
                     "fleet_configs": document.get("fleet_configs", []),
                     "ota_releases": document.get("ota_releases", []),
                     "ota_rollouts": document.get("ota_rollouts", []),
                     "distributed_scans": document.get("distributed_scans", []),
                     "operators": document.get("operators", []),
                     "approvals": document.get("approvals", [])}

    def snapshot(self) -> dict:
        with self.lock:
            return json.loads(json.dumps(self.data))

    def _save(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.path)

    def _commit(self) -> dict:
        self.data["revision"] += 1
        self._save()
        return self.snapshot()

    def set_current_actor(self, actor_id: str) -> None:
        self._actor_local.actor_id = actor_id

    def clear_current_actor(self) -> None:
        self._actor_local.actor_id = "local-operator"

    def _append_audit(self, action: str, project_id: str, subject_id: str,
                      outcome: str = "accepted", trace_id: str = "") -> dict:
        record = {"id": f"audit-{uuid.uuid4().hex[:16]}",
                  "trace_id": trace_id or f"trace-{uuid.uuid4().hex[:16]}",
                  "actor_id": getattr(self._actor_local, "actor_id", "local-operator"),
                  "project_id": project_id,
                  "action": action, "subject_id": subject_id, "outcome": outcome,
                  "created_at_ms": int(time.time() * 1000)}
        self.data["audit_events"].append(record)
        return record

    def create_project(self, body: dict) -> dict:
        name = str(body.get("name", "")).strip()
        if not name or len(name) > 80:
            raise ValueError("project name must contain 1-80 characters")
        now = int(time.time() * 1000)
        project = {"id": f"project-{uuid.uuid4().hex[:12]}", "name": name,
                   "description": str(body.get("description", "")).strip()[:500],
                   "created_at_ms": now, "updated_at_ms": now}
        with self.lock:
            self.data["projects"].append(project)
            self._commit()
        return project

    def upsert_job(self, body: dict) -> dict:
        job_id = str(body.get("id", "")).strip()
        project_id = str(body.get("project_id", "")).strip()
        if not job_id or not project_id:
            raise ValueError("job id and project_id are required")
        with self.lock:
            if not any(item.get("id") == project_id for item in self.data["projects"]):
                raise ValueError("project does not exist")
            now = int(time.time() * 1000)
            existing = next((item for item in self.data["jobs"] if item.get("id") == job_id), None)
            safe = {key: body.get(key) for key in (
                "project_id", "provider_id", "capability", "status", "checked", "total",
                "hosts", "scope", "error") if key in body}
            if existing is None:
                existing = {"id": job_id, "created_at_ms": now}
                self.data["jobs"].append(existing)
            existing.update(safe)
            existing["updated_at_ms"] = now
            self._append_audit("job.updated", project_id, job_id, str(existing.get("status", "updated")),
                               str(body.get("trace_id", "")))
            self._commit()
            return json.loads(json.dumps(existing))

    @staticmethod
    def _validate_provenance(value: object) -> dict:
        """Normalises an optional node-signed provenance claim attached to evidence.

        Absent for operator-entered/self-reported evidence (the common case); present
        when a caller (e.g. the outbox sync path) can point to an already-verified
        response signature proving which node's key authenticated the batch this
        record came from, rather than only recording an unauthenticated "source_node"
        string. Bounded and re-typed defensively since evidence bodies ultimately
        originate from local API callers, not just trusted internal code paths.
        """
        if not isinstance(value, dict) or not str(value.get("source_node", "")):
            return {}
        return {"source_node": str(value.get("source_node", ""))[:80],
                "verified": bool(value.get("verified", False)),
                "response_nonce": str(value.get("response_nonce", ""))[:64],
                "response_tag": str(value.get("response_tag", ""))[:64],
                "algorithm": str(value.get("algorithm", ""))[:40]}

    def add_evidence(self, body: dict) -> dict:
        project_id = str(body.get("project_id", "")).strip()
        if not project_id:
            raise ValueError("project_id is required")
        with self.lock:
            if not any(item.get("id") == project_id for item in self.data["projects"]):
                raise ValueError("project does not exist")
            core = {"project_id": project_id,
                      "job_id": str(body.get("job_id", "")),
                      "kind": str(body.get("kind", "observation"))[:48],
                      "title": str(body.get("title", "Evidence"))[:120],
                      "summary": str(body.get("summary", ""))[:1000],
                      "data": body.get("data", {}),
                      "captured_at_ms": int(body.get("captured_at_ms", time.time() * 1000))}
            # Only folded into the hashed core when actually present, so evidence
            # captured without a provenance claim (every pre-existing record, and
            # any future operator-entered one) hashes exactly as it always has.
            provenance = self._validate_provenance(body.get("provenance"))
            if provenance:
                core["provenance"] = provenance
            encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
            content_sha256 = hashlib.sha256(encoded).hexdigest()
            evidence_id = str(body.get("id", "")).strip() or f"evidence-{content_sha256[:20]}"
            existing = next((item for item in self.data["evidence"] if item.get("id") == evidence_id), None)
            if existing is not None:
                if existing.get("content_sha256") not in (None, content_sha256):
                    raise ValueError("evidence id already exists with different content")
                return json.loads(json.dumps(existing))
            previous = next((item.get("chain_sha256", "") for item in reversed(self.data["evidence"])
                             if item.get("project_id") == project_id and item.get("chain_sha256")), "")
            chain_sha256 = hashlib.sha256(f"{previous}|{content_sha256}".encode()).hexdigest()
            custody_tag = hmac.new(self.custody_key, chain_sha256.encode(), hashlib.sha256).hexdigest()
            record = {"id": evidence_id, **core, "content_sha256": content_sha256,
                      "previous_sha256": previous, "chain_sha256": chain_sha256,
                      "custody_tag": custody_tag,
                      "receipt": {"algorithm": "hmac-sha256", "tag": custody_tag}}
            self.data["evidence"].append(record)
            self._append_audit("evidence.captured", project_id, evidence_id, "stored",
                               str(body.get("trace_id", "")))
            self._commit()
            return json.loads(json.dumps(record))

    def verify_evidence(self, project_id: str) -> dict:
        with self.lock:
            records = [item for item in self.data["evidence"] if item.get("project_id") == project_id]
            previous = ""
            verified = 0
            legacy = 0
            errors = []
            core_keys = ("project_id", "job_id", "kind", "title", "summary", "data", "captured_at_ms")
            for record in records:
                if not record.get("content_sha256"):
                    legacy += 1
                    continue
                core = {key: record.get(key) for key in core_keys}
                if record.get("provenance"):
                    core["provenance"] = record["provenance"]
                content_hash = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                chain_hash = hashlib.sha256(f"{previous}|{content_hash}".encode()).hexdigest()
                tag = hmac.new(self.custody_key, chain_hash.encode(), hashlib.sha256).hexdigest()
                if (content_hash != record.get("content_sha256") or previous != record.get("previous_sha256") or
                        chain_hash != record.get("chain_sha256") or not hmac.compare_digest(tag, record.get("custody_tag", ""))):
                    errors.append(record.get("id", "unknown"))
                else:
                    verified += 1
                previous = record.get("chain_sha256", previous)
            return {"project_id": project_id, "verified": verified, "legacy": legacy,
                    "errors": errors, "valid": not errors}

    def evidence_bundle(self, project_id: str) -> dict:
        verification = self.verify_evidence(project_id)
        records = [item for item in self.snapshot()["evidence"] if item.get("project_id") == project_id]
        manifest = {"schema": "reconclave-evidence-bundle/v1", "project_id": project_id,
                    "exported_at_ms": int(time.time() * 1000), "verification": verification,
                    "records": records}
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        manifest["bundle_sha256"] = digest
        manifest["bundle_tag"] = hmac.new(self.custody_key, digest.encode(), hashlib.sha256).hexdigest()
        return manifest

    def create_automation(self, body: dict) -> dict:
        project_id = str(body.get("project_id", "")).strip()
        node_id = str(body.get("node_id", "")).strip()
        condition = str(body.get("condition", ""))
        playbook = str(body.get("playbook", ""))
        if condition not in ("dhcp_assigned", "internet_possible"):
            raise ValueError("unsupported automation condition")
        if playbook not in ("network_scout", "system_snapshot"):
            raise ValueError("unsupported automation playbook")
        interval_ms = int(body.get("interval_ms", 0))
        if interval_ms and not 10000 <= interval_ms <= 86400000:
            raise ValueError("recurring interval must be 10 seconds to 24 hours")
        with self.lock:
            if not any(item.get("id") == project_id for item in self.data["projects"]):
                raise ValueError("project does not exist")
            now = int(time.time() * 1000)
            rule = {"id": f"rule-{uuid.uuid4().hex[:12]}", "project_id": project_id,
                    "scope_id": str(body.get("scope_id", "")),
                    "node_id": node_id, "condition": condition, "playbook": playbook,
                    "interval_ms": interval_ms, "enabled": True,
                    "device_managed": body.get("device_managed") is True, "created_at_ms": now,
                    "updated_at_ms": now, "last_triggered_ms": 0, "last_error": ""}
            self.data["automations"].append(rule)
            self._commit()
            return json.loads(json.dumps(rule))

    def set_automation(self, rule_id: str, body: dict) -> dict:
        with self.lock:
            rule = next((item for item in self.data["automations"] if item.get("id") == rule_id), None)
            if rule is None:
                raise KeyError(rule_id)
            if "enabled" in body:
                rule["enabled"] = body["enabled"] is True
            if "device_managed" in body:
                rule["device_managed"] = body["device_managed"] is True
            for key in ("last_triggered_ms", "last_error"):
                if key in body:
                    rule[key] = body[key]
            rule["updated_at_ms"] = int(time.time() * 1000)
            self._commit()
            return json.loads(json.dumps(rule))

    def delete_automation(self, rule_id: str) -> dict:
        with self.lock:
            before = len(self.data["automations"])
            self.data["automations"] = [item for item in self.data["automations"] if item.get("id") != rule_id]
            if len(self.data["automations"]) == before:
                raise KeyError(rule_id)
            self._commit()
            return {"deleted": rule_id}

    @staticmethod
    def _validate_workflow_steps(raw_steps: object) -> list[dict]:
        if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= 32:
            raise ValueError("workflow must contain 1-32 steps")
        steps = []
        identifiers = set()
        for raw in raw_steps:
            if not isinstance(raw, dict):
                raise ValueError("every workflow step must be an object")
            step_id = str(raw.get("id", "")).strip()
            capability = str(raw.get("capability", "")).strip()
            arguments = raw.get("arguments", {})
            dependencies = raw.get("depends_on", [])
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", step_id):
                raise ValueError("invalid workflow step id")
            if step_id in identifiers:
                raise ValueError("duplicate workflow step id")
            if not re.fullmatch(r"[a-z][a-z0-9]*(?:\.[a-z0-9_-]+)+", capability):
                raise ValueError("invalid workflow capability")
            if not isinstance(arguments, dict):
                raise ValueError("workflow step arguments must be an object")
            if (not isinstance(dependencies, list) or
                    not all(isinstance(item, str) for item in dependencies)):
                raise ValueError("depends_on must be a list of step ids")
            retries = int(raw.get("retries", 0))
            if not 0 <= retries <= 3:
                raise ValueError("workflow retries must be between 0 and 3")
            timeout_ms = int(raw.get("timeout_ms", 300000))
            if not 1000 <= timeout_ms <= 3600000:
                raise ValueError("workflow step timeout must be 1 second to 1 hour")
            identifiers.add(step_id)
            steps.append({"id": step_id, "capability": capability,
                          "arguments": json.loads(json.dumps(arguments)),
                          "depends_on": list(dict.fromkeys(dependencies)),
                          "preferred_node": str(raw.get("preferred_node", "")).strip(),
                          "retries": retries, "timeout_ms": timeout_ms})
        for step in steps:
            if step["id"] in step["depends_on"] or any(
                    dependency not in identifiers for dependency in step["depends_on"]):
                raise ValueError("workflow dependency is missing or self-referential")
        pending = {step["id"]: set(step["depends_on"]) for step in steps}
        resolved = set()
        while pending:
            ready = {step_id for step_id, dependencies in pending.items()
                     if dependencies <= resolved}
            if not ready:
                raise ValueError("workflow dependencies contain a cycle")
            resolved.update(ready)
            for step_id in ready:
                del pending[step_id]
        return steps

    def create_workflow(self, body: dict) -> dict:
        project_id = str(body.get("project_id", "")).strip()
        name = str(body.get("name", "")).strip()
        if not name or len(name) > 80:
            raise ValueError("workflow name must contain 1-80 characters")
        steps = self._validate_workflow_steps(body.get("steps"))
        with self.lock:
            if not any(item.get("id") == project_id for item in self.data["projects"]):
                raise ValueError("project does not exist")
            now = int(time.time() * 1000)
            workflow = {"id": f"workflow-{uuid.uuid4().hex[:12]}",
                        "project_id": project_id, "name": name,
                        "description": str(body.get("description", "")).strip()[:500],
                        "steps": steps, "created_at_ms": now, "updated_at_ms": now}
            self.data["workflows"].append(workflow)
            self._commit()
            return json.loads(json.dumps(workflow))

    def _workflow_has_active_run(self, workflow_id: str) -> bool:
        return any(run.get("workflow_id") == workflow_id and run.get("status") in ("queued", "running")
                   for run in self.data["workflow_runs"])

    def update_workflow(self, workflow_id: str, body: dict) -> dict:
        with self.lock:
            workflow = next((item for item in self.data["workflows"] if item.get("id") == workflow_id), None)
            if workflow is None:
                raise KeyError(workflow_id)
            # A run's step states are keyed by step id and matched against the
            # workflow's step definitions on every scheduler tick (WorkflowEngine
            # .advance_once); changing steps out from under an in-flight run would
            # silently corrupt that match. Completed/cancelled/failed runs keep
            # their own frozen step snapshot already, so they're unaffected.
            if self._workflow_has_active_run(workflow_id):
                raise ValueError("cannot edit a workflow with an active run in progress")
            if "name" in body:
                name = str(body["name"]).strip()
                if not name or len(name) > 80:
                    raise ValueError("workflow name must contain 1-80 characters")
                workflow["name"] = name
            if "description" in body:
                workflow["description"] = str(body["description"]).strip()[:500]
            if "steps" in body:
                workflow["steps"] = self._validate_workflow_steps(body["steps"])
            workflow["updated_at_ms"] = int(time.time() * 1000)
            self._append_audit("workflow.updated", workflow["project_id"], workflow_id, "updated")
            self._commit()
            return json.loads(json.dumps(workflow))

    def delete_workflow(self, workflow_id: str) -> dict:
        with self.lock:
            workflow = next((item for item in self.data["workflows"] if item.get("id") == workflow_id), None)
            if workflow is None:
                raise KeyError(workflow_id)
            if self._workflow_has_active_run(workflow_id):
                raise ValueError("cannot delete a workflow with an active run in progress")
            self.data["workflows"] = [item for item in self.data["workflows"] if item.get("id") != workflow_id]
            self._append_audit("workflow.deleted", workflow["project_id"], workflow_id, "deleted")
            self._commit()
            return {"deleted": workflow_id}

    def add_scope(self, scope: dict) -> dict:
        with self.lock:
            if not any(item.get("id") == scope.get("project_id") for item in self.data["projects"]):
                raise ValueError("project does not exist")
            self.data["scopes"].append(json.loads(json.dumps(scope)))
            self._commit()
            return json.loads(json.dumps(scope))

    def add_distributed_scan(self, scan: dict) -> dict:
        with self.lock:
            if not any(item.get("id") == scan.get("project_id") for item in self.data["projects"]):
                raise ValueError("project does not exist")
            self.data["distributed_scans"].append(json.loads(json.dumps(scan)))
            self._append_audit("distributed_scan.created", scan["project_id"], scan["id"], scan["mode"])
            self._commit()
            return json.loads(json.dumps(scan))

    def update_distributed_scan(self, scan_id: str, update: dict) -> dict:
        with self.lock:
            scan = next((item for item in self.data["distributed_scans"] if item.get("id") == scan_id), None)
            if scan is None:
                raise KeyError(scan_id)
            scan.update(json.loads(json.dumps(update)))
            scan["updated_at_ms"] = int(time.time() * 1000)
            self._commit()
            return json.loads(json.dumps(scan))

    # -- operators, sessions, approvals (Phase 10) ---------------------------

    def _save_credentials(self) -> None:
        self.credentials_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.credentials_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._credentials, separators=(",", ":")), encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.credentials_path)

    def add_operator(self, operator: dict, salt_hex: str, password_hash_hex: str) -> dict:
        """`operator` is the public record (id/username/display_name/role/disabled/
        created_at_ms) -- it goes into self.data and is returned by snapshot() like
        everything else. The credential pair never does; it's looked up separately by
        get_credentials, only ever called from the login path.
        """
        with self.lock:
            self.data["operators"].append(json.loads(json.dumps(operator)))
            self._credentials[operator["id"]] = {"salt": salt_hex, "password_hash": password_hash_hex}
            self._save_credentials()
            self._append_audit("operator.created", "", operator["id"], operator["role"])
            self._commit()
            return json.loads(json.dumps(operator))

    def get_credentials(self, operator_id: str) -> dict | None:
        return self._credentials.get(operator_id)

    def add_session(self, session: dict) -> dict:
        with self.lock:
            now = int(time.time() * 1000)
            self._sessions = {key: value for key, value in self._sessions.items()
                              if value.get("expires_at_ms", 0) > now}
            self._sessions[session["id"]] = json.loads(json.dumps(session))
            return json.loads(json.dumps(session))

    def delete_session(self, session_id: str) -> None:
        with self.lock:
            self._sessions.pop(session_id, None)

    def get_session(self, session_id: str) -> dict | None:
        with self.lock:
            session = self._sessions.get(session_id)
            return json.loads(json.dumps(session)) if session is not None else None

    def add_approval(self, approval: dict) -> dict:
        with self.lock:
            self.data["approvals"].append(json.loads(json.dumps(approval)))
            self._append_audit("approval.requested", "", approval["id"], approval["action_type"])
            self._commit()
            return json.loads(json.dumps(approval))

    def update_approval(self, approval_id: str, update: dict) -> dict:
        with self.lock:
            approval = next((item for item in self.data["approvals"] if item.get("id") == approval_id), None)
            if approval is None:
                raise KeyError(approval_id)
            approval.update(json.loads(json.dumps(update)))
            self._append_audit("approval.decided", "", approval_id, approval["status"])
            self._commit()
            return json.loads(json.dumps(approval))

    def add_audit_event(self, event: dict) -> dict:
        with self.lock:
            record = self._append_audit(str(event.get("action", "event")),
                                        str(event.get("project_id", "")),
                                        str(event.get("subject_id", "")),
                                        str(event.get("outcome", "accepted")),
                                        str(event.get("trace_id", "")))
            record.update({key: value for key, value in event.items() if key not in record})
            self._commit()
            return json.loads(json.dumps(record))

    MAX_AUDIT_PAGE = 500

    def list_audit_events(self, project_id: str = "", cursor: str = "", limit: int = 100) -> dict:
        """Return audit events newest-first, paginated by a stable event-id cursor.

        An offset-based cursor would shift under concurrent appends (new
        records only ever land at the newest end); anchoring the cursor to a
        specific event id keeps a page's continuation point stable even while
        other audit events are appended between calls. An unknown cursor
        (e.g. it named an event since pruned) is treated as "no more pages"
        rather than raising, so callers mid-pagination fail closed instead of
        erroring.
        """
        with self.lock:
            events = [item for item in self.data["audit_events"]
                      if not project_id or item.get("project_id") == project_id]
        bounded_limit = max(1, min(int(limit), self.MAX_AUDIT_PAGE))
        ordered = list(reversed(events))
        start = 0
        if cursor:
            start = next((index + 1 for index, item in enumerate(ordered)
                         if item.get("id") == cursor), len(ordered))
        page = ordered[start:start + bounded_limit]
        end = start + len(page)
        next_cursor = page[-1]["id"] if page and end < len(ordered) else ""
        return {"events": json.loads(json.dumps(page)), "next_cursor": next_cursor,
                "count": len(page), "total": len(ordered)}

    def prune_audit_events(self, max_age_ms: int | None = None, max_count: int | None = None) -> dict:
        """Operator-triggered audit retention: remove old/excess records and log the action.

        Retention is deliberately not automatic (not run from `_commit()`) so
        audit history is never silently thinned in the background; an
        operator must explicitly request a bound, and the prune itself is
        recorded as its own audit event (including how many records were
        removed and the policy applied) so the retention action is itself
        auditable.
        """
        if max_age_ms is None and max_count is None:
            raise ValueError("at least one retention bound (max_age_ms or max_count) is required")
        if max_age_ms is not None and max_age_ms < 0:
            raise ValueError("max_age_ms must not be negative")
        if max_count is not None and max_count < 0:
            raise ValueError("max_count must not be negative")
        with self.lock:
            events = self.data["audit_events"]
            before = len(events)
            kept = events
            if max_age_ms is not None:
                cutoff = int(time.time() * 1000) - max_age_ms
                kept = [item for item in kept if item.get("created_at_ms", 0) >= cutoff]
            if max_count is not None and len(kept) > max_count:
                kept = kept[-max_count:]
            removed = before - len(kept)
            self.data["audit_events"] = kept
            record = self.add_audit_event({
                "action": "audit.pruned", "project_id": "", "subject_id": "",
                "outcome": "pruned", "removed_count": removed,
                "retention_policy": {"max_age_ms": max_age_ms, "max_count": max_count},
            })
            return {"removed_count": removed, "remaining_count": len(self.data["audit_events"]),
                    "retention_policy": {"max_age_ms": max_age_ms, "max_count": max_count},
                    "audit_event": record}

    def audit_bundle(self, project_id: str = "") -> dict:
        with self.lock:
            records = [item for item in self.snapshot()["audit_events"]
                      if not project_id or item.get("project_id") == project_id]
        manifest = {"schema": "reconclave-audit-bundle/v1", "project_id": project_id,
                    "exported_at_ms": int(time.time() * 1000), "records": records}
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        manifest["bundle_sha256"] = digest
        manifest["bundle_tag"] = hmac.new(self.custody_key, digest.encode(), hashlib.sha256).hexdigest()
        return manifest

    def acquire_dispatch_lease(self, scope: dict, capability: str, destination: str,
                               expires_at_ms: int) -> dict:
        with self.lock:
            now = int(time.time() * 1000)
            self.data["dispatch_leases"] = [item for item in self.data["dispatch_leases"]
                                            if item.get("expires_at_ms", 0) > now]
            active = [item for item in self.data["dispatch_leases"]
                      if item.get("scope_id") == scope["id"] and item.get("active")]
            recent = [item for item in self.data["dispatch_leases"]
                      if item.get("scope_id") == scope["id"] and item.get("created_at_ms", 0) > now - 60000]
            if len(active) >= scope["max_concurrency"]:
                raise PermissionError("engagement scope concurrency limit reached")
            if len(recent) >= scope["max_requests_per_minute"]:
                raise PermissionError("engagement scope request-rate limit reached")
            lease = {"id": f"lease-{uuid.uuid4().hex[:16]}", "scope_id": scope["id"],
                     "capability": capability, "destination_node": destination,
                     "created_at_ms": now, "expires_at_ms": expires_at_ms, "active": True}
            self.data["dispatch_leases"].append(lease)
            self._commit()
            return json.loads(json.dumps(lease))

    def release_dispatch_lease(self, lease_id: str) -> None:
        with self.lock:
            lease = next((item for item in self.data["dispatch_leases"] if item.get("id") == lease_id), None)
            if lease is not None and lease.get("active"):
                lease["active"] = False
                lease["released_at_ms"] = int(time.time() * 1000)
                self._commit()

    # Fields an operator (or a correlation pass) controls directly and that a
    # later re-import of the *same* finding identity (same plugin/target/port)
    # must never silently clobber back to defaults - matching the design doc's
    # "findings are never silently discarded, only reclassified" principle.
    _FINDING_OPERATOR_FIELDS = ("status", "status_updated_ms", "suppressed",
                                "suppression_reason", "suppressed_at_ms", "remediation")

    def upsert_findings(self, project_id: str, findings: list[dict]) -> list[dict]:
        with self.lock:
            if not any(item.get("id") == project_id for item in self.data["projects"]):
                raise ValueError("project does not exist")
            saved = []
            now = int(time.time() * 1000)
            for finding in findings:
                existing = next((item for item in self.data["findings"] if item.get("id") == finding["id"]), None)
                if existing is None:
                    record = {**finding, "first_seen_ms": now, "last_seen_ms": now}
                    self.data["findings"].append(record)
                    saved.append(json.loads(json.dumps(record)))
                    continue
                preserved = {key: existing[key] for key in self._FINDING_OPERATOR_FIELDS if key in existing}
                existing.update({**finding, **preserved, "last_seen_ms": now})
                saved.append(json.loads(json.dumps(existing)))
            self._commit()
            return saved

    def set_finding_status(self, finding_id: str, new_status: str, note: str = "") -> dict:
        """Operator (or correlation-pass) driven validation-state transition.

        Idempotent no-op when already at ``new_status``; otherwise the
        transition must appear in ``ALLOWED_STATUS_TRANSITIONS`` or this raises
        ``ValueError`` - matching this codebase's other explicit-allowlist
        validation (e.g. ``create_automation``'s condition/playbook checks).
        Every real transition is its own audit event recording old -> new.
        """
        with self.lock:
            finding = next((item for item in self.data["findings"] if item.get("id") == finding_id), None)
            if finding is None:
                raise KeyError(finding_id)
            self._transition_finding_status_locked(finding, new_status, note)
            self._commit()
            return json.loads(json.dumps(finding))

    def _transition_finding_status_locked(self, finding: dict, new_status: str, note: str = "") -> bool:
        """Returns True if a transition actually happened (and was audited),
        False for an already-there no-op. Raises ValueError for a disallowed
        transition - callers that want to treat that as "skip, don't override
        the operator" (e.g. correlation) must catch it themselves."""
        old_status = str(finding.get("status", "open"))
        new_status = str(new_status)
        if new_status == old_status:
            return False
        if new_status not in ALLOWED_STATUS_TRANSITIONS.get(old_status, set()):
            raise ValueError(f"cannot transition finding status from {old_status!r} to {new_status!r}")
        finding["status"] = new_status
        finding["status_updated_ms"] = int(time.time() * 1000)
        record = self._append_audit("finding.status", finding.get("project_id", ""),
                                    finding.get("id", ""), new_status, "")
        record.update({"old_status": old_status, "new_status": new_status, "note": str(note)[:300]})
        return True

    def set_finding_suppression(self, finding_id: str, suppressed: bool, reason: str = "") -> dict:
        """Suppress/unsuppress a finding.

        Suppressed findings stay in the ledger (never deleted) - they are only
        excluded from "active" counts and report highlights, matching the
        design doc's "evidence/findings are never silently discarded, only
        reclassified" principle.
        """
        with self.lock:
            finding = next((item for item in self.data["findings"] if item.get("id") == finding_id), None)
            if finding is None:
                raise KeyError(finding_id)
            suppressed = bool(suppressed)
            finding["suppressed"] = suppressed
            finding["suppression_reason"] = str(reason)[:500] if suppressed else ""
            finding["suppressed_at_ms"] = int(time.time() * 1000) if suppressed else 0
            self._append_audit("finding.suppressed" if suppressed else "finding.unsuppressed",
                               finding.get("project_id", ""), finding_id, "accepted", "")
            self._commit()
            return json.loads(json.dumps(finding))

    def set_finding_remediation(self, finding_id: str, body: dict) -> dict:
        with self.lock:
            finding = next((item for item in self.data["findings"] if item.get("id") == finding_id), None)
            if finding is None:
                raise KeyError(finding_id)
            status = str(body.get("status", "open"))
            if status not in REMEDIATION_STATUSES:
                raise ValueError("unsupported remediation status")
            due_at_ms = body.get("due_at_ms")
            if due_at_ms is not None:
                due_at_ms = int(due_at_ms)
                if due_at_ms < 0:
                    raise ValueError("remediation due_at_ms must not be negative")
            finding["remediation"] = {"owner": str(body.get("owner", ""))[:120],
                                      "due_at_ms": due_at_ms or 0,
                                      "notes": str(body.get("notes", ""))[:1000],
                                      "status": status}
            self._append_audit("finding.remediation", finding.get("project_id", ""), finding_id, status, "")
            self._commit()
            return json.loads(json.dumps(finding))

    def correlate_findings(self, project_id: str, evidence_ids: list[str] | None = None) -> dict:
        """Deterministically correlate a project's live evidence against its
        already-imported findings (see ``vulnerability_analysis.correlate_observations``
        for the actual matching logic and its stated precision limits).

        An explicit, operator/coordinator-triggered pass rather than an eager
        per-job hook: evidence-producing paths in this codebase are numerous
        (automation snapshots, outbox sync, TCP inspection, workflow steps,
        direct tool-runner invocations) and touching every one of them to fire
        correlation inline would spread this feature thin across files this
        task should not otherwise touch. A single explicit trigger point - here,
        or a scheduled call to it - keeps correlation auditable as its own
        distinct action and keeps the "candidate, not confirmed" result exactly
        as reviewable as any other operator-initiated analysis step.

        Exact target+port matches against host-bound findings attempt a status
        transition to "confirmed-observed" (skipped, not erroring, when the
        finding already carries an operator disposition or a later status -
        this never overrides an operator's own judgement or downgrades a
        suppression). Template matches produce new "candidate" findings that
        never duplicate an already-produced candidate for the same evidence.
        """
        with self.lock:
            if not any(item.get("id") == project_id for item in self.data["projects"]):
                raise ValueError("project does not exist")
            findings = self.data["findings"]
            evidence_records = [item for item in self.data["evidence"] if item.get("project_id") == project_id]
            if evidence_ids is not None:
                wanted = set(evidence_ids)
                evidence_records = [item for item in evidence_records if item.get("id") in wanted]
            now = int(time.time() * 1000)
            confirmed_finding_ids: list[str] = []
            new_candidates: list[dict] = []
            for evidence in evidence_records:
                outcome = correlate_observations(project_id, evidence.get("id", ""),
                                                 evidence.get("job_id", ""), evidence.get("data", {}), findings)
                for confirmation in outcome["confirmations"]:
                    finding = next((item for item in findings if item.get("id") == confirmation["finding_id"]), None)
                    if finding is None or finding.get("suppressed"):
                        continue
                    try:
                        transitioned = self._transition_finding_status_locked(
                            finding, "confirmed-observed",
                            note=(f"live observation in evidence {confirmation['evidence_id']} "
                                  f"matched target+port exactly"))
                    except ValueError:
                        continue  # finding already carries an operator disposition past this point
                    if transitioned:
                        confirmed_finding_ids.append(finding["id"])
                for candidate in outcome["candidates"]:
                    if any(item.get("id") == candidate["id"] for item in findings):
                        continue  # this exact candidate was already produced by an earlier pass
                    record = {**candidate, "first_seen_ms": now, "last_seen_ms": now}
                    findings.append(record)
                    new_candidates.append(json.loads(json.dumps(record)))
            if confirmed_finding_ids or new_candidates:
                record = self._append_audit("findings.correlated", project_id, "", "accepted", "")
                record.update({"confirmed_count": len(confirmed_finding_ids),
                              "new_candidate_count": len(new_candidates)})
            self._commit()
            return {"confirmed_finding_ids": confirmed_finding_ids,
                    "confirmed_count": len(confirmed_finding_ids),
                    "new_candidates": new_candidates, "new_candidate_count": len(new_candidates)}

    def findings_bundle(self, project_id: str = "") -> dict:
        """Signed export mirroring ``evidence_bundle``/``audit_bundle``'s exact
        shape and signing approach (canonical sort-keys JSON digest, HMAC-SHA256
        with the custody key), so a consumer of any of the three bundle types
        can verify them the same way.
        """
        with self.lock:
            records = [item for item in self.snapshot()["findings"]
                      if not project_id or item.get("project_id") == project_id]
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        suppressed_count = 0
        for item in records:
            by_severity[item.get("severity", "unknown")] = by_severity.get(item.get("severity", "unknown"), 0) + 1
            by_status[item.get("status", "open")] = by_status.get(item.get("status", "open"), 0) + 1
            if item.get("suppressed"):
                suppressed_count += 1
        active_count = sum(1 for item in records
                           if not item.get("suppressed") and item.get("status") != "false_positive")
        manifest = {"schema": "reconclave-findings-bundle/v1", "project_id": project_id,
                    "exported_at_ms": int(time.time() * 1000),
                    "summary": {"total": len(records), "active": active_count,
                                "suppressed": suppressed_count,
                                "by_severity": by_severity, "by_status": by_status},
                    "records": records}
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        manifest["bundle_sha256"] = digest
        manifest["bundle_tag"] = hmac.new(self.custody_key, digest.encode(), hashlib.sha256).hexdigest()
        return manifest

    def update_fleet(self, nodes: list[dict]) -> None:
        with self.lock:
            self.data["fleet_nodes"] = json.loads(json.dumps(nodes))
            self._commit()

    def set_fleet_config(self, config: dict) -> dict:
        with self.lock:
            existing = next((item for item in self.data["fleet_configs"]
                             if item.get("device_type") == config["device_type"]), None)
            if existing is None:
                self.data["fleet_configs"].append(config)
                existing = config
            else:
                existing.update(config)
            self._append_audit("fleet.config", "", config["device_type"], "updated")
            self._commit()
            return json.loads(json.dumps(existing))

    def add_ota_release(self, release: dict) -> dict:
        with self.lock:
            self.data["ota_releases"].append(json.loads(json.dumps(release)))
            self._append_audit("fleet.release", "", release["id"], "signed")
            self._commit()
            return json.loads(json.dumps(release))

    def _ota_artifact_path(self, artifact_sha256: str) -> pathlib.Path:
        # Raw firmware bytes live as sibling files, not inside the JSON document itself --
        # the workspace snapshot is a single JSON blob rewritten in full on every commit,
        # and a multi-hundred-KB-to-multi-MB image (base64-inflated in JSON) has no
        # business being reserialised on every unrelated write. Filename is the artifact's
        # own claimed identity, already validated as 64 lowercase hex by FleetManager.
        if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
            raise ValueError("artifact_sha256 must be 64 lowercase hex characters")
        return self.path.parent / "ota_artifacts" / f"{artifact_sha256}.bin"

    def store_ota_artifact(self, artifact_sha256: str, data: bytes) -> None:
        """Persists a release's firmware bytes, keyed by their own claimed SHA-256.

        Rejects a mismatch between the claimed digest and the bytes actually supplied --
        this is the one place that ever needs to check that, since every later read (a
        rollout advancing, a rollback) trusts the filename it already validated here.
        """
        if hashlib.sha256(data).hexdigest() != artifact_sha256:
            raise ValueError("artifact bytes do not match the claimed artifact_sha256")
        with self.lock:
            destination = self._ota_artifact_path(artifact_sha256)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary = destination.with_suffix(".tmp")
            temporary.write_bytes(data)
            temporary.chmod(0o600)
            os.replace(temporary, destination)

    def read_ota_artifact(self, artifact_sha256: str) -> bytes | None:
        path = self._ota_artifact_path(artifact_sha256)
        if not path.is_file():
            return None
        return path.read_bytes()

    def add_ota_rollout(self, rollout: dict) -> dict:
        with self.lock:
            self.data["ota_rollouts"].append(json.loads(json.dumps(rollout)))
            self._append_audit("fleet.rollout", "", rollout["id"], rollout["status"])
            self._commit()
            return json.loads(json.dumps(rollout))

    def update_ota_rollout(self, rollout_id: str, update: dict) -> dict:
        with self.lock:
            rollout = next((item for item in self.data["ota_rollouts"] if item.get("id") == rollout_id), None)
            if rollout is None:
                raise KeyError(rollout_id)
            rollout.update(json.loads(json.dumps(update)))
            rollout["updated_at_ms"] = int(time.time() * 1000)
            self._append_audit("fleet.rollout", "", rollout_id, rollout["status"])
            self._commit()
            return json.loads(json.dumps(rollout))

    def create_workflow_run(self, workflow_id: str, scope_id: str = "") -> dict:
        with self.lock:
            workflow = next((item for item in self.data["workflows"]
                             if item.get("id") == workflow_id), None)
            if workflow is None:
                raise KeyError(workflow_id)
            now = int(time.time() * 1000)
            run = {"id": f"run-{uuid.uuid4().hex[:16]}", "workflow_id": workflow_id,
                   "project_id": workflow["project_id"], "status": "queued",
                   "trace_id": f"trace-{uuid.uuid4().hex[:16]}",
                   "scope_id": scope_id,
                   "created_at_ms": now, "updated_at_ms": now,
                   "steps": [{"id": step["id"], "status": "pending", "attempts": 0,
                              "node_id": "", "result": None, "error": "",
                              "started_at_ms": 0}
                             for step in workflow["steps"]]}
            self.data["workflow_runs"].append(run)
            self._append_audit("workflow.queued", workflow["project_id"], run["id"], "queued")
            self._commit()
            return json.loads(json.dumps(run))

    def update_workflow_run(self, run_id: str, update: dict) -> dict:
        with self.lock:
            run = next((item for item in self.data["workflow_runs"]
                        if item.get("id") == run_id), None)
            if run is None:
                raise KeyError(run_id)
            if "status" in update:
                status = str(update["status"])
                if status not in ("queued", "running", "complete", "failed", "cancelled"):
                    raise ValueError("invalid workflow run status")
                run["status"] = status
            if "steps" in update:
                if not isinstance(update["steps"], list):
                    raise ValueError("workflow run steps must be a list")
                run["steps"] = json.loads(json.dumps(update["steps"]))
            run["updated_at_ms"] = int(time.time() * 1000)
            if update.get("status"):
                self._append_audit("workflow.status", run["project_id"], run_id,
                                   str(update["status"]), run.get("trace_id", ""))
            self._commit()
            return json.loads(json.dumps(run))
