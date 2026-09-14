"""Immutable signed engagement scopes and dispatch-time policy enforcement."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import pathlib
import time
import uuid


TARGET_CAPABILITIES = {"net.discovery.scan", "net.tcp.inspect"}
TARGET_PREFIXES = ("web.", "tls.", "dns.", "vuln.", "capture.", "tool.")
ALLOWED_CLASSES = {"inventory", "discovery", "vulnerability", "capture"}

# A standing grant is a *duration*, not an absolute expiry: it is minted once at
# provisioning time for a device that may run with no live coordinator (and, on an
# ESP32 target, no wall clock at all) to check back in against afterward. The
# device tracks its own elapsed "armed" time locally and compares it against this
# ceiling - see verify_standing_grant below and reconclave_node.py's ArmedClock.
STANDING_GRANT_MAX_DURATION_MS = 7 * 86400000


class EngagementPolicy:
    def __init__(self, workspace, key_path: pathlib.Path, delegation_key: bytes | None = None) -> None:
        self.workspace = workspace
        self.key_path = key_path
        self.delegation_key = delegation_key
        key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if key_path.exists():
            self.key = key_path.read_bytes()
            if len(self.key) != 32:
                raise ValueError("scope signing key must contain exactly 32 bytes")
        else:
            self.key = os.urandom(32)
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(self.key)

    @staticmethod
    def _canonical(value: dict) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def _signature(self, value: dict) -> str:
        return hmac.new(self.key, self._canonical(value), hashlib.sha256).hexdigest()

    def create_scope(self, body: dict) -> dict:
        now = int(time.time() * 1000)
        expires_at = int(body.get("expires_at_ms", 0))
        if not now < expires_at <= now + 31 * 86400000:
            raise ValueError("scope expiry must be within the next 31 days")
        included = self._networks(body.get("included_networks", []), "included_networks", False)
        excluded = self._networks(body.get("excluded_networks", []), "excluded_networks", True)
        classes = sorted(set(map(str, body.get("capability_classes", []))))
        if not classes or not set(classes) <= ALLOWED_CLASSES:
            raise ValueError("scope capability_classes are invalid")
        project_id = str(body.get("project_id", ""))
        revisions = [item for item in self.workspace.snapshot().get("scopes", [])
                     if item.get("project_id") == project_id]
        scope = {"id": f"scope-{uuid.uuid4().hex[:16]}", "project_id": project_id,
                 "revision": max([item.get("revision", 0) for item in revisions] or [0]) + 1,
                 "included_networks": included, "excluded_networks": excluded,
                 "capability_classes": classes, "expires_at_ms": expires_at,
                 "max_concurrency": min(max(int(body.get("max_concurrency", 2)), 1), 16),
                 "max_requests_per_minute": min(max(int(body.get("max_requests_per_minute", 60)), 1), 600),
                 "approved_by": str(body.get("approved_by", "local-operator"))[:80],
                 "created_at_ms": now}
        scope["signature"] = self._signature(scope)
        saved = self.workspace.add_scope(scope)
        self.workspace.add_audit_event({"project_id": project_id, "action": "scope.created",
                                        "subject_id": scope["id"], "outcome": "approved"})
        return saved

    @staticmethod
    def _networks(values: object, field: str, allow_empty: bool) -> list[str]:
        if not isinstance(values, list) or (not allow_empty and not values) or len(values) > 64:
            raise ValueError(f"{field} must be a bounded list")
        networks = []
        for value in values:
            network = ipaddress.ip_network(str(value), strict=True)
            if network.version != 4:
                raise ValueError("only IPv4 engagement scopes are currently supported")
            networks.append(str(network))
        return sorted(set(networks))

    def get_valid(self, scope_id: str, project_id: str) -> dict:
        scope = next((item for item in self.workspace.snapshot().get("scopes", [])
                      if item.get("id") == scope_id and item.get("project_id") == project_id), None)
        if scope is None:
            raise PermissionError("a matching engagement scope is required")
        signature = scope.get("signature", "")
        unsigned = {key: value for key, value in scope.items() if key != "signature"}
        if not hmac.compare_digest(signature, self._signature(unsigned)):
            raise PermissionError("engagement scope signature is invalid")
        if int(scope["expires_at_ms"]) <= int(time.time() * 1000):
            raise PermissionError("engagement scope has expired")
        return scope

    def authorize(self, scope_id: str, project_id: str, capability: str, arguments: dict) -> dict:
        if capability not in TARGET_CAPABILITIES and not capability.startswith(TARGET_PREFIXES):
            return {}
        scope = self.get_valid(scope_id, project_id)
        capability_class = "vulnerability" if capability.startswith("vuln.") else "capture" if capability.startswith("capture.") else "discovery"
        if capability_class not in scope["capability_classes"]:
            raise PermissionError(f"scope does not approve {capability_class} operations")
        raw_targets = [arguments.get(key) for key in ("network", "target", "host")]
        raw_targets += arguments.get("hosts", []) if isinstance(arguments.get("hosts"), list) else []
        targets = [value for value in raw_targets if value]
        if not targets:
            raise PermissionError("target-bearing capability requires explicit targets")
        includes = [ipaddress.ip_network(value) for value in scope["included_networks"]]
        excludes = [ipaddress.ip_network(value) for value in scope["excluded_networks"]]
        for raw in targets:
            target = ipaddress.ip_network(str(raw), strict=False)
            if not any(target.subnet_of(network) for network in includes) or any(target.overlaps(network) for network in excludes):
                raise PermissionError(f"target {raw} is outside the approved scope")
        return scope

    def delegate(self, scope_id: str, project_id: str, capability: str,
                 arguments: dict, destination_node: str) -> dict:
        scope = self.authorize(scope_id, project_id, capability, arguments)
        if not scope:
            return dict(arguments)
        if self.delegation_key is None:
            raise PermissionError("scope delegation key is not configured")
        now = int(time.time() * 1000)
        expires_at_ms = min(scope["expires_at_ms"], now + 300000)
        lease = self.workspace.acquire_dispatch_lease(scope, capability, destination_node,
                                                      expires_at_ms)
        token = {"scope_id": scope["id"], "project_id": project_id,
                 "capability": capability, "destination_node": destination_node,
                 "included_networks": scope["included_networks"],
                 "excluded_networks": scope["excluded_networks"],
                 "capability_classes": scope["capability_classes"],
                 "arguments_digest": hashlib.sha256(self._canonical(arguments)).hexdigest(),
                 "lease_id": lease["id"], "issued_at_ms": now, "expires_at_ms": expires_at_ms,
                 "nonce": uuid.uuid4().hex}
        token["tag"] = hmac.new(self.delegation_key, self._canonical(token), hashlib.sha256).hexdigest()
        return {**arguments, "_scope_delegation": token}

    def release(self, delegated_arguments: dict) -> None:
        token = delegated_arguments.get("_scope_delegation", {})
        if isinstance(token, dict):
            self.workspace.release_dispatch_lease(str(token.get("lease_id", "")))

    # ------------------------------------------------------------------
    # Standing scope grants: offline authorization for a device that may run
    # with no live coordinator to sign a per-request delegation against (see
    # delegate() above, which is dispatch-time and caps at five minutes). A
    # standing grant is minted once - typically at provisioning - and verified
    # locally by the device itself for as long as its own elapsed-time
    # bookkeeping says it remains within duration_ms. It is not, by itself, a
    # capability grant: nothing in this codebase yet calls verify_standing_grant
    # from a capability handler. It exists so that a future local automation
    # engine (docs/platform-roadmap.md's deferred "local automation engine"
    # phase) has a signed, bounded, self-contained authorization primitive to
    # check against.
    # ------------------------------------------------------------------

    def mint_standing_grant(self, scope_id: str, project_id: str, capability_classes: list[str],
                            duration_ms: int, destination_node: str) -> dict:
        scope = self.get_valid(scope_id, project_id)
        if self.delegation_key is None:
            raise PermissionError("scope delegation key is not configured")
        classes = sorted(set(map(str, capability_classes)))
        if not classes or not set(classes) <= set(scope["capability_classes"]):
            raise PermissionError("standing grant capability_classes exceed the scope's own approval")
        now = int(time.time() * 1000)
        # Never outlives the scope it was minted from, even though nothing will be
        # there to re-check that scope once the device goes offline - an offline
        # grant derived from a scope that itself expires sooner has no business
        # outliving it.
        ceiling = min(int(duration_ms), STANDING_GRANT_MAX_DURATION_MS, scope["expires_at_ms"] - now)
        if ceiling <= 0:
            raise PermissionError("standing grant duration must be positive and within scope validity")
        grant = {"grant_id": f"grant-{uuid.uuid4().hex[:16]}", "scope_id": scope["id"],
                 "project_id": project_id, "destination_node": destination_node,
                 "included_networks": scope["included_networks"],
                 "excluded_networks": scope["excluded_networks"],
                 "capability_classes": classes, "duration_ms": ceiling,
                 "minted_at_ms": now, "nonce": uuid.uuid4().hex}
        # Full, untruncated hex digest - the same convention docs/capabilities.md
        # documents for _scope_delegation tokens, and distinct from the 16-byte
        # truncated tag used for ordinary request/response auth.
        grant["tag"] = hmac.new(self.delegation_key, self._canonical(grant), hashlib.sha256).hexdigest()
        self.workspace.add_audit_event({"project_id": project_id, "action": "standing_grant.minted",
                                        "subject_id": grant["grant_id"], "outcome": destination_node})
        return grant

    @staticmethod
    def verify_standing_grant(delegation_key: bytes | None, grant: dict, capability: str,
                              elapsed_ms: int) -> None:
        """Raises PermissionError on any failure; returns None on success.

        A staticmethod taking the raw key rather than an instance method reading
        self.delegation_key, so a provider with only its shared execution-key
        bytes - not a live EngagementPolicy/WorkspaceStore instance - can verify a
        grant on its own, exactly the way reconclave_node.py's
        Node.verify_scope_delegation independently re-checks a delegated scope
        token's HMAC using only self.execution_key rather than calling back into
        this class.

        Deliberately clock-agnostic: elapsed_ms is supplied by the caller from
        whatever local clock it has (wall-clock time on a Linux companion node
        today; a persisted uptime counter on a future ESP32 port, matching how
        delegated scope tokens are already checked "for internal consistency"
        rather than wall time on ESP32 providers - see docs/capabilities.md's
        "Delegated scope tokens" section). This function never reads the system
        clock itself, so the same logic is reusable everywhere.
        """
        if not isinstance(grant, dict):
            raise PermissionError("a standing grant is required")
        if delegation_key is None:
            raise PermissionError("scope delegation key is not configured")
        unsigned = {key: value for key, value in grant.items() if key != "tag"}
        if not hmac.compare_digest(str(grant.get("tag", "")),
                                   hmac.new(delegation_key, EngagementPolicy._canonical(unsigned), hashlib.sha256).hexdigest()):
            raise PermissionError("standing grant signature is invalid")
        capability_class = ("vulnerability" if capability.startswith("vuln.") else
                            "capture" if capability.startswith("capture.") else "discovery")
        if capability_class not in grant.get("capability_classes", []):
            raise PermissionError(f"standing grant does not cover {capability_class} operations")
        if int(elapsed_ms) > int(grant.get("duration_ms", 0)):
            raise PermissionError("standing grant has expired")
