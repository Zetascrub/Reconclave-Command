"""Fleet inventory, desired-state drift, and signed staged OTA orchestration."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import threading
import time
import uuid

# Real-world firmware images for the two supported ESP32 targets run from a few hundred KB
# (poe-p4, ~557KB at last build) to a couple MB (cardputer-adv, ~1.47MB); this is a generous
# ceiling against accidental or malicious oversized uploads, not a tight fit to either.
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024


SAFE_CONFIG_KEYS = {"labels", "telemetry_interval_seconds", "enabled_capabilities"}


class FleetManager:
    def __init__(self, coordinator, workspace, signing_key: bytes) -> None:
        self.coordinator = coordinator
        self.workspace = workspace
        self.signing_key = signing_key
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="reconclave-fleet", daemon=True)

    def start(self) -> None: self.thread.start()
    def close(self) -> None:
        self.stop_event.set(); self.thread.join(timeout=2)

    def set_config(self, body: dict) -> dict:
        device_type = str(body.get("device_type", "")).strip()
        desired = body.get("desired", {})
        if not device_type or not isinstance(desired, dict) or not set(desired) <= SAFE_CONFIG_KEYS:
            raise ValueError("fleet config contains unsupported fields")
        if "telemetry_interval_seconds" in desired and not 5 <= int(desired["telemetry_interval_seconds"]) <= 3600:
            raise ValueError("telemetry interval must be 5-3600 seconds")
        return self.workspace.set_fleet_config({"device_type": device_type,
                                                "desired": desired,
                                                "updated_at_ms": int(time.time() * 1000)})

    def reconcile_once(self) -> list[dict]:
        snapshot = self.workspace.snapshot()
        configs = {item["device_type"]: item["desired"] for item in snapshot["fleet_configs"]}
        previous = {item["device_id"]: item for item in snapshot["fleet_nodes"]}
        now = int(time.time() * 1000)
        fleet = []
        for node in self.coordinator.state().get("nodes", []):
            desired = configs.get(node.get("device_type"), {})
            actual = {"enabled_capabilities": sorted(node.get("capabilities", []))}
            drift = {key: {"desired": value, "actual": actual.get(key)}
                     for key, value in desired.items() if actual.get(key) != value}
            prior = previous.get(node["device_id"], {})
            fleet.append({"device_id": node["device_id"], "device_type": node.get("device_type", "unknown"),
                          "firmware": node.get("firmware", "unknown"), "status": node.get("status", "unknown"),
                          "address": node.get("address", ""), "capabilities": node.get("capabilities", []),
                          "resources": node.get("resources", {}), "drift": drift,
                          "first_seen_ms": prior.get("first_seen_ms", now), "last_seen_ms": now})
        if fleet != snapshot["fleet_nodes"]:
            self.workspace.update_fleet(fleet)
        return fleet

    def create_release(self, body: dict) -> dict:
        target = str(body.get("device_type", "")).strip()
        version = str(body.get("version", "")).strip()
        sha256 = str(body.get("artifact_sha256", "")).lower()
        if not target or not re.fullmatch(r"[0-9A-Fa-f]{64}", sha256) or not re.fullmatch(r"[0-9A-Za-z._+-]{1,48}", version):
            raise ValueError("release requires device_type, safe version, and artifact SHA-256")
        artifact_b64 = body.get("artifact_base64")
        if not isinstance(artifact_b64, str) or not artifact_b64:
            raise ValueError("release requires the firmware artifact as artifact_base64")
        try:
            artifact = base64.b64decode(artifact_b64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("artifact_base64 is not valid base64") from error
        if not artifact or len(artifact) > MAX_ARTIFACT_BYTES:
            raise ValueError(f"artifact must be non-empty and at most {MAX_ARTIFACT_BYTES} bytes")
        # store_ota_artifact independently re-hashes the decoded bytes and rejects a
        # mismatch, so a bad artifact_sha256 claim is caught here rather than silently
        # accepted and only discovered later when a device's own verification rejects it.
        self.workspace.store_ota_artifact(sha256, artifact)
        release = {"id": f"release-{uuid.uuid4().hex[:16]}", "device_type": target,
                   "version": version, "artifact_sha256": sha256,
                   "created_at_ms": int(time.time() * 1000)}
        canonical = json.dumps(release, sort_keys=True, separators=(",", ":")).encode()
        release["signature"] = hmac.new(self.signing_key, canonical, hashlib.sha256).hexdigest()
        return self.workspace.add_ota_release(release)

    def _apply_release_to_device(self, device_id: str, release: dict) -> dict:
        """Two-phase OTA delivery for one target: arm the device via the ordinary signed
        capability envelope, then stream the artifact over the dedicated upload channel.

        Returns the device's authenticated result dict (containing `artifact_sha256`) on
        success; raises the same exceptions invoke()/upload_artifact() do on failure, which
        advance_rollout/rollback_rollout already catch and record per-target.
        """
        artifact = self.workspace.read_ota_artifact(release["artifact_sha256"])
        if artifact is None:
            raise ValueError("release artifact is not stored on this coordinator")
        upload_token = uuid.uuid4().hex
        arm = self.coordinator.invoke(device_id, "fleet.ota.apply",
                                      {"release": release, "upload_token": upload_token})
        if arm.get("payload", {}).get("status") != "ok":
            error = arm.get("payload", {}).get("error", {})
            raise ValueError(error.get("message", "device did not arm the OTA session"))
        return self.coordinator.upload_artifact(device_id, upload_token, artifact)

    def create_rollout(self, body: dict) -> dict:
        release_id = str(body.get("release_id", ""))
        snapshot = self.workspace.snapshot()
        release = next((item for item in snapshot["ota_releases"] if item["id"] == release_id), None)
        if release is None: raise KeyError(release_id)
        targets = [item["device_id"] for item in snapshot["fleet_nodes"]
                   if item["device_type"] == release["device_type"]]
        batch_size = min(max(int(body.get("batch_size", 1)), 1), 16)
        # The most recent completed/partial rollout for the same device_type names the
        # release every currently-running node most likely still has - that's what a
        # later rollback reverts to. A rollout with nothing to roll back to (first ever
        # release for this device_type) simply carries no previous_release_id.
        prior_rollouts = [item for item in snapshot["ota_rollouts"]
                          if item.get("release_id") != release_id and
                          next((r["device_type"] for r in snapshot["ota_releases"]
                               if r["id"] == item.get("release_id")), None) == release["device_type"] and
                          item.get("status") in ("complete", "partial", "rolled_back")]
        previous_release_id = prior_rollouts[-1]["release_id"] if prior_rollouts else ""
        rollout = {"id": f"rollout-{uuid.uuid4().hex[:16]}", "release_id": release_id,
                   "previous_release_id": previous_release_id,
                   "status": "staged", "batch_size": batch_size, "failure_threshold": .25,
                   "targets": [{"device_id": value, "status": "pending", "error": ""} for value in targets],
                   "created_at_ms": int(time.time() * 1000), "updated_at_ms": int(time.time() * 1000)}
        return self.workspace.add_ota_rollout(rollout)

    def advance_rollout(self, rollout_id: str) -> dict:
        snapshot = self.workspace.snapshot()
        rollout = next((item for item in snapshot["ota_rollouts"] if item["id"] == rollout_id), None)
        if rollout is None: raise KeyError(rollout_id)
        release = next(item for item in snapshot["ota_releases"] if item["id"] == rollout["release_id"])
        nodes = {item["device_id"]: item for item in self.coordinator.state().get("nodes", [])}
        batch = [item for item in rollout["targets"] if item["status"] == "pending"][:rollout["batch_size"]]
        rollout["status"] = "running"
        for target in batch:
            node = nodes.get(target["device_id"])
            if node is None or "fleet.ota.apply" not in node.get("capabilities", []):
                target.update(status="ineligible", error="node lacks signed OTA capability")
                continue
            try:
                result = self._apply_release_to_device(target["device_id"], release)
                verified = result.get("artifact_sha256") == release["artifact_sha256"]
                target.update(status="verified" if verified else "failed",
                              error="" if verified else "verification mismatch")
            except Exception as error: target.update(status="failed", error=str(error)[:200])
        failures = sum(item["status"] == "failed" for item in rollout["targets"])
        attempted = sum(item["status"] in ("verified", "failed") for item in rollout["targets"])
        if attempted and failures / attempted > rollout["failure_threshold"]:
            rollout["status"] = "rollback_required"
        elif not any(item["status"] == "pending" for item in rollout["targets"]):
            rollout["status"] = "complete" if not failures else "partial"
        return self.workspace.update_ota_rollout(rollout_id, rollout)

    def rollback_rollout(self, rollout_id: str) -> dict:
        """Reverts every already-updated target in a rollout to the release it replaced.

        Only meaningful once at least one target reached "verified" (an applied, checksum-
        confirmed update) and the rollout recorded a previous_release_id at creation time
        (the most recent prior completed/partial rollout for the same device_type). A
        target that never got the new release (still "pending"/"ineligible") has nothing
        to roll back - it's simply left alone, still on its original release.
        """
        snapshot = self.workspace.snapshot()
        rollout = next((item for item in snapshot["ota_rollouts"] if item["id"] == rollout_id), None)
        if rollout is None: raise KeyError(rollout_id)
        if not rollout.get("previous_release_id"):
            raise ValueError("no prior release recorded for this rollout to roll back to")
        previous_release = next((item for item in snapshot["ota_releases"]
                                 if item["id"] == rollout["previous_release_id"]), None)
        if previous_release is None: raise KeyError(rollout["previous_release_id"])
        nodes = {item["device_id"]: item for item in self.coordinator.state().get("nodes", [])}
        for target in rollout["targets"]:
            if target["status"] != "verified":
                continue
            node = nodes.get(target["device_id"])
            if node is None or "fleet.ota.apply" not in node.get("capabilities", []):
                target.update(status="rollback_failed", error="node lacks signed OTA capability")
                continue
            try:
                result = self._apply_release_to_device(target["device_id"], previous_release)
                reverted = result.get("artifact_sha256") == previous_release["artifact_sha256"]
                target.update(status="rolled_back" if reverted else "rollback_failed",
                              error="" if reverted else "verification mismatch on rollback")
            except Exception as error:
                target.update(status="rollback_failed", error=str(error)[:200])
        rollout["status"] = ("rolled_back" if not any(item["status"] == "rollback_failed"
                             for item in rollout["targets"]) else "rollback_partial")
        return self.workspace.update_ota_rollout(rollout_id, rollout)

    def _run(self) -> None:
        while not self.stop_event.wait(10):
            try: self.reconcile_once()
            except Exception as error: print(f"[fleet] reconcile error: {error}")
