"""Local operator accounts, sessions, and role-gated maker-checker approvals.

Phase 10 (docs/platform-roadmap.md): "starts with local accounts; external OIDC is a
later addition, not a first-release requirement" and must "preserve a simple
single-operator mode now" -- both honoured here by making every rule conditional on
whether any operator account actually exists yet. With zero operators, nothing in this
module is reachable and the platform behaves exactly as it always has (every action
attributed to the implicit "local-operator", no login). The moment the first operator is
created it becomes the sole admin, and from then on real accounts, roles, and (for the
two action types registered so far) two-person approval apply.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
import uuid

ROLES = ("admin", "operator", "viewer")
SESSION_LIFETIME_MS = 12 * 60 * 60 * 1000  # 12 hours
PBKDF2_ITERATIONS = 200_000
USERNAME_PATTERN = re.compile(r"[a-z0-9._-]{3,32}")


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, password_hash_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    _, computed = hash_password(password, salt)
    return hmac.compare_digest(computed, password_hash_hex)


def public_operator(operator: dict) -> dict:
    return {"id": operator["id"], "username": operator["username"],
           "display_name": operator["display_name"], "role": operator["role"],
           "disabled": bool(operator.get("disabled", False))}


class OperatorManager:
    def __init__(self, workspace) -> None:
        self.workspace = workspace

    def count(self) -> int:
        return len(self.workspace.snapshot()["operators"])

    def create_operator(self, body: dict, actor: dict | None) -> dict:
        operators = self.workspace.snapshot()["operators"]
        # Bootstrap: with no operators yet, anyone on this loopback-only machine can
        # create the first one, who becomes admin -- this is the single-operator-to-
        # multi-operator transition, not an open door (once it exists, every subsequent
        # create requires an authenticated admin).
        if operators and (actor is None or actor.get("role") != "admin"):
            raise PermissionError("only an admin operator may create new operators")
        username = str(body.get("username", "")).strip().lower()
        display_name = str(body.get("display_name", username)).strip()[:80] or username
        role = str(body.get("role", "operator")).strip()
        password = str(body.get("password", ""))
        if not USERNAME_PATTERN.fullmatch(username):
            raise ValueError("username must be 3-32 characters: lowercase letters, digits, . _ -")
        if any(item["username"] == username for item in operators):
            raise ValueError("username already exists")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        if len(password) < 10:
            raise ValueError("password must be at least 10 characters")
        salt_hex, password_hash_hex = hash_password(password)
        operator = {"id": f"op-{uuid.uuid4().hex[:12]}", "username": username,
                   "display_name": display_name,
                   "role": role if operators else "admin",  # the first operator is always admin
                   "disabled": False, "created_at_ms": int(time.time() * 1000)}
        return self.workspace.add_operator(operator, salt_hex, password_hash_hex)

    def login(self, username: str, password: str) -> dict:
        username = str(username).strip().lower()
        operator = next((item for item in self.workspace.snapshot()["operators"]
                         if item["username"] == username), None)
        credentials = self.workspace.get_credentials(operator["id"]) if operator else None
        # Runs verify_password even when the username doesn't exist (against a fixed
        # dummy hash) so a login attempt takes roughly the same time either way, rather
        # than letting response latency confirm which usernames are registered.
        if credentials is None:
            verify_password(str(password), *hash_password(""))
            raise PermissionError("invalid username or password")
        if operator.get("disabled") or not verify_password(str(password), credentials["salt"],
                                                            credentials["password_hash"]):
            raise PermissionError("invalid username or password")
        now = int(time.time() * 1000)
        session = {"id": uuid.uuid4().hex, "operator_id": operator["id"],
                  "created_at_ms": now, "expires_at_ms": now + SESSION_LIFETIME_MS}
        self.workspace.add_session(session)
        return {"token": session["id"], "operator": public_operator(operator)}

    def logout(self, token: str) -> None:
        self.workspace.delete_session(token)

    def resolve_session(self, token: str) -> dict | None:
        if not token:
            return None
        session = self.workspace.get_session(token)
        if session is None or session.get("expires_at_ms", 0) <= int(time.time() * 1000):
            return None
        operator = next((item for item in self.workspace.snapshot()["operators"]
                         if item.get("id") == session.get("operator_id")), None)
        if operator is None or operator.get("disabled"):
            return None
        return public_operator(operator)


class ApprovalManager:
    """Two-person control for a small, explicit set of high-consequence action types.

    `executors` maps an action_type to the callable that actually performs it
    (EngagementPolicy.create_scope, FleetManager.create_release, ...) -- approving a
    request just calls the same code path a direct, single-operator-mode call would.
    Only a role of "operator" or "admin" may request; only "admin" may decide, and never
    their own request (the maker-checker property this whole module exists for).
    """

    def __init__(self, workspace, executors: dict) -> None:
        self.workspace = workspace
        self.executors = executors

    def request(self, action_type: str, payload: dict, requested_by: dict) -> dict:
        if action_type not in self.executors:
            raise ValueError(f"unknown approval action type: {action_type}")
        if requested_by["role"] not in ("operator", "admin"):
            raise PermissionError("viewers may not request an approval")
        approval = {"id": f"appr-{uuid.uuid4().hex[:12]}", "action_type": action_type,
                   "payload": payload, "requested_by": requested_by["id"],
                   "requested_by_username": requested_by["username"],
                   "status": "pending", "decided_by": "", "decided_by_username": "",
                   "decided_at_ms": 0, "result": None, "error": "",
                   "created_at_ms": int(time.time() * 1000)}
        return self.workspace.add_approval(approval)

    def decide(self, approval_id: str, decision: str, decided_by: dict) -> dict:
        if decision not in ("approved", "rejected"):
            raise ValueError("decision must be 'approved' or 'rejected'")
        if decided_by["role"] != "admin":
            raise PermissionError("only an admin operator may decide an approval")
        approval = next((item for item in self.workspace.snapshot()["approvals"]
                         if item["id"] == approval_id), None)
        if approval is None:
            raise KeyError(approval_id)
        if approval["status"] != "pending":
            raise ValueError("this approval has already been decided")
        if decided_by["id"] == approval["requested_by"]:
            raise PermissionError("an operator cannot approve their own request")
        update = {"status": decision, "decided_by": decided_by["id"],
                 "decided_by_username": decided_by["username"],
                 "decided_at_ms": int(time.time() * 1000)}
        if decision == "approved":
            try:
                update["result"] = self.executors[approval["action_type"]](approval["payload"])
            except Exception as error:
                update["status"] = "failed"
                update["error"] = str(error)[:300]
        return self.workspace.update_approval(approval_id, update)
