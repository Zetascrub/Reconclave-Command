import pathlib
import tempfile
import unittest

from operators import ApprovalManager, OperatorManager, hash_password, verify_password
from workspace_store import WorkspaceStore


class PasswordHashingTests(unittest.TestCase):
    def test_round_trip_and_wrong_password_rejection(self):
        salt, digest = hash_password("correct horse battery staple")
        self.assertTrue(verify_password("correct horse battery staple", salt, digest))
        self.assertFalse(verify_password("wrong password", salt, digest))

    def test_malformed_salt_is_rejected_not_raised(self):
        self.assertFalse(verify_password("anything", "not-hex", "0" * 64))


class OperatorManagerTests(unittest.TestCase):
    def make_manager(self, directory):
        store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
        return OperatorManager(store), store

    def test_first_operator_bootstraps_as_admin_with_no_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            operator = manager.create_operator(
                {"username": "alice", "password": "correct horse battery staple", "role": "viewer"},
                actor=None)
            # Requested "viewer" is overridden -- the first operator is always admin.
            self.assertEqual(operator["role"], "admin")
            self.assertNotIn("password_hash", operator)
            self.assertNotIn("salt", operator)

    def test_second_operator_requires_an_authenticated_admin_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            admin = manager.create_operator({"username": "alice", "password": "x" * 12}, actor=None)
            with self.assertRaisesRegex(PermissionError, "admin"):
                manager.create_operator({"username": "bob", "password": "y" * 12}, actor=None)
            non_admin = {"id": "op-x", "username": "carol", "role": "operator"}
            with self.assertRaisesRegex(PermissionError, "admin"):
                manager.create_operator({"username": "bob", "password": "y" * 12}, actor=non_admin)
            created = manager.create_operator({"username": "bob", "password": "y" * 12, "role": "operator"},
                                              actor=admin)
            self.assertEqual(created["role"], "operator")

    def test_rejects_duplicate_username_bad_pattern_short_password_and_bad_role(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            admin = manager.create_operator({"username": "alice", "password": "x" * 12}, actor=None)
            with self.assertRaises(ValueError):
                manager.create_operator({"username": "alice", "password": "y" * 12}, actor=admin)
            with self.assertRaises(ValueError):
                manager.create_operator({"username": "AB", "password": "y" * 12}, actor=admin)
            with self.assertRaises(ValueError):
                manager.create_operator({"username": "short", "password": "tiny"}, actor=admin)
            with self.assertRaises(ValueError):
                manager.create_operator({"username": "eve", "password": "y" * 12, "role": "superuser"},
                                        actor=admin)

    def test_login_requires_matching_username_and_password_and_rejects_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            manager.create_operator({"username": "alice", "password": "correct horse battery staple"},
                                    actor=None)
            with self.assertRaises(PermissionError):
                manager.login("alice", "wrong password")
            with self.assertRaises(PermissionError):
                manager.login("nobody", "correct horse battery staple")
            session = manager.login("alice", "correct horse battery staple")
            self.assertIn("token", session)
            self.assertEqual(session["operator"]["username"], "alice")
            self.assertEqual(session["operator"]["role"], "admin")
            operator_id = session["operator"]["id"]
            store.data["operators"][0]["disabled"] = True
            with self.assertRaises(PermissionError):
                manager.login("alice", "correct horse battery staple")
            self.assertIsNone(manager.resolve_session(session["token"]))
            self.assertTrue(operator_id)

    def test_resolve_session_round_trips_and_rejects_unknown_or_expired_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            manager.create_operator({"username": "alice", "password": "x" * 12}, actor=None)
            session = manager.login("alice", "x" * 12)
            resolved = manager.resolve_session(session["token"])
            self.assertEqual(resolved["username"], "alice")
            self.assertIsNone(manager.resolve_session(""))
            self.assertIsNone(manager.resolve_session("not-a-real-token"))
            store._sessions[session["token"]]["expires_at_ms"] = 1  # noqa: session store is intentionally not in store.data (see workspace_store.py)
            self.assertIsNone(manager.resolve_session(session["token"]))

    def test_logout_invalidates_the_session(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            manager.create_operator({"username": "alice", "password": "x" * 12}, actor=None)
            session = manager.login("alice", "x" * 12)
            manager.logout(session["token"])
            self.assertIsNone(manager.resolve_session(session["token"]))

    def test_operator_snapshot_never_exposes_credential_material(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            manager.create_operator({"username": "alice", "password": "correct horse battery staple"},
                                    actor=None)
            snapshot_text = str(store.snapshot())
            self.assertNotIn("correct horse battery staple", snapshot_text)
            for operator in store.snapshot()["operators"]:
                self.assertNotIn("password_hash", operator)
                self.assertNotIn("salt", operator)

    def test_snapshot_never_exposes_session_tokens(self):
        # GET /api/workspace hands snapshot() to any authenticated browser, including a
        # viewer -- a session id leaking there would let anyone impersonate whoever it
        # belongs to. Sessions are deliberately not part of self.data at all.
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            manager.create_operator({"username": "alice", "password": "x" * 12}, actor=None)
            session = manager.login("alice", "x" * 12)
            self.assertNotIn(session["token"], str(store.snapshot()))
            self.assertNotIn("sessions", store.snapshot())

    def test_operators_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            manager, store = self.make_manager(directory)
            manager.create_operator({"username": "alice", "password": "correct horse battery staple"},
                                    actor=None)
            restarted_store = WorkspaceStore(store.path)
            restarted_manager = OperatorManager(restarted_store)
            session = restarted_manager.login("alice", "correct horse battery staple")
            self.assertEqual(session["operator"]["username"], "alice")


class ApprovalManagerTests(unittest.TestCase):
    def make_manager(self, directory, executors=None):
        store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
        operators = OperatorManager(store)
        admin = operators.create_operator({"username": "admin", "password": "x" * 12}, actor=None)
        junior = operators.create_operator({"username": "junior", "password": "y" * 12, "role": "operator"},
                                           actor=admin)
        viewer = operators.create_operator({"username": "viewer", "password": "z" * 12, "role": "viewer"},
                                           actor=admin)
        approvals = ApprovalManager(store, executors or {})
        return approvals, store, admin, junior, viewer

    def test_request_rejects_unknown_action_type(self):
        with tempfile.TemporaryDirectory() as directory:
            approvals, store, admin, junior, viewer = self.make_manager(directory)
            with self.assertRaises(ValueError):
                approvals.request("unknown.action", {}, junior)

    def test_viewer_cannot_request_an_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            approvals, store, admin, junior, viewer = self.make_manager(
                directory, executors={"scope.create": lambda payload: payload})
            with self.assertRaises(PermissionError):
                approvals.request("scope.create", {}, viewer)

    def test_operator_can_request_and_pending_approval_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            approvals, store, admin, junior, viewer = self.make_manager(
                directory, executors={"scope.create": lambda payload: payload})
            request = approvals.request("scope.create", {"network": "192.0.2.0/24"}, junior)
            self.assertEqual(request["status"], "pending")
            self.assertEqual(request["requested_by"], junior["id"])

    def test_only_admin_may_decide_and_never_their_own_request(self):
        with tempfile.TemporaryDirectory() as directory:
            approvals, store, admin, junior, viewer = self.make_manager(
                directory, executors={"scope.create": lambda payload: payload})
            request = approvals.request("scope.create", {"network": "192.0.2.0/24"}, junior)
            with self.assertRaisesRegex(PermissionError, "admin"):
                approvals.decide(request["id"], "approved", junior)
            self_request = approvals.request("scope.create", {"network": "192.0.2.0/24"}, admin)
            with self.assertRaisesRegex(PermissionError, "own request"):
                approvals.decide(self_request["id"], "approved", admin)

    def test_approval_executes_the_registered_action_and_records_the_result(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def create_scope(payload):
                calls.append(payload)
                return {"id": "scope-1", **payload}
            approvals, store, admin, junior, viewer = self.make_manager(
                directory, executors={"scope.create": create_scope})
            request = approvals.request("scope.create", {"network": "192.0.2.0/24"}, junior)
            decided = approvals.decide(request["id"], "approved", admin)
            self.assertEqual(decided["status"], "approved")
            self.assertEqual(decided["result"], {"id": "scope-1", "network": "192.0.2.0/24"})
            self.assertEqual(decided["decided_by"], admin["id"])
            self.assertEqual(calls, [{"network": "192.0.2.0/24"}])

    def test_rejection_never_calls_the_executor(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            approvals, store, admin, junior, viewer = self.make_manager(
                directory, executors={"scope.create": lambda payload: calls.append(payload)})
            request = approvals.request("scope.create", {"network": "192.0.2.0/24"}, junior)
            decided = approvals.decide(request["id"], "rejected", admin)
            self.assertEqual(decided["status"], "rejected")
            self.assertEqual(calls, [])

    def test_a_failing_executor_marks_the_approval_failed_with_the_error_captured(self):
        with tempfile.TemporaryDirectory() as directory:
            def failing(_payload):
                raise ValueError("scope already exists")
            approvals, store, admin, junior, viewer = self.make_manager(
                directory, executors={"scope.create": failing})
            request = approvals.request("scope.create", {"network": "192.0.2.0/24"}, junior)
            decided = approvals.decide(request["id"], "approved", admin)
            self.assertEqual(decided["status"], "failed")
            self.assertIn("scope already exists", decided["error"])

    def test_cannot_decide_an_already_decided_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            approvals, store, admin, junior, viewer = self.make_manager(
                directory, executors={"scope.create": lambda payload: payload})
            request = approvals.request("scope.create", {"network": "192.0.2.0/24"}, junior)
            approvals.decide(request["id"], "approved", admin)
            with self.assertRaisesRegex(ValueError, "already"):
                approvals.decide(request["id"], "rejected", admin)

    def test_decide_rejects_unknown_approval_id(self):
        with tempfile.TemporaryDirectory() as directory:
            approvals, store, admin, junior, viewer = self.make_manager(directory)
            with self.assertRaises(KeyError):
                approvals.decide("appr-missing", "approved", admin)


if __name__ == "__main__":
    unittest.main()
