import pathlib
import tempfile
import unittest

from workspace_store import WorkspaceStore


def _host_bound_finding(project_id: str, target: str, port: int, finding_id: str = "f1") -> dict:
    return {"id": finding_id, "project_id": project_id, "source": "nessus", "plugin_id": "123",
            "title": "TLS issue", "target": target, "port": port, "severity": "high",
            "confidence": .95, "risk_score": 9.03, "description": "Weak config",
            "solution": "Harden", "cves": ["CVE-2024-1234"], "status": "open"}


def _template_finding(project_id: str, title: str, description: str, finding_id: str = "t1") -> dict:
    return {"id": finding_id, "project_id": project_id, "source": "nessus-nasl", "plugin_id": "9001",
            "title": title, "target": "template", "port": None, "severity": "medium",
            "confidence": .5, "risk_score": 2.5, "description": description,
            "solution": "Upgrade", "cves": ["CVE-2023-1111"], "status": "open"}


class WorkspaceStoreTests(unittest.TestCase):
    def test_project_job_and_evidence_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "workspace.json"
            store = WorkspaceStore(path)
            project = store.create_project({"name": "Lab", "description": "Authorised range"})
            job = store.upsert_job({"id": "job-1", "project_id": project["id"],
                                    "provider_id": "rc-p4", "capability": "net.discovery.scan",
                                    "status": "running", "checked": 2, "total": 10})
            store.upsert_job({**job, "status": "complete", "hosts": ["192.0.2.4"]})
            evidence = store.add_evidence({"id": "ev-1", "project_id": project["id"],
                                           "job_id": "job-1", "kind": "network-hosts",
                                           "data": {"hosts": ["192.0.2.4"]}})
            self.assertEqual(evidence["id"], "ev-1")
            restored = WorkspaceStore(path).snapshot()
            self.assertEqual(restored["jobs"][0]["status"], "complete")
            self.assertEqual(restored["evidence"][0]["data"]["hosts"], ["192.0.2.4"])

            rule = store.create_automation({"project_id": project["id"], "node_id": "rc-p4",
                                            "condition": "dhcp_assigned",
                                            "playbook": "system_snapshot", "interval_ms": 0})
            store.set_automation(rule["id"], {"enabled": False})
            self.assertFalse(WorkspaceStore(path).snapshot()["automations"][0]["enabled"])
            store.delete_automation(rule["id"])
            self.assertEqual(store.snapshot()["automations"], [])

    def test_rejects_job_for_unknown_project(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            with self.assertRaisesRegex(ValueError, "project does not exist"):
                store.upsert_job({"id": "job-1", "project_id": "missing"})

    def test_automation_rejects_arbitrary_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            with self.assertRaisesRegex(ValueError, "unsupported automation playbook"):
                store.create_automation({"project_id": project["id"], "node_id": "rc-p4",
                                         "condition": "dhcp_assigned", "playbook": "shell"})

    def test_evidence_chain_detects_content_and_order_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "workspace.json"
            store = WorkspaceStore(path)
            project = store.create_project({"name": "Lab"})
            first = store.add_evidence({"project_id": project["id"], "kind": "observation",
                                        "data": {"value": 1}})
            second = store.add_evidence({"project_id": project["id"], "kind": "observation",
                                         "data": {"value": 2}})
            self.assertEqual(second["previous_sha256"], first["chain_sha256"])
            self.assertTrue(WorkspaceStore(path).verify_evidence(project["id"])["valid"])
            store.data["evidence"][0]["data"]["value"] = 9
            verification = store.verify_evidence(project["id"])
            self.assertFalse(verification["valid"])
            self.assertIn(first["id"], verification["errors"])

    def test_evidence_provenance_is_bounded_normalised_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "workspace.json"
            store = WorkspaceStore(path)
            project = store.create_project({"name": "Lab"})
            # Absent/malformed provenance never breaks a plain evidence write, and
            # never appears on the stored record - matching every pre-existing
            # record that predates this field.
            plain = store.add_evidence({"project_id": project["id"], "data": {"value": 1}})
            self.assertNotIn("provenance", plain)
            malformed = store.add_evidence({"project_id": project["id"], "data": {"value": 2},
                                            "provenance": "not-a-dict"})
            self.assertNotIn("provenance", malformed)
            signed = store.add_evidence({"project_id": project["id"], "data": {"value": 3},
                                         "provenance": {"source_node": "rc-p4", "verified": True,
                                                        "response_nonce": "n" * 16, "response_tag": "t" * 32,
                                                        "algorithm": "hmac-sha256-truncated16",
                                                        "unexpected_field": "dropped",
                                                        "source_node_overlong": "x" * 200}})
            self.assertEqual(signed["provenance"]["source_node"], "rc-p4")
            self.assertNotIn("unexpected_field", signed["provenance"])
            self.assertTrue(store.verify_evidence(project["id"])["valid"])
            self.assertEqual(WorkspaceStore(path).verify_evidence(project["id"])["valid"], True)

    def test_evidence_bundle_has_verifiable_manifest_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.add_evidence({"project_id": project["id"], "data": {"value": 1}})
            bundle = store.evidence_bundle(project["id"])
            self.assertEqual(bundle["schema"], "reconclave-evidence-bundle/v1")
            self.assertEqual(len(bundle["bundle_sha256"]), 64)
            self.assertEqual(len(bundle["bundle_tag"]), 64)

    def test_audit_pagination_orders_newest_first_with_stable_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            for index in range(5):
                store.add_audit_event({"action": "test.event", "subject_id": str(index)})
            first_page = store.list_audit_events(limit=2)
            self.assertEqual([item["subject_id"] for item in first_page["events"]], ["4", "3"])
            self.assertEqual(first_page["total"], 5)
            self.assertTrue(first_page["next_cursor"])

            # A record appended between page fetches must not shift the
            # already-issued cursor's continuation point.
            store.add_audit_event({"action": "test.event", "subject_id": "5-late"})
            second_page = store.list_audit_events(cursor=first_page["next_cursor"], limit=2)
            self.assertEqual([item["subject_id"] for item in second_page["events"]], ["2", "1"])

            third_page = store.list_audit_events(cursor=second_page["next_cursor"], limit=2)
            self.assertEqual([item["subject_id"] for item in third_page["events"]], ["0"])
            self.assertEqual(third_page["next_cursor"], "")

    def test_audit_pagination_limit_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            for index in range(3):
                store.add_audit_event({"action": "test.event", "subject_id": str(index)})
            self.assertEqual(len(store.list_audit_events(limit=0)["events"]), 1)
            self.assertEqual(len(store.list_audit_events(limit=10000)["events"]), 3)

    def test_audit_pagination_unknown_cursor_returns_empty_page(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            store.add_audit_event({"action": "test.event", "subject_id": "0"})
            page = store.list_audit_events(cursor="audit-does-not-exist")
            self.assertEqual(page["events"], [])
            self.assertEqual(page["next_cursor"], "")

    def test_audit_pagination_filters_by_project(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.add_audit_event({"action": "test.event", "project_id": project["id"], "subject_id": "in"})
            store.add_audit_event({"action": "test.event", "project_id": "other", "subject_id": "out"})
            page = store.list_audit_events(project_id=project["id"])
            self.assertEqual([item["subject_id"] for item in page["events"]], ["in"])

    def test_prune_audit_events_removes_by_age_and_records_the_action(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            old = store.add_audit_event({"action": "test.event", "subject_id": "old"})
            store.data["audit_events"][0]["created_at_ms"] -= 10_000_000
            store.add_audit_event({"action": "test.event", "subject_id": "recent"})
            result = store.prune_audit_events(max_age_ms=1_000_000)
            self.assertEqual(result["removed_count"], 1)
            remaining_ids = [item["id"] for item in store.snapshot()["audit_events"]]
            self.assertNotIn(old["id"], remaining_ids)
            prune_records = [item for item in store.snapshot()["audit_events"]
                             if item["action"] == "audit.pruned"]
            self.assertEqual(len(prune_records), 1)
            self.assertEqual(prune_records[0]["removed_count"], 1)
            self.assertEqual(prune_records[0]["retention_policy"], {"max_age_ms": 1_000_000, "max_count": None})

    def test_prune_audit_events_enforces_max_count_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            for index in range(5):
                store.add_audit_event({"action": "test.event", "subject_id": str(index)})
            result = store.prune_audit_events(max_count=3)
            self.assertEqual(result["removed_count"], 2)
            kept = [item["subject_id"] for item in store.snapshot()["audit_events"]
                   if item["action"] == "test.event"]
            self.assertEqual(kept, ["2", "3", "4"])

    def test_prune_audit_events_requires_a_bound_and_rejects_negative_values(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            with self.assertRaisesRegex(ValueError, "retention bound"):
                store.prune_audit_events()
            with self.assertRaisesRegex(ValueError, "max_age_ms"):
                store.prune_audit_events(max_age_ms=-1)
            with self.assertRaisesRegex(ValueError, "max_count"):
                store.prune_audit_events(max_count=-1)

    def test_audit_bundle_has_verifiable_signed_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            store.add_audit_event({"action": "test.event", "subject_id": "0"})
            bundle = store.audit_bundle()
            self.assertEqual(bundle["schema"], "reconclave-audit-bundle/v1")
            self.assertEqual(len(bundle["bundle_sha256"]), 64)
            self.assertEqual(len(bundle["bundle_tag"]), 64)
            expected_tag = __import__("hmac").new(
                store.custody_key, bundle["bundle_sha256"].encode(),
                __import__("hashlib").sha256).hexdigest()
            self.assertEqual(bundle["bundle_tag"], expected_tag)

    def test_audit_bundle_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            store.add_audit_event({"action": "test.event", "subject_id": "0"})
            bundle = store.audit_bundle()
            tampered = dict(bundle)
            tampered["records"] = [{**record, "outcome": "tampered"} for record in tampered["records"]]
            recomputed_digest = __import__("hashlib").sha256(
                __import__("json").dumps({k: v for k, v in tampered.items()
                                          if k not in ("bundle_sha256", "bundle_tag")},
                                         sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.assertNotEqual(recomputed_digest, tampered["bundle_sha256"])

    def test_audit_bundle_filters_by_project(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.add_audit_event({"action": "test.event", "project_id": project["id"], "subject_id": "in"})
            store.add_audit_event({"action": "test.event", "project_id": "other", "subject_id": "out"})
            bundle = store.audit_bundle(project["id"])
            self.assertEqual([item["subject_id"] for item in bundle["records"]], ["in"])

    def test_finding_status_transitions_validate_and_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [_host_bound_finding(project["id"], "10.0.0.5", 443)])
            updated = store.set_finding_status("f1", "confirmed", note="verified manually")
            self.assertEqual(updated["status"], "confirmed")
            events = [item for item in store.snapshot()["audit_events"] if item["action"] == "finding.status"]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["old_status"], "open")
            self.assertEqual(events[0]["new_status"], "confirmed")
            self.assertEqual(events[0]["note"], "verified manually")
            # confirmed -> candidate is not an allowed transition.
            with self.assertRaisesRegex(ValueError, "cannot transition"):
                store.set_finding_status("f1", "candidate")
            # Re-setting the same status is an idempotent no-op, not an error,
            # and does not add a second audit event.
            store.set_finding_status("f1", "confirmed")
            events_after = [item for item in store.snapshot()["audit_events"] if item["action"] == "finding.status"]
            self.assertEqual(len(events_after), 1)
            with self.assertRaises(KeyError):
                store.set_finding_status("missing-id", "confirmed")

    def test_finding_suppression_excludes_from_active_counts_and_never_deletes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [_host_bound_finding(project["id"], "10.0.0.5", 443)])
            suppressed = store.set_finding_suppression("f1", True, reason="accepted risk")
            self.assertTrue(suppressed["suppressed"])
            self.assertEqual(suppressed["suppression_reason"], "accepted risk")
            self.assertGreater(suppressed["suppressed_at_ms"], 0)
            self.assertEqual(len(store.snapshot()["findings"]), 1)  # still in the ledger
            bundle = store.findings_bundle(project["id"])
            self.assertEqual(bundle["summary"]["total"], 1)
            self.assertEqual(bundle["summary"]["suppressed"], 1)
            self.assertEqual(bundle["summary"]["active"], 0)
            cleared = store.set_finding_suppression("f1", False)
            self.assertFalse(cleared["suppressed"])
            self.assertEqual(cleared["suppression_reason"], "")
            self.assertEqual(cleared["suppressed_at_ms"], 0)
            self.assertEqual(store.findings_bundle(project["id"])["summary"]["active"], 1)

    def test_finding_remediation_tracking_persists_and_audits(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [_host_bound_finding(project["id"], "10.0.0.5", 443)])
            updated = store.set_finding_remediation("f1", {"owner": "ops-team", "due_at_ms": 5000,
                                                            "notes": "Patch TLS config", "status": "in_progress"})
            self.assertEqual(updated["remediation"], {"owner": "ops-team", "due_at_ms": 5000,
                                                       "notes": "Patch TLS config", "status": "in_progress"})
            events = [item for item in store.snapshot()["audit_events"] if item["action"] == "finding.remediation"]
            self.assertEqual(len(events), 1)
            with self.assertRaisesRegex(ValueError, "remediation status"):
                store.set_finding_remediation("f1", {"status": "bogus"})

    def test_upsert_findings_reimport_preserves_operator_disposition(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [_host_bound_finding(project["id"], "10.0.0.5", 443)])
            store.set_finding_status("f1", "false_positive")
            store.set_finding_suppression("f1", True, reason="dup of f2")
            # Re-importing the identical finding (same id) must not reset the
            # operator's disposition or suppression back to defaults.
            reimported = store.upsert_findings(project["id"], [_host_bound_finding(project["id"], "10.0.0.5", 443)])
            self.assertEqual(reimported[0]["status"], "false_positive")
            self.assertTrue(reimported[0]["suppressed"])
            self.assertEqual(reimported[0]["suppression_reason"], "dup of f2")

    def test_correlate_findings_confirms_exact_match_and_creates_reviewable_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [
                _host_bound_finding(project["id"], "10.0.0.5", 443, finding_id="f1"),
                _template_finding(project["id"], "Weak SSH host key algorithms",
                                  "SSH server allows weak key exchange algorithms", finding_id="t1"),
            ])
            store.add_evidence({"id": "ev-1", "project_id": project["id"], "kind": "tcp-services",
                                "data": {"hosts": [{"address": "10.0.0.5", "open_ports": [443]}]}})
            store.add_evidence({"id": "ev-2", "project_id": project["id"], "job_id": "job-9",
                                "kind": "nmap-services",
                                "data": {"hosts": [{"address": "10.0.0.9",
                                                    "services": [{"port": 22, "service": "ssh"}]}]}})
            result = store.correlate_findings(project["id"])
            self.assertEqual(result["confirmed_finding_ids"], ["f1"])
            self.assertEqual(result["confirmed_count"], 1)
            self.assertEqual(result["new_candidate_count"], 1)
            findings_by_id = {item["id"]: item for item in store.snapshot()["findings"]}
            self.assertEqual(findings_by_id["f1"]["status"], "confirmed-observed")
            candidate = result["new_candidates"][0]
            self.assertEqual(candidate["status"], "candidate")
            self.assertEqual(candidate["provenance"]["matched_template_id"], "t1")
            self.assertIn(candidate["id"], findings_by_id)
            audited = [item for item in store.snapshot()["audit_events"] if item["action"] == "findings.correlated"]
            self.assertEqual(len(audited), 1)
            self.assertEqual(audited[0]["confirmed_count"], 1)
            self.assertEqual(audited[0]["new_candidate_count"], 1)
            # Re-running correlation over the same evidence must not duplicate
            # the candidate or re-confirm (and re-audit) the same finding.
            second = store.correlate_findings(project["id"])
            self.assertEqual(second["confirmed_count"], 0)
            self.assertEqual(second["new_candidate_count"], 0)
            self.assertEqual(len(store.snapshot()["findings"]), 3)

    def test_correlate_findings_never_overrides_an_operator_disposition_or_suppression(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [_host_bound_finding(project["id"], "10.0.0.5", 443)])
            store.set_finding_status("f1", "false_positive")
            store.add_evidence({"project_id": project["id"], "kind": "tcp-services",
                                "data": {"hosts": [{"address": "10.0.0.5", "open_ports": [443]}]}})
            result = store.correlate_findings(project["id"])
            self.assertEqual(result["confirmed_count"], 0)
            self.assertEqual(store.snapshot()["findings"][0]["status"], "false_positive")

            store2 = WorkspaceStore(pathlib.Path(directory) / "workspace2.json")
            project2 = store2.create_project({"name": "Lab2"})
            store2.upsert_findings(project2["id"], [_host_bound_finding(project2["id"], "10.0.0.5", 443)])
            store2.set_finding_suppression("f1", True, reason="known/accepted")
            store2.add_evidence({"project_id": project2["id"], "kind": "tcp-services",
                                 "data": {"hosts": [{"address": "10.0.0.5", "open_ports": [443]}]}})
            result2 = store2.correlate_findings(project2["id"])
            self.assertEqual(result2["confirmed_count"], 0)
            self.assertEqual(store2.snapshot()["findings"][0]["status"], "open")
            self.assertTrue(store2.snapshot()["findings"][0]["suppressed"])

    def test_correlate_findings_rejects_unknown_project(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            with self.assertRaisesRegex(ValueError, "project does not exist"):
                store.correlate_findings("missing")

    def test_findings_bundle_has_verifiable_signed_manifest_with_matching_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [
                _host_bound_finding(project["id"], "10.0.0.5", 443, finding_id="f1"),
                _host_bound_finding(project["id"], "10.0.0.6", 8080, finding_id="f2"),
            ])
            store.set_finding_suppression("f2", True, reason="dup")
            bundle = store.findings_bundle(project["id"])
            self.assertEqual(bundle["schema"], "reconclave-findings-bundle/v1")
            self.assertEqual(len(bundle["bundle_sha256"]), 64)
            self.assertEqual(len(bundle["bundle_tag"]), 64)
            self.assertEqual(bundle["summary"]["total"], 2)
            self.assertEqual(bundle["summary"]["active"], 1)
            self.assertEqual(bundle["summary"]["suppressed"], 1)
            self.assertEqual(bundle["summary"]["by_severity"], {"high": 2})
            self.assertEqual(len(bundle["records"]), 2)
            expected_tag = __import__("hmac").new(
                store.custody_key, bundle["bundle_sha256"].encode(),
                __import__("hashlib").sha256).hexdigest()
            self.assertEqual(bundle["bundle_tag"], expected_tag)

    def test_findings_bundle_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Lab"})
            store.upsert_findings(project["id"], [_host_bound_finding(project["id"], "10.0.0.5", 443)])
            bundle = store.findings_bundle(project["id"])
            tampered = dict(bundle)
            tampered["records"] = [{**record, "severity": "critical"} for record in tampered["records"]]
            recomputed_digest = __import__("hashlib").sha256(
                __import__("json").dumps({k: v for k, v in tampered.items()
                                          if k not in ("bundle_sha256", "bundle_tag")},
                                         sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            self.assertNotEqual(recomputed_digest, tampered["bundle_sha256"])

    # -- OTA artifact blob storage (fleet_manager.create_release) -----------

    def test_store_ota_artifact_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            with self.assertRaisesRegex(ValueError, "do not match"):
                store.store_ota_artifact("a" * 64, b"these bytes do not hash to a"*64)

    def test_store_and_read_ota_artifact_round_trips_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "workspace.json"
            store = WorkspaceStore(path)
            data = b"\x00\x01firmware-bytes\x02\x03" * 100
            digest = __import__("hashlib").sha256(data).hexdigest()
            store.store_ota_artifact(digest, data)
            self.assertEqual(store.read_ota_artifact(digest), data)
            self.assertIsNone(store.read_ota_artifact("0" * 64))
            # The blob lives outside the JSON snapshot -- restarting the store must not
            # lose it, and the snapshot itself must not have grown to contain it.
            restored = WorkspaceStore(path)
            self.assertEqual(restored.read_ota_artifact(digest), data)
            self.assertNotIn(data.decode("latin-1"), __import__("json").dumps(store.snapshot()))

    def test_ota_artifact_path_rejects_non_hex_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            with self.assertRaises(ValueError):
                store.read_ota_artifact("../../etc/passwd")
            with self.assertRaises(ValueError):
                store.store_ota_artifact("not-hex", b"data")


if __name__ == "__main__":
    unittest.main()
