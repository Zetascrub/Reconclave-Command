import hashlib
import pathlib
import tempfile
import unittest

from field_report import import_field_report, normalise_field_report
from workspace_store import WorkspaceStore


def fixture():
    summary = "Reconclave staged enumeration\nScope: 192.168.8.128/27\nOutcome: complete\n"
    return {"schema": "sightline-field-report/v1", "mission_id": "a" * 16,
            "context": {"project_id": "CLIENT", "engagement_id": "SITE", "operator_id": "TEST"},
            "scope": "192.168.8.128/27", "interface": "eth0", "source_ip": "192.168.8.140",
            "profile": "deep", "outcome": "complete", "finished_at": 1790000000,
            "metrics": {"deep_hosts_checked": 1},
            "hosts": [{"address": "192.168.8.141", "open_ports": [50001, 80],
                       "tcp_coverage": "all-65535"}],
            "summary_text": summary, "summary_sha256": hashlib.sha256(summary.encode()).hexdigest(),
            "files": [{"name": "enumeration.txt", "size": len(summary),
                       "sha256": hashlib.sha256(summary.encode()).hexdigest()}]}


class FieldReportTests(unittest.TestCase):
    def test_import_and_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Client"})
            imported = import_field_report(store, project["id"], fixture())
            self.assertEqual(imported["kind"], "sightline-field-report")
            self.assertFalse(imported["data"]["origin_verified"])
            self.assertEqual(imported["data"]["hosts"][0]["open_ports"], [80, 50001])
            self.assertTrue(store.verify_evidence(project["id"])["valid"])
            self.assertEqual(import_field_report(store, project["id"], fixture())["id"], imported["id"])
            self.assertEqual(len(store.snapshot()["evidence"]), 1)

    def test_rejects_tampering_and_out_of_scope_hosts(self):
        report = fixture()
        report["summary_text"] += "altered"
        with self.assertRaisesRegex(ValueError, "hash"):
            normalise_field_report(report)
        report = fixture()
        report["hosts"][0]["address"] = "192.168.9.1"
        with self.assertRaisesRegex(ValueError, "outside scope"):
            normalise_field_report(report)
        report = fixture()
        report["files"][0]["name"] = "../escape"
        with self.assertRaisesRegex(ValueError, "inventory"):
            normalise_field_report(report)

    def test_responding_host_without_open_ports_and_invalid_time(self):
        report = fixture()
        report["hosts"].append({"address": "192.168.8.142", "open_ports": [],
                                "tcp_coverage": "top-100-at-most"})
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(pathlib.Path(directory) / "workspace.json")
            project = store.create_project({"name": "Client"})
            imported = import_field_report(store, project["id"], report)
            self.assertIn("1 hosts with open TCP", imported["summary"])
            self.assertEqual(len(imported["data"]["hosts"]), 2)
        report["finished_at"] = 10**30
        with self.assertRaisesRegex(ValueError, "completion time"):
            normalise_field_report(report)


if __name__ == "__main__":
    unittest.main()
