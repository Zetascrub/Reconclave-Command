import os
import signal
import socket
import subprocess
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from tool_runner import ToolRunner


NMAP_XML = """<nmaprun><host><address addr="192.168.1.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host></nmaprun>"""

# NOT captured from a real run: masscan is not installed in this dev environment
# (see docs/platform-roadmap.md's Phase 3 checklist). This follows masscan's
# documented -oX output shape, which is nmap-compatible (host/address/ports/port/
# state elements) and - without --banners, which this adapter never passes - has
# no <service> element, matching nmap's own "unknown" fallback. Treat
# _parse_nmap_xml's masscan path as unverified until run against the real binary.
MASSCAN_XML = """<?xml version="1.0"?><nmaprun scanner="masscan"><host>
<address addr="192.168.1.20" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>
</ports></host></nmaprun>"""

# NOT captured from a real run: arp-scan is not installed in this dev environment
# either. Follows arp-scan's documented --plain output: one "ip\tmac\tvendor" line
# per responding host, vendor sometimes empty for an unrecognised OUI.
ARPSCAN_PLAIN = "192.168.1.1\t00:11:22:33:44:55\tDell Inc.\n192.168.1.5\t66:77:88:99:aa:bb\t\n"

# Captured from a real local run of `dig +noall +answer +time=1 +tries=1 <TYPE> <name>`
# against example.com/github.com (see the adapter's docstring for the exact command
# this mirrors). TTL values are frozen at their captured values.
DIG_A_ANSWER = "example.com.\t\t288\tIN\tA\t172.66.147.243\nexample.com.\t\t288\tIN\tA\t104.20.23.154\n"
DIG_TXT_ANSWER = ('example.com.\t\t300\tIN\tTXT\t"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"\n'
                   'example.com.\t\t300\tIN\tTXT\t"v=spf1 -all"\n')
DIG_CNAME_CHAIN = "www.github.com.\t\t537\tIN\tCNAME\tgithub.com.\ngithub.com.\t\t44\tIN\tA\t20.26.156.215\n"

# NOT captured from a real permitted tcpdump run: this dev sandbox has no CAP_NET_RAW
# (verified: `tcpdump -i lo -c 1` fails with "You don't have permission to perform
# this capture on that device"), so a live capture could not be exercised here. This
# fixture instead follows tcpdump's documented `-q -tttt` one-line-per-packet text
# format. Command construction, interface/host/port validation, and the clean
# permission-denied failure path *were* exercised against the real installed binary
# during development; only _parse_tcpdump_lines below is fixture-only.
TCPDUMP_SAMPLE = ("2026-09-04 22:31:05.123456 IP 192.168.1.10.443 > 192.168.1.20.51234: tcp 0\n"
                   "2026-09-04 22:31:05.124512 IP 192.168.1.20.51234 > 192.168.1.10.443: tcp 0\n")


def _immediate_process(stdout: str = "", stderr: str = "", returncode: int = 0, pid: int = 4242) -> mock.MagicMock:
    process = mock.MagicMock()
    process.communicate.return_value = (stdout, stderr)
    process.returncode = returncode
    process.pid = pid
    process.poll.return_value = returncode
    return process


def _noop_ceiling() -> dict:
    return {"mechanism": "none", "command_prefix": [], "preexec_fn": None, "cgroup_leaf": None}


class ToolRunnerTests(unittest.TestCase):
    def _wait_for_completion(self, runner: ToolRunner, job_id: str, timeout: float = 2.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = runner.job_status({"job_id": job_id})
            if status["job_status"] != "running":
                return status
            time.sleep(0.005)
        self.fail(f"job {job_id} did not finish within {timeout}s")

    # ------------------------------------------------------------------
    # tool.nmap.services - async job model
    # ------------------------------------------------------------------

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_nmap_adapter_returns_immediately_without_blocking_on_the_subprocess(self, popen, _ceiling, _which):
        # communicate() blocks until the test explicitly releases it, so a
        # "running" status read right after nmap_services() returns proves the
        # handler did not block on the subprocess (a real blocking run() call
        # would have hung the test at that point).
        release = threading.Event()
        process = mock.MagicMock()
        process.pid = 4242

        def _communicate(timeout=None):
            release.wait(timeout=5)
            return (NMAP_XML, "")

        process.communicate.side_effect = _communicate
        process.returncode = 0
        popen.return_value = process
        runner = ToolRunner()
        started = runner.nmap_services({"hosts": ["192.168.1.10"], "ports": [443]})
        self.assertEqual(started["job_status"], "running")
        self.assertTrue(started["job_id"].startswith("tool-nmap-"))
        release.set()
        job = self._wait_for_completion(runner, started["job_id"])
        self.assertEqual(job["job_status"], "complete")
        command = popen.call_args.args[0]
        self.assertIn("-sT", command)
        self.assertNotIn("--script", command)
        self.assertEqual(command[-1], "192.168.1.10")
        self.assertEqual(job["result"]["hosts"][0]["services"][0]["service"], "https")
        self.assertTrue(popen.call_args.kwargs.get("start_new_session"))

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_nmap_script_category_is_allowlisted_and_appended_only_when_present(self, popen, _ceiling, _which):
        popen.return_value = _immediate_process(NMAP_XML)
        runner = ToolRunner()
        started = runner.nmap_services({"hosts": ["192.168.1.10"], "ports": [443],
                                        "script_category": "discovery"})
        self._wait_for_completion(runner, started["job_id"])
        command = popen.call_args.args[0]
        self.assertIn("--script", command)
        self.assertEqual(command[command.index("--script") + 1], "discovery")

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    def test_nmap_rejects_unsafe_or_unknown_script_categories_before_starting_any_job(self, _which):
        runner = ToolRunner()
        for bad_category in ("vuln", "exploit", "intrusive", "*", "http-slowloris"):
            with self.assertRaises(ValueError):
                runner.nmap_services({"hosts": ["192.168.1.10"], "ports": [443],
                                      "script_category": bad_category})
        self.assertEqual(runner.jobs, {})

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    def test_adapter_rejects_hostnames_and_unbounded_ports_before_starting_any_job(self, _which):
        runner = ToolRunner()
        with self.assertRaises(ValueError):
            runner.nmap_services({"hosts": ["example.com"], "ports": [443]})
        with self.assertRaises(ValueError):
            runner.nmap_services({"hosts": ["192.168.1.10"], "ports": list(range(1, 130))})
        self.assertEqual(runner.jobs, {})

    @mock.patch.object(ToolRunner, "_file_digest", return_value="a" * 64)
    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    def test_manifest_is_signed_and_binds_executable_identity(self, _which, _digest):
        manifest = ToolRunner(b"k" * 32).manifest("tool.nmap.services")
        self.assertEqual(manifest["executable_sha256"], "a" * 64)
        self.assertEqual(len(manifest["manifest_tag"]), 64)
        self.assertEqual(manifest["isolation"], "bubblewrap-ro-root-v1")
        self.assertIn("resource_limits", manifest)

    @mock.patch.object(ToolRunner, "_file_digest", return_value="a" * 64)
    @mock.patch("tool_runner.shutil.which")
    def test_available_is_gated_on_bwrap_and_each_executable_individually(self, which, _digest):
        # _file_digest is mocked too: manifest() (called by available() for every
        # capability) hashes whatever real file sits at the "which"-reported path for
        # a capability it considers present, and unlike test_manifest_is_signed_and_
        # binds_executable_identity above, this test's whole point is exercising
        # several capabilities' availability at once, on a machine that may not
        # actually have nmap installed at this hardcoded path (e.g. CI).
        def _which(name: str) -> str | None:
            return f"/usr/bin/{name}" if name in ("bwrap", "nmap") else None
        which.side_effect = _which
        availability = ToolRunner().available()
        self.assertTrue(availability["tool.nmap.services"]["available"])
        self.assertFalse(availability["tool.dns.lookup"]["available"])
        self.assertFalse(availability["tool.tcpdump.capture"]["available"])
        self.assertFalse(availability["tool.masscan.services"]["available"])
        self.assertFalse(availability["tool.arpscan.sweep"]["available"])

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------

    def test_terminate_process_group_skips_sigkill_when_process_exits_promptly(self):
        process = mock.MagicMock()
        process.pid = 556
        process.poll.return_value = 0  # already exited by the time we check
        with mock.patch("tool_runner.os.getpgid", return_value=556), \
             mock.patch("tool_runner.os.killpg") as killpg:
            ToolRunner._terminate_process_group(process, grace_seconds=0.05)
        killpg.assert_called_once_with(556, signal.SIGTERM)

    def test_terminate_process_group_escalates_to_sigkill_when_tool_ignores_sigterm(self):
        process = mock.MagicMock()
        process.pid = 557
        process.poll.return_value = None  # never exits on its own
        with mock.patch("tool_runner.os.getpgid", return_value=557), \
             mock.patch("tool_runner.os.killpg") as killpg:
            ToolRunner._terminate_process_group(process, grace_seconds=0.05)
        killpg.assert_any_call(557, signal.SIGTERM)
        killpg.assert_any_call(557, signal.SIGKILL)

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    @mock.patch("tool_runner.os.getpgid", return_value=999)
    @mock.patch("tool_runner.os.killpg")
    def test_job_cancel_terminates_running_job_and_is_idempotent(self, killpg, _getpgid, popen, _ceiling, _which):
        process = mock.MagicMock()
        process.pid = 999
        process.returncode = None

        def _communicate(timeout=None):
            # Block until job_cancel's SIGTERM "reaches" the process, exactly
            # like a real subprocess whose communicate() only returns once the
            # child has actually exited.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not killpg.call_args_list:
                time.sleep(0.005)
            process.returncode = 0
            return ("", "")

        process.communicate.side_effect = _communicate
        process.poll.side_effect = lambda: process.returncode
        popen.return_value = process

        runner = ToolRunner()
        started = runner.nmap_services({"hosts": ["192.168.1.10"], "ports": [443]})
        job_id = started["job_id"]
        self.assertEqual(started["job_status"], "running")
        # Wait for the worker thread to actually reach Popen before cancelling,
        # to avoid racing the cancel against job registration.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and runner.jobs[job_id].get("process") is None:
            time.sleep(0.005)
        self.assertIsNotNone(runner.jobs[job_id].get("process"))

        cancelled = runner.job_cancel({"job_id": job_id})
        self.assertTrue(cancelled["ok"])
        self.assertTrue(cancelled["cancelled"])
        self.assertEqual(cancelled["job_status"], "cancelled")
        killpg.assert_any_call(999, signal.SIGTERM)
        self.assertNotIn(mock.call(999, signal.SIGKILL), killpg.call_args_list)

        # Idempotent: cancelling an already-finished job is still an "ok" no-op.
        second = runner.job_cancel({"job_id": job_id})
        self.assertTrue(second["ok"])
        self.assertFalse(second["cancelled"])

        # Idempotent: cancelling nothing running (unknown job_id) is also "ok".
        missing = runner.job_cancel({"job_id": "tool-nmap-doesnotexist"})
        self.assertTrue(missing["ok"])
        self.assertEqual(missing["job_status"], "not_found")
        self.assertFalse(missing["cancelled"])

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    @mock.patch("tool_runner.os.getpgid", return_value=777)
    @mock.patch("tool_runner.os.killpg")
    @mock.patch("tool_runner.TERMINATE_GRACE_SECONDS", 0.05)
    def test_job_marks_failed_on_timeout_and_terminates_the_process_group(self, killpg, _getpgid, popen, _ceiling, _which):
        process = mock.MagicMock()
        process.pid = 777
        process.returncode = None
        process.poll.return_value = None
        process.communicate.side_effect = [subprocess.TimeoutExpired(cmd="nmap", timeout=1), ("", "")]
        popen.return_value = process
        runner = ToolRunner()
        started = runner.nmap_services({"hosts": ["192.168.1.10"], "ports": [443]})
        job = self._wait_for_completion(runner, started["job_id"], timeout=5.0)
        self.assertEqual(job["job_status"], "failed")
        self.assertIn("timed out", job["error"])
        killpg.assert_any_call(777, signal.SIGTERM)
        killpg.assert_any_call(777, signal.SIGKILL)

    def test_job_status_reports_not_found_for_unknown_job_id(self):
        status = ToolRunner().job_status({"job_id": "does-not-exist"})
        self.assertEqual(status["job_status"], "not_found")

    # ------------------------------------------------------------------
    # Resource ceilings
    # ------------------------------------------------------------------

    def test_resource_ceiling_prefers_a_writable_cgroup_v2_leaf(self):
        with tempfile.TemporaryDirectory() as cgroup_root:
            with open(os.path.join(cgroup_root, "cgroup.controllers"), "w", encoding="utf-8") as handle:
                handle.write("cpuset cpu io memory pids\n")
            with open(os.path.join(cgroup_root, "cgroup.subtree_control"), "w", encoding="utf-8") as handle:
                handle.write("")
            runner = ToolRunner(cgroup_root=cgroup_root)
            ceiling = runner._select_resource_ceiling("job-1", cpu_percent=50, memory_bytes=100 * 1024 * 1024)
            self.assertEqual(ceiling["mechanism"], "cgroup-v2")
            leaf = ceiling["cgroup_leaf"]
            self.assertTrue(os.path.isdir(leaf))
            with open(os.path.join(leaf, "cpu.max"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "50000 100000")
            with open(os.path.join(leaf, "memory.max"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), str(100 * 1024 * 1024))
            self.assertTrue(runner._write_cgroup_pid(leaf, os.getpid()))
            with open(os.path.join(leaf, "cgroup.procs"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), str(os.getpid()))

    def test_resource_ceiling_falls_back_to_systemd_run_when_cgroup_is_not_writable(self):
        with tempfile.TemporaryDirectory() as cgroup_root:
            # No cgroup.controllers file at all -> cgroup leaf creation must decline,
            # exactly like this dev sandbox's real read-only /sys/fs/cgroup.
            runner = ToolRunner(cgroup_root=cgroup_root)
            with mock.patch("tool_runner.shutil.which", return_value="/usr/bin/systemd-run"), \
                 mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}):
                ceiling = runner._select_resource_ceiling("job-2", cpu_percent=75, memory_bytes=256 * 1024 * 1024)
        self.assertEqual(ceiling["mechanism"], "systemd-run")
        self.assertIn("CPUQuota=75%", ceiling["command_prefix"])
        self.assertIn("MemoryMax=268435456", ceiling["command_prefix"])
        self.assertEqual(ceiling["command_prefix"][0], "/usr/bin/systemd-run")

    def test_resource_ceiling_falls_back_to_rlimit_when_neither_cgroup_nor_systemd_available(self):
        with tempfile.TemporaryDirectory() as cgroup_root:
            runner = ToolRunner(cgroup_root=cgroup_root)
            with mock.patch("tool_runner.shutil.which", return_value=None), \
                 mock.patch.dict(os.environ, {}, clear=True):
                ceiling = runner._select_resource_ceiling("job-3")
        self.assertEqual(ceiling["mechanism"], "rlimit")
        self.assertEqual(ceiling["command_prefix"], [])
        self.assertTrue(callable(ceiling["preexec_fn"]))

    def test_resource_ceiling_degrades_to_none_without_crashing_when_nothing_is_available(self):
        with tempfile.TemporaryDirectory() as cgroup_root:
            runner = ToolRunner(cgroup_root=cgroup_root)
            with mock.patch("tool_runner.shutil.which", return_value=None), \
                 mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch("tool_runner.resource", None):
                ceiling = runner._select_resource_ceiling("job-4")
        self.assertEqual(ceiling["mechanism"], "none")
        self.assertIsNone(ceiling["preexec_fn"])

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap")
    @mock.patch("tool_runner.subprocess.Popen")
    def test_job_applies_selected_ceiling_prefix_and_honestly_reports_the_mechanism_used(self, popen, _which):
        popen.return_value = _immediate_process(NMAP_XML, pid=4242)
        forced_ceiling = {
            "mechanism": "systemd-run",
            "command_prefix": ["/usr/bin/systemd-run", "--user", "--scope", "--quiet",
                                "-p", "CPUQuota=100%", "-p", "MemoryMax=536870912", "--"],
            "preexec_fn": None, "cgroup_leaf": None,
        }
        with mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=forced_ceiling):
            runner = ToolRunner()
            started = runner.nmap_services({"hosts": ["192.168.1.10"], "ports": [443]})
            job = self._wait_for_completion(runner, started["job_id"])
        command = popen.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/systemd-run")
        self.assertEqual(job["resource_ceiling"], {"mechanism": "systemd-run", "applied": True})

    def test_job_writes_pid_into_a_real_cgroup_leaf_and_reports_it_applied(self):
        with tempfile.TemporaryDirectory() as cgroup_root:
            with open(os.path.join(cgroup_root, "cgroup.controllers"), "w", encoding="utf-8") as handle:
                handle.write("cpuset cpu io memory pids\n")
            with mock.patch("tool_runner.shutil.which", return_value="/usr/bin/nmap"), \
                 mock.patch("tool_runner.subprocess.Popen") as popen:
                popen.return_value = _immediate_process(NMAP_XML, pid=9999)
                runner = ToolRunner(cgroup_root=cgroup_root)
                started = runner.nmap_services({"hosts": ["192.168.1.10"], "ports": [443]})
                job = self._wait_for_completion(runner, started["job_id"])
            self.assertEqual(job["resource_ceiling"], {"mechanism": "cgroup-v2", "applied": True})
            leaf = os.path.join(cgroup_root, "reconclave-tools", started["job_id"])
            with open(os.path.join(leaf, "cgroup.procs"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "9999")

    # ------------------------------------------------------------------
    # tool.dns.lookup - validated against real captured `dig` output
    # ------------------------------------------------------------------

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/dig")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_dns_lookup_builds_fixed_safe_command_and_parses_real_dig_answer_format(self, popen, _ceiling, _which):
        popen.return_value = _immediate_process(DIG_A_ANSWER)
        runner = ToolRunner()
        started = runner.dns_lookup({"names": ["example.com"], "record_type": "a"})
        job = self._wait_for_completion(runner, started["job_id"])
        command = popen.call_args.args[0]
        self.assertIn("+noall", command)
        self.assertIn("+answer", command)
        self.assertNotIn("+trace", command)
        self.assertEqual(command[-1], "example.com")
        self.assertEqual(job["job_status"], "complete")
        answers = job["result"]["answers"]
        self.assertEqual(len(answers), 2)
        self.assertEqual(answers[0], {"name": "example.com.", "ttl": 288, "class": "IN",
                                       "type": "A", "value": "172.66.147.243"})

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/dig")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_dns_lookup_keeps_quoted_txt_values_with_embedded_spaces_intact(self, popen, _ceiling, _which):
        popen.return_value = _immediate_process(DIG_TXT_ANSWER)
        runner = ToolRunner()
        started = runner.dns_lookup({"names": ["example.com"], "record_type": "TXT"})
        job = self._wait_for_completion(runner, started["job_id"])
        answers = job["result"]["answers"]
        self.assertEqual(answers[1]["value"], '"v=spf1 -all"')

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/dig")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_dns_lookup_parses_a_cname_chain(self, popen, _ceiling, _which):
        popen.return_value = _immediate_process(DIG_CNAME_CHAIN)
        runner = ToolRunner()
        started = runner.dns_lookup({"names": ["www.github.com"], "record_type": "A"})
        job = self._wait_for_completion(runner, started["job_id"])
        answers = job["result"]["answers"]
        self.assertEqual([answer["type"] for answer in answers], ["CNAME", "A"])
        self.assertEqual(answers[1]["value"], "20.26.156.215")

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/dig")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_dns_lookup_nxdomain_is_a_completed_empty_result_not_a_failure(self, popen, _ceiling, _which):
        # Real dig exits 0 with an empty answer section for NXDOMAIN; only a
        # genuine resolver/communication failure returns non-zero (verified
        # against the real binary: `dig @192.0.2.1 ...` exits 9).
        popen.return_value = _immediate_process("", returncode=0)
        runner = ToolRunner()
        started = runner.dns_lookup({"names": ["doesnotexist.invalid"], "record_type": "A"})
        job = self._wait_for_completion(runner, started["job_id"])
        self.assertEqual(job["job_status"], "complete")
        self.assertEqual(job["result"]["answers"], [])

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/dig")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_dns_lookup_reports_resolver_failure_as_a_failed_job(self, popen, _ceiling, _which):
        popen.return_value = _immediate_process("", stderr=";; no servers could be reached", returncode=9)
        runner = ToolRunner()
        started = runner.dns_lookup({"names": ["example.com"], "record_type": "A"})
        job = self._wait_for_completion(runner, started["job_id"])
        self.assertEqual(job["job_status"], "failed")
        self.assertIn("no servers could be reached", job["error"])

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/dig")
    def test_dns_lookup_rejects_invalid_hostnames_unbounded_names_and_bad_record_types(self, _which):
        runner = ToolRunner()
        with self.assertRaises(ValueError):
            runner.dns_lookup({"names": ["not a host"], "record_type": "A"})
        with self.assertRaises(ValueError):
            runner.dns_lookup({"names": [f"h{i}.example.com" for i in range(20)], "record_type": "A"})
        with self.assertRaises(ValueError):
            runner.dns_lookup({"names": ["example.com"], "record_type": "ANY"})
        self.assertEqual(runner.jobs, {})

    # ------------------------------------------------------------------
    # tool.tcpdump.capture - command construction validated against the real
    # binary; parsing validated against a constructed fixture (see module docstring)
    # ------------------------------------------------------------------

    @mock.patch("tool_runner.socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0")])
    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/tcpdump")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_tcpdump_capture_builds_bounded_command_and_parses_constructed_fixture(
            self, popen, _ceiling, _which, _interfaces):
        popen.return_value = _immediate_process(TCPDUMP_SAMPLE)
        runner = ToolRunner()
        started = runner.tcpdump_capture({"interface": "eth0", "count": 2, "host": "192.168.1.10", "port": 443})
        job = self._wait_for_completion(runner, started["job_id"])
        command = popen.call_args.args[0]
        self.assertNotIn("-A", command)  # never dump payload bytes
        self.assertNotIn("-X", command)
        self.assertEqual(command[command.index("-c") + 1], "2")
        self.assertEqual(command[command.index("-i") + 1], "eth0")
        self.assertEqual(command[-5:], ["host", "192.168.1.10", "and", "port", "443"])
        self.assertEqual(job["job_status"], "complete")
        packets = job["result"]["packets"]
        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0]["timestamp"], "2026-09-04 22:31:05.123456")
        self.assertIn("192.168.1.10.443", packets[0]["summary"])

    @mock.patch("tool_runner.socket.if_nameindex", return_value=[(1, "lo")])
    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/tcpdump")
    def test_tcpdump_capture_rejects_unknown_interface_and_out_of_bound_count(self, _which, _interfaces):
        runner = ToolRunner()
        with self.assertRaises(ValueError):
            runner.tcpdump_capture({"interface": "eth9", "count": 1})
        with self.assertRaises(ValueError):
            runner.tcpdump_capture({"interface": "lo", "count": 999})
        self.assertEqual(runner.jobs, {})

    def test_tcpdump_command_construction_and_permission_denied_path_against_real_binary(self):
        # Not mocked: exercises the actually-installed tcpdump/bwrap on this host.
        # Without CAP_NET_RAW (true of this sandbox and most non-root CI runners)
        # capture must fail cleanly through the normal async "failed" job path
        # rather than hang or crash the process.
        if shutil.which("tcpdump") is None or shutil.which("bwrap") is None:
            self.skipTest("tcpdump/bwrap not installed on this host")
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("running as root would actually capture instead of hitting the permission-denied path")
        runner = ToolRunner()
        started = runner.tcpdump_capture({"interface": "lo", "count": 1})
        job = self._wait_for_completion(runner, started["job_id"], timeout=15.0)
        self.assertEqual(job["job_status"], "failed")
        self.assertTrue(job["error"])

    # ------------------------------------------------------------------
    # tool.masscan.services - fixture-based only; masscan is not installed in
    # this dev environment (see MASSCAN_XML's comment and the real-binary test
    # below, which self-skips until it is).
    # ------------------------------------------------------------------

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/masscan")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_masscan_adapter_uses_a_fixed_non_operator_settable_rate(self, popen, _ceiling, _which):
        popen.return_value = _immediate_process(MASSCAN_XML)
        runner = ToolRunner()
        started = runner.masscan_services({"hosts": ["192.168.1.20"], "ports": [22]})
        self.assertTrue(started["job_id"].startswith("tool-masscan-"))
        job = self._wait_for_completion(runner, started["job_id"])
        command = popen.call_args.args[0]
        self.assertIn("--rate", command)
        self.assertEqual(command[command.index("--rate") + 1], "100")
        self.assertNotIn("--banners", command)
        self.assertEqual(job["job_status"], "complete")
        self.assertEqual(job["result"]["tool"], "masscan")
        self.assertEqual(job["result"]["hosts"][0]["services"][0]["port"], 22)

    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/masscan")
    def test_masscan_adapter_rejects_the_same_bounds_as_nmap(self, _which):
        runner = ToolRunner()
        with self.assertRaises(ValueError):
            runner.masscan_services({"hosts": ["example.com"], "ports": [443]})
        with self.assertRaises(ValueError):
            runner.masscan_services({"hosts": ["192.168.1.20"], "ports": list(range(1, 130))})
        self.assertEqual(runner.jobs, {})

    def test_masscan_command_construction_against_real_binary_if_installed(self):
        # Self-skips until masscan/bwrap are actually installed - see the module
        # docstring's fixture caveat above. Once installed, this exercises the
        # real permission story too: masscan needs CAP_NET_RAW on its own binary
        # (the manifest's "notes"), which a fresh install won't have yet, so this
        # is expected to land in the normal "failed" job path, not "complete",
        # until an operator runs the documented setcap step.
        if shutil.which("masscan") is None or shutil.which("bwrap") is None:
            self.skipTest("masscan/bwrap not installed on this host")
        runner = ToolRunner()
        started = runner.masscan_services({"hosts": ["127.0.0.1"], "ports": [22]})
        job = self._wait_for_completion(runner, started["job_id"], timeout=15.0)
        self.assertIn(job["job_status"], ("complete", "failed"))

    # ------------------------------------------------------------------
    # tool.arpscan.sweep - fixture-based only; arp-scan is not installed in this
    # dev environment either.
    # ------------------------------------------------------------------

    @mock.patch("tool_runner.socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0")])
    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/arp-scan")
    @mock.patch.object(ToolRunner, "_select_resource_ceiling", return_value=_noop_ceiling())
    @mock.patch("tool_runner.subprocess.Popen")
    def test_arpscan_adapter_builds_local_segment_command_and_parses_plain_output(
            self, popen, _ceiling, _which, _interfaces):
        popen.return_value = _immediate_process(ARPSCAN_PLAIN)
        runner = ToolRunner()
        started = runner.arpscan_sweep({"interface": "eth0"})
        self.assertTrue(started["job_id"].startswith("tool-arpscan-"))
        job = self._wait_for_completion(runner, started["job_id"])
        command = popen.call_args.args[0]
        self.assertIn("--localnet", command)
        self.assertIn("--plain", command)
        self.assertEqual(command[command.index("--interface") + 1], "eth0")
        self.assertEqual(job["job_status"], "complete")
        hosts = job["result"]["hosts"]
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0], {"address": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Dell Inc."})
        self.assertEqual(hosts[1]["vendor"], "")

    @mock.patch("tool_runner.socket.if_nameindex", return_value=[(1, "lo")])
    @mock.patch("tool_runner.shutil.which", return_value="/usr/bin/arp-scan")
    def test_arpscan_rejects_unknown_interface_before_starting_any_job(self, _which, _interfaces):
        runner = ToolRunner()
        with self.assertRaises(ValueError):
            runner.arpscan_sweep({"interface": "eth9"})
        self.assertEqual(runner.jobs, {})

    def test_arpscan_command_construction_against_real_binary_if_installed(self):
        # Self-skips until arp-scan/bwrap are actually installed - same caveat and
        # expected-permission-failure story as masscan's real-binary test above
        # (arp-scan also needs CAP_NET_RAW on its own binary to send raw frames).
        if shutil.which("arp-scan") is None or shutil.which("bwrap") is None:
            self.skipTest("arp-scan/bwrap not installed on this host")
        runner = ToolRunner()
        interface = next((name for _, name in socket.if_nameindex() if name != "lo"), "lo")
        started = runner.arpscan_sweep({"interface": interface})
        job = self._wait_for_completion(runner, started["job_id"], timeout=15.0)
        self.assertIn(job["job_status"], ("complete", "failed"))


if __name__ == "__main__":
    unittest.main()
